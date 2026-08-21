// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The single-owner actor and the handle consumers hold (SPEC §11.4, §11.5).
//!
//! One task owns the [`Vault`] and the [`SyncEngine`] by value; every call is a
//! [`Command`] on a channel, and the reply is an owned DTO or a [`FacadeError`]. The
//! engine's deliberately-`!Send` browser future stays inside the task, and the vault's
//! exclusive `&mut` access needs no consumer-visible lock. Lock state lives here, not
//! in the shells: auto-lock is a wake-checked absolute deadline (§11.5).
//!
//! # Not yet implemented in this cut
//!
//! Async commands are awaited inline, one at a time. The §11.4.2 preemption model —
//! `Lock`/`Shutdown` dropping an in-flight sync future — is a follow-up: here a `Lock`
//! issued while a sync is running is processed after that sync returns. The command
//! surface is also a subset (unlock/lock/add/read/generate/sync); enrollment,
//! revocation, groups, and the remaining mutators land next.

use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};

use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::keys::VaultKey;
use misty_otp::Clock;
use misty_sync::{duplicate_identity, StateStore, SyncEngine, Transport};
use misty_vault::{NewItem, Vault, VaultStore};

use crate::clock::HostClock;
use crate::dto::{CodeView, GroupView, ItemView, NewItemInput, SortKey, SyncReportView};
use crate::error::{ErrorCode, FacadeError, Result};

/// A lifecycle event a shell reports to the facade (SPEC §11.5.5). The shell reports;
/// the facade decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// The app was backgrounded or its tab hidden — lock now.
    Backgrounded,
    /// The OS screen lock engaged — lock now.
    ScreenLocked,
    /// The device is entering sleep — lock now.
    WillSleep,
    /// The user interacted — extend the deadline.
    UserActivity,
}

/// The facade's lock state, surfaced to the consumer as an owned DTO (SPEC §11.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LockState {
    /// Whether the vault is currently locked.
    pub locked: bool,
}

/// The facade's owned state (SPEC §11.5). Internal — it names the non-boundary
/// `Vault<S, C>` and never crosses the FFI edge; only [`LockState`] does.
enum Lifecycle<S: VaultStore, C: Clock> {
    /// Ciphertext only: the store, no `VaultKey`, no plaintext item in memory.
    Locked { store: S },
    /// A live vault owning the `VaultKey`; `deadline_ms` is a host-clock reading. The
    /// vault is boxed so the enum's variants stay close in size.
    Unlocked {
        vault: Box<Vault<S, C>>,
        vault_key: VaultKey,
        deadline_ms: i64,
    },
    /// Transient placeholder held only across a state transition.
    Poisoned,
}

/// One message into the owning task (SPEC §11.4.1). Every payload and reply is owned
/// and `'static`; no borrow of core state crosses the channel.
enum Command {
    Unlock {
        key_material: zeroize::Zeroizing<Vec<u8>>,
        reply: oneshot::Sender<Result<()>>,
    },
    Lock {
        reply: oneshot::Sender<()>,
    },
    LockStatus {
        reply: oneshot::Sender<LockState>,
    },
    /// A wake-only poll (SPEC §11.5.4): re-run the deadline check, carry no decision.
    Poll {
        reply: oneshot::Sender<LockState>,
    },
    ReportLifecycle {
        event: LifecycleEvent,
        reply: oneshot::Sender<LockState>,
    },
    List {
        reply: oneshot::Sender<Result<Vec<ItemView>>>,
    },
    Get {
        id: String,
        reply: oneshot::Sender<Result<Option<ItemView>>>,
    },
    Item {
        id: String,
        reply: oneshot::Sender<Result<ItemView>>,
    },
    Add {
        input: Box<NewItemInput>,
        reply: oneshot::Sender<Result<String>>,
    },
    GenerateCode {
        id: String,
        reply: oneshot::Sender<Result<CodeView>>,
    },
    SyncOnce {
        reply: oneshot::Sender<Result<SyncReportView>>,
    },
    Search {
        query: String,
        reply: oneshot::Sender<Result<Vec<ItemView>>>,
    },
    Sorted {
        key: SortKey,
        reply: oneshot::Sender<Result<Vec<ItemView>>>,
    },
    Trash {
        reply: oneshot::Sender<Result<Vec<ItemView>>>,
    },
    Groups {
        reply: oneshot::Sender<Result<Vec<GroupView>>>,
    },
    Group {
        id: String,
        reply: oneshot::Sender<Result<GroupView>>,
    },
    Conflicts {
        reply: oneshot::Sender<Result<Vec<Conflict>>>,
    },
    TrashItem {
        id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    RestoreItem {
        id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    DeleteItem {
        id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    RecordUse {
        id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    AddGroup {
        name: String,
        reply: oneshot::Sender<Result<String>>,
    },
    DeleteGroup {
        id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}
/// The handle consumers hold (SPEC §11.4): non-generic, cheap to clone. Every method
/// sends one [`Command`] to the owning task and awaits the owned reply.
#[derive(Clone, Debug)]
pub struct Facade {
    tx: mpsc::Sender<Command>,
}

impl Facade {
    async fn dispatch<R>(&self, build: impl FnOnce(oneshot::Sender<R>) -> Command) -> Result<R> {
        let (reply, rx) = oneshot::channel();
        let mut tx = self.tx.clone();
        tx.send(build(reply))
            .await
            .map_err(|_| FacadeError::internal("core task stopped"))?;
        rx.await
            .map_err(|_| FacadeError::internal("core task dropped the reply"))
    }

    /// Unlock the vault with raw key material (SPEC §11.5); zeroized on our side.
    pub async fn unlock(&self, key_material: Vec<u8>) -> Result<()> {
        self.dispatch(|reply| Command::Unlock {
            key_material: zeroize::Zeroizing::new(key_material),
            reply,
        })
        .await?
    }

    /// Lock the vault now, dropping the `VaultKey` (SPEC §11.5).
    pub async fn lock(&self) -> Result<()> {
        self.dispatch(|reply| Command::Lock { reply }).await
    }

    /// The current lock state.
    pub async fn lock_state(&self) -> Result<LockState> {
        self.dispatch(|reply| Command::LockStatus { reply }).await
    }

    /// A wake-only poll that re-runs the auto-lock deadline check (SPEC §11.5.4).
    pub async fn poll(&self) -> Result<LockState> {
        self.dispatch(|reply| Command::Poll { reply }).await
    }

    /// Report a shell lifecycle event (SPEC §11.5.5).
    pub async fn report_lifecycle(&self, event: LifecycleEvent) -> Result<LockState> {
        self.dispatch(|reply| Command::ReportLifecycle { event, reply })
            .await
    }

    /// All live items as owned snapshots.
    pub async fn list(&self) -> Result<Vec<ItemView>> {
        self.dispatch(|reply| Command::List { reply }).await?
    }

    /// One item by hex id, or `None` if absent.
    pub async fn get(&self, id: String) -> Result<Option<ItemView>> {
        self.dispatch(|reply| Command::Get { id, reply }).await?
    }

    /// One item by hex id, or `NOT_FOUND`.
    pub async fn item(&self, id: String) -> Result<ItemView> {
        self.dispatch(|reply| Command::Item { id, reply }).await?
    }

    /// Add an item; returns its new hex id.
    pub async fn add(&self, input: NewItemInput) -> Result<String> {
        self.dispatch(|reply| Command::Add {
            input: Box::new(input),
            reply,
        })
        .await?
    }

    /// Generate the current code for an item (SPEC §11.6 rule 4).
    pub async fn generate_code(&self, id: String) -> Result<CodeView> {
        self.dispatch(|reply| Command::GenerateCode { id, reply })
            .await?
    }

    /// Run one sync round-trip.
    pub async fn sync_once(&self) -> Result<SyncReportView> {
        self.dispatch(|reply| Command::SyncOnce { reply }).await?
    }

    /// Live items whose issuer/account/labels match `query`.
    pub async fn search(&self, query: String) -> Result<Vec<ItemView>> {
        self.dispatch(|reply| Command::Search { query, reply })
            .await?
    }

    /// Live items in a given sort order.
    pub async fn sorted(&self, key: SortKey) -> Result<Vec<ItemView>> {
        self.dispatch(|reply| Command::Sorted { key, reply })
            .await?
    }

    /// Items currently in the trash.
    pub async fn trash(&self) -> Result<Vec<ItemView>> {
        self.dispatch(|reply| Command::Trash { reply }).await?
    }

    /// All groups.
    pub async fn groups(&self) -> Result<Vec<GroupView>> {
        self.dispatch(|reply| Command::Groups { reply }).await?
    }

    /// One group by hex id, or `NOT_FOUND`.
    pub async fn group(&self, id: String) -> Result<GroupView> {
        self.dispatch(|reply| Command::Group { id, reply }).await?
    }

    /// The unresolved merge conflicts.
    pub async fn conflicts(&self) -> Result<Vec<Conflict>> {
        self.dispatch(|reply| Command::Conflicts { reply }).await?
    }

    /// Move an item to the trash.
    pub async fn trash_item(&self, id: String) -> Result<()> {
        self.dispatch(|reply| Command::TrashItem { id, reply })
            .await?
    }

    /// Restore a trashed item.
    pub async fn restore_item(&self, id: String) -> Result<()> {
        self.dispatch(|reply| Command::RestoreItem { id, reply })
            .await?
    }

    /// Permanently delete an item (tombstone it).
    pub async fn delete_item(&self, id: String) -> Result<()> {
        self.dispatch(|reply| Command::DeleteItem { id, reply })
            .await?
    }

    /// Record a use of an item (bumps its usage counter).
    pub async fn record_use(&self, id: String) -> Result<()> {
        self.dispatch(|reply| Command::RecordUse { id, reply })
            .await?
    }

    /// Create a group; returns its new hex id.
    pub async fn add_group(&self, name: String) -> Result<String> {
        self.dispatch(|reply| Command::AddGroup { name, reply })
            .await?
    }

    /// Delete a group.
    pub async fn delete_group(&self, id: String) -> Result<()> {
        self.dispatch(|reply| Command::DeleteGroup { id, reply })
            .await?
    }

    /// Stop the owning task.
    pub async fn shutdown(&self) -> Result<()> {
        self.dispatch(|reply| Command::Shutdown { reply }).await
    }
}
use misty_crypto::ItemId;
use misty_otp::{OtpConfig, SecretBytes};
use misty_vault::{BlobId, GroupId, IconRef as CoreIconRef};

use crate::dto::{Conflict, IconRef, RosterUpdateView};

/// The owning task's state (SPEC §11.4): it holds the vault and engine by value, and
/// is generic over every erased parameter. Monomorphized once at [`spawn`].
struct Core<S, C, T, SS, HC>
where
    S: VaultStore + Clone,
    C: Clock + Clone,
    T: Transport,
    SS: StateStore,
    HC: HostClock,
{
    lifecycle: Lifecycle<S, C>,
    engine: SyncEngine<T, SS>,
    device: DeviceIdentity,
    clock: C,
    roster: Roster,
    host: HC,
    timeout_ms: i64,
    last_now_ms: i64,
}

/// Build the facade and its owning task (SPEC §11.4).
///
/// The task starts **locked**; call [`Facade::unlock`] to open the vault. Drive the
/// returned future with `tokio::spawn` on native, `wasm_bindgen_futures::spawn_local`
/// on wasm, or a local executor in tests — never a production `block_on` (§11.4.3).
///
/// `S: Clone` because a failed unlock must leave the locked store intact; the mock and
/// native stores both satisfy it.
pub fn spawn<S, C, T, SS, HC>(
    store: S,
    clock: C,
    device: DeviceIdentity,
    roster: Roster,
    engine: SyncEngine<T, SS>,
    host: HC,
    timeout_ms: i64,
) -> (Facade, impl core::future::Future<Output = ()>)
where
    S: VaultStore + Clone,
    C: Clock + Clone,
    T: Transport,
    SS: StateStore,
    HC: HostClock,
{
    let (tx, rx) = mpsc::channel(64);
    let last_now_ms = host.now_ms();
    let core = Core {
        lifecycle: Lifecycle::Locked { store },
        engine,
        device,
        clock,
        roster,
        host,
        timeout_ms,
        last_now_ms,
    };
    (Facade { tx }, core.run(rx))
}
impl<S, C, T, SS, HC> Core<S, C, T, SS, HC>
where
    S: VaultStore + Clone,
    C: Clock + Clone,
    T: Transport,
    SS: StateStore,
    HC: HostClock,
{
    async fn run(mut self, mut rx: mpsc::Receiver<Command>) {
        // Each iteration is a "wake": the deadline is checked before the command runs
        // (SPEC §11.5.4). Async commands are awaited inline in this cut (see module docs).
        while let Some(cmd) = rx.next().await {
            self.check_deadline();
            match cmd {
                Command::Shutdown { reply } => {
                    let _ = reply.send(());
                    break;
                }
                Command::Unlock {
                    key_material,
                    reply,
                } => {
                    let r = self.unlock(&key_material);
                    let _ = reply.send(r);
                }
                Command::Lock { reply } => {
                    self.relock();
                    let _ = reply.send(());
                }
                Command::LockStatus { reply } | Command::Poll { reply } => {
                    let _ = reply.send(self.lock_state());
                }
                Command::ReportLifecycle { event, reply } => {
                    self.apply_lifecycle(event);
                    let _ = reply.send(self.lock_state());
                }
                Command::List { reply } => {
                    let r = self.do_list();
                    let _ = reply.send(r);
                }
                Command::Get { id, reply } => {
                    let r = self.do_get(&id);
                    let _ = reply.send(r);
                }
                Command::Item { id, reply } => {
                    let r = self.do_item(&id);
                    let _ = reply.send(r);
                }
                Command::Add { input, reply } => {
                    let r = self.do_add(input);
                    let _ = reply.send(r);
                }
                Command::GenerateCode { id, reply } => {
                    let r = self.do_generate(&id);
                    let _ = reply.send(r);
                }
                Command::SyncOnce { reply } => {
                    let r = self.do_sync().await;
                    let _ = reply.send(r);
                }
                Command::Search { query, reply } => {
                    let r = self.do_search(&query);
                    let _ = reply.send(r);
                }
                Command::Sorted { key, reply } => {
                    let r = self.do_sorted(key);
                    let _ = reply.send(r);
                }
                Command::Trash { reply } => {
                    let r = self.do_trash();
                    let _ = reply.send(r);
                }
                Command::Groups { reply } => {
                    let r = self.do_groups();
                    let _ = reply.send(r);
                }
                Command::Group { id, reply } => {
                    let r = self.do_group(&id);
                    let _ = reply.send(r);
                }
                Command::Conflicts { reply } => {
                    let r = self.do_conflicts();
                    let _ = reply.send(r);
                }
                Command::TrashItem { id, reply } => {
                    let r = self.do_trash_item(&id);
                    let _ = reply.send(r);
                }
                Command::RestoreItem { id, reply } => {
                    let r = self.do_restore_item(&id);
                    let _ = reply.send(r);
                }
                Command::DeleteItem { id, reply } => {
                    let r = self.do_delete_item(&id);
                    let _ = reply.send(r);
                }
                Command::RecordUse { id, reply } => {
                    let r = self.do_record_use(&id);
                    let _ = reply.send(r);
                }
                Command::AddGroup { name, reply } => {
                    let r = self.do_add_group(name);
                    let _ = reply.send(r);
                }
                Command::DeleteGroup { id, reply } => {
                    let r = self.do_delete_group(&id);
                    let _ = reply.send(r);
                }
            }
        }
    }
    fn lock_state(&self) -> LockState {
        LockState {
            locked: !matches!(self.lifecycle, Lifecycle::Unlocked { .. }),
        }
    }

    fn check_deadline(&mut self) {
        let now = self.host.now_ms();
        // A clock that ran backwards is fail-closed, not clamped (SPEC §11.5.4).
        let backwards = now < self.last_now_ms;
        self.last_now_ms = now;
        if let Lifecycle::Unlocked { deadline_ms, .. } = &self.lifecycle {
            if backwards || now >= *deadline_ms {
                self.relock();
            }
        }
    }

    fn extend_deadline(&mut self) {
        let now = self.host.now_ms();
        let timeout = self.timeout_ms;
        if let Lifecycle::Unlocked { deadline_ms, .. } = &mut self.lifecycle {
            *deadline_ms = now.saturating_add(timeout);
        }
    }

    fn relock(&mut self) {
        let taken = core::mem::replace(&mut self.lifecycle, Lifecycle::Poisoned);
        self.lifecycle = match taken {
            Lifecycle::Unlocked {
                vault, vault_key, ..
            } => {
                let store = (*vault).lock();
                drop(vault_key); // VaultKey is ZeroizeOnDrop.
                Lifecycle::Locked { store }
            }
            other => other,
        };
    }

    fn apply_lifecycle(&mut self, event: LifecycleEvent) {
        match event {
            LifecycleEvent::Backgrounded
            | LifecycleEvent::ScreenLocked
            | LifecycleEvent::WillSleep => self.relock(),
            LifecycleEvent::UserActivity => self.extend_deadline(),
        }
    }
    fn unlock(&mut self, key_material: &[u8]) -> Result<()> {
        match &self.lifecycle {
            Lifecycle::Unlocked { .. } => {
                self.extend_deadline();
                return Ok(());
            }
            Lifecycle::Poisoned => {
                return Err(FacadeError::internal("facade in a poisoned state"));
            }
            Lifecycle::Locked { .. } => {}
        }
        let bytes: [u8; 32] = key_material
            .try_into()
            .map_err(|_| FacadeError::internal("vault key must be 32 bytes"))?;
        // Clone the store so a failed open leaves the locked state intact (SPEC §11.5).
        let Lifecycle::Locked { store } = &self.lifecycle else {
            return Err(FacadeError::internal("expected a locked store"));
        };
        let store = store.clone();
        let vault = Vault::open(
            store,
            self.clock.clone(),
            VaultKey::from_bytes(bytes),
            duplicate_identity(&self.device),
            self.roster.clone(),
        )?;
        let now = self.host.now_ms();
        self.lifecycle = Lifecycle::Unlocked {
            vault: Box::new(vault),
            vault_key: VaultKey::from_bytes(bytes),
            deadline_ms: now.saturating_add(self.timeout_ms),
        };
        Ok(())
    }

    fn vault(&self) -> Result<&Vault<S, C>> {
        match &self.lifecycle {
            Lifecycle::Unlocked { vault, .. } => Ok(&**vault),
            _ => Err(FacadeError::locked()),
        }
    }
    fn do_list(&mut self) -> Result<Vec<ItemView>> {
        let items = self.vault()?.list().map(ItemView::from).collect();
        self.extend_deadline();
        Ok(items)
    }

    fn do_get(&mut self, id: &str) -> Result<Option<ItemView>> {
        let iid = parse_item_id(id)?;
        let view = self.vault()?.get(&iid).map(ItemView::from);
        self.extend_deadline();
        Ok(view)
    }

    fn do_item(&mut self, id: &str) -> Result<ItemView> {
        let iid = parse_item_id(id)?;
        let view = ItemView::from(self.vault()?.item(&iid)?);
        self.extend_deadline();
        Ok(view)
    }

    fn do_add(&mut self, input: Box<NewItemInput>) -> Result<String> {
        let new = build_new_item(*input)?;
        let Lifecycle::Unlocked { vault, .. } = &mut self.lifecycle else {
            return Err(FacadeError::locked());
        };
        let hex = vault.add(new)?.to_hex();
        self.extend_deadline();
        Ok(hex)
    }
    fn do_generate(&mut self, id: &str) -> Result<CodeView> {
        let iid = parse_item_id(id)?;
        let view = {
            let vault = self.vault()?;
            let item = vault.item(&iid)?;
            let code = item.otp()?.generate(vault.clock())?;
            CodeView {
                code: code.value().to_string(),
                valid_until_ms: code.valid_until_ms().map_or(0, |v| v as i64),
                period_ms: i64::from(item.period()) * 1000,
            }
        };
        self.extend_deadline();
        Ok(view)
    }

    async fn do_sync(&mut self) -> Result<SyncReportView> {
        let report = {
            let Lifecycle::Unlocked { vault, .. } = &mut self.lifecycle else {
                return Err(FacadeError::locked());
            };
            self.engine
                .sync_once(vault, &self.roster)
                .await
                .map_err(FacadeError::from)?
        };
        self.extend_deadline();
        Ok(sync_report_view(&report))
    }

    fn vault_mut(&mut self) -> Result<&mut Vault<S, C>> {
        match &mut self.lifecycle {
            Lifecycle::Unlocked { vault, .. } => Ok(&mut **vault),
            _ => Err(FacadeError::locked()),
        }
    }

    fn do_search(&mut self, query: &str) -> Result<Vec<ItemView>> {
        let items = self
            .vault()?
            .search(query)
            .into_iter()
            .map(ItemView::from)
            .collect();
        self.extend_deadline();
        Ok(items)
    }

    fn do_sorted(&mut self, key: SortKey) -> Result<Vec<ItemView>> {
        let items = self
            .vault()?
            .sorted(key.into())
            .into_iter()
            .map(ItemView::from)
            .collect();
        self.extend_deadline();
        Ok(items)
    }

    fn do_trash(&mut self) -> Result<Vec<ItemView>> {
        let items = self
            .vault()?
            .trash()
            .into_iter()
            .map(ItemView::from)
            .collect();
        self.extend_deadline();
        Ok(items)
    }
    fn do_groups(&mut self) -> Result<Vec<GroupView>> {
        let groups = self
            .vault()?
            .groups()
            .into_iter()
            .map(GroupView::from)
            .collect();
        self.extend_deadline();
        Ok(groups)
    }

    fn do_group(&mut self, id: &str) -> Result<GroupView> {
        let gid = parse_group_id(id)?;
        let view = GroupView::from(self.vault()?.group(&gid)?);
        self.extend_deadline();
        Ok(view)
    }

    fn do_conflicts(&mut self) -> Result<Vec<Conflict>> {
        let conflicts = self
            .vault()?
            .conflicts()
            .iter()
            .map(Conflict::from)
            .collect();
        self.extend_deadline();
        Ok(conflicts)
    }

    fn do_trash_item(&mut self, id: &str) -> Result<()> {
        let iid = parse_item_id(id)?;
        self.vault_mut()?.trash_item(&iid)?;
        self.extend_deadline();
        Ok(())
    }

    fn do_restore_item(&mut self, id: &str) -> Result<()> {
        let iid = parse_item_id(id)?;
        self.vault_mut()?.restore_item(&iid)?;
        self.extend_deadline();
        Ok(())
    }

    fn do_delete_item(&mut self, id: &str) -> Result<()> {
        let iid = parse_item_id(id)?;
        self.vault_mut()?.delete_item(&iid)?;
        self.extend_deadline();
        Ok(())
    }
    fn do_record_use(&mut self, id: &str) -> Result<()> {
        let iid = parse_item_id(id)?;
        self.vault_mut()?.record_use(&iid)?;
        self.extend_deadline();
        Ok(())
    }

    fn do_add_group(&mut self, name: String) -> Result<String> {
        let hex = self.vault_mut()?.add_group(name)?.to_hex();
        self.extend_deadline();
        Ok(hex)
    }

    fn do_delete_group(&mut self, id: &str) -> Result<()> {
        let gid = parse_group_id(id)?;
        self.vault_mut()?.delete_group(&gid)?;
        self.extend_deadline();
        Ok(())
    }
}
fn parse_item_id(hex_id: &str) -> Result<ItemId> {
    let bytes = hex::decode(hex_id)
        .map_err(|_| FacadeError::new(ErrorCode::NotFound, "malformed item id"))?;
    ItemId::from_slice(&bytes).map_err(|_| FacadeError::new(ErrorCode::NotFound, "unknown item id"))
}

fn parse_group_id(hex_id: &str) -> Result<GroupId> {
    let bytes = hex::decode(hex_id)
        .map_err(|_| FacadeError::new(ErrorCode::InvalidField, "malformed group id"))?;
    let arr: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| FacadeError::new(ErrorCode::InvalidField, "group id must be 16 bytes"))?;
    Ok(GroupId::from_bytes(arr))
}

fn icon_to_core(icon: IconRef) -> Result<CoreIconRef> {
    Ok(match icon {
        IconRef::Bundled { slug } => CoreIconRef::Bundled(slug),
        IconRef::Initials { color } => CoreIconRef::Initials { color },
        IconRef::Custom { blob_id } => {
            let bytes = hex::decode(&blob_id)
                .map_err(|_| FacadeError::new(ErrorCode::InvalidField, "malformed blob id"))?;
            let arr: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                FacadeError::new(ErrorCode::InvalidField, "blob id must be 16 bytes")
            })?;
            CoreIconRef::Custom(BlobId::from_bytes(arr))
        }
    })
}

fn sync_report_view(report: &misty_sync::SyncReport) -> SyncReportView {
    SyncReportView {
        conflicts: report.conflicts.iter().map(Conflict::from).collect(),
        roster_update: report
            .roster_update
            .as_ref()
            .map(|(id, envelope)| RosterUpdateView {
                item_id: id.to_hex(),
                envelope: envelope.clone(),
            }),
        pulled: report.changes_seen as u32,
        pushed: report.pushed as u32,
        applied: report.applied as u32,
    }
}
fn build_new_item(input: NewItemInput) -> Result<NewItem> {
    let secret = SecretBytes::new(input.secret);
    let mut builder = OtpConfig::builder(input.kind.into(), secret)
        .algorithm(input.algorithm.into())
        .digits(input.digits)
        .period(input.period)
        .counter(input.hotp_counter);
    if let Some(pin) = input.pin {
        builder = builder.pin(Some(SecretBytes::new(pin)));
    }
    let otp = builder.build()?;
    let mut new = NewItem::new(otp, input.issuer, input.account);
    if let Some(nickname) = input.nickname {
        new = new.nickname(nickname);
    }
    if let Some(note) = input.note {
        new = new.note(note);
    }
    for tag in input.tags {
        new = new.tag(tag);
    }
    for origin in input.origins {
        new = new.origin(origin);
    }
    for group in input.groups {
        new = new.group(parse_group_id(&group)?);
    }
    if let Some(icon) = input.icon {
        new = new.icon(icon_to_core(icon)?);
    }
    if let Some(color) = input.color {
        new = new.color(color);
    }
    if input.favorite {
        new = new.favorite(true);
    }
    Ok(new)
}
