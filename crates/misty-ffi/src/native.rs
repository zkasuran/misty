// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The UniFFI native binding (SPEC §11.7.1): the same [`misty`] facade lowered to
//! Kotlin (Android) and Swift (iOS / macOS / the Tauri desktop shell).
//!
//! Three properties of this module are load-bearing, and all three are §11 rules rather
//! than taste:
//!
//! 1. **The DTOs are not re-declared.** Every boundary type below is registered with
//!    `#[uniffi::remote(..)]`, which means UniFFI generates FFI scaffolding for
//!    `misty`'s *own* type and emits no new one. There is therefore no conversion layer
//!    that could drift from the facade, and no second definition to keep in sync with
//!    the wasm leg — the two bindings carry the identical values, which is the premise
//!    of the §11.8.2 conformance gate. Changing a facade DTO breaks this file at compile
//!    time; that is the point. `misty` itself never names UniFFI (§11.7).
//! 2. **The exported handle is `Send + Sync` and has no `&mut self`.** [`MistyFacade`]
//!    is an `Arc`-heap UniFFI object holding a channel sender to the owning actor in
//!    `crates/misty`; the vault's exclusive `&mut` access lives inside that task and
//!    never crosses the boundary (§11.4.4). There is no `Mutex` around a `Vault` here.
//! 3. **The thrown error is the flat triple.** [`MistyError`] carries `code`, `message`
//!    and `retryable` and nothing else. `code` crosses as the frozen `UPPER_SNAKE`
//!    string — never a discriminant — so it is byte-identical to what the wasm binding
//!    rejects with, and foreign code branches on it (§11.3.1, §11.3.2).
//!
//! Every method reduces to "send one command, await the owned reply" (§11.4.6). No
//! business rule, no secret handling, and no borrow of core state lives here.

use std::sync::Arc;

use misty::dto::{
    ClearableField, CodeView, Conflict, EditInput, GroupView, HashAlg, HlcView, IconRef, ItemView,
    NewItemInput, OtpKind, RosterUpdateView, SortKey, SyncReportView, TombstoneReason,
    TombstoneView,
};
use misty::{Facade, LifecycleEvent, LockState};

// --- the boundary types, registered as remote so `misty` keeps owning them (§11.7.1) ---
//
// Each block mirrors the real declaration in `crates/misty/src/{dto,facade}.rs`. UniFFI
// checks the mirror against the real type when it lowers a value, so a field added,
// removed, renamed, or retyped upstream fails this crate's build.

/// Mirrors [`misty::dto::OtpKind`].
#[uniffi::remote(Enum)]
pub enum OtpKind {
    /// RFC 6238 time-based.
    Totp,
    /// RFC 4226 counter-based.
    Hotp,
    /// Steam's five-character alphabet.
    Steam,
    /// Mobile-OTP (mOTP), PIN-salted.
    Motp,
    /// Blizzard authenticator.
    Blizzard,
    /// Yandex, PIN-salted.
    Yandex,
}

/// Mirrors [`misty::dto::HashAlg`].
#[uniffi::remote(Enum)]
pub enum HashAlg {
    /// SHA-1 (the RFC default).
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

/// Mirrors [`misty::dto::TombstoneReason`].
#[uniffi::remote(Enum)]
pub enum TombstoneReason {
    /// The user deleted it.
    User,
    /// It aged out of the trash.
    TrashExpired,
}

/// Mirrors [`misty::dto::SortKey`].
#[uniffi::remote(Enum)]
pub enum SortKey {
    /// The user's manual order.
    Manual,
    /// By issuer, case-insensitive.
    Issuer,
    /// Most recently used first.
    LastUsed,
    /// Most frequently used first.
    MostUsed,
    /// Most recently created first.
    Created,
}

/// Mirrors [`misty::dto::ClearableField`].
#[uniffi::remote(Enum)]
pub enum ClearableField {
    /// Clear the nickname.
    Nickname,
    /// Clear the note.
    Note,
    /// Clear the colour.
    Color,
    /// Clear the manual sort position.
    ManualOrder,
    /// Clear the PIN.
    Pin,
}

/// Mirrors [`misty::LifecycleEvent`].
#[uniffi::remote(Enum)]
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

/// Mirrors [`misty::dto::IconRef`]. A data-carrying enum, which UniFFI supports
/// natively; the wasm leg lowers the same shape to a tagged plain object (§11.7.2).
#[uniffi::remote(Enum)]
pub enum IconRef {
    /// A bundled icon, by slug.
    Bundled {
        /// The bundled icon's slug.
        slug: String,
    },
    /// A custom icon stored as a blob.
    Custom {
        /// The blob's id, lowercase hex.
        blob_id: String,
    },
    /// Rendered initials on a colour (ARGB).
    Initials {
        /// ARGB colour.
        color: u32,
    },
}

/// Mirrors [`misty::dto::Conflict`]. A conflict is **not** an error: it rides inside an
/// owned DTO and is never thrown (§11.3.1).
#[uniffi::remote(Enum)]
pub enum Conflict {
    /// Two live items disagree on the secret; both were kept, `forked` is the copy.
    DivergentSecret {
        /// The item kept under the original id (hex).
        kept: String,
        /// The forked copy under a derived id (hex).
        forked: String,
    },
    /// An item's PIN diverged.
    DivergentPin {
        /// The affected item id (hex).
        item: String,
    },
    /// A conflict this build does not render specifically; the id is still surfaced.
    Unknown {
        /// The affected item id (hex).
        item: String,
    },
}

/// Mirrors [`misty::dto::HlcView`].
#[uniffi::remote(Record)]
pub struct HlcView {
    /// Wall-clock milliseconds, bounded to `[2020-01-01, 2100-01-01)` (§4.1).
    pub wall_ms: u64,
    /// Tie-break counter.
    pub counter: u16,
    /// The writing device's id (hex).
    pub device_id: String,
}

/// Mirrors [`misty::dto::TombstoneView`].
#[uniffi::remote(Record)]
pub struct TombstoneView {
    /// When the deletion happened, as a clock reading.
    pub hlc: HlcView,
    /// Why.
    pub reason: TombstoneReason,
}

/// Mirrors [`misty::dto::ItemView`]. Carries no secret: the only trace of a PIN is
/// `has_pin`, and the secret has no field at all (§11.2, §11.6).
#[uniffi::remote(Record)]
pub struct ItemView {
    /// Item id, lowercase hex.
    pub id: String,
    /// The true OTP kind the user chose.
    pub kind: OtpKind,
    /// HMAC hash.
    pub algorithm: HashAlg,
    /// Number of digits.
    pub digits: u8,
    /// TOTP period, seconds.
    pub period: u16,
    /// HOTP counter.
    pub hotp_counter: u64,
    /// Whether a PIN is set (the only trace of one).
    pub has_pin: bool,
    /// Issuer label.
    pub issuer: String,
    /// Account label.
    pub account: String,
    /// Optional nickname.
    pub nickname: Option<String>,
    /// Optional note.
    pub note: Option<String>,
    /// Group ids (hex).
    pub groups: Vec<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Autofill origins (§9.1).
    pub origins: Vec<String>,
    /// Icon.
    pub icon: IconRef,
    /// Optional ARGB colour.
    pub color: Option<u32>,
    /// Favourite flag.
    pub favorite: bool,
    /// Manual sort position.
    pub manual_order: Option<i64>,
    /// Archived flag.
    pub archived: bool,
    /// Hidden flag.
    pub hidden: bool,
    /// Whether revealing a code requires re-auth.
    pub requires_reveal_auth: bool,
    /// Total use count (flattened G-counter).
    pub use_count: u64,
    /// Last-used time, unix ms.
    pub last_used_at: Option<i64>,
    /// Creation time, unix ms.
    pub created_at: i64,
    /// Time trashed, unix ms.
    pub trashed_at: Option<i64>,
    /// `is_live` predicate (§4).
    pub is_live: bool,
    /// `is_trashed` predicate (§4).
    pub is_trashed: bool,
    /// `is_deleted` predicate (§4).
    pub is_deleted: bool,
    /// Tombstone, if deleted.
    pub deleted: Option<TombstoneView>,
}

/// Mirrors [`misty::dto::GroupView`].
#[uniffi::remote(Record)]
pub struct GroupView {
    /// Group id, lowercase hex.
    pub id: String,
    /// Name.
    pub name: String,
    /// Optional ARGB colour.
    pub color: Option<u32>,
    /// Manual sort position.
    pub manual_order: Option<i64>,
    /// Creation time, unix ms.
    pub created_at: i64,
    /// `is_deleted` predicate.
    pub is_deleted: bool,
    /// Tombstone, if deleted.
    pub deleted: Option<TombstoneView>,
}

/// Mirrors [`misty::dto::CodeView`] — the accepted secret-egress exception (§11.6
/// rule 4). Produced on demand and never cached across the boundary; a foreign
/// `String` is not zeroizable, which §11.6 states rather than implies away.
#[uniffi::remote(Record)]
pub struct CodeView {
    /// The formatted digits. A platform string for at most one period.
    pub code: String,
    /// The instant the code expires, unix ms; the host expires it here.
    pub valid_until_ms: i64,
    /// The window length, ms, so the host can render a countdown.
    pub period_ms: i64,
}

/// Mirrors [`misty::dto::RosterUpdateView`].
#[uniffi::remote(Record)]
pub struct RosterUpdateView {
    /// The roster item's id (hex).
    pub item_id: String,
    /// Opaque ciphertext — not a secret (§11.6).
    pub envelope: Vec<u8>,
}

/// Mirrors [`misty::dto::SyncReportView`].
#[uniffi::remote(Record)]
pub struct SyncReportView {
    /// Conflicts surfaced by the merge.
    pub conflicts: Vec<Conflict>,
    /// A roster update, if one arrived.
    pub roster_update: Option<RosterUpdateView>,
    /// Changes pulled from the server.
    pub pulled: u32,
    /// Changes pushed to the server.
    pub pushed: u32,
    /// Remote changes applied to the vault.
    pub applied: u32,
}

/// Mirrors [`misty::LockState`].
#[uniffi::remote(Record)]
pub struct LockState {
    /// Whether the vault is currently locked.
    pub locked: bool,
}

/// Mirrors [`misty::dto::NewItemInput`]. `secret` and `pin` are owned byte buffers the
/// facade turns into `SecretBytes` and zeroizes at once (§11.6 rule 2) — foreign callers
/// should pass a byte buffer they can overwrite, not a platform `String` (§11.6).
#[uniffi::remote(Record)]
pub struct NewItemInput {
    /// OTP kind.
    pub kind: OtpKind,
    /// HMAC hash.
    pub algorithm: HashAlg,
    /// Digits.
    pub digits: u8,
    /// TOTP period, seconds.
    pub period: u16,
    /// HOTP counter.
    pub hotp_counter: u64,
    /// Raw secret bytes; zeroized after use.
    pub secret: Vec<u8>,
    /// Optional PIN bytes; zeroized after use.
    pub pin: Option<Vec<u8>>,
    /// Issuer label.
    pub issuer: String,
    /// Account label.
    pub account: String,
    /// Optional nickname.
    pub nickname: Option<String>,
    /// Optional note.
    pub note: Option<String>,
    /// Group ids (hex).
    pub groups: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Autofill origins (§9.1).
    pub origins: Vec<String>,
    /// Optional icon.
    pub icon: Option<IconRef>,
    /// Optional ARGB colour.
    pub color: Option<u32>,
    /// Favourite flag.
    pub favorite: bool,
}

/// Mirrors [`misty::dto::EditInput`]. A `None` field leaves the current value alone;
/// naming a field in `clear` resets a nullable field to absent — an `Option<Option<T>>`
/// would not lower cleanly through UniFFI, which is why the shape is this one (§11.2).
#[uniffi::remote(Record)]
pub struct EditInput {
    /// New issuer.
    pub issuer: Option<String>,
    /// New account.
    pub account: Option<String>,
    /// New nickname.
    pub nickname: Option<String>,
    /// New note.
    pub note: Option<String>,
    /// Replacement group set (hex ids).
    pub groups: Option<Vec<String>>,
    /// Replacement tag set.
    pub tags: Option<Vec<String>>,
    /// Replacement origin set (§9.1).
    pub origins: Option<Vec<String>>,
    /// New icon.
    pub icon: Option<IconRef>,
    /// New ARGB colour.
    pub color: Option<u32>,
    /// New manual sort position.
    pub manual_order: Option<i64>,
    /// New favourite flag.
    pub favorite: Option<bool>,
    /// New archived flag.
    pub archived: Option<bool>,
    /// New hidden flag.
    pub hidden: Option<bool>,
    /// New reveal-auth flag.
    pub requires_reveal_auth: Option<bool>,
    /// Set/replace the PIN (zeroized after use).
    pub pin: Option<Vec<u8>>,
    /// Nullable fields to reset to absent.
    pub clear: Vec<ClearableField>,
}

// --- the one error that crosses (§11.3.1) ---

/// The flat error payload: exactly the three fields §11.3.1 puts on the boundary.
///
/// It is a record rather than three fields on the error variant itself, and that is not
/// cosmetic. UniFFI lowers a Kotlin error enum to a subclass of `kotlin.Exception`, which
/// already declares `message`; a variant field of that name collides with it and the
/// generated Kotlin **does not compile** — `conflicting declarations: val message`. The
/// nested record keeps the vocabulary `code` / `message` / `retryable` identical on every
/// binding, which is what §11.3.2 actually depends on, at the cost of one access step on
/// the native side (`error.detail.code`). Renaming the field per-platform was the
/// alternative and is worse: it would leave JavaScript branching on `message` while
/// Kotlin and Swift branched on something else.
///
/// This was found by *compiling* the generated Kotlin. Generation alone succeeded, which
/// is the whole argument for §11.8.2 requiring every binding to run the suite rather than
/// merely to be produced.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ErrorDetail {
    /// The stable, machine-readable code, e.g. `"VAULT_LOCKED"` (§11.3.1).
    pub code: String,
    /// A human, redacted, non-normative message. Never parse this (§11.3.2, §11.3.4).
    pub message: String,
    /// Whether a bare retry of the identical call MAY succeed (§11.3.3).
    pub retryable: bool,
}

/// The single failure channel. UniFFI throws it; the wasm binding rejects with the same
/// three values (§11.3.1).
///
/// One variant on purpose: the taxonomy is flat, so a UniFFI enum and a JSON object carry
/// the same thing and the §11.8.2 fixtures are shared. Foreign code MUST branch on
/// `detail.code` — the frozen `UPPER_SNAKE` token — and MUST NOT parse `detail.message`,
/// which is English, redacted, and non-normative. Because new codes MAY be added without
/// a format-version bump, every foreign `switch` on the code needs a default arm that
/// treats an unknown code as a non-retryable failure.
#[derive(Debug, uniffi::Error)]
pub enum MistyError {
    /// A facade call failed.
    Failed {
        /// The flat `{ code, message, retryable }` payload.
        detail: ErrorDetail,
    },
}

impl MistyError {
    /// Build the boundary error from a code and a message, without going through
    /// [`misty::FacadeError`] — used for the few failures the binding itself can raise
    /// (starting the runtime), which still MUST arrive as one `FacadeError` (§11.3.1).
    fn of(code: misty::ErrorCode, message: impl Into<String>) -> Self {
        Self::Failed {
            detail: ErrorDetail {
                code: code.as_str().to_string(),
                message: message.into(),
                retryable: code.retryable(),
            },
        }
    }
}

impl core::fmt::Display for MistyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self::Failed { detail } = self;
        write!(f, "{}: {}", detail.code, detail.message)
    }
}

impl std::error::Error for MistyError {}

impl From<misty::FacadeError> for MistyError {
    fn from(error: misty::FacadeError) -> Self {
        Self::Failed {
            detail: ErrorDetail {
                code: error.code.as_str().to_string(),
                retryable: error.retryable(),
                message: error.message,
            },
        }
    }
}

/// A binding-side result: the owned DTO, or the one flat error.
type Bound<T> = Result<T, MistyError>;

// --- the exported handle (§11.4.4, §11.7.1) ---

/// The Misty facade, exposed to Kotlin and Swift.
///
/// Heap-allocated behind `Arc`, `Send + Sync`, and with no `&mut self` method — UniFFI
/// requires all three, and they are the same constraints §11.4.4 imposes for its own
/// reasons: the handle is a channel to the actor that owns the vault, so the one-writer
/// rule is enforced by ownership rather than by a lock foreign code could forget.
///
/// This build is configured with the in-memory mock core (§11.8.1): `MemoryStore` +
/// `MockTransport` + a fixed clock. A production build swaps the store, transport, and
/// clock; nothing in the generated Kotlin or Swift changes, because the generics are
/// erased at the facade (§11.1).
#[derive(uniffi::Object)]
pub struct MistyFacade {
    /// The channel to the owning actor task.
    inner: Facade,
    /// The runtime the actor task runs on. `Option` only so [`Drop`] can take it and
    /// call `shutdown_background`: dropping a `Runtime` from inside an async context
    /// panics, and UniFFI is free to release the object from any thread.
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for MistyFacade {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl MistyFacade {
    /// Build the facade over the mock core and start its owning task.
    ///
    /// The task is driven by `tokio::spawn` on a runtime this object owns, which is what
    /// §11.4.3 requires of a native build — never `misty_sync::block_on`, which has no
    /// timer and could not make a production sleeper progress. The vault starts
    /// **locked**; call [`unlock`](Self::unlock).
    #[uniffi::constructor]
    pub fn new() -> Bound<Arc<Self>> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_time()
            .build()
            .map_err(|e| {
                MistyError::of(
                    misty::ErrorCode::Internal,
                    format!("could not start the runtime: {e}"),
                )
            })?;
        let (inner, task) = crate::mock_facade();
        runtime.spawn(task);
        Ok(Arc::new(Self {
            inner,
            runtime: Some(runtime),
        }))
    }

    // --- lifecycle (§11.5) ---

    /// Unlock the vault with raw key material; zeroized on our side.
    pub async fn unlock(&self, key_material: Vec<u8>) -> Bound<()> {
        Ok(self.inner.unlock(key_material).await?)
    }

    /// Lock the vault now, dropping the vault key.
    pub async fn lock(&self) -> Bound<()> {
        Ok(self.inner.lock().await?)
    }

    /// The current lock state.
    pub async fn lock_state(&self) -> Bound<LockState> {
        Ok(self.inner.lock_state().await?)
    }

    /// A wake-only poll that re-runs the auto-lock deadline check (§11.5.4). A shell
    /// calls this on every wake; there is no timer to miss.
    pub async fn poll(&self) -> Bound<LockState> {
        Ok(self.inner.poll().await?)
    }

    /// Report a shell lifecycle event (§11.5.5). The shell reports; the facade decides.
    pub async fn report_lifecycle(&self, event: LifecycleEvent) -> Bound<LockState> {
        Ok(self.inner.report_lifecycle(event).await?)
    }

    /// Stop the owning task. Shutdown is an explicit command, never a dropped future —
    /// UniFFI has no future-drop cancellation (§11.7.1).
    pub async fn shutdown(&self) -> Bound<()> {
        Ok(self.inner.shutdown().await?)
    }

    // --- readers ---

    /// All live items.
    pub async fn list(&self) -> Bound<Vec<ItemView>> {
        Ok(self.inner.list().await?)
    }

    /// One item by hex id, or `null` if absent.
    pub async fn get(&self, id: String) -> Bound<Option<ItemView>> {
        Ok(self.inner.get(id).await?)
    }

    /// One item by hex id, or `NOT_FOUND`.
    pub async fn item(&self, id: String) -> Bound<ItemView> {
        Ok(self.inner.item(id).await?)
    }

    /// Live items whose issuer/account/labels match `query`.
    pub async fn search(&self, query: String) -> Bound<Vec<ItemView>> {
        Ok(self.inner.search(query).await?)
    }

    /// Live items in a given sort order.
    pub async fn sorted(&self, key: SortKey) -> Bound<Vec<ItemView>> {
        Ok(self.inner.sorted(key).await?)
    }

    /// Items currently in the trash.
    pub async fn trash(&self) -> Bound<Vec<ItemView>> {
        Ok(self.inner.trash().await?)
    }

    /// All groups, tombstones included.
    pub async fn groups(&self) -> Bound<Vec<GroupView>> {
        Ok(self.inner.groups().await?)
    }

    /// One group by hex id, or `NOT_FOUND`.
    pub async fn group(&self, id: String) -> Bound<GroupView> {
        Ok(self.inner.group(id).await?)
    }

    /// The unresolved merge conflicts.
    pub async fn conflicts(&self) -> Bound<Vec<Conflict>> {
        Ok(self.inner.conflicts().await?)
    }

    // --- codes and sync ---

    /// Generate the current code for an item (§11.6 rule 4).
    pub async fn generate_code(&self, id: String) -> Bound<CodeView> {
        Ok(self.inner.generate_code(id).await?)
    }

    /// Run one sync round-trip.
    pub async fn sync_once(&self) -> Bound<SyncReportView> {
        Ok(self.inner.sync_once().await?)
    }

    // --- item and group lifecycle ---

    /// Add an item; returns its new hex id.
    pub async fn add(&self, input: NewItemInput) -> Bound<String> {
        Ok(self.inner.add(input).await?)
    }

    /// Apply a sparse edit.
    pub async fn update(&self, id: String, edit: EditInput) -> Bound<()> {
        Ok(self.inner.update(id, edit).await?)
    }

    /// Move an item to the trash.
    pub async fn trash_item(&self, id: String) -> Bound<()> {
        Ok(self.inner.trash_item(id).await?)
    }

    /// Restore an item from the trash.
    pub async fn restore_item(&self, id: String) -> Bound<()> {
        Ok(self.inner.restore_item(id).await?)
    }

    /// Delete an item, leaving a tombstone.
    pub async fn delete_item(&self, id: String) -> Bound<()> {
        Ok(self.inner.delete_item(id).await?)
    }

    /// Record a use of an item (the G-counter and last-used time).
    pub async fn record_use(&self, id: String) -> Bound<()> {
        Ok(self.inner.record_use(id).await?)
    }

    /// Create a group; returns its new hex id.
    pub async fn add_group(&self, name: String) -> Bound<String> {
        Ok(self.inner.add_group(name).await?)
    }

    /// Delete a group, leaving a tombstone.
    pub async fn delete_group(&self, id: String) -> Bound<()> {
        Ok(self.inner.delete_group(id).await?)
    }

    /// Replace a mis-typed secret on an existing item; zeroized after use.
    pub async fn repair_secret(&self, id: String, secret: Vec<u8>) -> Bound<()> {
        Ok(self.inner.repair_secret(id, secret).await?)
    }

    /// Advance a HOTP counter by one; returns the new value.
    pub async fn advance_hotp_counter(&self, id: String) -> Bound<u64> {
        Ok(self.inner.advance_hotp_counter(id).await?)
    }

    /// Set a HOTP counter to an explicit value; returns the stored value.
    pub async fn set_hotp_counter(&self, id: String, counter: u64) -> Bound<u64> {
        Ok(self.inner.set_hotp_counter(id, counter).await?)
    }

    /// Age expired items out of the trash; returns their hex ids.
    pub async fn sweep_trash(&self) -> Bound<Vec<String>> {
        Ok(self.inner.sweep_trash().await?)
    }

    /// Drop tombstones past the retention horizon; returns their hex ids.
    pub async fn purge_tombstones(&self) -> Bound<Vec<String>> {
        Ok(self.inner.purge_tombstones().await?)
    }

    /// Merge an incoming item into an existing one rather than storing a duplicate
    /// (§3.1).
    pub async fn merge_duplicate(&self, existing: String, input: NewItemInput) -> Bound<()> {
        Ok(self.inner.merge_duplicate(existing, input).await?)
    }

    // --- roster (§6.3, §6.4) ---

    /// Revoke a device: the epoch rotates and the vault is re-sealed under a successor
    /// roster (§6.4).
    pub async fn revoke_device(&self, device_id: String) -> Bound<()> {
        Ok(self.inner.revoke_device(device_id).await?)
    }

    /// Approve a pending enrollment after the user has compared the confirmation code
    /// out of band (§6.3).
    pub async fn approve_enrollment(
        &self,
        enroll_id: String,
        typed_code: String,
        server_url: String,
        enrolled_at: i64,
    ) -> Bound<()> {
        Ok(self
            .inner
            .approve_enrollment(enroll_id, typed_code, server_url, enrolled_at)
            .await?)
    }
}
