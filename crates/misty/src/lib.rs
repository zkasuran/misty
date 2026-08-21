// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Misty's facade — the one owned, non-generic, `'static` API the four consumers
//! (web/wasm, browser extension, desktop, mobile) build against, specified in
//! [`docs/SPEC.md`] §11.
//!
//! This crate **owns** the live [`misty_vault::Vault`] and [`misty_sync::SyncEngine`],
//! monomorphizes away their generic parameters, and presents everything as owned
//! [`dto`] values and one flat [`FacadeError`]. No generic, lifetime, borrow, or
//! trait object crosses out of it. The store, transport, clock, and sleeper are the
//! only knobs left, so the same code is the production build, the wasm build, and the
//! mock build the conformance suite runs (SPEC §11.8).
//!
//! Concurrency is a single-owner actor (SPEC §11.4): one task owns the vault and the
//! engine by value, and every call is a message on a channel, so the engine's
//! deliberately-`!Send` browser future never crosses the boundary and the vault's
//! exclusive `&mut` access needs no consumer-visible lock.
//!
//! [`docs/SPEC.md`]: https://github.com/zkasuran/misty/blob/main/docs/SPEC.md
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![cfg_attr(
    not(test),
    warn(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::indexing_slicing
    )
)]

pub mod clock;
pub mod dto;
pub mod error;
pub mod facade;

pub use clock::{HostClock, ManualClock};
pub use error::{ErrorCode, FacadeError, Result};
pub use facade::{spawn, Facade, LifecycleEvent, LockState};

#[cfg(not(target_arch = "wasm32"))]
pub use clock::InstantClock;
