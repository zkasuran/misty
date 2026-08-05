// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The single source of entropy in Misty.
//!
//! # Audit note
//!
//! Every random byte in this crate — vault keys, item keys, recovery keys,
//! nonces, salts, device ids — comes from exactly one of the two functions
//! below, which call [`getrandom`] and nothing else. There is deliberately no
//! seeded RNG, no `rand::thread_rng`, and no way to inject a PRNG through the
//! public API: the only call to `getrandom::getrandom` in the crate is in this
//! file, and the only other mention of the dependency is the error conversion
//! in `error.rs`.
//!
//! Determinism for tests is obtained by passing explicit key and nonce values
//! into crate-internal `*_with` functions, not by swapping the RNG.
//!
//! On `wasm32-unknown-unknown` the `getrandom/js` feature (enabled in
//! `Cargo.toml` for that target only) routes these calls at
//! `crypto.getRandomValues`. Without it the wasm build links but traps at the
//! first key generation, which is why the feature is not optional.

use crate::Result;

/// Fills `dest` with bytes from the operating system CSPRNG.
///
/// # Errors
///
/// Returns [`Error::Random`](crate::Error::Random) if the OS entropy source is
/// unavailable. Callers MUST propagate this: generating a key from a degraded
/// source is worse than failing.
pub fn fill(dest: &mut [u8]) -> Result<()> {
    getrandom::getrandom(dest)?;
    Ok(())
}

/// Returns `N` fresh bytes from the operating system CSPRNG.
///
/// # Errors
///
/// As [`fill`].
pub fn array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        // Not a randomness test — a wiring test. A stubbed-out CSPRNG that
        // returns zeros is the failure mode worth catching.
        let a = array::<32>().unwrap();
        let b = array::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
