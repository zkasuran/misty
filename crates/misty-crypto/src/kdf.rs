// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Argon2id, and the three tiers from SPEC §2.3.
//!
//! | Tier | Memory | Iterations | Parallelism | Used on |
//! |---|---|---|---|---|
//! | [`Interactive`](KdfTier::Interactive) | 64 MiB | 3 | 4 | low-memory mobile |
//! | [`Moderate`](KdfTier::Moderate) | 256 MiB | 3 | 4 | default |
//! | [`Sensitive`](KdfTier::Sensitive) | 1 GiB | 4 | 4 | desktop, backup files |
//!
//! Parameters are stored in cleartext in the header of whatever they protect,
//! so a phone with 2 GiB of RAM can still open a backup a desktop wrote at the
//! `Sensitive` tier — it just pays the memory cost once. That is also why
//! parameters read out of a header are attacker-controlled and must be bounded
//! before use: see [`KdfParams::validate`].

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::keys::{KdfKey, KEY_LEN};
use crate::{Error, Result};

/// `kdf_id` for Argon2id, the only KDF this format version defines.
pub const KDF_ID_ARGON2ID: u8 = 1;

/// Salt length used by every Misty format. Argon2 accepts 8 and up; 16 is what
/// the headers reserve.
pub const SALT_LEN: usize = 16;

/// Smallest memory cost this build will run, in KiB. Argon2 itself requires
/// `8 * parallelism`.
pub const MIN_MEMORY_KIB: u32 = 8;

/// Largest memory cost this build will run, in KiB (2 GiB).
///
/// A hostile header claiming 64 GiB is a denial-of-service vector: the
/// allocation either fails or drives the process into the OOM killer, on a
/// path that runs *before* any authentication can happen. 2 GiB is double the
/// highest tier Misty ever writes, which leaves room for a future tier without
/// leaving room for an attack.
pub const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024;

/// Largest iteration count this build will run.
pub const MAX_ITERATIONS: u32 = 16;

/// Largest lane count this build will run.
pub const MAX_PARALLELISM: u32 = 16;

const KIB: u32 = 1024;
const GIB: u64 = 1024 * 1024 * 1024;

/// One of the three named cost tiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KdfTier {
    /// 64 MiB, 3 iterations, 4 lanes. For devices that cannot spare more.
    Interactive,
    /// 256 MiB, 3 iterations, 4 lanes. The default.
    Moderate,
    /// 1 GiB, 4 iterations, 4 lanes. Desktop unlock and backup files.
    Sensitive,
}

impl KdfTier {
    /// The parameters this tier stands for.
    #[must_use]
    pub const fn params(self) -> KdfParams {
        match self {
            Self::Interactive => KdfParams::new(64 * KIB, 3, 4),
            Self::Moderate => KdfParams::new(256 * KIB, 3, 4),
            Self::Sensitive => KdfParams::new(1024 * KIB, 4, 4),
        }
    }

    /// Stable lowercase name, for UI and diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Moderate => "moderate",
            Self::Sensitive => "sensitive",
        }
    }

    /// Picks the strongest tier a device with `available_memory_bytes` of
    /// *free* memory can run without thrashing.
    ///
    /// The thresholds leave roughly 4x headroom over the tier's own working
    /// set, because Argon2's allocation is not the only thing in the process
    /// and a swapped-out Argon2 lane is both slow and a disclosure risk:
    ///
    /// * 4 GiB or more free → [`Sensitive`](Self::Sensitive) (1 GiB working set)
    /// * 1 GiB or more free → [`Moderate`](Self::Moderate) (256 MiB)
    /// * otherwise → [`Interactive`](Self::Interactive) (64 MiB)
    ///
    /// This only ever chooses what to *write*. Reading is governed by the
    /// parameters in the header.
    #[must_use]
    pub const fn recommended_for(available_memory_bytes: u64) -> Self {
        if available_memory_bytes >= 4 * GIB {
            Self::Sensitive
        } else if available_memory_bytes >= GIB {
            Self::Moderate
        } else {
            Self::Interactive
        }
    }
}
/// Argon2id cost parameters, exactly as they appear in a header.
///
/// `Copy` and not secret: these bytes are written in cleartext on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KdfParams {
    /// Memory cost in KiB (`argon2_memory_kib` in the backup header).
    pub memory_kib: u32,
    /// Iterations, Argon2's time cost.
    pub iterations: u32,
    /// Lanes, Argon2's parallelism.
    pub parallelism: u32,
}

impl KdfParams {
    /// Builds a parameter set without validating it.
    ///
    /// `const` so [`KdfTier::params`] can be `const`. Anything that came from a
    /// file MUST be run through [`validate`](Self::validate) first;
    /// [`derive_key`](Self::derive_key) does that itself.
    #[must_use]
    pub const fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Self {
        Self {
            memory_kib,
            iterations,
            parallelism,
        }
    }

    /// Rejects parameters this build will not run.
    ///
    /// # Errors
    ///
    /// [`Error::KdfParamsRejected`] if any cost is outside
    /// `MIN_MEMORY_KIB..=MAX_MEMORY_KIB`, `1..=MAX_ITERATIONS`,
    /// `1..=MAX_PARALLELISM`, or if `memory_kib < 8 * parallelism`, which
    /// Argon2 itself forbids.
    pub fn validate(&self) -> Result<()> {
        let reject = |detail: &'static str| {
            Err(Error::KdfParamsRejected {
                memory_kib: self.memory_kib,
                iterations: self.iterations,
                parallelism: self.parallelism,
                detail,
            })
        };
        if self.memory_kib < MIN_MEMORY_KIB {
            return reject("memory cost below the minimum");
        }
        if self.memory_kib > MAX_MEMORY_KIB {
            return reject("memory cost above the maximum this build will allocate");
        }
        if self.iterations == 0 {
            return reject("iteration count must be at least 1");
        }
        if self.iterations > MAX_ITERATIONS {
            return reject("iteration count above the maximum this build will run");
        }
        if self.parallelism == 0 {
            return reject("parallelism must be at least 1");
        }
        if self.parallelism > MAX_PARALLELISM {
            return reject("parallelism above the maximum this build will run");
        }
        if self.memory_kib < self.parallelism.saturating_mul(8) {
            return reject("memory cost must be at least 8 KiB per lane");
        }
        Ok(())
    }

    /// The named tier these parameters correspond to, if any.
    #[must_use]
    pub fn tier(&self) -> Option<KdfTier> {
        [KdfTier::Interactive, KdfTier::Moderate, KdfTier::Sensitive]
            .into_iter()
            .find(|tier| tier.params() == *self)
    }
    /// Runs Argon2id over `passphrase` and `salt`, producing a 32-byte
    /// [`KdfKey`].
    ///
    /// # Errors
    ///
    /// [`Error::KdfParamsRejected`] if [`validate`](Self::validate) fails, or
    /// [`Error::Kdf`] if Argon2 rejects the inputs (a salt shorter than 8
    /// bytes, for instance).
    pub fn derive_key(&self, passphrase: &[u8], salt: &[u8]) -> Result<KdfKey> {
        self.validate()?;
        let params = self.to_argon2()?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; KEY_LEN];
        let derived = argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map(|()| KdfKey::from_bytes(out))
            .map_err(|error| Error::Kdf {
                detail: error.to_string(),
            });
        out.zeroize();
        derived
    }

    fn to_argon2(self) -> Result<Params> {
        Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|error| Error::Kdf {
            detail: error.to_string(),
        })
    }
}

/// Argon2id with a secret ("pepper") and associated data.
///
/// Misty uses neither — there is no server-side pepper by design, since SPEC §6
/// has the server hold no key. This exists so the RFC 9106 known-answer test,
/// whose vector includes both, can run. `derive_key` is tied to it by
/// `derive_key_matches_the_raw_path`, so the KAT covers the production path
/// too.
#[cfg(test)]
pub(crate) fn argon2id_raw(
    passphrase: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    params: KdfParams,
    out: &mut [u8],
) -> Result<()> {
    let kdf_error = |error: argon2::Error| Error::Kdf {
        detail: error.to_string(),
    };
    let mut builder = argon2::ParamsBuilder::new();
    builder
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.parallelism)
        .output_len(out.len());
    if !associated_data.is_empty() {
        builder.data(argon2::AssociatedData::new(associated_data).map_err(kdf_error)?);
    }
    let params = builder.build().map_err(kdf_error)?;
    let argon2 = Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
        .map_err(kdf_error)?;
    argon2
        .hash_password_into(passphrase, salt, out)
        .map_err(kdf_error)
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Authoritative: RFC 9106 §5.3. Includes the secret and associated-data
    /// inputs, which is why it goes through [`argon2id_raw`].
    #[test]
    fn argon2id_rfc9106_vector() {
        let mut out = [0u8; 32];
        argon2id_raw(
            &[0x01; 32],
            &[0x02; 16],
            &[0x03; 8],
            &[0x04; 12],
            KdfParams::new(32, 3, 4),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            out,
            hex_literal::hex!("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }

    #[test]
    fn tiers_match_the_spec_table() {
        assert_eq!(KdfTier::Interactive.params(), KdfParams::new(65536, 3, 4));
        assert_eq!(KdfTier::Moderate.params(), KdfParams::new(262_144, 3, 4));
        assert_eq!(KdfTier::Sensitive.params(), KdfParams::new(1_048_576, 4, 4));
        for tier in [KdfTier::Interactive, KdfTier::Moderate, KdfTier::Sensitive] {
            tier.params().validate().unwrap();
            assert_eq!(tier.params().tier(), Some(tier));
        }
    }

    #[test]
    fn recommended_for_walks_the_thresholds() {
        assert_eq!(KdfTier::recommended_for(0), KdfTier::Interactive);
        assert_eq!(
            KdfTier::recommended_for(1024 * 1024 * 1024 - 1),
            KdfTier::Interactive
        );
        assert_eq!(
            KdfTier::recommended_for(1024 * 1024 * 1024),
            KdfTier::Moderate
        );
        assert_eq!(
            KdfTier::recommended_for(4 * 1024 * 1024 * 1024),
            KdfTier::Sensitive
        );
        assert_eq!(KdfTier::recommended_for(u64::MAX), KdfTier::Sensitive);
    }

    #[test]
    fn absurd_parameters_are_rejected() {
        // 64 GiB, as a hostile header might claim.
        let absurd = KdfParams::new(64 * 1024 * 1024, 3, 4);
        assert!(matches!(
            absurd.validate(),
            Err(Error::KdfParamsRejected { .. })
        ));
        for bad in [
            KdfParams::new(0, 3, 4),
            KdfParams::new(4, 3, 4),
            KdfParams::new(65536, 0, 4),
            KdfParams::new(65536, 17, 4),
            KdfParams::new(65536, 3, 0),
            KdfParams::new(65536, 3, 17),
            KdfParams::new(8, 3, 4),
        ] {
            assert!(
                matches!(bad.validate(), Err(Error::KdfParamsRejected { .. })),
                "{bad:?} should be rejected"
            );
        }
        assert!(KdfParams::new(32, 3, 4).validate().is_ok());
    }

    #[test]
    fn unknown_parameters_have_no_tier() {
        assert_eq!(KdfParams::new(65536, 1, 1).tier(), None);
    }

    /// Ties the RFC 9106 known-answer test to the production path.
    ///
    /// With an empty secret and empty associated data, [`argon2id_raw`] and
    /// [`KdfParams::derive_key`] must agree — so the authoritative vector above
    /// covers `derive_key` as well, even though it calls a different `argon2`
    /// entry point.
    #[test]
    fn derive_key_matches_the_raw_path() {
        let params = KdfParams::new(32, 3, 4);
        let mut expected = [0u8; KEY_LEN];
        argon2id_raw(
            b"correct horse",
            &[0x5a; 16],
            &[],
            &[],
            params,
            &mut expected,
        )
        .unwrap();
        let derived = params.derive_key(b"correct horse", &[0x5a; 16]).unwrap();
        assert_eq!(derived.expose_secret(), &expected);
    }

    #[test]
    fn derive_key_is_deterministic_and_salt_dependent() {
        let params = KdfParams::new(32, 1, 1);
        let a = params.derive_key(b"passphrase", &[1u8; 16]).unwrap();
        let b = params.derive_key(b"passphrase", &[1u8; 16]).unwrap();
        let c = params.derive_key(b"passphrase", &[2u8; 16]).unwrap();
        assert!(a.constant_time_eq(&b));
        assert!(!a.constant_time_eq(&c));
    }
}
