// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Every knob, read from the environment.
//!
//! There is no configuration file format, because one more parser is one more
//! attack surface for no benefit: a container, a systemd unit, and a shell all
//! set environment variables natively. A malformed value is a hard startup
//! failure, never a silent default — a server that quietly ran with a 1-byte
//! envelope cap or an unsigned time key would look healthy while being useless.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Why startup configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A value could not be parsed as its type.
    #[error("{name}: {detail}")]
    Invalid {
        /// The environment variable.
        name: &'static str,
        /// What was wrong. Never echoes the value, which may be a key.
        detail: String,
    },
    /// A signing key file could not be read.
    #[error("MISTY_TIME_SIGNING_KEY_FILE: {0}")]
    KeyFile(#[from] std::io::Error),
}

/// Server configuration.
///
/// [`Config::from_env`] is the only intended constructor outside tests;
/// [`Config::for_test`] gives the same defaults with an explicit database path.
#[derive(Clone, Debug)]
pub struct Config {
    /// Where to listen. TLS is **not** terminated here; see `README.md`.
    pub bind: SocketAddr,
    /// SQLite database path. The directory must exist and be writable.
    pub database: PathBuf,

    /// Largest single envelope accepted, in bytes.
    pub max_envelope_bytes: u64,
    /// Largest request body accepted, in bytes. Enforced from `Content-Length`
    /// before any body is read, so a huge declared length costs nothing.
    pub max_body_bytes: usize,
    /// Largest sealed enrollment blob accepted, in bytes.
    pub max_sealed_bytes: u64,
    /// Most items one vault may hold.
    pub max_items_per_vault: u64,
    /// Most total envelope bytes one vault may hold.
    pub max_vault_bytes: u64,
    /// Default `limit` on the changes feed.
    pub default_changes_limit: u32,
    /// Largest accepted `limit` on the changes feed.
    pub max_changes_limit: u32,

    /// Access-token lifetime. SPEC §6.1 says 15 minutes.
    pub access_token_ttl: Duration,
    /// Refresh-token lifetime.
    pub refresh_token_ttl: Duration,
    /// How long an auth challenge stays redeemable.
    pub challenge_ttl: Duration,
    /// How long an enrollment record survives before it is swept.
    pub enroll_ttl: Duration,
    /// How long a reclaimed (tombstone) item row survives before its slot is
    /// released. SPEC §4 purges tombstones after 90 days.
    pub tombstone_retention: Duration,
    /// How often the background sweeper runs.
    pub sweep_interval: Duration,

    /// Requests per minute per `vault_id`.
    pub rate_limit_vault_per_minute: u32,
    /// Requests per minute per client IP.
    pub rate_limit_ip_per_minute: u32,
    /// Bucket depth, i.e. how large a burst is tolerated.
    pub rate_limit_burst: u32,
    /// Whether to believe `X-Forwarded-For`.
    ///
    /// Off by default: on, a client could spoof its way into someone else's
    /// rate-limit bucket. Turn it on only when a reverse proxy you control is
    /// the sole path to the socket, which is also the only configuration where
    /// the header means anything.
    pub trust_forwarded_for: bool,

    /// Optional shared secret required to bootstrap a *new* vault's first
    /// device.
    ///
    /// This is not a user identity and is not stored per vault; it is an invite
    /// secret that stops an open instance from being a free disk. Existing
    /// vaults never present it.
    pub registration_token: Option<String>,
    /// Hard cap on the number of vaults, or `None` for unlimited.
    pub max_vaults: Option<u64>,
}

fn var(name: &'static str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        _ => None,
    }
}

fn parse<T>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match var(name) {
        None => Ok(default),
        Some(text) => text.parse().map_err(|error: T::Err| ConfigError::Invalid {
            name,
            detail: error.to_string(),
        }),
    }
}

fn parse_secs(name: &'static str, default_secs: u64) -> Result<Duration, ConfigError> {
    let secs: u64 = parse(name, default_secs)?;
    if secs == 0 {
        return Err(ConfigError::Invalid {
            name,
            detail: "must be at least 1 second".into(),
        });
    }
    Ok(Duration::from_secs(secs))
}

fn parse_bool(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match var(name) {
        None => Ok(default),
        Some(text) => match text.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(ConfigError::Invalid {
                name,
                detail: "expected one of 1/0, true/false, yes/no, on/off".into(),
            }),
        },
    }
}

impl Config {
    /// Reads the whole configuration from the environment.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] on the first value that does not parse or is out of
    /// range. Defaults are documented in `README.md`.
    pub fn from_env() -> Result<Self, ConfigError> {
        let max_envelope_bytes: u64 = parse("MISTY_MAX_ENVELOPE_BYTES", 64 * 1024)?;
        if max_envelope_bytes < 512 {
            return Err(ConfigError::Invalid {
                name: "MISTY_MAX_ENVELOPE_BYTES",
                detail: "must be at least 512; a smaller cap rejects an empty item".into(),
            });
        }
        // Base64 inflates by 4/3, plus JSON framing. Derived rather than
        // configured separately so the two caps cannot drift into a state where
        // no valid envelope fits in an accepted body.
        let default_body =
            usize::try_from(max_envelope_bytes / 3 * 4 + 8 * 1024).unwrap_or(usize::MAX);
        let max_body_bytes: usize = parse("MISTY_MAX_BODY_BYTES", default_body)?;

        let default_changes_limit: u32 = parse("MISTY_DEFAULT_CHANGES_LIMIT", 100)?;
        let max_changes_limit: u32 = parse("MISTY_MAX_CHANGES_LIMIT", 500)?;
        if default_changes_limit == 0 || default_changes_limit > max_changes_limit {
            return Err(ConfigError::Invalid {
                name: "MISTY_DEFAULT_CHANGES_LIMIT",
                detail: "must be in 1..=MISTY_MAX_CHANGES_LIMIT".into(),
            });
        }

        Ok(Self {
            bind: parse("MISTY_BIND", SocketAddr::from(([127, 0, 0, 1], 8080)))?,
            database: var("MISTY_DB").map_or_else(|| PathBuf::from("misty.sqlite3"), PathBuf::from),
            max_envelope_bytes,
            max_body_bytes,
            max_sealed_bytes: parse("MISTY_MAX_SEALED_BYTES", 8 * 1024)?,
            max_items_per_vault: parse("MISTY_MAX_ITEMS_PER_VAULT", 10_000)?,
            max_vault_bytes: parse("MISTY_MAX_VAULT_BYTES", 64 * 1024 * 1024)?,
            default_changes_limit,
            max_changes_limit,
            access_token_ttl: parse_secs("MISTY_ACCESS_TOKEN_TTL_SECS", 900)?,
            refresh_token_ttl: parse_secs("MISTY_REFRESH_TOKEN_TTL_SECS", 30 * 24 * 3600)?,
            challenge_ttl: parse_secs("MISTY_CHALLENGE_TTL_SECS", 60)?,
            enroll_ttl: parse_secs("MISTY_ENROLL_TTL_SECS", 600)?,
            tombstone_retention: parse_secs("MISTY_TOMBSTONE_RETENTION_SECS", 90 * 24 * 3600)?,
            sweep_interval: parse_secs("MISTY_SWEEP_INTERVAL_SECS", 60)?,
            rate_limit_vault_per_minute: parse("MISTY_RATE_LIMIT_VAULT_PER_MINUTE", 120)?,
            rate_limit_ip_per_minute: parse("MISTY_RATE_LIMIT_IP_PER_MINUTE", 600)?,
            rate_limit_burst: parse("MISTY_RATE_LIMIT_BURST", 60)?,
            trust_forwarded_for: parse_bool("MISTY_TRUST_FORWARDED_FOR", false)?,
            registration_token: var("MISTY_REGISTRATION_TOKEN"),
            max_vaults: match parse::<u64>("MISTY_MAX_VAULTS", 0)? {
                0 => None,
                n => Some(n),
            },
        })
    }

    /// The production defaults with an explicit database path and an ephemeral
    /// port. Tests only.
    #[must_use]
    pub fn for_test(database: PathBuf) -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            database,
            max_envelope_bytes: 64 * 1024,
            max_body_bytes: 64 * 1024 / 3 * 4 + 8 * 1024,
            max_sealed_bytes: 8 * 1024,
            max_items_per_vault: 10_000,
            max_vault_bytes: 64 * 1024 * 1024,
            default_changes_limit: 100,
            max_changes_limit: 500,
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(30 * 24 * 3600),
            challenge_ttl: Duration::from_secs(60),
            enroll_ttl: Duration::from_secs(600),
            tombstone_retention: Duration::from_secs(90 * 24 * 3600),
            sweep_interval: Duration::from_secs(60),
            rate_limit_vault_per_minute: 100_000,
            rate_limit_ip_per_minute: 100_000,
            rate_limit_burst: 100_000,
            trust_forwarded_for: false,
            registration_token: None,
            max_vaults: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests mutate process-global environment state, so they run under one
    // lock rather than in parallel.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<T>(pairs: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for (name, value) in pairs {
            // SAFETY-equivalent note: `set_var` is safe in this edition; the
            // lock is what makes it correct under `cargo test`'s thread pool.
            std::env::set_var(name, value);
        }
        let out = f();
        for (name, _) in pairs {
            std::env::remove_var(name);
        }
        out
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        let config = with_env(&[], Config::from_env).unwrap();
        assert_eq!(config.access_token_ttl, Duration::from_secs(900));
        assert_eq!(config.max_items_per_vault, 10_000);
        assert!(!config.trust_forwarded_for);
        assert!(config.registration_token.is_none());
    }

    #[test]
    fn a_malformed_value_fails_startup_instead_of_defaulting() {
        let error = with_env(&[("MISTY_MAX_ITEMS_PER_VAULT", "lots")], Config::from_env)
            .expect_err("should reject");
        assert!(matches!(
            error,
            ConfigError::Invalid {
                name: "MISTY_MAX_ITEMS_PER_VAULT",
                ..
            }
        ));
    }

    #[test]
    fn an_absurdly_small_envelope_cap_is_rejected() {
        let error =
            with_env(&[("MISTY_MAX_ENVELOPE_BYTES", "1")], Config::from_env).expect_err("reject");
        assert!(matches!(
            error,
            ConfigError::Invalid {
                name: "MISTY_MAX_ENVELOPE_BYTES",
                ..
            }
        ));
    }

    #[test]
    fn a_zero_ttl_is_rejected() {
        let error =
            with_env(&[("MISTY_CHALLENGE_TTL_SECS", "0")], Config::from_env).expect_err("reject");
        assert!(matches!(
            error,
            ConfigError::Invalid {
                name: "MISTY_CHALLENGE_TTL_SECS",
                ..
            }
        ));
    }

    #[test]
    fn bools_accept_the_usual_spellings_and_reject_the_rest() {
        assert!(
            with_env(&[("MISTY_TRUST_FORWARDED_FOR", "yes")], Config::from_env)
                .unwrap()
                .trust_forwarded_for
        );
        assert!(with_env(&[("MISTY_TRUST_FORWARDED_FOR", "maybe")], Config::from_env).is_err());
    }
}
