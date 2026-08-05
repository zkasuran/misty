// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-`vault_id` and per-IP token buckets (SPEC §6.1).
//!
//! # Where IPs live
//!
//! Here, in memory, and nowhere else. SPEC §6.1 requires that IPs never reach a
//! durable log, and this module is the reason that is achievable: the address is
//! hashed into a bucket key, the bucket is dropped when it goes idle, and no code
//! path formats a bucket key into a message. The private `Key` type's own `Debug`
//! is redacted so that a future `tracing::debug!(?key, …)` cannot leak one by
//! accident.
//!
//! # Why token buckets
//!
//! A fixed window lets a caller send two full windows' worth of traffic across a
//! boundary; a leaky bucket smooths that out and gives an honest `Retry-After`
//! (the time until one token exists) rather than a guess.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use crate::error::ApiError;
use crate::ids::VaultId;

/// What a bucket counts against.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    /// One client address. Ephemeral by construction.
    Ip(IpAddr),
    /// One vault.
    Vault(VaultId),
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Deliberately uninformative: this type must never be printable into a
        // log line, and the cheapest way to guarantee that is to make it
        // impossible.
        f.write_str(match self {
            Self::Ip(_) => "Key::Ip([redacted])",
            Self::Vault(_) => "Key::Vault([redacted])",
        })
    }
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

/// Bucket parameters.
#[derive(Clone, Copy, Debug)]
struct Rate {
    per_minute: u32,
    capacity: u32,
}

/// Token-bucket rate limiter.
pub struct RateLimiter {
    buckets: Mutex<HashMap<Key, Bucket>>,
    ip: Rate,
    vault: Rate,
    /// Most buckets held at once. A limiter that grows without bound is a
    /// memory-exhaustion vector dressed up as a defence against one.
    max_buckets: usize,
}

impl RateLimiter {
    /// Builds a limiter from configuration.
    #[must_use]
    pub fn new(config: &crate::Config) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            ip: Rate {
                per_minute: config.rate_limit_ip_per_minute,
                capacity: config.rate_limit_burst,
            },
            vault: Rate {
                per_minute: config.rate_limit_vault_per_minute,
                capacity: config.rate_limit_burst,
            },
            max_buckets: 100_000,
        }
    }

    /// Charges one request to `address`.
    ///
    /// # Errors
    ///
    /// [`ApiError::RateLimited`] with a `Retry-After` in seconds.
    pub fn check_ip(&self, address: IpAddr) -> Result<(), ApiError> {
        self.check(Key::Ip(address), self.ip)
    }

    /// Charges one request to `vault`.
    ///
    /// # Errors
    ///
    /// [`ApiError::RateLimited`] with a `Retry-After` in seconds.
    pub fn check_vault(&self, vault: VaultId) -> Result<(), ApiError> {
        self.check(Key::Vault(vault), self.vault)
    }

    fn check(&self, key: Key, rate: Rate) -> Result<(), ApiError> {
        if rate.per_minute == 0 || rate.capacity == 0 {
            return Ok(());
        }
        let per_second = f64::from(rate.per_minute) / 60.0;
        let capacity = f64::from(rate.capacity);
        let now = Instant::now();

        let Ok(mut buckets) = self.buckets.lock() else {
            // A poisoned limiter must not become an open door.
            return Err(ApiError::RateLimited {
                retry_after_secs: 1,
            });
        };

        // Shedding the whole table under pressure is crude but bounded, and it
        // fails towards *more* limiting: every caller starts from a full bucket
        // at worst, and the cap is far above any legitimate working set.
        if buckets.len() >= self.max_buckets && !buckets.contains_key(&key) {
            buckets.retain(|_, bucket| {
                let refilled = bucket.tokens
                    + now.saturating_duration_since(bucket.updated).as_secs_f64() * per_second;
                refilled < capacity
            });
        }

        let bucket = buckets.entry(key).or_insert(Bucket {
            tokens: capacity,
            updated: now,
        });
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * per_second).min(capacity);
        bucket.updated = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }
        let deficit = 1.0 - bucket.tokens;
        let wait = (deficit / per_second).ceil().max(1.0);
        Err(ApiError::RateLimited {
            // `as` is safe here: `wait` is a small positive number by
            // construction, and a saturating conversion is the right answer for
            // any pathological rate anyway.
            retry_after_secs: wait.min(3600.0) as u64,
        })
    }

    /// Drops buckets that have refilled completely, i.e. idle callers.
    ///
    /// Called by the background sweeper. This is what keeps addresses from
    /// accumulating: an idle client's address is forgotten within a sweep or two.
    pub fn evict_idle(&self) {
        let now = Instant::now();
        let Ok(mut buckets) = self.buckets.lock() else {
            return;
        };
        let ip_rate = f64::from(self.ip.per_minute) / 60.0;
        let vault_rate = f64::from(self.vault.per_minute) / 60.0;
        buckets.retain(|key, bucket| {
            let (rate, capacity) = match key {
                Key::Ip(_) => (ip_rate, f64::from(self.ip.capacity)),
                Key::Vault(_) => (vault_rate, f64::from(self.vault.capacity)),
            };
            let refilled =
                bucket.tokens + now.saturating_duration_since(bucket.updated).as_secs_f64() * rate;
            refilled < capacity
        });
    }

    /// How many buckets are held. Tests and `/healthz`-adjacent diagnostics only.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.buckets.lock().map_or(0, |buckets| buckets.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn limiter(per_minute: u32, burst: u32) -> RateLimiter {
        let mut config = crate::Config::for_test("unused".into());
        config.rate_limit_ip_per_minute = per_minute;
        config.rate_limit_vault_per_minute = per_minute;
        config.rate_limit_burst = burst;
        RateLimiter::new(&config)
    }

    #[test]
    fn a_burst_is_allowed_then_refused() {
        let limiter = limiter(60, 3);
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..3 {
            limiter.check_ip(address).unwrap();
        }
        let error = limiter.check_ip(address).expect_err("fourth is refused");
        match error {
            ApiError::RateLimited { retry_after_secs } => assert!(retry_after_secs >= 1),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn buckets_are_independent() {
        let limiter = limiter(60, 1);
        limiter
            .check_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .unwrap();
        limiter
            .check_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .unwrap();
        assert!(limiter
            .check_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .is_err());
    }

    #[test]
    fn vault_and_ip_buckets_do_not_share() {
        let limiter = limiter(60, 1);
        let vault = VaultId::from_bytes([1; 16]);
        limiter.check_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        limiter.check_vault(vault).unwrap();
        assert!(limiter.check_vault(vault).is_err());
    }

    #[test]
    fn a_zero_rate_disables_the_limit() {
        let limiter = limiter(0, 0);
        for _ in 0..1000 {
            limiter.check_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        }
    }

    #[test]
    fn idle_buckets_are_evicted_so_addresses_are_forgotten() {
        let limiter = limiter(60_000, 10);
        limiter.check_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        assert_eq!(limiter.bucket_count(), 1);
        // At 1000 tokens/second the bucket refills within the test's own runtime.
        std::thread::sleep(std::time::Duration::from_millis(20));
        limiter.evict_idle();
        assert_eq!(limiter.bucket_count(), 0);
    }

    #[test]
    fn a_key_cannot_be_printed() {
        let key = Key::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        let text = format!("{key:?}");
        assert_eq!(text, "Key::Ip([redacted])");
        assert!(!text.contains("203"));
    }
}
