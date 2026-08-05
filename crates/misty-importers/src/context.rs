// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the caller hands an importer: limits, a passphrase, the items it already
//! has, and — for the generic formats — a column mapping.

use core::fmt;
use std::collections::HashSet;

use misty_otp::SecretBytes;
use sha2::{Digest, Sha256};

/// Bounds every importer parses inside.
///
/// These exist because an importer eats files from strangers. Each one is
/// generous enough for a real export and small enough that a hostile file cannot
/// turn into an allocation. Every limit is public so a caller can tighten it;
/// `tests/hostile_inputs.rs` proves the defaults hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest input accepted, in bytes. Aegis embeds icon images in its vault,
    /// so a real 200-account export can genuinely reach several megabytes.
    pub max_input_bytes: usize,
    /// Most rows read from one file. SPEC 5 puts a vault at under 10k items.
    pub max_rows: usize,
    /// Longest issuer, account, nickname, tag, or group name, in bytes.
    pub max_text_field_bytes: usize,
    /// Longest note, in bytes. Larger than the other text fields because people
    /// keep real prose there.
    pub max_note_bytes: usize,
    /// Most columns in one CSV row.
    pub max_csv_columns: usize,
    /// Most tags or groups kept per row.
    pub max_tags: usize,
    /// Most memory a *file's own* KDF header may ask for, in bytes. Aegis's
    /// default scrypt cost is 32 MiB; a header asking for 64 GiB is an attack.
    pub max_kdf_memory_bytes: u64,
    /// Most KDF iterations a file's own header may ask for.
    pub max_kdf_iterations: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 32 * 1024 * 1024,
            max_rows: 20_000,
            max_text_field_bytes: 4096,
            max_note_bytes: 16 * 1024,
            max_csv_columns: 256,
            max_tags: 64,
            max_kdf_memory_bytes: 512 * 1024 * 1024,
            max_kdf_iterations: 10_000_000,
        }
    }
}

/// What to do with a row that exactly matches something the caller already has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DuplicatePolicy {
    /// Report it as [`SkipReason::DuplicateOfExisting`](crate::SkipReason) and do
    /// not produce an item. The default: re-importing the same file twice should
    /// not double every account.
    #[default]
    Skip,
    /// Produce the item anyway, with
    /// [`ImportWarning::DuplicateOfExisting`](crate::ImportWarning). For a caller
    /// that wants to show both and let the user choose.
    Keep,
}

/// The `(issuer, account, secret)` triples the caller already holds.
///
/// Stored as salted-domain-separated SHA-256 digests rather than as the values,
/// for two reasons: a `HashSet` needs `Hash`, which no secret type in Misty
/// implements, and comparing digests means this crate never compares two secrets
/// with `==` (SPEC 2.1 makes that a review-blocking bug).
///
/// Issuer and account are compared after trimming surrounding whitespace and
/// **without** case folding. Case folding would be friendlier across vendors
/// ("GitHub" versus "Github") and is deliberately not done: a false duplicate is
/// a silently dropped account, and an account the user cannot generate codes for
/// is worse than one listed twice.
#[derive(Clone, Default)]
pub struct ExistingItems {
    triples: HashSet<[u8; 32]>,
    pairs: HashSet<[u8; 32]>,
}

const DEDUPE_CONTEXT: &[u8] = b"misty/import-dedupe/v1";

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DEDUPE_CONTEXT);
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The digest that decides whether two rows are the same account, as
/// `(issuer, account, secret)` (SPEC 3.1.5).
pub(crate) fn triple_digest(issuer: Option<&str>, account: &str, secret: &[u8]) -> [u8; 32] {
    digest(&[
        issuer.unwrap_or("").trim().as_bytes(),
        account.trim().as_bytes(),
        secret,
    ])
}

/// The digest that decides whether two rows name the same `(issuer, account)`
/// with possibly different secrets — two real accounts, per SPEC 3.1.5.
fn pair_digest(issuer: Option<&str>, account: &str) -> [u8; 32] {
    digest(&[
        issuer.unwrap_or("").trim().as_bytes(),
        account.trim().as_bytes(),
    ])
}

impl ExistingItems {
    /// An empty set: every row is new.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one item the caller already has.
    ///
    /// The secret is read here, which is why the parameter is a
    /// [`SecretBytes`] rather than a `&[u8]`: the call site is meant to be
    /// obvious in review.
    pub fn add(&mut self, issuer: Option<&str>, account: &str, secret: &SecretBytes) {
        self.triples
            .insert(triple_digest(issuer, account, secret.expose_secret()));
        self.pairs.insert(pair_digest(issuer, account));
    }

    /// Whether the exact triple is already present (SPEC 3.1: a genuine
    /// duplicate).
    #[must_use]
    pub fn contains(&self, issuer: Option<&str>, account: &str, secret: &SecretBytes) -> bool {
        self.triples
            .contains(&triple_digest(issuer, account, secret.expose_secret()))
    }

    /// Whether some item has this issuer and account, whatever its secret
    /// (SPEC 3.1: two real accounts, both kept, but the user must be made to name
    /// them apart).
    #[must_use]
    pub fn contains_pair(&self, issuer: Option<&str>, account: &str) -> bool {
        self.pairs.contains(&pair_digest(issuer, account))
    }

    /// How many items have been recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.triples.len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.triples.is_empty()
    }
}

/// Deliberately opaque: the digests are derived from secrets.
impl fmt::Debug for ExistingItems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExistingItems")
            .field("len", &self.triples.len())
            .finish()
    }
}

/// Everything an importer needs beyond the bytes themselves.
///
/// `Debug` prints whether a passphrase is present, never its content.
#[derive(Clone, Default)]
pub struct ImportContext<'a> {
    passphrase: Option<&'a [u8]>,
    existing: Option<&'a ExistingItems>,
    mapping: Option<&'a crate::mapping::ColumnMapping>,
    duplicates: DuplicatePolicy,
    limits: Limits,
}

impl<'a> ImportContext<'a> {
    /// A context with default limits, no passphrase, and nothing to deduplicate
    /// against.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Supply the passphrase for an encrypted export.
    ///
    /// Borrowed rather than owned so the caller keeps control of the buffer and
    /// can zeroize it; this crate never copies it anywhere but into the KDF.
    #[must_use]
    pub fn with_passphrase(mut self, passphrase: &'a [u8]) -> Self {
        self.passphrase = Some(passphrase);
        self
    }

    /// Supply the items the caller already holds, for duplicate detection.
    #[must_use]
    pub fn with_existing(mut self, existing: &'a ExistingItems) -> Self {
        self.existing = Some(existing);
        self
    }

    /// Supply a column mapping for the generic CSV and JSON importers.
    #[must_use]
    pub fn with_mapping(mut self, mapping: &'a crate::mapping::ColumnMapping) -> Self {
        self.mapping = Some(mapping);
        self
    }

    /// Choose what happens to exact duplicates.
    #[must_use]
    pub fn with_duplicate_policy(mut self, policy: DuplicatePolicy) -> Self {
        self.duplicates = policy;
        self
    }

    /// Tighten (or loosen) the parsing limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The passphrase, if one was supplied.
    #[must_use]
    pub fn passphrase(&self) -> Option<&'a [u8]> {
        self.passphrase
    }

    /// The caller's existing items.
    #[must_use]
    pub fn existing(&self) -> Option<&'a ExistingItems> {
        self.existing
    }

    /// The column mapping, if one was supplied.
    #[must_use]
    pub fn mapping(&self) -> Option<&'a crate::mapping::ColumnMapping> {
        self.mapping
    }

    /// What to do with exact duplicates.
    #[must_use]
    pub fn duplicate_policy(&self) -> DuplicatePolicy {
        self.duplicates
    }

    /// The parsing limits.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
}

impl fmt::Debug for ImportContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportContext")
            .field("passphrase", &self.passphrase.map(|_| "[redacted]"))
            .field("existing", &self.existing)
            .field("mapping", &self.mapping)
            .field("duplicates", &self.duplicates)
            .field("limits", &self.limits)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(bytes: &[u8]) -> SecretBytes {
        SecretBytes::from_slice(bytes)
    }

    #[test]
    fn triples_match_exactly_and_pairs_match_loosely() {
        let mut existing = ExistingItems::new();
        existing.add(Some("GitHub"), "ada@example.com", &secret(b"AAAAAAAAAA"));

        assert!(existing.contains(Some("GitHub"), "ada@example.com", &secret(b"AAAAAAAAAA")));
        // Whitespace is trimmed.
        assert!(existing.contains(
            Some(" GitHub "),
            " ada@example.com ",
            &secret(b"AAAAAAAAAA")
        ));
        // A different secret is a different account (SPEC 3.1.5), not a duplicate.
        assert!(!existing.contains(Some("GitHub"), "ada@example.com", &secret(b"BBBBBBBBBB")));
        // But the pair still collides, which is what the UI must warn about.
        assert!(existing.contains_pair(Some("GitHub"), "ada@example.com"));
        // Case is NOT folded: deliberately.
        assert!(!existing.contains_pair(Some("github"), "ada@example.com"));
        assert_eq!(existing.len(), 1);
    }

    #[test]
    fn field_boundaries_cannot_be_confused() {
        // Length-prefixing every part means "ab"+"c" cannot collide with "a"+"bc".
        let mut existing = ExistingItems::new();
        existing.add(Some("ab"), "c", &secret(b"s"));
        assert!(!existing.contains(Some("a"), "bc", &secret(b"s")));
    }

    #[test]
    fn debug_hides_the_passphrase() {
        let passphrase = b"correct horse battery staple";
        let ctx = ImportContext::new().with_passphrase(passphrase);
        let rendered = format!("{ctx:?}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(!rendered.contains("horse"), "{rendered}");
    }
}
