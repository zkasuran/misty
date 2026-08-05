// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one place a row becomes an outcome.
//!
//! Every importer pushes its rows through [`Collector`], so duplicate detection,
//! field validation, the row limit, and outcome bookkeeping happen identically for
//! all fourteen formats instead of fourteen times with three subtle differences.

use std::collections::HashSet;

use crate::context::{triple_digest, DuplicatePolicy, ImportContext};
use crate::error::RowError;
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{BatchPart, ImportReport, ImportWarning, RowId, RowOutcome, SkipReason};
use crate::text;

pub(crate) struct Collector<'c, 'ctx> {
    format: SourceFormat,
    ctx: &'c ImportContext<'ctx>,
    items: Vec<ImportedItem>,
    outcomes: Vec<RowOutcome>,
    batch_parts: Vec<BatchPart>,
    seen: HashSet<[u8; 32]>,
}

impl<'c, 'ctx> Collector<'c, 'ctx> {
    pub(crate) fn new(format: SourceFormat, ctx: &'c ImportContext<'ctx>) -> Self {
        Self {
            format,
            ctx,
            items: Vec::new(),
            outcomes: Vec::new(),
            batch_parts: Vec::new(),
            seen: HashSet::new(),
        }
    }

    pub(crate) fn ctx(&self) -> &'c ImportContext<'ctx> {
        self.ctx
    }

    /// Whether the row limit has been reached. Importers check this before
    /// reading another row, so a file claiming a million entries stops costing
    /// memory at the limit instead of at the end.
    pub(crate) fn is_full(&self) -> bool {
        self.outcomes.len() >= self.ctx.limits().max_rows
    }

    /// How many rows have been looked at.
    pub(crate) fn rows(&self) -> usize {
        self.outcomes.len()
    }

    /// Offer a row. Validation, duplicate detection and bookkeeping happen here.
    pub(crate) fn accept(
        &mut self,
        row: RowId,
        item: ImportedItem,
        mut warnings: Vec<ImportWarning>,
    ) {
        if let Err(error) = self.validate(&item) {
            self.fail(row, error);
            return;
        }

        let issuer = item.issuer.as_deref();
        let key = triple_digest(issuer, &item.account, item.otp.secret().expose_secret());
        let fresh_in_batch = self.seen.insert(key);
        let known = self
            .ctx
            .existing()
            .is_some_and(|existing| existing.contains(issuer, &item.account, item.otp.secret()));

        match (self.ctx.duplicate_policy(), fresh_in_batch, known) {
            (DuplicatePolicy::Skip, false, _) => {
                self.skip(row, SkipReason::DuplicateInBatch);
                return;
            }
            (DuplicatePolicy::Skip, true, true) => {
                self.skip(row, SkipReason::DuplicateOfExisting);
                return;
            }
            (DuplicatePolicy::Keep, fresh, dup) if !fresh || dup => {
                warnings.push(ImportWarning::DuplicateOfExisting);
            }
            _ => {}
        }

        // SPEC 3.1: the same `(issuer, account)` with a *different* secret is two
        // real accounts. Keep both, and tell the caller so it can make the user
        // name them apart instead of silently creating an ambiguous pair.
        if !known
            && self
                .ctx
                .existing()
                .is_some_and(|existing| existing.contains_pair(issuer, &item.account))
        {
            warnings.push(ImportWarning::CollidesWithExisting);
        }

        // Yandex keys with a prefix of what it prints (SPEC 7); saying so is the
        // difference between a user believing an import worked and knowing why a
        // code is wrong.
        if let Some(used) = item.otp.kind().secret_prefix_used() {
            if item.otp.secret().len() > used {
                warnings.push(ImportWarning::SecretPrefixUsed(used));
            }
        }

        let at = self.items.len();
        self.items.push(item);
        self.outcomes.push(RowOutcome::Imported {
            row,
            item: at,
            warnings,
        });
    }

    pub(crate) fn skip(&mut self, row: RowId, reason: SkipReason) {
        self.outcomes.push(RowOutcome::Skipped { row, reason });
    }

    pub(crate) fn fail(&mut self, row: RowId, error: RowError) {
        self.outcomes.push(RowOutcome::Failed { row, error });
    }

    /// Record that this file contained one part of a multi-part export.
    pub(crate) fn note_batch_part(&mut self, index: u32, total: u32) {
        if total > 1 && !self.batch_parts.iter().any(|part| part.index == index) {
            self.batch_parts.push(BatchPart { index, total });
        }
    }

    pub(crate) fn finish(self) -> ImportReport {
        ImportReport {
            items: self.items,
            outcomes: self.outcomes,
            format: self.format,
            batch_parts: self.batch_parts,
        }
    }

    /// Length and code-point checks on every text field, in one place.
    fn validate(&self, item: &ImportedItem) -> core::result::Result<(), RowError> {
        let limits = self.ctx.limits();
        let max = limits.max_text_field_bytes;

        if let Some(issuer) = &item.issuer {
            text::check_field("issuer", issuer, max, false)?;
        }
        text::check_field("account", &item.account, max, false)?;
        if let Some(nickname) = &item.nickname {
            text::check_field("nickname", nickname, max, false)?;
        }
        if let Some(note) = &item.note {
            text::check_field("note", note, limits.max_note_bytes, true)?;
        }
        for tag in &item.tags {
            text::check_field("tags", tag, max, false)?;
        }
        for group in &item.groups {
            text::check_field("group", group, max, false)?;
        }
        for origin in &item.origins {
            text::check_field("origin", origin, max, false)?;
        }
        if item.tags.len() > limits.max_tags {
            return Err(RowError::FieldTooLong {
                field: "tags",
                len: item.tags.len(),
                max: limits.max_tags,
            });
        }
        if item.groups.len() > limits.max_tags {
            return Err(RowError::FieldTooLong {
                field: "group",
                len: item.groups.len(),
                max: limits.max_tags,
            });
        }
        Ok(())
    }
}
