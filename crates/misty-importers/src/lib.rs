// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Import from every other authenticator, and export in a form every other
//! authenticator can read.
//!
//! Lock-in is the loudest complaint users have about the app most of them are
//! leaving, and refusing to build it is a decision Misty has already made
//! (SPEC 8). This crate is that decision in code: it reads the export formats of
//! fourteen other applications and emits Misty's model, and it writes
//! `otpauth://` and plaintext JSON so a user can leave Misty just as easily.
//!
//! # What this crate promises
//!
//! * **Fully offline.** There is no network code here, for any reason, and no
//!   dependency that has any. An importer that fetched an issuer icon would leak
//!   the user's entire service list to a CDN.
//! * **Per-row failure isolation.** One malformed row produces one
//!   [`RowOutcome::Failed`] and the batch continues. A user importing 200 accounts
//!   does not lose 199 of them to one bad line.
//! * **Preview before write.** [`Importer::preview`] returns exactly what
//!   [`Importer::import`] would add, with every secret left out, so the UI can
//!   show it before anything is committed.
//! * **No secret in any error, ever.** Errors name the row and the problem, never
//!   the value. `tests/redaction.rs` asserts it across every importer and every
//!   hostile input.
//! * **Nothing panics.** Every parser here eats files from strangers.
//!
//! # Architecture
//!
//! This crate does **not** depend on `misty-vault`. It emits a plain
//! [`Vec<ImportedItem>`] plus a per-row [`Vec<RowOutcome>`] and lets the caller
//! insert them. That keeps it independent of the vault layer, testable without a
//! database, and usable from the browser extension, which has no SQLite.
//!
//! It does depend on [`misty_otp`] for [`OtpConfig`](misty_otp::OtpConfig) and
//! [`SecretBytes`](misty_otp::SecretBytes), and it delegates every `otpauth://`
//! URI to that crate's parser rather than writing a second one.
//!
//! # Example
//!
//! ```
//! use misty_importers::{ImportContext, Importer, RowOutcome};
//!
//! let file = b"otpauth://totp/ACME:ada@example.com?secret=JBSWY3DPEHPK3PXP\n\
//!              this line is not a uri\n\
//!              otpauth://hotp/ACME:bob?secret=JBSWY3DPEHPK3PXP&counter=7\n";
//!
//! let importer = misty_importers::detect(file).expect("a recognizable format");
//! let ctx = ImportContext::new();
//!
//! // Dry run first: this is what the UI shows, and it holds no secrets.
//! let preview = importer.preview(file, &ctx)?;
//! assert_eq!(preview.would_import(), 2);
//! assert_eq!(preview.failed(), 1);
//! assert_eq!(preview.items[0].issuer.as_deref(), Some("ACME"));
//! assert_eq!(preview.items[0].secret_len, 10);
//!
//! // Then the real thing. One bad line did not cost the other two.
//! let report = importer.import(file, &ctx)?;
//! assert_eq!(report.imported(), 2);
//! assert_eq!(report.failed(), 1);
//! assert!(matches!(report.outcomes[1], RowOutcome::Failed { .. }));
//! # Ok::<(), misty_importers::ImportError>(())
//! ```
//!
//! [`docs/SPEC.md`]: https://github.com/zkasuran/misty/blob/main/docs/SPEC.md

#![forbid(unsafe_code)]
#![warn(missing_docs)]
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

mod build;
mod collect;
mod context;
mod csv;
mod error;
pub mod export;
mod formats;
mod importer;
mod interop;
mod json;
mod mapping;
mod model;
mod outcome;
mod protobuf;
mod text;

pub use context::{DuplicatePolicy, ExistingItems, ImportContext, Limits};
pub use error::{ImportError, ProtobufError, Result, RowError};
pub use formats::*;
pub use importer::{
    detect, detect_all, detect_format, import_auto, importer_for, importers, preview_auto,
    Confidence, Detection, Importer,
};
pub use mapping::ColumnMapping;
pub use model::{ImportedItem, ItemPreview, SourceFormat};
pub use outcome::{
    BatchPart, ImportReport, ImportWarning, PreviewReport, RowId, RowOutcome, SkipReason,
};
