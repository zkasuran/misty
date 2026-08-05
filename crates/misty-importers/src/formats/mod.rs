// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One module per format, and the registry [`crate::detect`] searches.
//!
//! Order in [`ALL`] is priority order. It matters in exactly one way: sniffing
//! returns a [`Confidence`](crate::Confidence), the best wins, and registry order
//! breaks ties. The two generic readers are last and never claim better than
//! `Possible`, so a vendor format is never read as anonymous CSV or JSON.

use crate::importer::Importer;

mod aegis;
mod andotp;
mod authy;
mod bitwarden;
mod ente;
mod freeotp;
mod generic;
mod keepass;
mod lastpass;
mod migration;
mod otpauth;
mod proton;
mod raivo;
mod twofas;
mod xml;

pub use aegis::AegisImporter;
pub use andotp::AndOtpImporter;
pub use authy::AuthyImporter;
pub use bitwarden::BitwardenImporter;
pub use ente::EnteAuthImporter;
pub use freeotp::{FreeOtpImporter, FreeOtpPlusImporter};
pub use generic::{CsvImporter, JsonImporter};
pub use keepass::KeePassXcImporter;
pub use lastpass::LastPassImporter;
pub use migration::GoogleMigrationImporter;
pub use otpauth::OtpauthImporter;
pub use proton::ProtonPassImporter;
pub use raivo::RaivoImporter;
pub use twofas::TwoFasImporter;

pub(crate) use bitwarden::totp_field;
pub(crate) use otpauth::{is_uri_line, item_from_uri, sniff_uri_list};

/// Every importer, in priority order.
pub(crate) static ALL: &[&dyn Importer] = &[
    // Formats with a magic string or a shape only they produce.
    &GoogleMigrationImporter,
    &AegisImporter,
    &TwoFasImporter,
    &AndOtpImporter,
    &FreeOtpPlusImporter,
    &FreeOtpImporter,
    &RaivoImporter,
    &LastPassImporter,
    &AuthyImporter,
    &ProtonPassImporter,
    &BitwardenImporter,
    &KeePassXcImporter,
    // Ente before plain otpauth: its export *is* a URI list, with metadata the
    // plain reader would drop.
    &EnteAuthImporter,
    &OtpauthImporter,
    // Last, and never better than `Possible`.
    &CsvImporter,
    &JsonImporter,
];
