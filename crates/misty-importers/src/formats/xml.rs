// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The two lines of XML plumbing both XML formats need.
//!
//! FreeOTP's `tokens.xml` and KeePassXC's export both store what this crate wants
//! as element *text*, and both put `&amp;` and `&quot;` in it — a `SharedPreferences`
//! file holds JSON inside XML, and a KeePass `otp` attribute holds a URI whose
//! query separators are ampersands.
//!
//! `quick-xml` reports an entity reference as its own [`Event::GeneralRef`], which
//! splits `key=A&amp;size=6` into three events. Reading only the `Text` events and
//! keeping the last would silently produce `size=6` as the value: a token that
//! imports and generates nothing. [`text_until`] uses `Reader::read_text`, which
//! returns everything up to the closing tag as one span, and unescapes it in one
//! step.
//!
//! [`Event::GeneralRef`]: quick_xml::events::Event::GeneralRef

use quick_xml::name::QName;
use quick_xml::Reader;

use crate::error::{ImportError, Result};

/// Deepest element nesting either reader tolerates.
///
/// XML has no natural depth limit and `quick-xml` keeps a stack of open tag names,
/// so ten megabytes of `<a><a><a>…` would otherwise buy an attacker a very large
/// allocation from a very small file. Bounding the depth is cheaper than bounding
/// the memory.
pub(crate) const MAX_DEPTH: usize = 256;

/// Everything between the current start tag and its matching end tag, unescaped.
///
/// Consumes the end tag, so a caller must not expect an [`Event::End`] for it.
///
/// Decoding and unescaping are two explicit steps rather than one
/// `xml_content()` call, because that method's meaning depends on an XML version
/// argument and this crate does not care which version a `SharedPreferences` file
/// claims to be.
///
/// [`Event::End`]: quick_xml::events::Event::End
pub(crate) fn text_until(reader: &mut Reader<&[u8]>, end: QName<'_>) -> Result<String> {
    let position = reader.buffer_position();
    let fail = ImportError::Xml { offset: position };
    let raw = reader.read_text(end).map_err(|_| fail.clone())?;
    let decoded = raw.decode().map_err(|_| fail.clone())?;
    let unescaped = quick_xml::escape::unescape(&decoded).map_err(|_| fail)?;
    Ok(unescaped.into_owned())
}
