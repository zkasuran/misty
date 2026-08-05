// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One typed error for every way a request can fail, and its wire form.
//!
//! Every endpoint returns an [`ApiError`] rather than a bare status code, and
//! every hostile input in `tests/hostile_input.rs` lands on one of these. Two
//! rules hold throughout:
//!
//! * **Nothing derived from an envelope appears in an error.** No length, no
//!   hash, no offset. The one exception is a `409`, which returns the *current*
//!   envelope verbatim because that is what SPEC §6.1 requires so the client can
//!   merge and retry.
//! * **Nothing distinguishes "no such vault" from "wrong signature".** Both are
//!   [`ApiError::Unauthorized`] with the same body. A distinguishable answer
//!   would turn the auth endpoints into an existence oracle, which is exactly the
//!   enumeration the design refuses to allow.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::ids::IdError;

/// A stable, machine-readable error identifier.
///
/// Clients branch on this, never on the human-readable message. Adding a variant
/// is a compatible change; renaming one is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed request: bad id, bad base64, bad JSON, absurd query value.
    BadRequest,
    /// Missing, expired, or unverifiable credentials.
    Unauthorized,
    /// Valid credentials for a different vault, or a device that is not admitted.
    Forbidden,
    /// No such item or enrollment.
    NotFound,
    /// The path exists but not for this method.
    MethodNotAllowed,
    /// `If-Match` did not match, or the resource already exists. Carries the
    /// current `version` and `envelope`.
    Conflict,
    /// Neither `If-Match` nor `If-None-Match` was supplied on a write.
    PreconditionRequired,
    /// A single envelope exceeded the per-envelope cap.
    PayloadTooLarge,
    /// The body was not `application/json`.
    UnsupportedMediaType,
    /// Rate limited. Carries `Retry-After`.
    RateLimited,
    /// The vault is at its item-count or total-bytes limit.
    QuotaExceeded,
    /// A bug on our side. Never carries detail.
    Internal,
}

/// Every way a request can fail.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// A malformed request, with a message naming the field at fault.
    #[error("{0}")]
    BadRequest(String),

    /// Credentials absent, expired, or wrong. Deliberately indistinguishable
    /// from "no such vault" and "no such device".
    #[error("authentication failed")]
    Unauthorized,

    /// A token that authenticates, but not for this vault.
    #[error("not permitted for this vault")]
    Forbidden,

    /// No such item or enrollment record.
    #[error("not found")]
    NotFound,

    /// The path is routable but not for this method.
    #[error("method not allowed on this path")]
    MethodNotAllowed,

    /// `If-Match`/`If-None-Match` failed. Returns the current state so the
    /// client can merge locally and retry (SPEC §6.1). The server never merges.
    #[error("version conflict")]
    Conflict {
        /// The item's current concurrency token, or `"0"` if there is no such
        /// item. An opaque printable-ASCII string per SPEC §6.1.1, never a number.
        version: String,
        /// The current envelope, base64 (standard alphabet, padded), or `None`
        /// if the row's bytes have been reclaimed or the row does not exist.
        ///
        /// Serialised as an explicit `null` rather than omitted: a reclaimed row
        /// still has a version the client must record, so "no bytes" and "no
        /// answer" have to be distinguishable (SPEC §6.1).
        envelope: Option<String>,
    },

    /// A create-only resource already exists, or a device id is taken by a
    /// different key.
    ///
    /// Separate from [`Self::Conflict`] because that one's body carries a
    /// `version` and an `envelope`, and a `409` from `/v1/enroll/begin` has
    /// neither. Reusing it meant answering with `version: 0`, which a client could
    /// reasonably misread as "no such item".
    #[error("{what} already exists")]
    AlreadyExists {
        /// What was already there: `"enrollment"`, `"enrollment response"`, or
        /// `"device"`.
        what: &'static str,
    },

    /// A write arrived with no precondition at all.
    #[error("a write requires If-Match: \"{{version}}\" or If-None-Match: *")]
    PreconditionRequired,

    /// One envelope was larger than [`crate::Config::max_envelope_bytes`].
    #[error("envelope exceeds the {max}-byte cap")]
    PayloadTooLarge {
        /// The configured cap.
        max: u64,
    },

    /// Wrong or missing `Content-Type`.
    #[error("expected Content-Type: application/json")]
    UnsupportedMediaType,

    /// A rate-limit bucket was empty.
    #[error("rate limited")]
    RateLimited {
        /// Seconds until the bucket has a token again.
        retry_after_secs: u64,
    },

    /// The vault cannot hold more.
    #[error("{what} limit reached for this vault")]
    QuotaExceeded {
        /// Which limit: `"item count"` or `"total bytes"`.
        what: &'static str,
    },

    /// An internal failure. The `String` is logged, never returned.
    #[error("internal error")]
    Internal(String),
}

impl From<IdError> for ApiError {
    fn from(error: IdError) -> Self {
        Self::BadRequest(error.to_string())
    }
}

/// The JSON body of every error response.
#[derive(Debug, Serialize)]
struct Body<'a> {
    error: ErrorCode,
    message: &'a str,
    /// Present only on `409`.
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    /// Present only on `409`, and an explicit `null` there for a row whose bytes
    /// have been reclaimed. The double `Option` is what makes "omitted" and
    /// "present and null" different serialisations rather than the same one.
    #[serde(skip_serializing_if = "Option::is_none")]
    envelope: Option<Option<&'a str>>,
}

impl ApiError {
    /// The machine-readable code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::BadRequest(_) => ErrorCode::BadRequest,
            Self::Unauthorized => ErrorCode::Unauthorized,
            Self::Forbidden => ErrorCode::Forbidden,
            Self::NotFound => ErrorCode::NotFound,
            Self::MethodNotAllowed => ErrorCode::MethodNotAllowed,
            Self::Conflict { .. } | Self::AlreadyExists { .. } => ErrorCode::Conflict,
            Self::PreconditionRequired => ErrorCode::PreconditionRequired,
            Self::PayloadTooLarge { .. } => ErrorCode::PayloadTooLarge,
            Self::UnsupportedMediaType => ErrorCode::UnsupportedMediaType,
            Self::RateLimited { .. } => ErrorCode::RateLimited,
            Self::QuotaExceeded { .. } => ErrorCode::QuotaExceeded,
            Self::Internal(_) => ErrorCode::Internal,
        }
    }

    /// The HTTP status.
    ///
    /// Two choices deviate from a naive reading and are argued in
    /// `README.md`: a failed precondition is `409` (not `412`) because SPEC §6.1
    /// requires the response to carry the current envelope, and an exhausted
    /// vault quota is `507` (not `413`) because `413` tells a client to shrink
    /// its request when the real problem is that the vault is full.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::Conflict { .. } | Self::AlreadyExists { .. } => StatusCode::CONFLICT,
            Self::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
            Self::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::QuotaExceeded { .. } => StatusCode::INSUFFICIENT_STORAGE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();

        // An internal error's detail is for the operator, not the caller. It is
        // logged without a vault id or item id attached, because the caller
        // controls neither the message nor whether it is reached.
        if let Self::Internal(detail) = &self {
            tracing::error!(target: "misty_server::error", detail = %detail, "internal error");
        }

        let message = self.to_string();
        let (version, envelope) = match &self {
            Self::Conflict { version, envelope } => {
                (Some(version.as_str()), Some(envelope.as_deref()))
            }
            _ => (None, None),
        };

        let body = axum::Json(Body {
            error: code,
            message: &message,
            version,
            envelope,
        });

        let mut response = (status, body).into_response();
        if let Self::RateLimited { retry_after_secs } = &self {
            let value = HeaderValue::from_str(&retry_after_secs.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("60"));
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        if let Self::QuotaExceeded { .. } = &self {
            // Nothing the client can wait for; say so rather than inviting a
            // retry loop.
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("0"));
        }
        response
    }
}

/// Shorthand for handler results.
pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_match_the_spec() {
        assert_eq!(
            ApiError::Conflict {
                version: "1".into(),
                envelope: None
            }
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(ApiError::Unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            ApiError::RateLimited {
                retry_after_secs: 3
            }
            .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ApiError::PayloadTooLarge { max: 8 }.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn an_internal_error_never_returns_its_detail() {
        let error = ApiError::Internal("connection to /var/lib/misty/db failed".into());
        assert_eq!(error.to_string(), "internal error");
    }

    #[test]
    fn auth_failures_are_indistinguishable() {
        // Same code, same message: no oracle for "does this vault exist".
        let a = ApiError::Unauthorized;
        let b = ApiError::Unauthorized;
        assert_eq!(a.to_string(), b.to_string());
        assert_eq!(a.code(), b.code());
    }

    /// Serialises an error the way `IntoResponse` does, so the shape of a `409`
    /// body is checkable without a socket.
    fn body_json(error: &ApiError) -> serde_json::Value {
        let message = error.to_string();
        let (version, envelope) = match error {
            ApiError::Conflict { version, envelope } => {
                (Some(version.as_str()), Some(envelope.as_deref()))
            }
            _ => (None, None),
        };
        serde_json::to_value(Body {
            error: error.code(),
            message: &message,
            version,
            envelope,
        })
        .expect("serialise")
    }

    #[test]
    fn a_conflict_with_no_bytes_serialises_envelope_as_an_explicit_null() {
        // SPEC §6.1: `envelope` is nullable, and the difference between "null" and
        // "absent" is load-bearing — a reclaimed row still carries a version the
        // client must record, so a client that saw no `envelope` key could not tell
        // "no bytes" from "this server does not send envelopes".
        let value = body_json(&ApiError::Conflict {
            version: "4".into(),
            envelope: None,
        });
        let object = value.as_object().expect("an object");
        assert!(object.contains_key("envelope"), "the key must be present");
        assert!(object["envelope"].is_null());
        assert_eq!(object["version"], serde_json::json!("4"));
        assert!(
            object["version"].is_string(),
            "§6.1.1: an opaque token, not a number"
        );
    }

    #[test]
    fn a_non_conflict_error_omits_both_fields() {
        let value = body_json(&ApiError::NotFound);
        let object = value.as_object().expect("an object");
        assert!(!object.contains_key("envelope"));
        assert!(!object.contains_key("version"));
        assert_eq!(object["error"], serde_json::json!("not_found"));
    }
}
