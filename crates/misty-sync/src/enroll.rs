// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device-to-device enrollment over the transport (SPEC §6.3).
//!
//! The cryptography is [`misty_crypto::enrollment`]'s and is not restated here:
//! the X25519 agreement, the HKDF schedule with both public keys bound into
//! `info`, the BLAKE2b confirmation code and every refusal already live there and
//! are tested there. What this module adds is the four HTTP calls in between, the
//! QR payload encoding, and the ordering that makes a failure at any step
//! recoverable.
//!
//! ```text
//! new device                        server                    existing device
//! ───────────────────────────────────────────────────────────────────────────
//! begin(): identity + ephemeral
//! show QR + 6-digit code
//!   POST /v1/enroll/begin ─────────▶ hold request
//!                                                    ◀── scan QR, or
//!                                    request ────────▶  GET /v1/enroll/poll
//!                                              user compares the 6 digits
//!                                                        roster.add + sign
//!                                    ◀───────────────  PUT roster envelope
//!                                    ◀───────────────  POST /v1/enroll/complete
//!   GET /v1/enroll/poll ───────────▶ sealed grant
//! open(): unseal, check the roster chains, adopt
//! ```
//!
//! # The roster is pushed before the grant, and the order is not arbitrary
//!
//! If the grant went first and the roster write then failed, the new device would
//! hold `VK` and be able to write envelopes that **every other device rejects**,
//! because no roster on the server lists it — a device that appears to work and
//! silently does not replicate. Pushed the other way round, a failure leaves a
//! roster naming a device that never finished joining, which costs one unused row
//! and nothing else.
//!
//! # SPEC §6.3.1 has no QR encoding
//!
//! §2.6 defines `misty-recovery:v1:` for the Recovery Kit and §6.3 defines
//! nothing for the enrollment QR, so [`ENROLL_QR_PREFIX`] fills the gap by
//! symmetry: a scheme-like prefix, a version, and the payload. It is
//! wire-visible — it is what a camera reads — so SPEC §6.6's table should list it
//! next to the recovery prefix.

use base64::Engine as _;
use misty_crypto::enrollment::{
    self, EnrollmentGrant, EnrollmentRequest, NewDeviceEnrollment, SealedEnrollment,
};
use misty_crypto::identity::{DeviceIdentity, DeviceRecord};
use misty_crypto::{DeviceId, EnrollId};

use crate::client::SyncClient;
use crate::error::{Result, SyncError};
use crate::limits;
use crate::transport::Transport;
use crate::wire::Want;

/// Prefix of the enrollment QR payload. Wire-visible; see the module docs.
pub const ENROLL_QR_PREFIX: &str = "misty-enroll:v1:";

/// Base64 used inside a QR: URL-safe and unpadded, so the payload survives a
/// URL and stays in the alphanumeric QR mode where it is cheapest to render.
const QR_B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Encodes a request as the QR payload the new device displays.
///
/// # Errors
///
/// [`SyncError::Malformed`] if the request will not encode, or
/// [`SyncError::StringTooLong`](SyncError::Malformed) — in practice only the
/// former, since the request's own fields are bounded by
/// [`EnrollmentRequest::validate`].
pub fn encode_qr_payload(request: &EnrollmentRequest) -> Result<String> {
    Ok(format!(
        "{ENROLL_QR_PREFIX}{}",
        QR_B64.encode(encode_request(request)?)
    ))
}

/// Decodes a scanned QR payload.
///
/// # Errors
///
/// [`SyncError::Malformed`] for a payload that is not this scheme, not base64,
/// not CBOR, or whose fields are out of bounds.
pub fn decode_qr_payload(text: &str) -> Result<EnrollmentRequest> {
    let field = "qr";
    let malformed = || SyncError::Malformed {
        operation: "scan enrollment QR",
        field,
    };
    let body = text
        .trim()
        .strip_prefix(ENROLL_QR_PREFIX)
        .ok_or_else(malformed)?;
    if body.len() > limits::MAX_ENROLLMENT_PAYLOAD_LEN {
        return Err(malformed());
    }
    decode_request(&QR_B64.decode(body.as_bytes()).map_err(|_| malformed())?)
}

/// CBOR-encodes a request, the same encoding `POST /v1/enroll/begin` carries.
///
/// # Errors
///
/// [`SyncError::Malformed`] if encoding fails.
pub fn encode_request(request: &EnrollmentRequest) -> Result<Vec<u8>> {
    request.validate()?;
    let mut out = Vec::new();
    ciborium::into_writer(request, &mut out).map_err(|_| SyncError::Malformed {
        operation: "encode enrollment request",
        field: "request",
    })?;
    Ok(out)
}

/// Decodes and bounds a request.
///
/// # Errors
///
/// [`SyncError::Malformed`] if it does not decode, or
/// [`SyncError::Crypto`] if its fields are out of bounds.
pub fn decode_request(bytes: &[u8]) -> Result<EnrollmentRequest> {
    if bytes.len() > limits::MAX_ENROLLMENT_PAYLOAD_LEN {
        return Err(SyncError::Malformed {
            operation: "decode enrollment request",
            field: "request",
        });
    }
    let request: EnrollmentRequest =
        ciborium::from_reader(bytes).map_err(|_| SyncError::Malformed {
            operation: "decode enrollment request",
            field: "request",
        })?;
    request.validate()?;
    Ok(request)
}

/// CBOR-encodes a sealed grant for `POST /v1/enroll/complete`.
///
/// # Errors
///
/// [`SyncError::Malformed`] if encoding fails.
pub fn encode_sealed(sealed: &SealedEnrollment) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(sealed, &mut out).map_err(|_| SyncError::Malformed {
        operation: "encode sealed grant",
        field: "sealed_response",
    })?;
    Ok(out)
}

/// Decodes a sealed grant.
///
/// # Errors
///
/// [`SyncError::Malformed`] if it does not decode or is over the cap.
pub fn decode_sealed(bytes: &[u8]) -> Result<SealedEnrollment> {
    if bytes.len() > limits::MAX_ENROLLMENT_PAYLOAD_LEN {
        return Err(SyncError::Malformed {
            operation: "decode sealed grant",
            field: "sealed_response",
        });
    }
    ciborium::from_reader(bytes).map_err(|_| SyncError::Malformed {
        operation: "decode sealed grant",
        field: "sealed_response",
    })
}

/// Builds the roster record for a device that is being enrolled.
///
/// The fields come from the request, which the confirmation code covers, so a
/// substituted `device_id` or `ed25519_pub` cannot reach the roster without the
/// user seeing a different six digits.
///
/// # Errors
///
/// [`SyncError::Crypto`] if the name or platform is over its bound, or if the
/// public key is not a valid Ed25519 point.
pub fn record_for(
    request: &EnrollmentRequest,
    enrolled_at: i64,
    enrolled_by: DeviceId,
) -> Result<DeviceRecord> {
    let record = DeviceRecord {
        device_id: request.device_id,
        ed25519_pub: request.ed25519_pub,
        name: request.name.clone(),
        platform: request.platform.clone(),
        enrolled_at,
        enrolled_by: Some(enrolled_by),
    };
    record.validate()?;
    Ok(record)
}

/// The new device's side of an enrollment.
///
/// Wraps [`NewDeviceEnrollment`] with the two HTTP calls it needs. The ephemeral
/// X25519 private key lives inside and never leaves, which is why this type is
/// held across the whole exchange rather than rebuilt per call: a restart in the
/// middle means starting a new enrollment, and that is correct — the code the user
/// is comparing covers the key that was thrown away.
#[derive(Debug)]
pub struct Enrollment {
    inner: NewDeviceEnrollment,
}

impl Enrollment {
    /// Starts an enrollment for `identity`.
    ///
    /// # Errors
    ///
    /// [`SyncError::Crypto`] if the CSPRNG fails or the strings are over bound.
    pub fn begin(identity: &DeviceIdentity, name: &str, platform: &str) -> Result<Self> {
        Ok(Self {
            inner: NewDeviceEnrollment::begin(identity, name, platform)?,
        })
    }

    /// The request, for rendering.
    #[must_use]
    pub const fn request(&self) -> &EnrollmentRequest {
        self.inner.request()
    }

    /// This enrollment's id.
    #[must_use]
    pub const fn enroll_id(&self) -> EnrollId {
        self.inner.request().enroll_id
    }

    /// The 6-digit code the user compares out of band (SPEC §6.3.1).
    #[must_use]
    pub fn confirmation_code(&self) -> String {
        self.inner.confirmation_code()
    }

    /// The QR payload to display.
    ///
    /// # Errors
    ///
    /// As [`encode_qr_payload`].
    pub fn qr_payload(&self) -> Result<String> {
        encode_qr_payload(self.inner.request())
    }

    /// `POST /v1/enroll/begin`, so the camera-less path can reach the request.
    ///
    /// # Errors
    ///
    /// Anything the transport or the server reports.
    pub async fn publish<T: Transport>(&self, client: &mut SyncClient<T>) -> Result<()> {
        let request = self.inner.request();
        client
            .enroll_begin(
                &request.enroll_id,
                &request.x25519_pub,
                &encode_request(request)?,
            )
            .await
    }

    /// `GET /v1/enroll/poll/{id}`, returning the grant once it exists.
    ///
    /// `Ok(None)` means "not approved yet": poll again. Every refusal
    /// [`NewDeviceEnrollment::open`] can make is an `Err`, so a grant a hostile
    /// server forged, replayed from another enrollment, or delivered with a roster
    /// this device is not in does not come back as `None`.
    ///
    /// # Errors
    ///
    /// [`SyncError::Crypto`] for a grant that does not unseal or does not chain,
    /// [`SyncError::Malformed`] for one that does not decode, or anything the
    /// transport reports.
    pub async fn poll<T: Transport>(
        &self,
        client: &mut SyncClient<T>,
    ) -> Result<Option<EnrollmentGrant>> {
        let answer = client
            .enroll_poll(&self.inner.request().enroll_id, Want::Response)
            .await?;
        let Some(sealed) = answer.sealed_response else {
            return Ok(None);
        };
        Ok(Some(self.inner.open(&decode_sealed(&sealed)?)?))
    }
}

/// A request an existing device has received but not yet approved.
///
/// SPEC §6.3.2 requires the approving device to **display the new device's name,
/// platform and the 6-digit code for the user to compare out of band before
/// approving**. This type is that screen's model, and it has no method that seals
/// anything: sealing is [`seal`](Self::seal), which takes the code the user
/// typed and refuses if it does not match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingApproval {
    request: EnrollmentRequest,
}

impl PendingApproval {
    /// From a scanned QR payload.
    ///
    /// # Errors
    ///
    /// As [`decode_qr_payload`].
    pub fn from_qr(text: &str) -> Result<Self> {
        Ok(Self {
            request: decode_qr_payload(text)?,
        })
    }

    /// From the server, for the camera-less path: the user reads the six digits
    /// off the new device and types them here, and the request behind them is
    /// fetched.
    ///
    /// `Ok(None)` means the new device has not published yet.
    ///
    /// # Errors
    ///
    /// [`SyncError::Malformed`] for a request that does not decode, or anything
    /// the transport reports.
    pub async fn fetch<T: Transport>(
        client: &mut SyncClient<T>,
        enroll_id: &EnrollId,
    ) -> Result<Option<Self>> {
        let answer = client.enroll_poll(enroll_id, Want::Request).await?;
        let Some(bytes) = answer.enroll_request else {
            return Ok(None);
        };
        let request = decode_request(&bytes)?;
        if request.enroll_id != *enroll_id {
            return Err(SyncError::Crypto(misty_crypto::Error::EnrollIdMismatch));
        }
        Ok(Some(Self { request }))
    }

    /// The request, for building a roster record.
    #[must_use]
    pub const fn request(&self) -> &EnrollmentRequest {
        &self.request
    }

    /// The name to show the user.
    #[must_use]
    pub fn device_name(&self) -> &str {
        &self.request.name
    }

    /// The platform to show the user.
    #[must_use]
    pub fn platform(&self) -> &str {
        &self.request.platform
    }

    /// The six digits to show the user.
    #[must_use]
    pub fn confirmation_code(&self) -> String {
        self.request.confirmation_code()
    }

    /// The id the new device generated for itself.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.request.device_id
    }

    /// Seals the grant. Sends nothing.
    ///
    /// This is where the confirmation code is checked — by
    /// [`misty_crypto::enrollment::approve`], in constant time, against the request
    /// the server actually delivered. Nothing before this point has any effect, so a
    /// user who compares the six digits and finds them wrong has published nothing
    /// and granted nothing.
    ///
    /// `grant.roster` must already contain the new device and be signed by
    /// `approver`; `misty-crypto` checks both, because a grant delivering a roster
    /// the new device is not in would leave it permanently unable to write.
    ///
    /// # Errors
    ///
    /// [`SyncError::Crypto`] with
    /// [`ConfirmationCodeMismatch`](misty_crypto::Error::ConfirmationCodeMismatch)
    /// if `typed_code` does not match the request, or with
    /// [`DeviceNotInRoster`](misty_crypto::Error::DeviceNotInRoster) if the roster
    /// does not name the joining device.
    pub fn seal(
        &self,
        typed_code: &str,
        grant: &enrollment::GrantContents<'_>,
        approver: &DeviceIdentity,
    ) -> Result<SealedEnrollment> {
        Ok(enrollment::approve(
            &self.request,
            typed_code,
            grant,
            approver,
        )?)
    }

    /// `POST`s a sealed grant.
    ///
    /// Push the roster **first** — see the module docs on ordering. Prefer
    /// [`SyncEngine::approve_enrollment`](crate::SyncEngine::approve_enrollment),
    /// which does the three steps in the order that cannot go wrong.
    ///
    /// # Errors
    ///
    /// Anything the transport reports.
    pub async fn deliver<T: Transport>(
        &self,
        client: &mut SyncClient<T>,
        sealed: &SealedEnrollment,
    ) -> Result<()> {
        client
            .enroll_complete(&self.request.enroll_id, &encode_sealed(sealed)?)
            .await
    }
}
