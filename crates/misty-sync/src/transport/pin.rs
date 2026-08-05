// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Certificate pinning (SPEC §1, `A2`; SPEC §9 "TLS 1.3 only, certificate
//! pinning").
//!
//! A pin is the SHA-256 of the server's **leaf certificate, as DER**. Not the
//! SPKI, and the choice is worth defending because SPKI pinning is the usual
//! advice:
//!
//! * SPKI pinning survives re-issuance with the same key, which is the operational
//!   win. It needs an X.509 parser to find `subjectPublicKeyInfo` inside the
//!   certificate.
//! * Leaf pinning needs no parser at all — one SHA-256 over bytes rustls already
//!   handed us — and therefore adds no attack surface to a client whose whole job
//!   is to be suspicious of what the network says.
//!
//! A pin set holds *several* pins for exactly this reason: the operational cost of
//! leaf pinning is paid by publishing the next certificate's pin alongside the
//! current one before rotating, which is the same discipline SPKI pinning needs
//! for a key rotation anyway. Trading a parser for a slightly stricter release
//! process is the right way round for this crate.
//!
//! # Pinning is the trust anchor, and PKI validation is optional on top
//!
//! [`PinnedVerifier`] checks two things: that the leaf's fingerprint is in the
//! pin set, and that the handshake signature verifies under that leaf's key —
//! the latter is rustls's own job and is delegated to the crypto provider. With an
//! exact-leaf pin, that pair is *stronger* than PKI validation: it proves the peer
//! holds the private key for one specific certificate we named, with no
//! certificate authority anywhere in the trust path and therefore no CA to
//! mis-issue.
//!
//! So no root store is bundled. If a deployment wants chain validation as well —
//! for expiry checking, or because it prefers defence in depth — it supplies its
//! own roots through [`PinnedVerifier::with_roots`] and both checks run. What is
//! deliberately *not* offered is a mode with roots and no pins: that is what every
//! other HTTP client already does, and it is not what SPEC §9 asks for.
//!
//! # What pinning does not do
//!
//! With no roots supplied, nothing checks `notAfter`. An expired certificate whose
//! pin still matches is accepted. That is a considered trade: the pin names one
//! certificate, so accepting it past its expiry means trusting the operator's own
//! retired key, and the mitigation is to remove the pin — which is the same action
//! expiry would force anyway. It is called out here rather than left to be
//! discovered.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

/// Length of a pin: SHA-256.
pub const PIN_LEN: usize = 32;

/// One pinned certificate.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertificatePin([u8; PIN_LEN]);

impl CertificatePin {
    /// A pin from raw SHA-256 bytes.
    #[must_use]
    pub const fn from_bytes(digest: [u8; PIN_LEN]) -> Self {
        Self(digest)
    }

    /// A pin from lowercase or uppercase hex.
    ///
    /// # Errors
    ///
    /// [`SyncError::BadPin`](crate::SyncError::BadPin) if it is not 64 hex
    /// characters.
    pub fn from_hex(text: &str) -> crate::Result<Self> {
        let mut out = [0u8; PIN_LEN];
        hex::decode_to_slice(text.trim().as_bytes(), &mut out).map_err(|_| {
            crate::SyncError::BadPin {
                expected: PIN_LEN * 2,
                found: text.trim().len(),
            }
        })?;
        Ok(Self(out))
    }

    /// The pin of a certificate, as DER.
    #[must_use]
    pub fn of_certificate(der: &[u8]) -> Self {
        let mut digest = [0u8; PIN_LEN];
        digest.copy_from_slice(&Sha256::digest(der));
        Self(digest)
    }

    /// The pin, as hex, for publishing in a deployment's configuration.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl core::fmt::Debug for CertificatePin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CertificatePin({})", hex::encode(self.0))
    }
}

/// The certificates a client will accept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PinSet {
    pins: Vec<CertificatePin>,
}

impl PinSet {
    /// An empty set. A transport built with one accepts nothing, which is the
    /// correct failure mode for a misconfiguration.
    #[must_use]
    pub const fn new() -> Self {
        Self { pins: Vec::new() }
    }

    /// Adds a pin.
    #[must_use]
    pub fn with(mut self, pin: CertificatePin) -> Self {
        self.pins.push(pin);
        self
    }

    /// Adds a pin from hex.
    ///
    /// # Errors
    ///
    /// As [`CertificatePin::from_hex`].
    pub fn with_hex(self, text: &str) -> crate::Result<Self> {
        Ok(self.with(CertificatePin::from_hex(text)?))
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Whether a certificate's DER matches any pin.
    ///
    /// Constant time across the whole set: the comparison never short-circuits on
    /// a matching prefix, and the loop visits every pin whatever the outcome.
    /// Overkill for a public digest, and the habit is what stops the next such
    /// comparison — over something that is not public — from being written with
    /// `==`.
    #[must_use]
    pub fn accepts(&self, der: &[u8]) -> bool {
        let candidate = CertificatePin::of_certificate(der);
        let mut matched = subtle::Choice::from(0u8);
        for pin in &self.pins {
            matched |= pin.0.ct_eq(&candidate.0);
        }
        bool::from(matched)
    }
}

/// A rustls verifier that requires a pin, and optionally a chain.
#[derive(Debug)]
pub struct PinnedVerifier {
    pins: PinSet,
    provider: Arc<rustls::crypto::CryptoProvider>,
    chain: Option<Arc<rustls::client::WebPkiServerVerifier>>,
    mismatched: Arc<core::sync::atomic::AtomicBool>,
}

impl PinnedVerifier {
    /// A verifier that accepts exactly the certificates in `pins`.
    #[must_use]
    pub fn new(pins: PinSet) -> Self {
        Self {
            pins,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            chain: None,
            mismatched: Arc::new(core::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Whether a pin mismatch has happened since this was last asked, clearing the
    /// flag.
    ///
    /// A TLS handshake failure reaches the caller as an opaque connect error: the
    /// rustls alert is several boxed layers down and cannot be downcast through
    /// hyper's connector. This flag is how
    /// [`NativeTransport`](crate::NativeTransport) tells
    /// [`TransportKind::PinMismatch`](crate::TransportKind::PinMismatch) from
    /// [`Connect`](crate::TransportKind::Connect), which are different problems
    /// with different answers — "your pin is stale" against "you are offline".
    ///
    /// It is a hint, not a proof: a client issues its requests sequentially, so in
    /// practice the flag belongs to the connection that just failed, but nothing
    /// here enforces that. It only ever refines an error that was going to be
    /// returned anyway.
    pub fn take_pin_mismatch(&self) -> bool {
        self.mismatched
            .swap(false, core::sync::atomic::Ordering::Relaxed)
    }

    /// Also validates the chain against `roots`.
    ///
    /// # Errors
    ///
    /// [`SyncError::BadServerUrl`](crate::SyncError::BadServerUrl) if the roots
    /// cannot build a verifier — the nearest available variant, since a root store
    /// that webpki refuses is a configuration error rather than a protocol one.
    pub fn with_roots(mut self, roots: RootCertStore) -> crate::Result<Self> {
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&self.provider),
        )
        .build()
        .map_err(|_| crate::SyncError::BadServerUrl)?;
        self.chain = Some(verifier);
        Ok(self)
    }

    /// The pin set.
    #[must_use]
    pub const fn pins(&self) -> &PinSet {
        &self.pins
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // The pin first. A chain check that ran before it could spend time on an
        // attacker's certificate for no reason, and the pin is the cheaper and
        // stricter of the two.
        if !self.pins.accepts(end_entity.as_ref()) {
            self.mismatched
                .store(true, core::sync::atomic::Ordering::Relaxed);
            return Err(TlsError::General("certificate pin mismatch".to_owned()));
        }
        if let Some(chain) = &self.chain {
            chain.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // Unreachable: the client offers only TLS 1.3, and `rustls` is built
        // without its `tls12` feature, so there is no code path that negotiates
        // 1.2. Refusing here rather than delegating means that if a future build
        // *did* enable 1.2 by accident, the handshake would fail rather than
        // quietly succeed at a version SPEC §9 forbids.
        Err(TlsError::General(
            "TLS 1.2 is not offered by this client".to_owned(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DER: &[u8] = b"a certificate, as DER, more or less";

    #[test]
    fn a_pin_is_the_sha256_of_the_certificate() {
        let pin = CertificatePin::of_certificate(DER);
        assert_eq!(pin.to_hex().len(), 64);
        assert_eq!(CertificatePin::from_hex(&pin.to_hex()).expect("hex"), pin);
        assert_eq!(
            CertificatePin::from_hex(&pin.to_hex().to_uppercase()).expect("hex"),
            pin
        );
    }

    #[test]
    fn a_malformed_pin_is_refused() {
        for text in ["", "ab", &"a".repeat(63), &"a".repeat(65), &"z".repeat(64)] {
            assert!(CertificatePin::from_hex(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn an_empty_pin_set_accepts_nothing() {
        // The correct failure mode for a misconfiguration: refuse everything rather
        // than fall back to trusting whatever the network offers.
        assert!(PinSet::new().is_empty());
        assert!(!PinSet::new().accepts(DER));
    }

    #[test]
    fn a_pin_set_accepts_exactly_what_it_names() {
        let pins = PinSet::new()
            .with(CertificatePin::of_certificate(DER))
            .with(CertificatePin::of_certificate(b"the next one"));
        assert!(pins.accepts(DER));
        assert!(pins.accepts(b"the next one"));
        assert!(!pins.accepts(b"someone else's certificate"));
        // One flipped byte is a different certificate.
        let mut nearly = DER.to_vec();
        if let Some(byte) = nearly.get_mut(0) {
            *byte ^= 0x01;
        }
        assert!(!pins.accepts(&nearly));
    }

    #[test]
    fn a_verifier_reports_a_mismatch_once() {
        let verifier = PinnedVerifier::new(PinSet::new().with(CertificatePin::from_bytes([0; 32])));
        assert!(!verifier.take_pin_mismatch());
        let der = rustls::pki_types::CertificateDer::from(DER.to_vec());
        assert!(verifier
            .verify_server_cert(
                &der,
                &[],
                &rustls::pki_types::ServerName::try_from("example.com").expect("name"),
                &[],
                rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(0)),
            )
            .is_err());
        assert!(verifier.take_pin_mismatch(), "the flag was raised");
        assert!(!verifier.take_pin_mismatch(), "and cleared by reading it");
    }

    #[test]
    fn the_verifier_advertises_the_providers_schemes() {
        // `verify_tls12_signature` cannot be exercised from a test — rustls keeps
        // `DigitallySignedStruct`'s constructor private — but the client never
        // offers TLS 1.2 anyway, and the build leaves it out. What is checkable is
        // that the schemes offered come from the provider rather than a hand-written
        // list that could drift from it.
        let verifier = PinnedVerifier::new(PinSet::new());
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());
        assert!(schemes.contains(&SignatureScheme::ED25519), "{schemes:?}");
    }
}
