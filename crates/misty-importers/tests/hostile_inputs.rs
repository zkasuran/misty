// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile input, against every importer.
//!
//! The rule this suite enforces: **for any bytes and any importer, `sniff`,
//! `needs_passphrase`, `import` and `preview` return.** They may return an error,
//! they may skip every row, they may import nothing. They may not panic, hang, or
//! allocate proportionally to a number an attacker wrote in a header.
//!
//! Every input here is fed to all sixteen importers, not only to the one that owns
//! the format, because `detect` runs them all and the UI will happily let a user
//! point the wrong importer at a file.

mod common;

use misty_importers::{
    ImportContext, ImportError, Limits, ProtobufError, RowOutcome, SourceFormat,
};

/// Deterministic pseudo-random bytes. A fixed LCG rather than a real RNG so a
/// failure is reproducible from the test name alone.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            u8::try_from((state >> 33) & 0xff).unwrap_or(0)
        })
        .collect()
}

/// Printable ASCII garbage, which is nastier than binary noise: it survives UTF-8
/// validation, so every text-based importer has to actually parse it.
fn ascii_noise(len: usize) -> Vec<u8> {
    noise(len)
        .into_iter()
        .map(|byte| match byte % 8 {
            0 => b',',
            1 => b'\n',
            2 => b'"',
            3 => b'{',
            4 => b'}',
            5 => b'<',
            6 => b'&',
            _ => b'A' + (byte % 26),
        })
        .collect()
}

/// One `otpauth-migration://` URI whose protobuf declares a four-gigabyte field.
fn four_gigabyte_protobuf() -> Vec<u8> {
    use base64::Engine as _;
    // Field 1, wire type 2, length 2^32, then twenty bytes.
    let mut payload = vec![0x0a];
    let mut len = 4u64 * 1024 * 1024 * 1024;
    loop {
        let byte = u8::try_from(len & 0x7f).unwrap_or(0);
        len >>= 7;
        if len == 0 {
            payload.push(byte);
            break;
        }
        payload.push(byte | 0x80);
    }
    payload.extend_from_slice(b"not four gigabytes.");
    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
    format!("otpauth-migration://offline?data={encoded}\n").into_bytes()
}

/// UTF-16LE, with a byte-order mark: what a Windows text editor writes.
fn utf16(text: &str) -> Vec<u8> {
    let mut out = vec![0xff, 0xfe];
    for unit in text.encode_utf16() {
        out.extend(unit.to_le_bytes());
    }
    out
}

/// The whole hostile corpus, as `(name, bytes)`.
fn corpus() -> Vec<(String, Vec<u8>)> {
    let mut cases: Vec<(String, Vec<u8>)> = vec![
        ("empty".to_owned(), Vec::new()),
        ("one nul byte".to_owned(), vec![0]),
        ("ten megabytes of binary noise".to_owned(), noise(10 * 1024 * 1024)),
        (
            "ten megabytes of printable noise".to_owned(),
            ascii_noise(10 * 1024 * 1024),
        ),
        ("four gigabyte protobuf".to_owned(), four_gigabyte_protobuf()),
        (
            "deeply nested json arrays".to_owned(),
            format!("{}1{}", "[".repeat(5000), "]".repeat(5000)).into_bytes(),
        ),
        (
            "deeply nested json objects".to_owned(),
            format!(
                "{{{}\"a\":1{}}}",
                "\"a\":{".repeat(5000),
                "}".repeat(5000)
            )
            .into_bytes(),
        ),
        (
            "deeply nested xml".to_owned(),
            format!("{}{}", "<a>".repeat(50_000), "</a>".repeat(50_000)).into_bytes(),
        ),
        (
            "billion laughs".to_owned(),
            br#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">
             <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
             <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
             ]><map><string name="a">&lol3;</string></map>"#
                .to_vec(),
        ),
        (
            "absurd digit count".to_owned(),
            b"otpauth://totp/A:b?secret=AAAAAAAAAAAAAAAA&digits=255\n\
              otpauth://totp/A:c?secret=AAAAAAAAAAAAAAAA&digits=0\n\
              otpauth://totp/A:d?secret=AAAAAAAAAAAAAAAA&period=99999\n"
                .to_vec(),
        ),
        (
            "absurd digit count in json".to_owned(),
            br#"[{"secret":"AAAAAAAAAAAAAAAA","label":"a","digits":9999999999,"type":"TOTP","period":-4}]"#
                .to_vec(),
        ),
        (
            "embedded nul in a uri".to_owned(),
            b"otpauth://totp/AC%00ME:ada?secret=AAAAAAAAAAAAAAAA\n".to_vec(),
        ),
        (
            "embedded nul in json".to_owned(),
            b"[{\"secret\":\"AAAAAAAAAAAAAAAA\",\"issuer\":\"AC\\u0000ME\",\"label\":\"ada\",\"type\":\"TOTP\"}]"
                .to_vec(),
        ),
        (
            "bidi override in json".to_owned(),
            "[{\"secret\":\"AAAAAAAAAAAAAAAA\",\"issuer\":\"ada\u{202e}moc.elpmaxe\",\"label\":\"x\",\"type\":\"TOTP\"}]"
                .as_bytes()
                .to_vec(),
        ),
        (
            "a hundred thousand csv columns".to_owned(),
            format!("{}\nsecret,issuer\nAAAAAAAAAAAAAAAA,ok\n", "x,".repeat(100_000))
                .into_bytes(),
        ),
        (
            "utf16 aegis vault".to_owned(),
            utf16(&String::from_utf8_lossy(&common::fixture("aegis/plain.json"))),
        ),
        (
            "hostile scrypt cost".to_owned(),
            br#"{"version":1,"header":{"slots":[{"type":1,"uuid":"x","key":"00","key_params":{"nonce":"000000000000000000000000","tag":"00000000000000000000000000000000"},"n":68719476736,"r":8,"p":1,"salt":"00"}],"params":{"nonce":"000000000000000000000000","tag":"00000000000000000000000000000000"}},"db":"AAAA"}"#
                .to_vec(),
        ),
        (
            "hostile pbkdf2 iterations".to_owned(),
            {
                let mut file = 0xffff_ffffu32.to_be_bytes().to_vec();
                file.extend([0x55; 12]);
                file.extend([0x66; 12]);
                file.extend([0u8; 32]);
                file
            },
        ),
    ];

    // Every fixture, truncated. A file cut off mid-record is the most common real
    // corruption there is: an interrupted download, a full disk.
    for (slug, file, bytes) in common::all_fixtures() {
        for fraction in [2, 5] {
            let cut = bytes.len() / fraction;
            cases.push((
                format!("{slug}/{file} truncated to 1/{fraction}"),
                bytes.get(..cut).unwrap_or_default().to_vec(),
            ));
        }
        // And with one byte flipped in the middle, which for an encrypted vault is
        // the case the AEAD tag exists to catch.
        let mut flipped = bytes.clone();
        let middle = flipped.len() / 2;
        if let Some(byte) = flipped.get_mut(middle) {
            *byte ^= 0xff;
        }
        cases.push((format!("{slug}/{file} with a flipped byte"), flipped));
    }

    cases
}

#[test]
fn no_importer_panics_hangs_or_over_allocates_on_hostile_input() {
    let passphrase = common::FIXTURE_PASSPHRASE;
    // Tighter than the defaults, so an over-allocation shows up as a limit error
    // rather than as a slow test.
    let limits = Limits {
        max_rows: 500,
        ..Limits::default()
    };

    for (name, bytes) in corpus() {
        for importer in misty_importers::importers() {
            let format = importer.format();
            // Sniffing must be cheap and total.
            let _ = importer.sniff(&bytes);
            let _ = importer.needs_passphrase(&bytes);

            for ctx in [
                ImportContext::new().with_limits(limits),
                ImportContext::new()
                    .with_limits(limits)
                    .with_passphrase(passphrase),
            ] {
                match importer.import(&bytes, &ctx) {
                    Ok(report) => {
                        assert!(
                            report.items.len() <= report.outcomes.len(),
                            "{format} on {name:?}: more items than rows"
                        );
                        for item in &report.items {
                            // Anything that did import is a *valid* token: the OTP
                            // engine's invariants hold or the row failed.
                            assert!(!item.otp.secret().is_empty(), "{format} on {name:?}");
                            assert!(
                                (1..=10).contains(&item.otp.digits()),
                                "{format} on {name:?}"
                            );
                            assert!(
                                (1..=3600).contains(&item.otp.period()),
                                "{format} on {name:?}"
                            );
                        }
                        for outcome in &report.outcomes {
                            if let RowOutcome::Failed { error, .. } = outcome {
                                let rendered = error.to_string();
                                assert!(!rendered.is_empty(), "{format} on {name:?}");
                            }
                        }
                    }
                    Err(_) => {
                        // An error is a perfectly good answer to hostile input.
                    }
                }
                // The preview path must be exactly as robust: it is what the UI
                // calls first.
                let _ = importer.preview(&bytes, &ctx);
            }
        }
    }
}

#[test]
fn a_start_tag_full_of_duplicate_attribute_names_stays_linear() {
    // RUSTSEC-2026-0194: `quick-xml` before 0.41 checked a start tag for duplicate
    // attribute names in quadratic time, so a single tag with tens of thousands of
    // repeated names was a denial of service from a small file. This crate parses
    // XML a user downloaded from somewhere, which is exactly the exposure, so the
    // dependency floor is 0.41 and this test is what keeps the shape covered
    // whatever the version underneath does.
    //
    // The assertion is a time budget rather than an error, because "it returned an
    // error" is not the property that matters here: a quadratic parser also returns
    // an error, eventually. 20 000 duplicates is 4 × 10^8 comparisons if the
    // behaviour is quadratic, which does not fit in ten seconds in a debug build,
    // and takes milliseconds if it is not.
    const ATTRIBUTES: usize = 20_000;
    let mut file = String::with_capacity(ATTRIBUTES * 16 + 64);
    file.push_str("<map><string");
    for _ in 0..ATTRIBUTES {
        file.push_str(" name=\"a\"");
    }
    file.push_str(">{}</string></map>");

    let started = std::time::Instant::now();
    for format in [SourceFormat::FreeOtp, SourceFormat::KeePassXcXml] {
        let importer = misty_importers::importer_for(format).expect("importer");
        let _ = importer.sniff(file.as_bytes());
        let _ = importer.import(file.as_bytes(), &ImportContext::new());
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "parsing {ATTRIBUTES} duplicate attribute names took {elapsed:?}, which is not linear"
    );
}

#[test]
fn a_document_declaring_a_hundred_thousand_namespaces_is_bounded() {
    // The companion advisory to the one above: `NsReader` accumulated one entry per
    // namespace declaration with no bound, so a small file could make it allocate
    // without limit. This crate uses `Reader`, not `NsReader` — namespaces carry no
    // meaning in a `SharedPreferences` file or a KDBX export, so `xmlns:` attributes
    // are ordinary attributes it ignores — and this test pins that: the input is
    // read in bounded time and the reader has no per-namespace state to grow.
    const NAMESPACES: usize = 100_000;
    let mut file = String::with_capacity(NAMESPACES * 24 + 64);
    file.push_str("<KeePassFile");
    for index in 0..NAMESPACES {
        file.push_str(&format!(" xmlns:n{index}=\"urn:{index}\""));
    }
    file.push_str("><Root><Group><Name>g</Name></Group></Root></KeePassFile>");

    let started = std::time::Instant::now();
    for format in [SourceFormat::FreeOtp, SourceFormat::KeePassXcXml] {
        let importer = misty_importers::importer_for(format).expect("importer");
        let _ = importer.sniff(file.as_bytes());
        let _ = importer.import(file.as_bytes(), &ImportContext::new());
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "reading {NAMESPACES} namespace declarations took {elapsed:?}"
    );
}

#[test]
fn a_four_gigabyte_protobuf_length_is_refused_before_allocating() {
    let bytes = four_gigabyte_protobuf();
    let error = misty_importers::import_auto(&bytes, &ImportContext::new())
        .expect_err("a declared length past the end of the buffer");
    assert!(
        matches!(
            error,
            ImportError::Protobuf(ProtobufError::LengthTooLarge { len, .. })
                if len == 4 * 1024 * 1024 * 1024
        ),
        "{error}"
    );
}

#[test]
fn absurd_parameters_fail_their_row_and_nothing_else() {
    let file = b"otpauth://totp/A:good?secret=AAAAAAAAAAAAAAAA\n\
                 otpauth://totp/A:bad-digits?secret=AAAAAAAAAAAAAAAA&digits=255\n\
                 otpauth://totp/A:bad-period?secret=AAAAAAAAAAAAAAAA&period=99999\n\
                 otpauth://totp/A:also-good?secret=BBBBBBBBBBBBBBBB\n";
    let report = misty_importers::import_auto(file, &ImportContext::new()).expect("imports");
    assert_eq!(report.imported(), 2);
    assert_eq!(report.failed(), 2);
}

#[test]
fn a_hostile_kdf_cost_is_named_rather_than_clamped() {
    // 128 * 8 * 2^36 bytes of scrypt memory. SPEC 2.3: reject and name the
    // parameter, because clamping derives a different key and reports the user's
    // correct passphrase as wrong.
    let vault = br#"{"version":1,"header":{"slots":[{"type":1,"uuid":"x","key":"00","key_params":{"nonce":"000000000000000000000000","tag":"00000000000000000000000000000000"},"n":68719476736,"r":8,"p":1,"salt":"00"}],"params":{"nonce":"000000000000000000000000","tag":"00000000000000000000000000000000"}},"db":"AAAA"}"#;
    let ctx = ImportContext::new().with_passphrase(b"anything");
    let error = misty_importers::importer_for(SourceFormat::Aegis)
        .expect("aegis importer")
        .import(vault, &ctx)
        .expect_err("hostile cost");
    assert!(
        matches!(error, ImportError::KdfParam { name: "n", .. }),
        "{error}"
    );
}

#[test]
fn a_flipped_byte_in_an_encrypted_vault_is_a_decryption_failure() {
    for (fixture, format) in [
        ("aegis/encrypted.json", SourceFormat::Aegis),
        ("andotp/encrypted.bin", SourceFormat::AndOtp),
        ("2fas/encrypted.json", SourceFormat::TwoFas),
    ] {
        let mut bytes = common::fixture(fixture);
        // The last byte is inside the ciphertext or the tag for all three layouts.
        if let Some(byte) = bytes.last_mut() {
            *byte ^= 0x01;
        }
        let ctx = ImportContext::new().with_passphrase(common::FIXTURE_PASSPHRASE);
        let importer = misty_importers::importer_for(format).expect("importer");
        assert!(
            importer.import(&bytes, &ctx).is_err(),
            "{fixture}: a tampered vault must not import"
        );
    }
}
