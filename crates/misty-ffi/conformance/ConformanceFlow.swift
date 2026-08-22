// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//
// The Swift leg of the SPEC §11.8.2 conformance gate.
//
// This is the same scripted flow as `crates/misty-ffi/tests/native.rs` (the exported
// UniFFI object, in Rust) and `crates/misty-ffi/tests/web.rs` (the wasm bundle in a
// headless browser), against the same fixtures, asserting the same literals — which is
// the whole point. P4 shipped a client and a server that each passed their own suite
// against their own mock and then did not interoperate (§6.1.1); §11.8 applies that
// lesson to a four-consumer phase, and this file is one of the consumers.
//
// It is deliberately plain Swift with no test framework: it must run identically under
// `swiftc` on a Linux CI box and under Xcode on a macOS runner, and pulling in XCTest
// would make the Linux leg the odd one out.
//
// Inputs come from `mockFixtures()` so nothing is re-derived here. Expected outputs are
// literals, mirroring `conformance/fixtures.json`; if Rust handed those over too, this
// file would be asserting the core against itself.
//

import Foundation

// MARK: - expected outputs, pinned (conformance/fixtures.json)

private enum Expected {
    static let code = "746722"
    static let periodMs: Int64 = 30_000
    static let issuer = "GitHub"
    static let account = "ada@example.com"
    static let pushedOnFirstSync: UInt32 = 1
    static let itemsAfterSync = 1
    static let searchHitsForIssuer = 1

    // Only the stable `code` is asserted — never `message`, which is English, redacted,
    // and non-normative (§11.3.2).
    static let unknownItemId = "NOT_FOUND"
    static let readWhileLocked = "VAULT_LOCKED"
    static let syncWhileLocked = "VAULT_LOCKED"
}

// MARK: - a minimal check recorder

private final class Checks {
    private var failures: [String] = []
    private var passed = 0

    func expect<T: Equatable>(_ actual: T, _ expected: T, _ what: String) {
        if actual == expected {
            passed += 1
        } else {
            fail("\(what): expected \(expected), got \(actual)")
        }
    }

    func expectTrue(_ actual: Bool, _ what: String) {
        expect(actual, true, what)
    }

    func fail(_ message: String) {
        failures.append(message)
        FileHandle.standardError.write(Data("  ✗ \(message)\n".utf8))
    }

    /// Assert that `body` fails with a specific stable `code` (§11.3.2). A binding that
    /// threw the right *kind* of failure with the wrong code would pass a bare
    /// `do/catch`, so the code is compared explicitly.
    func expectCode(_ expected: String, _ what: String, _ body: () async throws -> Void) async {
        do {
            try await body()
            fail("\(what): expected the call to fail with \(expected), but it succeeded")
        } catch let error as MistyError {
            switch error {
            case let .Failed(detail):
                expect(detail.code, expected, "\(what) code")
                // Retryability is a pure function of the code and is frozen (§11.3.3);
                // neither of these codes is transient.
                expect(detail.retryable, false, "\(what) retryable")
                expect(detail.message.isEmpty, false, "\(what) carries a message")
            }
        } catch {
            fail("\(what): threw something that is not a MistyError: \(error)")
        }
    }

    func report(_ label: String) -> Int32 {
        if failures.isEmpty {
            print("\(label): \(passed) assertions passed")
            return 0
        }
        print("\(label): \(failures.count) failed, \(passed) passed")
        return 1
    }
}

// MARK: - the flow

private func newTotp(secret: Data) -> NewItemInput {
    NewItemInput(
        kind: .totp,
        algorithm: .sha1,
        digits: 6,
        period: 30,
        hotpCounter: 0,
        secret: secret,
        pin: nil,
        issuer: Expected.issuer,
        account: Expected.account,
        nickname: nil,
        note: nil,
        groups: [],
        tags: [],
        origins: [],
        icon: nil,
        color: nil,
        favorite: false
    )
}

private func runFlow(_ checks: Checks) async throws {
    let fixtures = mockFixtures()
    let facade = try MistyFacade()

    // enroll — represented by the mock core's pre-signed two-device roster (§11.8.1).
    // The joining half of a live §6.3 handshake needs core types that are quarantined
    // behind the facade and have no FFI projection; it is covered in Rust instead.
    checks.expectTrue(try await facade.lockState().locked, "the facade starts locked")
    try await facade.unlock(keyMaterial: fixtures.vaultKey)
    checks.expect(try await facade.lockState().locked, false, "unlocked")

    // add
    let id = try await facade.add(input: newTotp(secret: fixtures.totpSecret))
    let item = try await facade.item(id: id)
    checks.expect(item.issuer, Expected.issuer, "issuer")
    checks.expect(item.account, Expected.account, "account")
    checks.expect(item.hasPin, false, "no PIN was set")
    checks.expect(item.kind, .totp, "kind survives the boundary")
    checks.expect(item.algorithm, .sha1, "algorithm survives the boundary")

    // generate — an exact value, because the clock is pinned (§11.8.2). A length check
    // would pass for six digits of the wrong code.
    let code = try await facade.generateCode(id: id)
    checks.expect(code.code, Expected.code, "generated code")
    checks.expect(code.periodMs, Expected.periodMs, "period")

    // sync
    let report = try await facade.syncOnce()
    checks.expect(report.pushed, Expected.pushedOnFirstSync, "pushed")
    checks.expect(report.conflicts.count, 0, "no conflicts")
    checks.expect(try await facade.list().count, Expected.itemsAfterSync, "items after sync")
    checks.expect(
        try await facade.search(query: Expected.issuer).count,
        Expected.searchHitsForIssuer,
        "search hits"
    )

    // A fixed corpus of failures, asserted on `code` alone (§11.3.2).
    await checks.expectCode(Expected.unknownItemId, "unknown item id") {
        _ = try await facade.item(id: String(repeating: "00", count: 16))
    }

    // lock
    try await facade.lock()
    checks.expectTrue(try await facade.lockState().locked, "locked")
    await checks.expectCode(Expected.readWhileLocked, "read while locked") {
        _ = try await facade.list()
    }
    await checks.expectCode(Expected.syncWhileLocked, "sync while locked") {
        _ = try await facade.syncOnce()
    }

    // unlock
    try await facade.unlock(keyMaterial: fixtures.vaultKey)
    checks.expect(try await facade.lockState().locked, false, "unlocked again")

    // revoke — the epoch rotates and the vault is re-sealed under a successor roster
    // (§6.4); the code survives it.
    try await facade.revokeDevice(deviceId: fixtures.peerDeviceId)
    checks.expect(
        try await facade.generateCode(id: id).code,
        Expected.code,
        "the code survives epoch rotation"
    )
    _ = try await facade.syncOnce()

    // A lifecycle event locks immediately (§11.5.5).
    checks.expectTrue(
        try await facade.reportLifecycle(event: .backgrounded).locked,
        "backgrounding locks immediately"
    )

    // Shutdown is an explicit command, never a dropped future: UniFFI has no
    // future-drop cancellation (§11.7.1).
    try await facade.shutdown()
}

@main
struct ConformanceFlow {
    static func main() async {
        let checks = Checks()
        do {
            try await runFlow(checks)
        } catch {
            checks.fail("the flow threw: \(error)")
        }
        exit(checks.report("swift conformance (SPEC §11.8.2)"))
    }
}
