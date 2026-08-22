// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//
// The Kotlin leg of the SPEC §11.8.2 conformance gate.
//
// The same scripted flow as `crates/misty-ffi/tests/native.rs` (the exported UniFFI
// object, in Rust), `conformance/ConformanceFlow.swift` (the generated Swift), and
// `crates/misty-ffi/tests/web.rs` (the wasm bundle in a headless browser), against the
// same fixtures, asserting the same literals.
//
// Deliberately plain Kotlin with no test framework and no Gradle: it has to run under a
// bare `kotlinc` + `java` on a CI box that has no Android SDK, and pulling in JUnit would
// make this leg the odd one out. `apps/mobile` (P8) will wrap the same generated bindings
// in a real Android project; that does not change the contract asserted here.
//
// Inputs come from `mockFixtures()` so nothing is re-derived. Expected outputs are
// literals mirroring `conformance/fixtures.json`; if Rust handed those over too, this
// file would be asserting the core against itself.
//

import kotlinx.coroutines.runBlocking
import uniffi.misty.HashAlg
import uniffi.misty.LifecycleEvent
import uniffi.misty.MistyException
import uniffi.misty.MistyFacade
import uniffi.misty.NewItemInput
import uniffi.misty.OtpKind
import uniffi.misty.mockFixtures

// --- expected outputs, pinned (conformance/fixtures.json) ---

private object Expected {
    const val CODE = "746722"
    const val PERIOD_MS = 30_000L
    const val ISSUER = "GitHub"
    const val ACCOUNT = "ada@example.com"
    const val PUSHED_ON_FIRST_SYNC = 1u
    const val ITEMS_AFTER_SYNC = 1
    const val SEARCH_HITS_FOR_ISSUER = 1

    // Only the stable `code` is asserted — never `message`, which is English, redacted,
    // and non-normative (§11.3.2).
    const val UNKNOWN_ITEM_ID = "NOT_FOUND"
    const val READ_WHILE_LOCKED = "VAULT_LOCKED"
    const val SYNC_WHILE_LOCKED = "VAULT_LOCKED"
}

// --- a minimal check recorder ---

private class Checks {
    private val failures = mutableListOf<String>()
    private var passed = 0

    fun <T> expect(actual: T, expected: T, what: String) {
        if (actual == expected) {
            passed++
        } else {
            fail("$what: expected $expected, got $actual")
        }
    }

    fun expectTrue(actual: Boolean, what: String) = expect(actual, true, what)

    fun fail(message: String) {
        failures.add(message)
        System.err.println("  x $message")
    }

    /**
     * Assert that [body] fails with a specific stable `code` (§11.3.2). A binding that
     * threw the right *kind* of failure with the wrong code would pass a bare
     * try/catch, so the code is compared explicitly.
     */
    suspend fun expectCode(expected: String, what: String, body: suspend () -> Unit) {
        try {
            body()
            fail("$what: expected the call to fail with $expected, but it succeeded")
        } catch (error: MistyException.Failed) {
            expect(error.`detail`.`code`, expected, "$what code")
            // Retryability is a frozen function of the code (§11.3.3); neither of these
            // codes is transient.
            expect(error.`detail`.`retryable`, false, "$what retryable")
            expect(error.`detail`.`message`.isEmpty(), false, "$what carries a message")
        } catch (error: Throwable) {
            fail("$what: threw something that is not a MistyException.Failed: $error")
        }
    }

    fun report(label: String): Int {
        if (failures.isEmpty()) {
            println("$label: $passed assertions passed")
            return 0
        }
        println("$label: ${failures.size} failed, $passed passed")
        return 1
    }
}

// --- the flow ---

private fun newTotp(secret: ByteArray) = NewItemInput(
    `kind` = OtpKind.TOTP,
    `algorithm` = HashAlg.SHA1,
    `digits` = 6u,
    `period` = 30u,
    `hotpCounter` = 0uL,
    `secret` = secret,
    `pin` = null,
    `issuer` = Expected.ISSUER,
    `account` = Expected.ACCOUNT,
    `nickname` = null,
    `note` = null,
    `groups` = emptyList(),
    `tags` = emptyList(),
    `origins` = emptyList(),
    `icon` = null,
    `color` = null,
    `favorite` = false,
)

private suspend fun runFlow(checks: Checks) {
    val fixtures = mockFixtures()
    val facade = MistyFacade()

    // enroll — represented by the mock core's pre-signed two-device roster (§11.8.1).
    // The joining half of a live §6.3 handshake needs core types that are quarantined
    // behind the facade and have no FFI projection; it is covered in Rust instead.
    checks.expectTrue(facade.lockState().`locked`, "the facade starts locked")
    facade.unlock(fixtures.`vaultKey`)
    checks.expect(facade.lockState().`locked`, false, "unlocked")

    // add
    val id = facade.add(newTotp(fixtures.`totpSecret`))
    val item = facade.item(id)
    checks.expect(item.`issuer`, Expected.ISSUER, "issuer")
    checks.expect(item.`account`, Expected.ACCOUNT, "account")
    checks.expect(item.`hasPin`, false, "no PIN was set")
    checks.expect(item.`kind`, OtpKind.TOTP, "kind survives the boundary")
    checks.expect(item.`algorithm`, HashAlg.SHA1, "algorithm survives the boundary")

    // generate — an exact value, because the clock is pinned (§11.8.2). A length check
    // would pass for six digits of the wrong code.
    val code = facade.generateCode(id)
    checks.expect(code.`code`, Expected.CODE, "generated code")
    checks.expect(code.`periodMs`, Expected.PERIOD_MS, "period")

    // sync
    val report = facade.syncOnce()
    checks.expect(report.`pushed`, Expected.PUSHED_ON_FIRST_SYNC, "pushed")
    checks.expect(report.`conflicts`.size, 0, "no conflicts")
    checks.expect(facade.list().size, Expected.ITEMS_AFTER_SYNC, "items after sync")
    checks.expect(
        facade.search(Expected.ISSUER).size,
        Expected.SEARCH_HITS_FOR_ISSUER,
        "search hits",
    )

    // A fixed corpus of failures, asserted on `code` alone (§11.3.2).
    checks.expectCode(Expected.UNKNOWN_ITEM_ID, "unknown item id") {
        facade.item("00".repeat(16))
    }

    // lock
    facade.lock()
    checks.expectTrue(facade.lockState().`locked`, "locked")
    checks.expectCode(Expected.READ_WHILE_LOCKED, "read while locked") { facade.list() }
    checks.expectCode(Expected.SYNC_WHILE_LOCKED, "sync while locked") { facade.syncOnce() }

    // unlock
    facade.unlock(fixtures.`vaultKey`)
    checks.expect(facade.lockState().`locked`, false, "unlocked again")

    // revoke — the epoch rotates and the vault is re-sealed under a successor roster
    // (§6.4); the code survives it.
    facade.revokeDevice(fixtures.`peerDeviceId`)
    checks.expect(
        facade.generateCode(id).`code`,
        Expected.CODE,
        "the code survives epoch rotation",
    )
    facade.syncOnce()

    // A lifecycle event locks immediately (§11.5.5).
    checks.expectTrue(
        facade.reportLifecycle(LifecycleEvent.BACKGROUNDED).`locked`,
        "backgrounding locks immediately",
    )

    // Shutdown is an explicit command, never a dropped coroutine: UniFFI has no
    // future-drop cancellation (§11.7.1).
    facade.shutdown()
}

fun main() {
    val checks = Checks()
    try {
        runBlocking { runFlow(checks) }
    } catch (error: Throwable) {
        checks.fail("the flow threw: $error")
    }
    // The JVM keeps non-daemon threads alive; exit explicitly so a lingering JNA or
    // coroutine thread cannot hold the process open after the verdict is in.
    System.exit(checks.report("kotlin conformance (SPEC §11.8.2)"))
}
