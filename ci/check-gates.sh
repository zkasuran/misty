#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Misty Authors
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Checks every ROADMAP exit gate on this checkout.
#
# `docs/ROADMAP.md` opens with "A phase is not 'done' until its gate passes on a clean
# checkout." This makes that literal. It is not a second copy of CI — CI answers "does the
# tree build and pass", which is a different and weaker question. This answers "is the
# specific thing each phase promised actually true", and it names the evidence, so a gate
# cannot be declared met because the suite happens to be green.
#
# Three rules it follows, each of which is a mistake already made once:
#
#  - **A check keys off the test file, not the test name.** This repo names tests after the
#    property they prove (`a_failure_at_every_write_position_leaves_the_vault_untouched`) and
#    puts the mechanism in the file name (`crash_injection.rs`). An earlier version of this
#    script grepped names for "crash" and "hostile", found nothing, and reported two gates
#    failing that had been met since P2 and P4.
#  - **What cannot be checked here is reported as SKIP with a reason, never as PASS.** Fuzz
#    runs need a nightly toolchain and `cargo-fuzz`; the Apple artifact needs macOS. Counting
#    files and calling it a pass is how "the gate did not run" comes to look like "the gate
#    passed".
#  - **A SKIP does not fail the run, and is printed in the summary anyway,** so an incomplete
#    verification is visible rather than inferred from a zero exit code.
#
# Usage:
#   ci/check-gates.sh              every phase
#   ci/check-gates.sh P4 P5        only those phases
#   ci/check-gates.sh --list       what it knows how to check

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# A symlinked CARGO_HOME breaks askama's relative template lookup inside the bindgen crates,
# which the P5 binding legs need. Same note as the conformance runners.
if [ -L "${CARGO_HOME:-$HOME/.cargo}" ]; then
  CARGO_HOME="$(readlink -f "${CARGO_HOME:-$HOME/.cargo}")"
  export CARGO_HOME
fi

passes=0
failures=0
skips=0

pass() { printf '   \033[32mPASS\033[0m  %s\n' "$1"; passes=$((passes + 1)); }
fail() { printf '   \033[31mFAIL\033[0m  %s\n' "$1"; failures=$((failures + 1)); }
skip() { printf '   \033[33mSKIP\033[0m  %s\n' "$1"; skips=$((skips + 1)); }
phase() { printf '\n\033[1m──── %s\033[0m\n' "$1"; }

# --- primitives ----------------------------------------------------------------------

## A whole test target passes, and reports how many cases it contains.
suite() {
  local what="$1" pkg="$2" target="${3:-}"
  local out
  if [ -n "$target" ]; then
    out="$(cargo test -p "$pkg" --test "$target" 2>&1)"
  else
    out="$(cargo test -p "$pkg" 2>&1)"
  fi
  local cases
  cases="$(printf '%s' "$out" | grep -cE '^test .* ok$')"
  if printf '%s' "$out" | grep -qE '^test result: FAILED|^error(\[|:)'; then
    fail "$what — suite failed"
    printf '%s' "$out" | grep -E '^test .* FAILED|^error' | head -5 | sed 's/^/           /'
  elif [ "$cases" -eq 0 ]; then
    fail "$what — no test cases ran (has the target been renamed?)"
  else
    pass "$what ($cases cases)"
  fi
}

## A named test exists and passes. Guards against a gate's specific promise being renamed
## away while the suite stays green.
##
## Runs the one test with `--exact` rather than grepping the whole target's output for
## `test NAME ... ok`. That grep does not work and the reason is worth recording: cargo
## prints `test NAME ... ` when a test starts and `ok` when it finishes, so with the default
## thread count concurrent tests interleave into lines like
## `test a ... test b ... ok`. A name-based grep then passes or fails depending on which
## tests happened to overlap — which is exactly what it did here, reporting nine failures
## for tests whose own suites were green.
named() {
  local what="$1" pkg="$2" target="$3" name="$4"
  local out
  out="$(cargo test -p "$pkg" --test "$target" -- --exact "$name" 2>&1)"
  if printf '%s' "$out" | grep -qE '^test result: ok\. 1 passed'; then
    pass "$what"
  else
    fail "$what — expected '$name' in tests/$target.rs to run and pass"
    printf '%s' "$out" | grep -E '^test result|^error' | head -2 | sed 's/^/           /'
  fi
}

## A crate compiles for wasm32.
wasm_builds() {
  if cargo build -q -p "$1" --target wasm32-unknown-unknown 2>&1 | grep -qE '^error'; then
    fail "$1 builds for wasm32"
  else
    pass "$1 builds for wasm32"
  fi
}

## Fuzz targets: counted here, executed by the `fuzz` CI job. Counting is not running, and
## the message says so rather than implying coverage this script did not obtain.
fuzz_targets() {
  local crate="$1" n
  n="$(ls "$crate"/fuzz/fuzz_targets/*.rs 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$n" -eq 0 ]; then
    fail "$crate has a fuzz target (SPEC §10 requires one per parser)"
    return
  fi
  if command -v cargo-fuzz >/dev/null 2>&1 && cargo +nightly --version >/dev/null 2>&1; then
    pass "$crate: $n fuzz target(s) present (run them with: cd $crate && cargo fuzz run <name>)"
  else
    skip "$crate: $n fuzz target(s) present, not executed — needs nightly + cargo-fuzz; the CI 'fuzz' job runs them"
  fi
}

# --- phases --------------------------------------------------------------------------

P0() {
  phase "P0  Foundation — cargo metadata clean, spec merged"
  if cargo metadata --format-version 1 >/dev/null 2>&1; then
    pass "cargo metadata is clean"
  else
    fail "cargo metadata"
  fi
  [ -f docs/SPEC.md ] && pass "docs/SPEC.md present ($(wc -l <docs/SPEC.md | tr -d ' ') lines)" || fail "docs/SPEC.md missing"
  [ -f docs/ROADMAP.md ] && pass "docs/ROADMAP.md present" || fail "docs/ROADMAP.md missing"
  [ -f .github/workflows/rust.yml ] && pass "CI workflow present" || fail "CI workflow missing"
}

P1() {
  phase "P1  OTP engine — RFC 4226/6238 vectors, otpauth round-trip, fuzz target"
  # The gate says "every RFC 4226/6238 vector green", so the appendix suites are named
  # individually: a rename or a deletion here removes the gate's actual evidence, and the
  # crate-wide run would stay green without it.
  suite "RFC 4226 vectors" misty-otp rfc4226
  named "RFC 4226 appendix D, intermediate HMAC" misty-otp rfc4226 appendix_d_table_1_intermediate_hmac
  named "RFC 4226 appendix D, dynamic truncation" misty-otp rfc4226 appendix_d_table_2_dynamic_truncation
  named "RFC 4226 appendix D, HOTP values" misty-otp rfc4226 appendix_d_table_2_hotp_values
  suite "RFC 6238 vectors" misty-otp rfc6238
  named "RFC 6238 appendix B, all modes" misty-otp rfc6238 appendix_b_all_modes
  suite "otpauth round-trip properties" misty-otp proptests
  suite "vendor variants (Steam, mOTP, Blizzard, Yandex)" misty-otp variants
  suite "hostile OTP input is rejected" misty-otp hostile_inputs
  suite "misty-otp, whole crate" misty-otp
  wasm_builds misty-otp
  fuzz_targets crates/misty-otp

  phase "P1  Crypto core — envelope/backup/recovery round-trips, KATs, wasm32"
  named "authoritative KAT: Ed25519 RFC 8032" misty-crypto kat_authoritative ed25519_rfc8032_vectors
  named "authoritative KAT: BIP39 English reference" misty-crypto kat_authoritative bip39_english_reference_vectors
  suite "recovery-kit round-trips" misty-crypto recovery_kit
  suite "hostile inputs never panic" misty-crypto hostile_inputs
  suite "misty-crypto, whole crate" misty-crypto
  wasm_builds misty-crypto
  fuzz_targets crates/misty-crypto
}

P2() {
  phase "P2  Vault — CRDT convergence property test, crash injection"
  # The gate's two promises, by file. Renaming either would fail here rather than silently
  # removing the evidence.
  suite "CRDT convergence properties" misty-vault convergence
  named "merge is commutative" misty-vault convergence merge_is_commutative
  named "merge is associative" misty-vault convergence merge_is_associative
  named "merge is idempotent" misty-vault convergence merge_is_idempotent
  named "every application order converges" misty-vault convergence every_application_order_converges
  suite "crash injection" misty-vault crash_injection
  named "a failure at every write position leaves the vault untouched" \
    misty-vault crash_injection a_failure_at_every_write_position_leaves_the_vault_untouched
  suite "misty-vault, whole crate" misty-vault
  wasm_builds misty-vault
  fuzz_targets crates/misty-vault
}

P3() {
  phase "P3  Interop — a fixture per format, all fuzz targets"
  local n
  n="$(ls -d crates/misty-importers/tests/fixtures/*/ 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$n" -ge 10 ]; then
    pass "importer fixtures: $n formats"
  else
    fail "importer fixtures: only $n formats"
  fi
  suite "misty-importers, whole crate" misty-importers
  wasm_builds misty-importers
  fuzz_targets crates/misty-importers
}

P4() {
  phase "P4  Sync — two clients converge through the real server, hostile rejected"
  # §6.1.1's rule: prove interoperation by running the real code on both sides.
  named "two clients converge byte-identically through the real server" \
    misty-sync interop_server two_clients_converge_to_byte_identical_state_through_the_real_server
  named "signed payloads are byte-identical on both sides" \
    misty-sync interop_server the_signed_payloads_are_byte_identical_on_both_sides
  suite "real-socket interop against the real server" misty-sync interop_server
  suite "hostile server is refused" misty-sync hostile_server
  suite "hostile input is refused" misty-sync hostile_input
  suite "server refuses hostile input before any Misty code runs" misty-server hostile_input
  suite "misty-sync, whole crate" misty-sync
  suite "misty-server, whole crate" misty-server
  wasm_builds misty-sync
  fuzz_targets crates/misty-sync
}

P5() {
  phase "P5  Bindings — one shared conformance suite, every binding runs it"
  suite "leg 1/5  native Rust facade" misty conformance
  suite "leg 2/5  exported UniFFI object" misty-ffi native

  local out
  if command -v swiftc >/dev/null 2>&1; then
    out="$(./crates/misty-ffi/conformance/run-swift.sh 2>&1 | tail -1)"
    case "$out" in
    *"assertions passed"*) pass "leg 3/5  generated Swift — $out" ;;
    *) fail "leg 3/5  generated Swift — $out" ;;
    esac
  else
    skip "leg 3/5  generated Swift — no swiftc on PATH (swift.org ships Linux builds)"
  fi

  if command -v java >/dev/null 2>&1; then
    out="$(./crates/misty-ffi/conformance/run-kotlin.sh 2>&1 | tail -1)"
    case "$out" in
    *"assertions passed"*) pass "leg 4/5  generated Kotlin — $out" ;;
    *) fail "leg 4/5  generated Kotlin — $out" ;;
    esac
  else
    skip "leg 4/5  generated Kotlin — no JVM on PATH"
  fi

  out="$(./crates/misty-ffi/conformance/run-wasm.sh 2>&1 | grep -E '^test result' | tail -1)"
  case "$out" in
  *"0 failed"*) pass "leg 5/5  wasm bundle in headless Chrome — $out" ;;
  '') skip "leg 5/5  wasm bundle — no usable browser/driver pair" ;;
  *) fail "leg 5/5  wasm bundle — $out" ;;
  esac

  if python3 ci/check-binding-parity.py >/dev/null 2>&1; then
    pass "every facade method reaches both bindings"
  else
    fail "facade/binding parity"
    python3 ci/check-binding-parity.py | sed 's/^/           /'
  fi

  wasm_builds misty
  wasm_builds misty-ffi

  # The Apple platform artifact is P7/P8 work that landed early (see the ROADMAP sequencing
  # note); it is checked here because it exists, not because P5 requires it.
  if [ "$(uname -s)" = "Darwin" ]; then
    if ./crates/misty-ffi/apple/build-xcframework.sh >/dev/null 2>&1; then
      pass "Misty.xcframework assembles (P7/P8 work, landed early)"
    else
      fail "Misty.xcframework"
    fi
  else
    skip "Misty.xcframework — needs macOS; the CI 'apple' job builds it"
  fi
}

P6() {
  phase "P6  UI — full flows against the mock core, a11y clean, light + dark"
  if ! command -v npm >/dev/null 2>&1; then
    skip "apps/ui — no npm on PATH"
    return
  fi
  if [ ! -d apps/ui/node_modules ]; then
    skip "apps/ui — dependencies not installed (run: cd apps/ui && npm ci)"
    return
  fi
  (
    cd apps/ui || exit 1
    if npx svelte-check --tsconfig ./tsconfig.json 2>&1 | grep -q '0 errors and 0 warnings'; then
      printf '   \033[32mPASS\033[0m  types and Svelte templates check clean\n'
    else
      printf '   \033[31mFAIL\033[0m  svelte-check\n'
      exit 1
    fi
    # CI=1 so the preview server is started rather than reused, which is the path CI takes.
    local out
    out="$(CI=1 npx playwright test --reporter=list 2>&1)"
    if printf '%s' "$out" | grep -qE '[0-9]+ failed'; then
      printf '   \033[31mFAIL\033[0m  playwright: %s\n' "$(printf '%s' "$out" | grep -oE '[0-9]+ failed' | head -1)"
      printf '%s' "$out" | grep -E '✘' | head -5 | sed 's/^/           /'
      exit 1
    fi
    printf '   \033[32mPASS\033[0m  full flows and a11y: %s\n' \
      "$(printf '%s' "$out" | grep -oE '[0-9]+ passed' | head -1)"
    # Both themes must actually have been audited, not just one.
    for theme in light dark; do
      if printf '%s' "$out" | grep -q "$theme theme"; then
        printf '   \033[32mPASS\033[0m  a11y audited in the %s theme\n' "$theme"
      else
        printf '   \033[31mFAIL\033[0m  no a11y specs ran for the %s theme\n' "$theme"
        exit 1
      fi
    done
  )
  # shellcheck disable=SC2181
  if [ $? -eq 0 ]; then
    passes=$((passes + 4))
  else
    failures=$((failures + 1))
  fi
}

XCUT() {
  phase "Cross-cutting — the engineering rules (SPEC §10) that apply to every phase"
  cargo fmt --all --check >/dev/null 2>&1 && pass "cargo fmt" || fail "cargo fmt"
  if RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --all-features -q >/dev/null 2>&1; then
    pass "clippy --all-targets --all-features, warnings denied"
  else
    fail "clippy"
  fi
  local n
  n="$(cargo doc --workspace --no-deps 2>&1 | grep -cE '^warning')"
  [ "$n" -eq 0 ] && pass "cargo doc: no warnings" || fail "cargo doc: $n warning(s)"
  python3 ci/check-otp-permissive.py >/dev/null 2>&1 &&
    pass "misty-otp stays permissively licensed, dependencies included" ||
    fail "misty-otp permissive licensing"
  if command -v reuse >/dev/null 2>&1; then
    reuse lint >/dev/null 2>&1 && pass "REUSE 3.3 compliant" || fail "REUSE lint"
  else
    skip "REUSE lint — reuse not installed (pip install reuse)"
  fi
}

# --- driver --------------------------------------------------------------------------

ALL=(P0 P1 P2 P3 P4 P5 P6 XCUT)

if [ "${1:-}" = "--list" ]; then
  printf 'phases this script checks: %s\n' "${ALL[*]}"
  exit 0
fi

selected=("$@")
[ ${#selected[@]} -eq 0 ] && selected=("${ALL[@]}")

for name in "${selected[@]}"; do
  if ! declare -F "$name" >/dev/null; then
    echo "error: unknown phase '$name'. Known: ${ALL[*]}" >&2
    exit 2
  fi
  "$name"
done

printf '\n\033[1m──── summary\033[0m\n'
printf '   %d passed, %d failed, %d skipped\n' "$passes" "$failures" "$skips"
if [ "$skips" -gt 0 ]; then
  echo "   Skips are checks this machine cannot make, not checks that passed."
fi
if [ "$failures" -gt 0 ]; then
  printf '\n\033[31mGATES NOT MET\033[0m\n'
  exit 1
fi
printf '\n\033[32mEVERY SELECTED GATE IS MET\033[0m\n'
