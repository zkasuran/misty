#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Misty Authors
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds the Misty core for the browser and drops the generated package into
# `src/lib/core/pkg/`, where the app imports it.
#
# What this produces is **not a mock**. It is `crates/misty` — the real vault, the real
# CRDT merge, the real envelope layer, the real sync state machine — compiled to
# `wasm32-unknown-unknown` with `MemoryStore` and `MockTransport` substituted for the disk
# and the network (SPEC §11.8.1). A hand-written TypeScript mock is forbidden precisely
# because it can drift from the core while both stay green; this cannot drift, because it
# *is* the core. Swapping in a real store and transport is a build configuration change
# and nothing in this app moves.
#
# The output is generated and git-ignored. Run this before `dev`, `build`, or the tests;
# the npm scripts do it for you.
#
# Usage: apps/ui/scripts/build-core.sh [--release]

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
app="$(cd "$here/.." && pwd)"
root="$(cd "$app/../.." && pwd)"

profile="debug"
cargo_flags=()
if [ "${1:-}" = "--release" ]; then
  profile="release"
  cargo_flags=(--release)
fi

# See the note in crates/misty-ffi/conformance/run-swift.sh: a symlinked CARGO_HOME breaks
# askama's relative template lookup inside the bindgen crates.
if [ -L "${CARGO_HOME:-$HOME/.cargo}" ]; then
  CARGO_HOME="$(readlink -f "${CARGO_HOME:-$HOME/.cargo}")"
  export CARGO_HOME
fi

out="$app/src/lib/core/pkg"
wasm="$root/target/wasm32-unknown-unknown/$profile/misty_ffi.wasm"

echo "==> building the core for wasm32 ($profile)"
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
cargo build --manifest-path "$root/Cargo.toml" -p misty-ffi \
  --target wasm32-unknown-unknown "${cargo_flags[@]}"

# The CLI must match the `wasm-bindgen` crate the module was compiled against; the shared
# helper reads that version out of Cargo.lock so this cannot be set wrong by hand.
bindgen="$("$root/ci/wasm-bindgen.sh")/wasm-bindgen"

echo "==> generating the JS package with $("$bindgen" --version)"
rm -rf "$out"
# `--target web` emits an ES module with an explicit `init()`, which is what lets the app
# decide *when* the core loads rather than having a bundler decide for it. No `--target
# bundler`: that path wants to synthesise its own glue and fights Vite's asset handling
# for the `.wasm` file.
#
# Deliberately *not* `--omit-default-module-path`. That flag strips the generated
# `new URL('misty_ffi_bg.wasm', import.meta.url)` default, after which `init()` cannot find
# the module and resolves to a hang rather than an error. Keeping the default is also what
# lets Vite see the `new URL(..., import.meta.url)` and rewrite it to the hashed asset it
# emits, so the app never hardcodes a build path.
"$bindgen" "$wasm" --out-dir "$out" --target web

# Nothing here is hand-editable, and the next build overwrites it. Say so in the tree so
# a reader who finds it does not go looking for its history.
cat >"$out/README.md" <<'NOTE'
<!--
SPDX-FileCopyrightText: 2026 The Misty Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Generated — do not edit, do not commit

`wasm-bindgen` output for `crates/misty-ffi`, produced by
`apps/ui/scripts/build-core.sh`. Regenerated on every build and git-ignored.

This is the real Misty core compiled for the browser with an in-memory store and a
mock transport (SPEC §11.8.1), not a stand-in for it.
NOTE

echo "==> wrote $(basename "$out")/:"
ls -1 "$out" | sed 's/^/    /'
