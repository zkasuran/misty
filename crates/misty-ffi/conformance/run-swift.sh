#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Misty Authors
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs the Swift leg of the SPEC §11.8.2 conformance gate: build the cdylib, generate
# the Swift bindings from *that artifact* (library mode, so the metadata comes from the
# library that gets linked), compile the generated module together with the flow, and
# run it.
#
# This works on Linux as well as macOS. The Swift *language* leg needs a Swift
# toolchain, not an Apple one — swift.org ships Linux toolchains — so this can run on
# every pull request instead of only on the macOS runner. What genuinely needs macOS is
# the Apple *platform* artifact: an `.xcframework` for `aarch64-apple-ios` /
# `*-apple-darwin` slices, built by the `apple` CI job. Keeping the two apart means an
# API break in the Swift binding is caught on the cheap runner.
#
# Usage: crates/misty-ffi/conformance/run-swift.sh [--release]

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
profile="debug"
cargo_profile_flag=()
if [ "${1:-}" = "--release" ]; then
  profile="release"
  cargo_profile_flag=(--release)
fi

# UniFFI's bindgen templates are resolved by `askama` through a path relative to
# CARGO_MANIFEST_DIR. If CARGO_HOME is reached through a symlink, `..` resolves against
# the *physical* path and the template lookup lands somewhere that does not exist. Point
# CARGO_HOME at the real directory when it is a link.
if [ -L "${CARGO_HOME:-$HOME/.cargo}" ]; then
  CARGO_HOME="$(readlink -f "${CARGO_HOME:-$HOME/.cargo}")"
  export CARGO_HOME
fi

case "$(uname -s)" in
Darwin) libname="libmisty_ffi.dylib" ;;
*) libname="libmisty_ffi.so" ;;
esac

lib="$root/target/$profile/$libname"
out="$root/target/bindings/swift"
bin="$root/target/bindings/swift-conformance"

echo "==> building the cdylib"
cargo build --manifest-path "$root/Cargo.toml" -p misty-ffi "${cargo_profile_flag[@]}"

echo "==> generating Swift from $libname"
rm -rf "$out"
cargo run --manifest-path "$root/Cargo.toml" -p misty-ffi --features cli \
  --bin uniffi-bindgen "${cargo_profile_flag[@]}" -- \
  generate --library "$lib" --language swift --out-dir "$out"

# Swift looks for `module.modulemap` on the header search path; UniFFI emits
# `<namespace>FFI.modulemap`. Its `use "Darwin"` line names a module that only exists on
# Apple platforms, so it is dropped — the header needs nothing from it that the C
# importer does not already provide.
grep -v '^ *use "' "$out/mistyFFI.modulemap" >"$out/module.modulemap"

echo "==> compiling the conformance flow"
swiftc \
  -swift-version 5 \
  -module-name MistyConformance \
  -I "$out" \
  -L "$root/target/$profile" \
  -lmisty_ffi \
  -Xlinker -rpath -Xlinker "$root/target/$profile" \
  "$out/misty.swift" \
  "$here/ConformanceFlow.swift" \
  -o "$bin"

echo "==> running"
"$bin"
