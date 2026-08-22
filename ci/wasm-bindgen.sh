#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Misty Authors
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Prints the path to a `wasm-bindgen` distribution matching the version pinned in
# Cargo.lock, downloading it into target/ first if it is not already there.
#
# Two things need it and they must agree: the conformance runner
# (`crates/misty-ffi/conformance/run-wasm.sh`, which needs
# `wasm-bindgen-test-runner`) and the UI's core build (`apps/ui/scripts/build-core.sh`,
# which needs `wasm-bindgen` itself). A mismatch between the CLI and the `wasm-bindgen`
# crate the module was compiled against is an ABI break in the generated glue, not a
# warning — so the version comes from Cargo.lock and nowhere else, and both callers read
# it from here rather than each having their own copy of this logic to drift.
#
# Usage:
#   dir="$(ci/wasm-bindgen.sh)"      # prints the directory holding both binaries
#   "$dir/wasm-bindgen" --version
#
# Progress goes to stderr, because stdout is the return value.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$(uname -s)-$(uname -m)" in
Linux-x86_64) target="x86_64-unknown-linux-musl" ;;
Darwin-arm64) target="aarch64-apple-darwin" ;;
Darwin-x86_64) target="x86_64-apple-darwin" ;;
*)
  echo "error: no prebuilt wasm-bindgen for $(uname -s)-$(uname -m)." >&2
  exit 1
  ;;
esac

version="$(python3 - "$root/Cargo.lock" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
match = re.search(r'\[\[package\]\]\nname = "wasm-bindgen"\nversion = "([^"]+)"', text)
print(match.group(1) if match else "")
PY
)"
[ -n "$version" ] || { echo "error: no wasm-bindgen version in Cargo.lock." >&2; exit 1; }

dir="$root/target/wasm-bindgen-$version"
if [ ! -x "$dir/wasm-bindgen" ] || [ ! -x "$dir/wasm-bindgen-test-runner" ]; then
  echo "==> fetching wasm-bindgen $version" >&2
  mkdir -p "$dir"
  url="https://github.com/rustwasm/wasm-bindgen/releases/download/$version/wasm-bindgen-$version-$target.tar.gz"
  if curl -sfL --max-time 300 -o "$dir/wb.tar.gz" "$url"; then
    tar xzf "$dir/wb.tar.gz" -C "$dir" --strip-components=1
    rm -f "$dir/wb.tar.gz"
  else
    echo "    no prebuilt release for $target; building from source" >&2
    cargo install wasm-bindgen-cli --version "$version" --locked --root "$dir" >&2
    for binary in wasm-bindgen wasm-bindgen-test-runner; do
      [ -x "$dir/bin/$binary" ] && mv "$dir/bin/$binary" "$dir/$binary"
    done
  fi
fi

for binary in wasm-bindgen wasm-bindgen-test-runner; do
  [ -x "$dir/$binary" ] || {
    echo "error: $binary $version is missing from $dir after the fetch." >&2
    exit 1
  }
done

echo "$dir"
