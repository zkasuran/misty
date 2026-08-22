#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Misty Authors
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs the Kotlin leg of the SPEC §11.8.2 conformance gate: build the cdylib, generate
# Kotlin from *that artifact*, compile it together with the flow, and execute it on a JVM
# with the library on JNA's search path.
#
# No Gradle and no Android SDK. UniFFI's Kotlin output needs exactly two things off Maven
# Central — JNA (the FFI layer it binds through) and kotlinx-coroutines (the `suspend`
# machinery its async methods use) — so fetching two jars is the whole dependency story.
# P8 (`apps/mobile`) will wrap the same generated bindings in a real Android project; that
# does not change the contract asserted here, and this leg deliberately does not wait for
# it. "Generation succeeds" proves the toolchain lowered the API; only running it proves
# Kotlin computes the same answers as Swift, wasm, and Rust.
#
# Everything is cached under target/ and nothing is installed system-wide.
#
# Usage: crates/misty-ffi/conformance/run-kotlin.sh [--release]
#
# Overrides, all optional:
#   KOTLINC=/path/to/kotlinc   a Kotlin compiler to use instead of a downloaded one
#   KOTLIN_VERSION=2.4.10      which compiler to download when KOTLINC is unset

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
work="$root/target/conformance-kotlin"
mkdir -p "$work/jars"

profile="debug"
cargo_profile_flag=()
if [ "${1:-}" = "--release" ]; then
  profile="release"
  cargo_profile_flag=(--release)
fi

kotlin_version="${KOTLIN_VERSION:-2.4.10}"
jna_version="5.19.1"
coroutines_version="1.11.0"

# See the note in run-swift.sh: askama resolves the bindgen templates through a path
# relative to CARGO_MANIFEST_DIR, which a symlinked CARGO_HOME breaks.
if [ -L "${CARGO_HOME:-$HOME/.cargo}" ]; then
  CARGO_HOME="$(readlink -f "${CARGO_HOME:-$HOME/.cargo}")"
  export CARGO_HOME
fi

case "$(uname -s)" in
Darwin) libname="libmisty_ffi.dylib" ;;
*) libname="libmisty_ffi.so" ;;
esac

command -v java >/dev/null || { echo "error: no java on PATH; the Kotlin leg needs a JVM." >&2; exit 1; }

# --- 1. the library, and Kotlin generated from it ------------------------------------

echo "==> building the cdylib"
cargo build --manifest-path "$root/Cargo.toml" -p misty-ffi "${cargo_profile_flag[@]}"

echo "==> generating Kotlin from $libname"
bindings="$work/bindings"
rm -rf "$bindings"
# Library mode: the metadata comes out of the artifact that will actually be loaded, so
# the bindings cannot describe a different build than the one under test.
cargo run --manifest-path "$root/Cargo.toml" -p misty-ffi --features cli \
  --bin uniffi-bindgen "${cargo_profile_flag[@]}" -- \
  generate --library "$root/target/$profile/$libname" \
  --language kotlin --out-dir "$bindings"

generated="$bindings/uniffi/misty/misty.kt"
[ -f "$generated" ] || { echo "error: expected generated Kotlin at $generated" >&2; exit 1; }

# --- 2. a Kotlin compiler ------------------------------------------------------------

kotlinc="${KOTLINC:-}"
if [ -z "$kotlinc" ] && command -v kotlinc >/dev/null; then kotlinc="$(command -v kotlinc)"; fi
if [ -z "$kotlinc" ]; then
  kotlinc="$work/kotlinc-$kotlin_version/kotlinc/bin/kotlinc"
  if [ ! -x "$kotlinc" ]; then
    echo "==> fetching the Kotlin compiler $kotlin_version"
    dest="$work/kotlinc-$kotlin_version"
    mkdir -p "$dest"
    curl -sL --max-time 600 -o "$dest/kc.zip" \
      "https://github.com/JetBrains/kotlin/releases/download/v$kotlin_version/kotlin-compiler-$kotlin_version.zip"
    unzip -qo "$dest/kc.zip" -d "$dest"
    rm -f "$dest/kc.zip"
  fi
fi
[ -x "$kotlinc" ] || { echo "error: no usable kotlinc (tried '$kotlinc')." >&2; exit 1; }

# --- 3. the two jars UniFFI's Kotlin output needs ------------------------------------

fetch_jar() {
  local group_path="$1" artifact="$2" version="$3"
  local jar="$work/jars/$artifact-$version.jar"
  if [ ! -f "$jar" ]; then
    # Progress goes to stderr, deliberately. This function's *stdout* is the return
    # value — the caller reads it through `$( )` — so a chatty `echo` here ends up
    # concatenated into the classpath, and kotlinc then silently ignores the bogus
    # entry and reports a hundred `unresolved reference 'jna'` errors instead. A
    # pre-populated cache hides it, which is exactly why it survived local testing.
    echo "==> fetching $artifact $version" >&2
    curl -sL --max-time 300 --fail -o "$jar" \
      "https://repo1.maven.org/maven2/$group_path/$artifact/$version/$artifact-$version.jar" ||
      { echo "error: could not download $artifact $version." >&2; return 1; }
  fi
  echo "$jar"
}

jna_jar="$(fetch_jar net/java/dev/jna jna "$jna_version")"
coroutines_jar="$(fetch_jar org/jetbrains/kotlinx kotlinx-coroutines-core-jvm "$coroutines_version")"

# The Kotlin standard library ships with the compiler, and `java` needs it at *runtime*
# as well — `kotlinc` puts it on the compile classpath implicitly, which is why a missing
# stdlib shows up only when the program starts, as `NoClassDefFoundError:
# kotlin/coroutines/Continuation`. Take it from the same distribution as the compiler so
# the two versions cannot disagree.
stdlib_jar="$(dirname "$(dirname "$(readlink -f "$kotlinc")")")/lib/kotlin-stdlib.jar"
[ -f "$stdlib_jar" ] || {
  echo "error: no kotlin-stdlib.jar beside the compiler at $stdlib_jar." >&2
  exit 1
}

classpath="$jna_jar:$coroutines_jar:$stdlib_jar"

# kotlinc does not complain about a classpath entry that does not exist; it just fails to
# resolve everything that entry was supposed to provide, a hundred errors deep and far
# from the cause. Check the entries are real files before handing them over, so a broken
# path reports itself as one.
IFS=':' read -r -a classpath_entries <<<"$classpath"
for entry in "${classpath_entries[@]}"; do
  [ -f "$entry" ] || {
    echo "error: classpath entry is not a file: '$entry'" >&2
    exit 1
  }
done

# --- 4. compile and run --------------------------------------------------------------

echo "==> compiling the conformance flow"
classes="$work/classes"
rm -rf "$classes" && mkdir -p "$classes"
# -Xjvm-default=all so the generated interfaces' default members work on the JVM, and
# -nowarn because the generated file is machine-written and its style is not ours to fix.
"$kotlinc" \
  -classpath "$classpath" \
  -d "$classes" \
  -nowarn \
  -Xjvm-default=all \
  "$generated" \
  "$here/ConformanceFlow.kt" 2>&1 | grep -vE "^(warning|info):" || true

[ -d "$classes" ] && [ -n "$(ls -A "$classes")" ] || {
  echo "error: kotlinc produced no classes." >&2
  exit 1
}

echo "==> running"
# jna.library.path is how the generated bindings find the cdylib; jna.nosys keeps JNA from
# preferring a system copy of itself over the jar we just fetched.
#
# --enable-native-access is not optional housekeeping: from JDK 24 on, loading a native
# library from an unnamed module is a restricted operation that warns now and will be
# blocked outright later. Every UniFFI Kotlin consumer hits this, so it belongs here
# rather than in a reader's notes.
exec java \
  --enable-native-access=ALL-UNNAMED \
  -classpath "$classes:$classpath" \
  -Djna.library.path="$root/target/$profile" \
  -Djna.nosys=true \
  ConformanceFlowKt
