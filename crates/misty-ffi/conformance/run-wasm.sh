#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Misty Authors
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs the wasm leg of the SPEC §11.8.2 conformance gate: compile `tests/web.rs` to
# `wasm32-unknown-unknown` and execute it in a real headless browser, driving the
# `web::MistyFacade` surface JavaScript actually holds.
#
# The fiddly part is not the test, it is getting a *matched* browser and driver.
# ChromeDriver refuses to drive a Chrome whose major version differs from its own, and
# the failure it reports through `wasm-bindgen-test-runner` is a bare `http status: 404`
# with the real cause buried in the driver's log. This script pins the pair explicitly
# instead of hoping whatever is on PATH agrees, because "the gate did not run" and "the
# gate passed" must never look the same from the outside.
#
# Everything is cached under target/ and nothing is installed system-wide.
#
# Usage: crates/misty-ffi/conformance/run-wasm.sh
#
# Overrides, all optional:
#   CHROME=/path/to/chrome              a browser to use instead of the discovered one
#   CHROMEDRIVER=/path/to/chromedriver  a driver to use; must match CHROME's major version
#   WASM_BINDGEN_TEST_TIMEOUT=180       per-test timeout, seconds

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
work="$root/target/conformance-wasm"
mkdir -p "$work"

# See the note in run-swift.sh: a symlinked CARGO_HOME breaks askama's relative template
# lookup inside the bindgen crates. Harmless here, consistent to keep.
if [ -L "${CARGO_HOME:-$HOME/.cargo}" ]; then
  CARGO_HOME="$(readlink -f "${CARGO_HOME:-$HOME/.cargo}")"
  export CARGO_HOME
fi

case "$(uname -s)-$(uname -m)" in
Linux-x86_64) cft_platform="linux64" ;;
Darwin-arm64) cft_platform="mac-arm64" ;;
Darwin-x86_64) cft_platform="mac-x64" ;;
*)
  echo "error: unsupported platform $(uname -s)-$(uname -m) for the wasm conformance leg" >&2
  exit 1
  ;;
esac

# --- 1. a browser -------------------------------------------------------------------

find_chrome() {
  if [ -n "${CHROME:-}" ]; then echo "$CHROME"; return; fi
  for candidate in \
    /usr/local/bin/chrome \
    "$(command -v google-chrome || true)" \
    "$(command -v google-chrome-stable || true)" \
    "$(command -v chromium || true)" \
    "$(command -v chromium-browser || true)" \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
    [ -n "$candidate" ] && [ -x "$candidate" ] && { echo "$candidate"; return; }
  done
}

chrome="$(find_chrome)"
if [ -z "$chrome" ]; then
  echo "error: no Chrome/Chromium found. Set CHROME=/path/to/chrome." >&2
  exit 1
fi

# "Google Chrome for Testing 151.0.7922.10" -> 151.0.7922.10
chrome_version="$("$chrome" --version 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+){2,3}' | head -1)"
chrome_major="${chrome_version%%.*}"
if [ -z "$chrome_major" ]; then
  echo "error: could not read a version out of '$chrome --version'." >&2
  exit 1
fi
echo "==> browser: $chrome ($chrome_version)"

# --- 2. a driver whose major version matches ----------------------------------------

driver_major() {
  "$1" --version 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+){2,3}' | head -1 | cut -d. -f1
}

driver=""
if [ -n "${CHROMEDRIVER:-}" ] && [ -x "${CHROMEDRIVER}" ] &&
  [ "$(driver_major "$CHROMEDRIVER")" = "$chrome_major" ]; then
  driver="$CHROMEDRIVER"
fi

cached="$work/chromedriver-$chrome_version/chromedriver"
if [ -z "$driver" ] && [ -x "$cached" ] && [ "$(driver_major "$cached")" = "$chrome_major" ]; then
  driver="$cached"
fi

if [ -z "$driver" ]; then
  # Chrome for Testing publishes a driver for every build, so ask for this exact version
  # and fall back to the newest build sharing the major.
  echo "==> fetching a chromedriver matching Chrome $chrome_major"
  base="https://storage.googleapis.com/chrome-for-testing-public"
  url="$base/$chrome_version/$cft_platform/chromedriver-$cft_platform.zip"
  if ! curl -sfIL --max-time 30 "$url" >/dev/null 2>&1; then
    echo "    no exact build; resolving the newest $chrome_major.* from Chrome for Testing"
    resolved="$(curl -sf --max-time 60 \
      https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json |
      python3 -c "
import json,sys
major = '$chrome_major'
platform = '$cft_platform'
best = None
for v in json.load(sys.stdin)['versions']:
    if v['version'].split('.')[0] != major:
        continue
    for d in v['downloads'].get('chromedriver', []):
        if d['platform'] == platform:
            best = d['url']
print(best or '')
")"
    [ -n "$resolved" ] || {
      echo "error: no chromedriver published for Chrome $chrome_major on $cft_platform." >&2
      exit 1
    }
    url="$resolved"
  fi
  tmp="$work/chromedriver-$chrome_version"
  rm -rf "$tmp" && mkdir -p "$tmp"
  curl -sL --max-time 180 -o "$tmp/d.zip" "$url"
  unzip -qo "$tmp/d.zip" -d "$tmp"
  found="$(find "$tmp" -name chromedriver -type f | head -1)"
  [ -n "$found" ] || { echo "error: the chromedriver archive had no binary in it." >&2; exit 1; }
  mv "$found" "$tmp/chromedriver" 2>/dev/null || true
  chmod +x "$tmp/chromedriver"
  rm -f "$tmp/d.zip"
  driver="$tmp/chromedriver"
fi
echo "==> driver:  $driver ($("$driver" --version 2>/dev/null | head -1))"

# --- 3. wasm-bindgen-test-runner, at exactly the locked wasm-bindgen version ---------

# Shared with apps/ui's core build, so the CLI and the crate cannot drift apart.
runner="$("$root/ci/wasm-bindgen.sh")/wasm-bindgen-test-runner"
echo "==> runner:  $("$runner" --version)"

# --- 4. capabilities, with the browser pinned ---------------------------------------

# `binary` is the whole point: without it the driver launches the first Chrome it finds
# on PATH, which on a machine with more than one is a coin flip and produces a
# "session not created: only supports Chrome version N" that never reaches the console.
cat >"$work/webdriver.json" <<JSON
{
  "goog:chromeOptions": {
    "binary": "$chrome",
    "args": [
      "--headless=new",
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu"
    ]
  }
}
JSON

# --- 5. run --------------------------------------------------------------------------

port="${WASM_CONFORMANCE_PORT:-9515}"
"$driver" --port="$port" >"$work/chromedriver.log" 2>&1 &
driver_pid=$!
# shellcheck disable=SC2317
cleanup() { kill "$driver_pid" 2>/dev/null || true; wait "$driver_pid" 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 40); do
  if curl -sf --max-time 2 "http://127.0.0.1:$port/status" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
curl -sf --max-time 2 "http://127.0.0.1:$port/status" >/dev/null 2>&1 || {
  echo "error: chromedriver did not come up. Log:" >&2
  cat "$work/chromedriver.log" >&2
  exit 1
}

echo "==> running the conformance flow in headless Chrome"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="$runner"
export CHROMEDRIVER_REMOTE="http://127.0.0.1:$port"
export WASM_BINDGEN_TEST_WEBDRIVER_JSON="$work/webdriver.json"
export WASM_BINDGEN_TEST_TIMEOUT="${WASM_BINDGEN_TEST_TIMEOUT:-180}"

rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

# Tee the harness output so the failure path can tell an assertion apart from a broken
# browser. Dumping the driver log for a plain assertion failure buries the real message
# under irrelevant `bind() failed` noise, which is what it did the first time.
if cargo test --manifest-path "$root/Cargo.toml" -p misty-ffi \
  --target wasm32-unknown-unknown --test web 2>&1 | tee "$work/harness.log"; then
  exit 0
fi

echo >&2
if grep -q "test result:" "$work/harness.log"; then
  # The harness ran, so the browser and driver are fine and the assertion above is the
  # whole story. Saying so beats printing a driver log that has nothing to do with it.
  echo "the wasm leg ran and an assertion failed; the message above is the cause." >&2
  echo "driver log, if you want it: $work/chromedriver.log" >&2
else
  echo "the wasm leg never got as far as running tests, which points at the browser or" >&2
  echo "the driver rather than the code. The runner only reports a bare HTTP status, so" >&2
  echo "the actual cause is in here:" >&2
  tail -30 "$work/chromedriver.log" >&2
fi
exit 1
