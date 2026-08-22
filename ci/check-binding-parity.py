#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Misty Authors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every facade method reaches every binding, and the two bindings agree (SPEC §11.7).

`crates/misty` is the one API; `crates/misty-ffi` lowers it to two toolchains. If a
facade method reaches only one of them, the four consumers no longer have the same API
and §11.8's shared conformance suite is quietly testing two different surfaces — which
is the P4 interop failure (§6.1.1) reappearing one layer up. Adding a facade method and
forgetting a binding is an easy, silent mistake; this makes it a build failure.

The check is deliberately source-level and dumb. It cannot execute the bindings — that
is what the §11.8.2 conformance legs are for — so it asserts the weaker property those
legs assume: that the surfaces line up at all.

Run: python3 ci/check-binding-parity.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FACADE = ROOT / "crates/misty/src/facade.rs"
WASM = ROOT / "crates/misty-ffi/src/web.rs"
UNIFFI = ROOT / "crates/misty-ffi/src/native.rs"

# Facade methods that deliberately do not cross. Keep this empty if at all possible, and
# state a reason next to anything added — an exemption here is a hole in "one API".
EXEMPT: dict[str, str] = {}


def methods(path: Path, pattern: str) -> set[str]:
    """Every method name matching `pattern` in `path`.

    The signatures wrap across lines when they take several arguments, so the pattern
    stops at the opening parenthesis rather than expecting `&self` on the same line —
    the bug that made an earlier hand-rolled version of this check silently under-report
    and declare a missing method on both sides.
    """
    source = path.read_text(encoding="utf-8")
    return set(re.findall(pattern, source, re.MULTILINE))


def main() -> int:
    facade = methods(FACADE, r"^    pub async fn ([a-z_0-9]+)\s*\(")
    wasm = methods(WASM, r"^    pub fn ([a-z_0-9]+)\s*\(")
    uniffi = methods(UNIFFI, r"^    pub async fn ([a-z_0-9]+)\s*\(")

    # The UniFFI constructor and the wasm constructor are not facade methods.
    wasm.discard("new")
    uniffi.discard("new")

    if not facade:
        print("error: parsed no methods out of the facade; the pattern has rotted.")
        return 1

    problems: list[str] = []

    for name in sorted(facade - wasm - EXEMPT.keys()):
        problems.append(f"  {name}: in the facade, missing from the wasm binding")
    for name in sorted(facade - uniffi - EXEMPT.keys()):
        problems.append(f"  {name}: in the facade, missing from the UniFFI binding")

    # A binding exposing something the facade does not have means logic has leaked into
    # `misty-ffi`, which §11.4.6 forbids: it holds no vault, sync, crypto or lock logic.
    for name in sorted(wasm - facade):
        problems.append(f"  {name}: exposed by the wasm binding but not on the facade")
    for name in sorted(uniffi - facade):
        problems.append(f"  {name}: exposed by the UniFFI binding but not on the facade")

    for name in sorted(wasm ^ uniffi):
        side = "wasm only" if name in wasm else "UniFFI only"
        problems.append(f"  {name}: the two bindings disagree ({side})")

    if problems:
        print("error: the facade and its bindings have drifted (SPEC §11.7):")
        print("\n".join(problems))
        if EXEMPT:
            print("\nexemptions currently allowed:")
            for name, why in sorted(EXEMPT.items()):
                print(f"  {name}: {why}")
        return 1

    print(
        f"ok: all {len(facade)} facade methods cross both bindings, "
        "and the two bindings expose the same surface"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
