#!/usr/bin/env python3
"""Guard the permissive licensing of `totem-otp`.

`crates/totem-otp` ships under `MIT OR Apache-2.0` so other authenticators can
adopt it (see docs/LICENSING.md). Permissive-to-copyleft compatibility is one-way:
the moment that crate gains a copyleft dependency, its own permissive terms become
undistributable and we would not notice until someone tried to use it.

This checks two things:
  1. `totem-otp` declares exactly `MIT OR Apache-2.0`.
  2. Nothing in its normal/build dependency closure is copyleft or unlicensed.

Dev-dependencies are excluded: they are not linked into anything we distribute.
"""

from __future__ import annotations

import json
import subprocess
import sys

CRATE = "totem-otp"
EXPECTED_LICENSE = "MIT OR Apache-2.0"

PERMISSIVE = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "ISC",
    "MIT",
    "MIT-0",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Unlicense",
    "Zlib",
}

# SPDX exceptions that do not add copyleft obligations.
BENIGN_EXCEPTIONS = {"LLVM-exception", "no-exception"}


def branch_is_permissive(branch: str) -> bool:
    """True if every AND-ed term in one OR-branch is permissive."""
    for term in branch.split(" AND "):
        term = term.strip().strip("()").strip()
        if " WITH " in term:
            lic, _, exc = term.partition(" WITH ")
            if exc.strip() not in BENIGN_EXCEPTIONS:
                return False
            term = lic.strip()
        if term not in PERMISSIVE:
            return False
    return True


def is_permissive(expr: str) -> bool:
    """True if at least one OR-branch of an SPDX expression is fully permissive."""
    normalised = expr.replace("/", " OR ")
    return any(branch_is_permissive(b) for b in normalised.split(" OR "))


def main() -> int:
    try:
        raw = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--all-features"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        print(f"cargo metadata failed:\n{exc.stderr}", file=sys.stderr)
        return 2

    meta = json.loads(raw)
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}

    root = next((pid for pid, p in packages.items() if p["name"] == CRATE), None)
    if root is None:
        print(f"note: {CRATE} is not in the workspace yet; nothing to check")
        return 0

    declared = packages[root].get("license")
    if declared != EXPECTED_LICENSE:
        print(
            f"FAIL: {CRATE} declares license {declared!r}, expected {EXPECTED_LICENSE!r}.\n"
            f"      It must not inherit the workspace AGPL license. See docs/LICENSING.md.",
            file=sys.stderr,
        )
        return 1

    # Walk the normal/build closure. Dev-dependencies are not distributed.
    seen: set[str] = set()
    stack = [root]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes.get(pid, {}).get("deps", []):
            kinds = {k.get("kind") for k in dep.get("dep_kinds", [])}
            if kinds and kinds <= {"dev"}:
                continue
            stack.append(dep["pkg"])

    problems = []
    for pid in sorted(seen - {root}):
        pkg = packages[pid]
        expr = pkg.get("license")
        if not expr:
            problems.append((pkg["name"], pkg["version"], "no license field"))
        elif not is_permissive(expr):
            problems.append((pkg["name"], pkg["version"], expr))

    if problems:
        print(
            f"FAIL: {CRATE} is {EXPECTED_LICENSE} but depends on crates that are not"
            " permissively licensed:",
            file=sys.stderr,
        )
        for name, version, why in problems:
            print(f"       {name} {version}: {why}", file=sys.stderr)
        print(
            "\n       Permissive-to-copyleft compatibility runs one way. Either drop the"
            "\n       dependency, or relicense totem-otp and update docs/LICENSING.md,"
            "\n       REUSE.toml, and the crate manifest together.",
            file=sys.stderr,
        )
        return 1

    print(f"ok: {CRATE} is {EXPECTED_LICENSE}; {len(seen) - 1} dependencies all permissive")
    return 0


if __name__ == "__main__":
    sys.exit(main())
