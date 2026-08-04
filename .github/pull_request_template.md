<!-- Prefix the title with an area: otp: crypto: vault: sync: ui: docs: ci: deps: -->

## What this changes

<!-- One paragraph. What was true before, what is true after. -->

## Why

<!-- Link the issue, or explain the motivation if there isn't one. -->

## Security relevance

<!-- Delete this section only if the change genuinely cannot affect security.
     Otherwise: what could an attacker do before that they cannot after, or what
     new surface does this add? If it touches docs/SPEC.md §2 constructions, say
     which one and confirm the spec is updated in this same PR. -->

## Checklist

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo deny check`
- [ ] Core crates still build for `wasm32-unknown-unknown`
- [ ] No `unsafe`, and no `unwrap`/`expect`/`panic!` reachable from parsed input or FFI
- [ ] New parsing paths have a hostile-input test and a fuzz target
- [ ] Format changes update the frozen golden-byte vectors and include a migration
- [ ] `docs/SPEC.md` updated if behaviour it specifies changed
- [ ] Commits signed off (`git commit -s`)
- [ ] No new dependency, or the commit message justifies it
- [ ] No telemetry, analytics, or crash reporting added
