# Native build dependency status

PAM requires Rust dependencies that do not compile C/C++ sources. Calling the
platform linker and binding to installed OS frameworks are separate from
compiling bundled native source. This requirement is not yet satisfied by the
whole application: the existing macOS GUI has a confirmed conflict.

## Database repair (task #142)

The pinned Turso 0.7.2 release selected SimSIMD unconditionally. The same-version
`vendor/turso_core` patch removes it and uses Rust dense vector distance
implementations. Zero-vector cosine semantics are retained; SIMD rounding and
performance equivalence are not promised. SQL regression tests cover ordinary,
empty, zero, mismatched, extreme, and nonfinite vectors.

The same-version `vendor/aegis` patch removes an unconditional `cc` build
dependency and requires `pure-rust`. Its cryptographic runtime sources are
unchanged. Both vendor directories retain licenses and record archive checksums
and upstream revisions in `PATCH.md`. These are maintenance obligations: review
and remove the patches when upstream offers suitable feature controls.

Verify the database separately from the GUI, from the repository root:

```sh
cargo tree -p pam_store --locked --edges normal,build
CC=/usr/bin/false CXX=/usr/bin/false CARGO_TARGET_DIR=target/no-c-store cargo test -p pam_store --locked
```

Use a fresh repository-local target directory when proving compiler independence;
a cached build alone is insufficient. Do not run Cargo concurrently with another
worktree. Inspect the dependency graph as well: compiler environment variables do
not intercept build scripts that invoke a compiler directly. The selected database
graph contains no `cc`, `cmake`, or `simsimd`. Turso SDK build metadata still selects
`bindgen`; its current build script does not invoke it for this host.

## Unresolved GUI conflict (issue #16)

Wry 0.55.1 unconditionally enables `objc2/exception` on Apple targets. The
`objc2-exception-helper` build script compiles `try_catch.m`. Real Wry call sites
catch exceptions during URL-scheme responses and IPC handler registration.
Disabling default features or custom protocol support does not remove all these
uses. Removing catches or substituting Rust exception stubs is not a safe,
behavior-preserving fix.

Additionally, Tauri's build chain selects `embed-resource`, whose library depends
on `cc` for Windows resource cross-compilation. This dependency can appear on a
macOS host even if its resource compilation path is not executed.

A GUI runtime replacement or an explicitly accepted exception requires a product
decision. Until that decision and its validation are complete, do not describe
PAM's entire dependency graph as compiler-free. Database validation on this
macOS host is not evidence of all-platform or whole-application compliance.
