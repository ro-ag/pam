# Native build dependency status

PAM's own dependency choices are pure Rust, with two named exceptions that do
compile C or Objective-C sources: the platform shims Tauri and objc2 on macOS
(the Objective-C exception helper; see "Unresolved GUI conflict" below), and
SQLite, compiled from the amalgamation bundled in `libsqlite3-sys` (owner
decision 2026-10-02, ptrack issue 38: the audit and authorization spine runs on
SQLite proper, through `rusqlite`). Calling the platform linker and binding to
installed OS frameworks are separate from compiling bundled native source.

## Toolchain required to build

A C compiler is required on every supported target, because `cc` compiles the
bundled SQLite during `cargo build`. Nothing is downloaded at build time and no
`bindgen` or `clang-sys` is involved: the bindings are pre-generated. This also
applies to `cargo install` from source.

| Target | Compiler | Notes |
| --- | --- | --- |
| macOS arm64 | Xcode command line tools (`xcode-select --install`) | Already needed for the Objective-C helper that Wry builds. |
| Windows amd64 (`x86_64-pc-windows-msvc`) | MSVC build tools (Visual Studio Build Tools, "Desktop development with C++") | Rust's MSVC target already needs them to link; `cc` uses the same `cl.exe`. |
| Windows arm64 (`aarch64-pc-windows-msvc`) | The same build tools with the ARM64 toolset (MSVC ARM64 build tools) | `cl.exe` for the ARM64 target; native on an ARM64 host. |

Linux and Intel Macs are not supported targets.

## Database (SQLite, bundled)

`pam_store` links SQLite statically through `rusqlite` with the `bundled`,
`cache` and `limits` features. The engine is the amalgamation shipped inside
`libsqlite3-sys`, never the system library, so every target runs the same
version. The committed `Cargo.lock` pins `rusqlite` 0.40.1 and
`libsqlite3-sys` 0.38.1, which bundles SQLite 3.53.2. Do not run `cargo update`
for these without reading which SQLite the new `libsqlite3-sys` bundles.

No compile flags are set (`LIBSQLITE3_FLAGS` is not used): every setting that
matters for security (double-quoted string literals off, foreign keys on, WAL,
`synchronous = FULL`, `secure_delete`, no `ATTACH`) is applied per connection at
open and read back by a test. See [the SQLite store design](specs/2026-10-02-sqlite-store.md).

Read back what a build contains, from a SQL session over a store opened by that
build or through the store's tests: `SELECT sqlite_version();` and
`PRAGMA compile_options;`. `sqlite_version()` equals the bundled version
(`crates/pam_store/src/open_test.rs` asserts it).

The earlier engine, Turso, and the same-version `vendor/turso_core` and
`vendor/aegis` patches that kept it free of C (task #142) were removed on
2026-10-02. The compiler-denied proof that used to cover `pam_store`
(`CC=/usr/bin/false cargo test -p pam_store`) no longer applies to it. Verify
that nothing of the old engine remains with `cargo tree -i turso`,
`cargo tree -i turso_core` and `cargo tree -i aegis`, which match no package.

## Transport (plan 49)

The public transport uses no third-party socket library. The `zeromq` crate, its
same-version `vendor/zeromq` patch (declared frame sizes checked before
allocation) and that patch's separate gate step were removed when both daemon
planes moved to PAM's own length-prefixed frame protocol on tokio stream
sockets; the frame-size checks now live in `pam_daemon::framed` and run in the
ordinary test suite. Eight packages left the lockfile with it: `zeromq`,
`win_uds` (the FFI crate that gave Windows its `AF_UNIX` sockets),
`asynchronous-codec`, `crossbeam-queue`, `futures`, `scc`, `sdd` and `saa`.
`cargo tree -i zeromq` and `cargo tree -i win_uds` match no package. No vendor
patches remain; the repository has no `vendor/` directory.

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

The product decision was made on 2026-09-12 (issue #16): the shims Tauri and
objc2 compile on macOS are an accepted exception, not PAM code. Do not describe
PAM's entire dependency graph as compiler-free: the platform shims and bundled
SQLite are compiled. Validation on one host is not evidence of all-platform
compliance.
