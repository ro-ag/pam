# PAM build-only patch: aegis 0.9.15

Upstream revision: `44f769fcc55c65f71c94e44aa78535a3fa4782e6`.
Crates.io archive SHA-256: `58541132f980da31e9aa99f7bdee69bc84bf1e168b9b91ef2dbe8abb7b4ce5dd`.
Upstream licenses and source are retained. Local registry markers and lockfile are omitted.

PAM requires Turso's `pure-rust-crypto` feature. Upstream's build script
returns before compiling C with this feature, but still selects and compiles
the `cc` build dependency. Remove that dependency in both manifests and replace
the build script with a fail-closed check requiring `pure-rust`. Preserve the
mutually exclusive WebAssembly feature check. Cryptographic runtime sources
are unchanged; native backend builds are deliberately unsupported by this patch.

Remove this patch when upstream provides a dependency-free pure Rust build path.
