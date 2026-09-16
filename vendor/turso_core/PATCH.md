# PAM patch: Rust-only dense vector distances

Vendored from the crates.io `turso_core` 0.7.2 archive locked by PAM:
SHA-256 `7a833cc3bf8d4e6c101c504fa470f8ab4270c2202ff2591b61b2e373b4f20d9b`.
The archive records upstream revision
`046e9cbf67d22491e8ecc941ec2891b02a9f3cad`, directory `core`, in
`.cargo_vcs_info.json`. Source: https://github.com/tursodatabase/turso.
The MIT license is preserved in `LICENSE.md`, obtained from that exact
upstream revision (the published core archive omitted the license file).

## Narrow downstream changes

- Remove the target-specific SimSIMD dependency from the normalized
  `Cargo.toml`. The upstream `Cargo.toml.orig` is retained as provenance only;
  Cargo does not use it.
- Route dense f32/f64 cosine, negative dot product, and Euclidean distance
  directly through the existing Rust implementations on every target.
  Remove the native imports/wrappers. Public SQL names, vector encodings,
  dimension/type checks, and other vector operations remain unchanged.
- Correct dense cosine normalization to preserve the previous scalar backend:
  two zero norms yield zero; a zero dot product otherwise yields one;
  nonpositive or NaN distance intermediates yield zero. Compute the two
  normalization divisions separately so multiplying the norms cannot overflow.
  The f32 cosine accumulator remains f32 and normalization uses f64.
- Keep existing Rust dot/L2 arithmetic: f32 dot accumulates in f64, while
  f32 L2 accumulates squared differences in f32. Overflow can therefore still
  produce infinity in f32 L2. SIMD rounding/performance is not promised.
- Retarget existing vector fixtures to the Rust implementations and remove
  the six obsolete dense Rust-versus-SIMD comparison properties; retaining
  them would compare each implementation with itself. Upstream inline tests
  are retained in their original layout; PAM adds SQL regressions separately.

The registry installation marker `.cargo-ok` and the crate-local `Cargo.lock`
are omitted. PAM's workspace lockfile is authoritative. All other upstream
files are unchanged except the three vector distance source files and the
normalized manifest described above.

## Warning-clean under `-D warnings`

PAM's gate compiles the workspace with `RUSTFLAGS="-D warnings"`, and this
path dependency's warnings are replayed into it. Three sites are touched,
each marked with a `PAM:` comment and no behavioural change:

- `storage/btree.rs`: `#[allow(dead_code)]` on `move_to_root` and
  `indexbtree_move_to_unpacked`, which nothing in the selected build calls.
- `types.rs`: `ExternalAggState` compares its function-pointer fields
  through a hand-written `PartialEq` using `std::ptr::fn_addr_eq` (same
  semantics as the previous derive; the derive trips
  `unpredictable_function_pointer_comparisons`).
- `vector/operations/text.rs`: `vector_from_text` spells its elided return
  lifetime (`Vector<'_>`).

## Integration and validation

PAM selects this same-version crate using `[patch.crates-io]`; this directory
alone does not change resolution. No new dependency or compiler is introduced.
This patch removes SimSIMD's mandatory C compilation; it does not claim that
all other selected dependencies have been audited for compiler use.

Validate through PAM's SQL API and workspace gates after applying the patch.
Do not invoke this vendored crate's development/test dependency graph as a
no-C validation: upstream development dependencies include native components.
A clean selected-platform build with C/C++ compilation denied is the relevant
compliance gate. Regression coverage must include f32/f64 ordinary, zero,
empty, mismatched, large, and nonfinite vectors.
