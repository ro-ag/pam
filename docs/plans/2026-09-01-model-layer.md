# Model Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the daemon a pure-Rust local inference engine (candle, GGUF, Qwen3 dense + MoE), assisted model download, a registry with an 18 GB engine floor, per-tier defaults, vendor-CLI curator detection, GUI-only administration with a full `/models` screen, and the CI workflow that lands it.

**Architecture:** New `pam_model` library crate (gguf / catalog / registry / download / tokenizer / runtime / curator) with no daemon knowledge; `pam_daemon` adds a `ModelService` task, a `model_job` table (migration 3), and `admin.models.*` / `admin.curator.*` ops through the existing `AdminService` intercept; `pam_gui` extends the bridge whitelist and the frontend gains a `/models` route and a Settings Models section. Spec: `docs/specs/2026-09-01-model-layer-design.md` — every requirement below traces to it.

**Tech Stack:** Rust 1.97 (edition 2024), tokio, candle-core/nn/transformers `=0.9.2`, tokenizers 0.22 (`fancy-regex` only), sha2, system curl, turso store, Tauri 2, React 19 + TanStack Query/Router, Tailwind v4 tokens, vitest.

## Global Constraints

- **C-free dependency tree**: no crate that runs `cc`/`cmake`. Verify every new dep with `cargo tree -e normal,build | grep -E '^(cc|cmake|onig_sys|esaxx-rs|.*-sys) '` — only `objc2`-family Rust bindings are allowed. candle pinned `=0.9.2`; tokenizers `default-features = false, features = ["fancy-regex"]`.
- **Engine floor**: `MODEL_FLOOR_BYTES = 18_000_000_000`. Models under it are `ModelClass::TestOnly`: loadable and promptable, refused as tier default with cause `below_floor`. The catalog never lists anything under the floor.
- **Administration GUI-only**: all model ops are `admin.*` ops; no new `pam` subcommand; `status` gains a read-only `model` block only.
- **Sibling tests**: unit tests in `module_test.rs`, declared `#[cfg(test)] mod module_test;` from the parent. Never `#[cfg(test)] mod tests` inline.
- **Frontend**: Tailwind v4 semantic tokens only (ESLint bans arbitrary values), CVA variants, existing `Panel`/`Badge`/`Button`/`FailureNote` furniture, `font-voice` serif for Pam sentences, `font-data` mono for facts, `font-display` for big numbers.
- **Gates**: `tools/check.sh` (fmt, clippy `-D warnings` pedantic, tests, eslint, tsc+vite build, vitest) must be green on the settled tree before every PR. No `#[allow]` sprinkles to silence clippy; fix the code.
- **Commits**: conventional prefix, `#<task-id>` in the subject (ptrack link), **no AI attribution trailers of any kind**. PR title carries the `#<task-id>` too.
- **Branch per task** (`feat/<slug>`), PR to `main`, squash merge, branch deleted.
- **Refusal legibility**: every failure = `{ cause, detail, recovery }`; recovery names the GUI screen or the concrete fix.

---

## Wave map (parallelism)

| Wave | Tasks (ptrack ids) | Disjoint file sets |
| --- | --- | --- |
| 1 | #32 crate core · #38 CI | `crates/pam_model/**` + `Cargo.toml` · `.github/workflows/ci.yml` |
| 2 | #33 download · #34 runtime+tokenizer · #35 curator | `download*.rs` · `runtime*.rs`, `tokenizer*.rs` · `curator*.rs` (each also adds its `Cargo.toml` deps — rebase on conflict, only the deps block touches) |
| 3 | #36 daemon service + store + admin ops | `crates/pam_store/**`, `crates/pam_daemon/**`, `crates/pam/src/render.rs` |
| 4 | #37 GUI bridge + frontend | `crates/pam_gui/**`, `frontend/**` |
| 5 | #16 integrate and verify (owner-side checkpoint, run by the coordinator) | — |

Task #32 pre-declares the module files that wave 2 fills (empty modules with a doc comment) so `lib.rs` never conflicts.

---

### Task 1 (ptrack #32): `pam_model` crate core — gguf, catalog, registry

**Files:**
- Modify: `Cargo.toml` (workspace members + `[workspace.dependencies]`: `pam_model = { path = "crates/pam_model" }`, `sha2 = "0.10"`, `hex = "0.4"`, candle trio pinned `=0.9.2` with `default-features = false`, tokenizers `0.22` with `default-features = false, features = ["fancy-regex"]`, `sysinfo` gains the `system` feature it already has — no change)
- Create: `crates/pam_model/Cargo.toml`, `crates/pam_model/src/lib.rs`, `gguf.rs`, `gguf_test.rs`, `catalog.rs`, `catalog_test.rs`, `registry.rs`, `registry_test.rs`, `error.rs`
- Create (stubs, one doc comment each, filled by wave 2): `download.rs`, `tokenizer.rs`, `runtime.rs`, `curator.rs`
- Create: `crates/pam_model/testdata/README.md` (no binary fixtures are committed; tests synthesize GGUF headers in memory)

**Interfaces (Produces):**

```rust
// lib.rs
pub mod catalog; pub mod curator; pub mod download; pub mod error; pub mod gguf;
pub mod registry; pub mod runtime; pub mod tokenizer;
pub use catalog::{CATALOG, Preset, find_preset};
pub use gguf::{GgufError, GgufInfo, read_info};
pub use registry::{MODEL_FLOOR_BYTES, ModelClass, ModelEntry, Registry, RegistryError, VerifyOutcome, classify, default_models_dir};

// gguf.rs — bounded header parser (pam-old hardening ported)
pub const GGUF_MAX_HEADER_BYTES: u64 = 256 * 1024 * 1024;
pub const GGUF_MAX_STRING_BYTES: u64 = 256 * 1024 * 1024;
pub const GGUF_MAX_TENSOR_NAME_BYTES: u64 = 127;
pub const GGUF_MAX_TENSORS: u64 = 1 << 20;
pub const GGUF_MAX_METADATA_KV: u64 = 1 << 16;
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GgufInfo {
    pub architecture: String,        // general.architecture, e.g. "qwen3moe"
    pub name: Option<String>,        // general.name
    pub quant_label: String,         // from general.file_type (LLAMA_FTYPE table), "unknown(<n>)" fallback
    pub parameter_count: u64,        // sum over tensors of the product of dims
    pub context_length: Option<u64>, // <arch>.context_length
    pub expert_count: Option<u32>,   // <arch>.expert_count
    pub tensor_count: u64,
    pub version: u32,
}
#[derive(Debug, thiserror::Error)] pub enum GgufError { Io(std::io::Error), BadMagic, UnsupportedVersion(u32), TooLarge { what: &'static str, value: u64, limit: u64 }, Malformed(String), MissingMetadata(&'static str) }
pub fn read_info(path: &std::path::Path) -> Result<GgufInfo, GgufError>;           // blocking
pub fn parse_info<R: std::io::Read + std::io::Seek>(reader: R) -> Result<GgufInfo, GgufError>;
pub fn quant_label_for(file_type: u32) -> String;

// catalog.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Preset {
    pub id: &'static str, pub label: &'static str, pub vendor: &'static str, pub file_name: &'static str,
    pub url: &'static str, pub size_bytes: u64, pub sha256: &'static str, pub license_id: &'static str,
    pub license_url: &'static str, pub quant: &'static str, pub params_label: &'static str,
    pub min_host_ram_bytes: u64,
}
pub const CATALOG: &[Preset]; // the four Qwen3-Coder-30B-A3B entries from the spec, exact bytes + sha256
pub fn find_preset(id: &str) -> Option<&'static Preset>;
impl Preset { pub fn fits_host(&self, total_ram_bytes: u64) -> bool; pub fn model_id(&self) -> String /* "<vendor>/<file stem>" */ }

// registry.rs
pub const MODEL_FLOOR_BYTES: u64 = 18_000_000_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)] #[serde(rename_all = "snake_case")]
pub enum ModelClass { Engine, TestOnly }
pub fn classify(size_bytes: u64) -> ModelClass;
pub fn default_models_dir() -> Option<std::path::PathBuf>; // $HOME/llm
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ModelEntry {
    pub id: String,            // "<vendor>/<file stem>"
    pub vendor: String, pub file_name: String, pub path: std::path::PathBuf, pub size_bytes: u64,
    pub info: Option<GgufInfo>, pub info_error: Option<String>,
    pub class: ModelClass,
    pub verified: Option<VerifiedRecord>, // from the `.<file>.pam-model.verified` sidecar
    pub catalog_id: Option<&'static str>, // preset whose file_name matches
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedRecord { pub sha256: String, pub size_bytes: u64, pub verified_ts: i64, pub matches_catalog: Option<bool> }
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VerifyOutcome { pub sha256: String, pub size_bytes: u64, pub matches_catalog: Option<bool> }
#[derive(Debug, thiserror::Error)] pub enum RegistryError { Io(std::io::Error), NotFound(String), OutsideModelsDir(std::path::PathBuf), NotADirectory(std::path::PathBuf), Gguf(#[from] GgufError) }
#[derive(Debug, Clone)] pub struct Registry { dir: std::path::PathBuf }
impl Registry {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Self;
    pub fn dir(&self) -> &std::path::Path;
    pub fn dest_for(&self, vendor: &str, file_name: &str) -> std::path::PathBuf;   // dir/vendor/file_name
    pub fn scan(&self) -> Result<Vec<ModelEntry>, RegistryError>;                 // blocking; two levels; sorted by id
    pub fn find(&self, id: &str) -> Result<Option<ModelEntry>, RegistryError>;
    pub fn verify(&self, entry: &ModelEntry) -> Result<VerifyOutcome, RegistryError>; // blocking sha256 (1 MiB chunks) + sidecar write
    pub fn record_verified(&self, path: &std::path::Path, record: &VerifiedRecord) -> Result<(), RegistryError>; // download completion uses this
    pub fn delete(&self, entry: &ModelEntry) -> Result<(), RegistryError>;        // refuses outside dir; removes file + verified sidecar
}
pub fn sha256_file(path: &std::path::Path) -> std::io::Result<(String, u64)>;    // hex digest + bytes read
```

- [ ] Write `gguf_test.rs` first: helper `fn synth_gguf(version: u32, arch: &str, file_type: u32, tensors: &[(&str, &[u64], u32 /*ggml dtype*/)], extra_kv: &[(&str, GgufValue)]) -> Vec<u8>` building a real little-endian GGUF header; tests: parses v3 qwen3moe with `expert_count` and `context_length`; parses v2; `BadMagic`; `UnsupportedVersion(1)`; `TooLarge` when tensor count > `GGUF_MAX_TENSORS`; `Malformed` when a tensor name exceeds 127 bytes; `Malformed` on overlapping tensor offsets; `quant_label_for(15) == "Q4_K_M"`, `quant_label_for(999) == "unknown(999)"`; `parameter_count` equals the summed dim products.
- [ ] Implement `gguf.rs` (types: u8 0, i8 1, u16 2, i16 3, u32 4, i32 5, f32 6, bool 7, string 8, array 9, u64 10, i64 11, f64 12; header = magic, version u32, tensor_count u64, kv_count u64, kv pairs, tensor infos {name, n_dims u32, dims [u64], dtype u32, offset u64}; alignment from `general.alignment` default 32, power of two ≤ 4096; validate offsets are aligned, strictly increasing, non-overlapping using ggml type sizes for the dtypes candle supports — F32 4, F16 2, BF16 2, Q4_0 18/32, Q4_1 20/32, Q5_0 22/32, Q5_1 24/32, Q8_0 34/32, Q8_1 36/32, Q2_K 84/256, Q3_K 110/256, Q4_K 144/256, Q5_K 176/256, Q6_K 210/256, Q8_K 292/256; unknown dtype → `Malformed`). Never read past the header.
- [ ] Write `catalog_test.rs`: every preset ≥ `MODEL_FLOOR_BYTES`; ids unique; sha256 is 64 lowercase hex; `find_preset` hit/miss; `fits_host(32 GB) == true` for Q4_K_M and false for Q8_0; `model_id()` = `"qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M"`.
- [ ] Implement `catalog.rs` with the four spec entries (vendor `qwen`, url `https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/resolve/main/<file>`, license `apache-2.0` → `https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/blob/main/LICENSE`, params_label `30B-A3B (MoE)`; RAM 32/32/48/64 GB as `u64` decimal GB).
- [ ] Write `registry_test.rs` on `tempfile::tempdir()`: `scan` on an empty dir → empty; a synthesized tiny GGUF at `qwen/tiny.gguf` → one entry, `class == TestOnly`, `info.is_some()`; a garbage `.gguf` → entry with `info_error` and no panic; `classify(MODEL_FLOOR_BYTES) == Engine`, `classify(MODEL_FLOOR_BYTES - 1) == TestOnly`; `verify` writes the sidecar and a rescan shows `verified`; `verify` on a file whose name matches a preset reports `matches_catalog == Some(false)` (digest differs); `delete` refuses a path outside the dir (`OutsideModelsDir`) and removes file + sidecar inside; `dest_for`.
- [ ] Implement `registry.rs` (sidecar name `.<file_name>.pam-model.verified`, JSON `VerifiedRecord`, atomic write via temp + rename).
- [ ] `error.rs`: nothing beyond re-exports if the per-module errors suffice — delete the file if empty rather than leaving a stub.
- [ ] Stubs: `download.rs`, `tokenizer.rs`, `runtime.rs`, `curator.rs` each `//! <one line naming the wave-2 task that fills it>` and nothing else (they must compile empty).
- [ ] `crates/pam_model/Cargo.toml`: deps `serde`, `serde_json`, `thiserror`, `sha2`, `hex`, `tokio` (workspace, plus `process`, `io-util`, `fs`), `tokenizers`, candle trio; `[target.'cfg(target_os = "macos")'.dependencies]` re-declares the candle trio with `features = ["metal"]`; `[lints] workspace = true`; dev-deps `tempfile`.
- [ ] Prove C-free: `cargo tree -p pam_model -e normal,build | grep -E '^(cc|cmake|onig_sys|esaxx-rs) '` prints nothing; paste the command and empty output in the PR body.
- [ ] Gate: `tools/check.sh`. Commit `feat(model): pam_model crate core — gguf parser, catalog, registry (#32)`. PR title `feat(model): pam_model crate core (#32)`.

---

### Task 2 (ptrack #38): CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `CLAUDE.md` "Working agreements" bullet "CI stays cheap" → add one sentence: "CI exists since plan #3: `ci.yml` runs the Linux gate on PRs to `main`, pushes to `main`, and tags, with the other four targets gated behind it."

**Produces:** the check names the landing rule waits on: `gate (ubuntu-24.04)`, `targets (ubuntu-24.04-arm)`, `targets (macos-15)`, `targets (windows-2025)`, `targets (windows-11-arm)`.

- [ ] Write the workflow:

```yaml
name: CI
on:
  pull_request:
    branches: [main]
    paths-ignore: ["docs/**", "**/*.md"]
  push:
    branches: [main]
    tags: ["v*"]
    paths-ignore: ["docs/**", "**/*.md"]
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
env:
  CARGO_TERM_COLOR: always
  CARGO_INCREMENTAL: "0"
jobs:
  gate:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Tauri system deps
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev patchelf
      - uses: dtolnay/rust-toolchain@stable   # rust-toolchain.toml pins 1.97.0; this action honors it
        with: { components: "rustfmt, clippy" }
      - uses: Swatinem/rust-cache@v2
      - uses: actions/setup-node@v4
        with: { node-version: 22, cache: npm, cache-dependency-path: frontend/package-lock.json }
      - run: npm --prefix frontend ci
      - run: tools/check.sh
  targets:
    needs: gate
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-24.04-arm, macos-15, windows-2025, windows-11-arm]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - if: startsWith(matrix.os, 'ubuntu')
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --workspace
      - if: matrix.os == 'macos-15'
        uses: actions/setup-node@v4
        with: { node-version: 22, cache: npm, cache-dependency-path: frontend/package-lock.json }
      - if: matrix.os == 'macos-15'
        run: npm --prefix frontend ci && npm --prefix frontend run build && cargo build --release -p pam --features gui-embed
```

- [ ] Verify `tools/check.sh` runs unchanged on Linux (it uses `npm --prefix`, bash; no macOS-only calls). If `cargo test` needs the `PAM_BASE_DIR` short path on runners, the testkit already uses `short_tempdir()`; do not widen timeouts.
- [ ] Open the PR; this PR is itself the first CI run. Fix whatever the five runners report by root cause (missing apt package, a Windows path assumption in a test) — never by skipping a target. Record each fix in the PR body. Commit `ci: linux gate with arm64/macos/windows targets (#38)`.

---

### Task 3 (ptrack #33): download via curl

**Files:**
- Modify: `crates/pam_model/src/download.rs` (replace stub), `crates/pam_model/Cargo.toml` (no new deps expected; `tokio` `process` feature is already declared by Task 1)
- Create: `crates/pam_model/src/download_test.rs`, `crates/pam_model/src/download_server_test.rs` (the range-serving test server — a test-only module declared from `download_test.rs`)
- Modify: `crates/pam_model/src/lib.rs` (`#[cfg(test)] mod download_test;` and re-exports)

**Interfaces:**
- Consumes: `registry::{Registry, VerifiedRecord, sha256_file}`.
- Produces:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadRequest {
    pub url: String, pub dest: std::path::PathBuf,
    pub expected_size: Option<u64>, pub expected_sha256: Option<String>, pub license_id: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct DownloadProgress { pub bytes: u64, pub total: Option<u64> }
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)] #[serde(tag = "state", rename_all = "snake_case")]
pub enum DownloadState {
    Running(DownloadProgress),
    Done { sha256: String, size_bytes: u64 },
    Failed { cause: String, detail: String },   // causes: curl_missing, checkpoint_conflict, download_failed, digest_mismatch, size_mismatch, already_exists, locked, io
    Cancelled,
}
#[derive(Debug, thiserror::Error)]
pub enum DownloadError { #[error("curl not found on PATH")] CurlMissing, #[error("{0}")] AlreadyExists(std::path::PathBuf), #[error("{0}")] Locked(std::path::PathBuf), #[error("checkpoint conflict: {0}")] CheckpointConflict(String), #[error(transparent)] Io(#[from] std::io::Error) }
#[derive(Debug, Clone)] pub struct DownloadHandle { /* watch::Receiver<DownloadState> + cancel watch::Sender + JoinHandle in Arc */ }
impl DownloadHandle {
    pub fn state(&self) -> DownloadState;
    pub fn cancel(&self);                           // kills curl; part stays
    pub async fn wait(&self) -> DownloadState;      // terminal state
}
pub fn curl_path() -> Result<std::path::PathBuf, DownloadError>;   // PATH lookup, cached with OnceLock
pub fn start(request: DownloadRequest) -> Result<DownloadHandle, DownloadError>; // needs a tokio runtime; spawns the job task
pub fn sidecar_paths(dest: &std::path::Path) -> SidecarPaths;      // .{name}.pam-model.{part,json,lock}
#[derive(Debug, Clone, PartialEq, Eq)] pub struct SidecarPaths { pub part: PathBuf, pub checkpoint: PathBuf, pub lock: PathBuf }
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint { pub schema_version: u32, pub canonical_source: String, pub expected_digest: String /* "sha256:<hex>" or "sha256:unknown" */, pub expected_size_bytes: u64 /* 0 when unknown */, pub license_digest: String, pub etag: Option<String> }
pub fn curl_recovery_line() -> &'static str;  // per-OS install hint (brew/apt/winget)
```

- [ ] Write `download_server_test.rs`: `pub async fn serve(body: Vec<u8>, etag: &str) -> (SocketAddr, JoinHandle<()>)` — tokio `TcpListener`, minimal HTTP/1.1: `HEAD` and `GET` on any path, honors `Range: bytes=N-` with `206` + `Content-Range`, sends `ETag`, `Content-Length`, closes after one response; also a `fail_after: Option<usize>` variant that drops the socket after N bytes to force a resume.
- [ ] Write `download_test.rs` against real `curl` (skip with a clear `eprintln!` + `return` only when `curl_path()` errs — every CI runner has curl, so this never triggers there): full transfer → `Done` with matching sha256 and `dest` present, sidecars gone; server drops mid-transfer → `Failed{download_failed}` with the `part` kept and the checkpoint present → second `start` with the same request resumes (server asserts the `Range` header) → `Done`; wrong `expected_sha256` → `Failed{digest_mismatch}`, `part` removed, `dest` absent; `cancel()` during transfer → `Cancelled`, `part` kept; checkpoint whose `canonical_source` differs → `Err(CheckpointConflict)`; existing `dest` → `Err(AlreadyExists)`; concurrent `start` on the same dest → `Err(Locked)`; `sidecar_paths` naming matches pam-old (`.Qwen3.gguf.pam-model.part`).
- [ ] Implement `download.rs`: lock file created `create_new` + `try_lock` (std `File::try_lock`, stable since 1.89) holding a fresh ULID-free random string is unnecessary — write the pid; checkpoint written atomically (temp + rename); curl args `--fail --location --silent --show-error --continue-at - --output <part> --etag-save <checkpoint dir tmp> --retry 0 <url>`; progress task polls `part` metadata every 500 ms into the watch; after exit: size check, sha256 (`registry::sha256_file` in `spawn_blocking`), `std::fs::rename(part, dest)` refusing an existing dest, `Registry::record_verified` when a digest was expected and matched (write via the `dest` parent as models dir), sidecars removed. Bound curl stderr to 4 KiB for `detail`.
- [ ] Gate + commit `feat(model): resumable GGUF download through system curl (#33)`.

---

### Task 4 (ptrack #34): candle runtime + tokenizer from GGUF

**Files:**
- Modify: `crates/pam_model/src/runtime.rs`, `tokenizer.rs` (replace stubs), `lib.rs` (test mods + re-exports)
- Create: `runtime_test.rs`, `tokenizer_test.rs`, `crates/pam_model/tests/bench.rs` (opt-in `PAM_BENCH_MODEL`)

**Interfaces:**
- Consumes: `registry::ModelEntry`, `gguf::GgufInfo`.
- Produces:

```rust
// tokenizer.rs — port of candle 0.11 quantized/tokenizer.rs (Apache-2.0, attribution in module docs)
pub struct GgufTokenizer { pub inner: tokenizers::Tokenizer, pub bos_id: Option<u32>, pub eos_id: u32, pub add_bos: bool }
pub fn from_gguf(content: &candle_core::quantized::gguf_file::Content) -> Result<GgufTokenizer, TokenizerError>;
pub fn chatml(system: Option<&str>, user: &str) -> String; // "<|im_start|>system\n…<|im_end|>\n<|im_start|>user\n…<|im_end|>\n<|im_start|>assistant\n"
#[derive(Debug, thiserror::Error)] pub enum TokenizerError { MissingKey(&'static str), UnsupportedModel(String), Build(String) }

// runtime.rs
pub const CONTEXT_TOKENS: usize = 8192;
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GenerateRequest { pub system: Option<String>, pub prompt: String, pub max_tokens: usize, pub temperature: f64, pub stop: Vec<String> }
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct GenerateResult { pub text: String, pub prompt_tokens: usize, pub completion_tokens: usize, pub prompt_ms: u64, pub decode_ms: u64, pub tokens_per_sec: f64 }
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct LoadedModel { pub id: String, pub quant: String, pub architecture: String, pub context_length: usize, pub weight_bytes: u64, pub device: String /* "metal" | "cpu" */, pub loaded_at: i64, pub last_used_at: i64, pub last_tokens_per_sec: Option<f64> }
#[derive(Debug, Clone, PartialEq, serde::Serialize)] #[serde(tag = "state", rename_all = "snake_case")]
pub enum RuntimeState { Idle, Loading { phase: String, id: String }, Loaded(LoadedModel) }
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RuntimeSnapshot { pub state: RuntimeState, pub busy: bool }
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    #[error("no model is loaded")] NoModelLoaded,
    #[error("architecture {0:?} is not supported (qwen3, qwen3moe)")] UnsupportedArchitecture(String),
    #[error("load failed: {0}")] LoadFailed(String),
    #[error("prompt is {tokens} tokens; the context allows {limit}")] PromptTooLong { tokens: usize, limit: usize },
    #[error("another generation is running")] Busy,
    #[error("generation cancelled")] Cancelled,
    #[error("generation failed: {0}")] GenerationFailed(String),
    #[error("the model thread crashed; runtime reset to idle")] Crashed,
}
impl RuntimeError { pub fn cause(&self) -> &'static str /* no_model_loaded, unsupported_architecture, load_failed, prompt_too_long, busy, cancelled, generation_failed, runtime_crashed */ }
#[derive(Debug, Clone)] pub struct Runtime { /* Arc<inner>: std::sync::mpsc::SyncSender<Command>, Mutex<RuntimeSnapshot> mirror */ }
impl Runtime {
    pub fn new() -> Self;                                   // spawns the "pam-model" thread lazily on first load
    pub async fn load(&self, entry: &ModelEntry) -> Result<LoadedModel, RuntimeError>;
    pub async fn unload(&self) -> Result<(), RuntimeError>;  // Ok even when idle
    pub async fn generate(&self, request: GenerateRequest, cancel: tokio::sync::watch::Receiver<bool>) -> Result<GenerateResult, RuntimeError>;
    pub fn snapshot(&self) -> RuntimeSnapshot;               // sync, from the mirror
}
```

- [ ] `tokenizer_test.rs`: build a `gguf_file::Content` in memory (write a tiny GGUF with `tokenizer.ggml.model = "gpt2"`, ~40 byte-level tokens incl. `<|im_start|>`, `<|im_end|>`, `<|endoftext|>` as control tokens, a handful of merges) and assert `from_gguf` round-trips `"hi there"` encode→decode, `eos_id` picks `<|im_end|>` when `tokenizer.ggml.eos_token_id` says so, `chatml` output is byte-exact for a fixed input, `UnsupportedModel` for `tokenizer.ggml.model = "llama"`.
- [ ] Implement `tokenizer.rs`: BPE from `tokenizer.ggml.tokens` + `merges`, ByteLevel pre-tokenizer with the Qwen split regex (`(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+`), token types 3 (control) and 4 (user-defined) registered as special added tokens, ByteLevel decoder.
- [ ] `runtime_test.rs` (no weights): `snapshot()` starts `Idle`; `generate` on idle → `NoModelLoaded`; `load` on an entry whose `info.architecture == "llama"` → `UnsupportedArchitecture` **before** touching candle; `load` on a path that is not a GGUF → `LoadFailed` and state returns to `Idle`; `unload` when idle is `Ok`; `RuntimeError::cause` table.
- [ ] Implement `runtime.rs`: thread owns `enum Model { Dense(candle_transformers::models::quantized_qwen3::ModelWeights), Moe(candle_transformers::models::quantized_qwen3_moe::GGUFQWenMoE) }` + `GgufTokenizer` + `Device`; commands over `std::sync::mpsc::sync_channel(0)` with `tokio::sync::oneshot` replies; `generate` = `chatml` → encode → `PromptTooLong` check → forward prompt in one call (`offset 0`) → loop `LogitsProcessor::sample` (`candle_transformers::generation::{LogitsProcessor, Sampling}`; temperature 0 → argmax) → stop on `eos_id`, any `stop` string, or `max_tokens`; check `cancel.has_changed()`/`*cancel.borrow()` each token; `clear_kv_cache` (dense) or reload-free reset for MoE (its `forward` takes the offset; a fresh generation starts at offset 0 after `clear_kv_cache` — if `GGUFQWenMoE` lacks one in 0.9.2, keep a per-generation reload of the KV by re-creating the model from the cached `Content` — measure and document which); timing via `Instant`; `tokens_per_sec = completion_tokens / decode_s`. Device: `Device::new_metal(0)` on macOS falling back to `Device::Cpu` with a `tracing::warn!`, `Device::Cpu` elsewhere. A panic on the thread is caught via `catch_unwind` around each command; on `RecvError` the async side reports `Crashed` and resets the mirror to `Idle`, re-spawning the thread on the next `load`.
- [ ] `tests/bench.rs`: when `PAM_BENCH_MODEL` is unset print `bench skipped: set PAM_BENCH_MODEL=<gguf>` and return; else scan the file's parent with `Registry`, `load`, `generate("Say hello in five words.", max_tokens 32)`, assert non-empty text, `completion_tokens > 0`, `tokens_per_sec > 0.0`, and print the result. Document the command in the module docs: `PAM_BENCH_MODEL=~/llm/qwen/Qwen3-0.6B-Q8_0.gguf cargo test -p pam_model --test bench -- --nocapture`.
- [ ] Gate + commit `feat(model): candle runtime with GGUF tokenizer for qwen3 dense and MoE (#34)`.

---

### Task 5 (ptrack #35): curator adapter

**Files:**
- Modify: `crates/pam_model/src/curator.rs` (replace stub), `lib.rs`
- Create: `curator_test.rs`

**Produces:**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)] #[serde(rename_all = "lowercase")]
pub enum AgentId { Claude, Codex, Copilot, Gemini }
impl AgentId { pub const ALL: [AgentId; 4]; pub fn as_str(self) -> &'static str; pub fn parse(s: &str) -> Option<Self>; pub fn binary_name(self) -> &'static str /* "claude"|"codex"|"copilot"|"gemini" (+ ".cmd"/".exe" probing on Windows) */ }
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AgentCli { pub id: AgentId, pub path: std::path::PathBuf, pub version: Option<String> }
pub fn detect(path_env: &std::ffi::OsStr, version_deadline: std::time::Duration) -> Vec<AgentCli>;   // blocking; call in spawn_blocking
pub const INVOKE_MAX_OUTPUT: usize = 256 * 1024;
#[derive(Debug, thiserror::Error)] pub enum CuratorError { #[error("{0} exited with {1}: {2}")] Failed(AgentId, i32, String), #[error("{0} produced no output within {1:?}")] Timeout(AgentId, std::time::Duration), #[error(transparent)] Io(#[from] std::io::Error) }
pub async fn invoke(cli: &AgentCli, prompt: &str, deadline: std::time::Duration) -> Result<String, CuratorError>;
pub fn invoke_args(id: AgentId, prompt: &str) -> (Vec<String>, bool /* prompt on stdin? */);
```

- [ ] Verify the real flags on this machine before coding them: run `claude --help`, `codex exec --help`, `copilot --help` and pick the non-interactive, tool-free, single-turn form; `gemini` is not installed here — use `--prompt` per its README and mark it `unverified` in the docs. Record the verified forms in the module docs.
- [ ] `curator_test.rs`: `detect` on a temp PATH containing a fake `claude` script (Unix: `#!/bin/sh\necho "1.2.3"`, mode 755; Windows: `claude.cmd` echoing) → one `AgentCli` with `version == Some("1.2.3")`; a non-executable file is skipped; an empty PATH → empty; `invoke` against a fake script that echoes stdin/args → returns the text; a script that sleeps past the deadline → `Timeout`; exit 3 → `Failed(…, 3, stderr)`; `invoke_args` table per agent; `AgentId::parse` round-trip.
- [ ] Implement with `tokio::process::Command`, `kill_on_drop(true)`, cwd = fresh `tempfile::tempdir()`, env `PATH` = the given `path_env`, stdout/stderr read to bounded buffers.
- [ ] Gate + commit `feat(model): vendor agent CLI detection and non-interactive invoke (#35)`.

---

### Task 6 (ptrack #36): daemon ModelService, store, admin ops, status

**Files:**
- Modify: `crates/pam_store/src/migrations.rs` (migration 3), `crates/pam_store/src/store.rs` (+ `store_test.rs`), `crates/pam_store/src/lib.rs` (re-exports)
- Create: `crates/pam_daemon/src/model_service.rs`, `model_service_test.rs`, `admin_models.rs`, `admin_models_test.rs`
- Modify: `crates/pam_daemon/src/lib.rs`, `admin.rs` (dispatch arm + field + op consts), `daemon.rs` (service construction, `DaemonHandle::models()`, `ExecContext` gains `models: Arc<ModelService>`), `executor.rs` (`status` body gains `model`), `crates/pam_daemon/Cargo.toml` (`pam_model`, `sysinfo`), `crates/pam_daemon/tests/daemon.rs` (integration), `crates/pam/src/render.rs` (+ test) for the extra status line
- Modify: `crates/pam_testkit/src/lib.rs` if a helper is needed to point `model.models_dir` at a temp dir (`TestDaemon::spawn_with` + setting write is enough — prefer no change)

**Interfaces:**
- Consumes: everything `pam_model` exports.
- Produces (store):

```rust
pub struct ModelJobRow { pub id: String, pub kind: String, pub model_id: String, pub source: Option<String>, pub state: String, pub bytes_done: i64, pub bytes_total: Option<i64>, pub detail: Option<String>, pub created_ts: i64, pub updated_ts: i64 }
impl Store {
    pub async fn insert_model_job(&self, id: &str, kind: &str, model_id: &str, source: Option<&str>, bytes_total: Option<i64>) -> Result<(), StoreError>;
    pub async fn update_model_job_progress(&self, id: &str, bytes_done: i64, bytes_total: Option<i64>) -> Result<(), StoreError>;
    pub async fn finish_model_job(&self, id: &str, state: &str /* done|failed|cancelled */, detail: Option<&str>) -> Result<(), StoreError>;
    pub async fn list_model_jobs(&self, limit: u64) -> Result<Vec<ModelJobRow>, StoreError>;   // newest first
    pub async fn fail_running_model_jobs(&self, detail: &str) -> Result<u64, StoreError>;      // boot recovery
}
```

- Produces (daemon):

```rust
// model_service.rs
pub const SETTING_MODELS_DIR: &str = "model.models_dir";
pub const SETTING_DEFAULT_LIGHT: &str = "model.default.light";
pub const SETTING_DEFAULT_HEAVY: &str = "model.default.heavy";
pub const SETTING_IDLE_UNLOAD_MIN: &str = "model.idle_unload_min";
pub const SETTING_CURATOR: &str = "curator.agent";
pub const DEFAULT_IDLE_UNLOAD_MIN: u64 = 10;
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)] #[serde(rename_all = "lowercase")] pub enum Tier { Light, Heavy }
#[derive(Debug, thiserror::Error)] pub enum ModelUnavailable { #[error("no default model for tier {0:?}")] NoDefault(Tier), #[error("default model {0} is not installed")] Missing(String), #[error(transparent)] Runtime(#[from] pam_model::runtime::RuntimeError), #[error(transparent)] Store(#[from] StoreError) }
pub struct ModelService { /* store, registry (RwLock, rebuilt on models_dir change), runtime, downloads: Mutex<HashMap<job_id, DownloadHandle>>, host_ram_bytes */ }
impl ModelService {
    pub async fn new(store: Arc<Store>) -> Result<Arc<Self>, StoreError>;  // reads settings, fails running jobs (daemon_restart), spawns idle-unload ticker
    pub fn registry(&self) -> Registry;
    pub fn runtime(&self) -> &Runtime;
    pub fn host_ram_bytes(&self) -> u64;
    pub async fn defaults(&self) -> Result<(Option<String>, Option<String>), StoreError>;
    pub async fn resolve(&self, tier: Tier) -> Result<ModelEntry, ModelUnavailable>;     // heavy→light fallback
    pub async fn generate(&self, tier: Tier, request: GenerateRequest) -> Result<GenerateResult, ModelUnavailable>; // lazy load + swap
    pub async fn ensure_loaded(&self, entry: &ModelEntry) -> Result<LoadedModel, RuntimeError>;
    pub async fn start_download(&self, req: DownloadRequest, model_id: &str) -> Result<String /* job id */, ModelServiceError>;
    pub async fn cancel_download(&self, job_id: &str) -> bool;
    pub async fn start_verify(&self, entry: ModelEntry) -> Result<String, ModelServiceError>;
    pub async fn status(&self) -> Result<serde_json::Value, StoreError>;   // the admin.models.status body
}
// admin_models.rs — op consts OP_MODELS_LIST … OP_CURATOR_TEST (names exactly as the spec table), `impl AdminService { pub(crate) async fn dispatch_models(&self, op: &str, args: &Value) -> Option<Result<AdminOk, AdminRefusal>> }` returning None for non-model ops.
pub const MODEL_ADMIN_OPS: &[&str]; // all 15 names, for the GUI whitelist test
```

- [ ] Migration 3 + store methods with `store_test.rs` cases (insert/list order, progress, finish states, boot recovery only touches `running`).
- [ ] `model_service_test.rs` (no weights): `resolve` with no defaults → `NoDefault(Light)`; heavy unset + light set → heavy resolves to light's entry; default pointing at a missing id → `Missing`; `start_download` refuses a second download for the same dest with `already_downloading`; idle-unload ticker unloads after the configured minutes (use `tokio::time::pause` + a fake `Runtime` state is not possible — test the pure `should_unload(last_used, now, idle_min)` helper instead).
- [ ] `admin_models_test.rs` through `AdminService` with a temp models dir: `list` empty; `catalog` returns four presets with `fits_host`/`installed` flags; `defaults.set` on a synthesized `TestOnly` GGUF → refusal `below_floor`; `defaults.set` unknown → `unknown_model`; `download` with an unknown preset → `invalid_admin_args`; `download` from the range test server (reuse `pam_model`'s test server by exposing it behind a `pub mod testing` gated with `#[cfg(any(test, feature = "testing"))]` — add feature `testing` to `pam_model` and a dev-dep with that feature here) → job row `done`, entry `verified`; `curator.set` on an undetected agent → `not_detected`; `try` with nothing loaded → `no_model_loaded`; every op leaves exactly one terminal audit row (`assert_single_terminal_audit`).
- [ ] Wire: `run_daemon_with` builds `ModelService::new` after the store opens; `AdminService::new(store, approvals, models)`; `Pipeline`/`ExecContext` carry `models`; `status` body gains `model` (`state`, `id`, `tokens_per_sec`, `defaults`); `render_status` prints `model: idle` / `model: <id> loaded (<tps> tok/s)`; `DaemonHandle::models()`.
- [ ] Integration in `crates/pam_daemon/tests/daemon.rs`: `status` shows `model.state == "idle"` on a fresh daemon; an `admin.models.list` envelope with `caller.agent != pam-gui` trips the wire (`admin_denied`) — proves the new ops sit behind the same guard.
- [ ] Gate + commit `feat(daemon): model service, model_job store, admin.models and admin.curator ops (#36)`.

---

### Task 7 (ptrack #37): GUI bridge + `/models` screen + Settings Models section

**Files:**
- Modify: `crates/pam_gui/src/bridge.rs` (`ADMIN_OPS` grows via `pam_daemon::admin_models::MODEL_ADMIN_OPS`; `admin_call` deadline 120 s for `admin.models.try`), `bridge_test.rs`, `tests/bridge.rs`
- Modify: `frontend/src/lib/ipc.ts` (types + wrappers), `ipc.test.ts`, `router.tsx` (`/models` route), `components/shell/Sidebar.tsx` (Models becomes `NavLink`), `shell.test.tsx`
- Create: `frontend/src/screens/Models.tsx`, `Models.test.tsx`, `frontend/src/screens/SettingsModels.tsx`, `SettingsModels.test.tsx`, `frontend/src/lib/bytes.ts` + `bytes.test.ts` (`formatBytes(n)` → `18.6 GB`, decimal GB to match the floor wording)
- Modify: `frontend/src/screens/Settings.tsx` (mount `<ModelsSection />` between Security and Daemon; `KNOWN_CAPABILITIES` unchanged)

**Interfaces (ipc.ts additions — exact names the tests use):**

```ts
export type ModelClass = "engine" | "test_only";
export interface GgufInfo { architecture: string; name: string | null; quant_label: string; parameter_count: number; context_length: number | null; expert_count: number | null; tensor_count: number; version: number }
export interface VerifiedRecord { sha256: string; size_bytes: number; verified_ts: number; matches_catalog: boolean | null }
export interface ModelEntry { id: string; vendor: string; file_name: string; path: string; size_bytes: number; info: GgufInfo | null; info_error: string | null; class: ModelClass; verified: VerifiedRecord | null; catalog_id: string | null }
export interface CatalogPreset { id: string; label: string; vendor: string; file_name: string; url: string; size_bytes: number; sha256: string; license_id: string; license_url: string; quant: string; params_label: string; min_host_ram_bytes: number; fits_host: boolean; installed: boolean }
export type RuntimeState = { state: "idle" } | { state: "loading"; phase: string; id: string } | { state: "loaded"; id: string; quant: string; architecture: string; context_length: number; weight_bytes: number; device: string; loaded_at: number; last_used_at: number; last_tokens_per_sec: number | null };
export interface ModelJob { id: string; kind: "download" | "verify"; model_id: string; source: string | null; state: "running" | "done" | "failed" | "cancelled"; bytes_done: number; bytes_total: number | null; detail: string | null; created_ts: number; updated_ts: number }
export interface ModelsStatus { runtime: { state: RuntimeState; busy: boolean }; jobs: ModelJob[]; defaults: { light: string | null; heavy: string | null }; idle_unload_min: number; models_dir: string; host_ram_bytes: number }
export interface GenerateResult { text: string; prompt_tokens: number; completion_tokens: number; prompt_ms: number; decode_ms: number; tokens_per_sec: number }
export type AgentId = "claude" | "codex" | "copilot" | "gemini";
export interface AgentCli { id: AgentId; path: string; version: string | null }
export function modelsList(): Promise<{ models: ModelEntry[]; models_dir: string }>;
export function modelsCatalog(): Promise<{ presets: CatalogPreset[]; host_ram_bytes: number; floor_bytes: number }>;
export function modelsDownload(source: { preset_id: string } | { url: string; vendor: string }): Promise<{ job_id: string }>;
export function modelsDownloadCancel(jobId: string): Promise<{ job_id: string; cancelled: true }>;
export function modelsDelete(modelId: string): Promise<{ deleted: true }>;
export function modelsVerify(modelId: string): Promise<{ job_id: string }>;
export function modelsLoad(modelId: string): Promise<{ state: RuntimeState }>;
export function modelsUnload(): Promise<{ state: RuntimeState }>;
export function modelsStatus(): Promise<ModelsStatus>;
export function modelsDefaultsSet(tier: "light" | "heavy", modelId: string | null): Promise<{ tier: string; model_id: string | null }>;
export function modelsSettingsSet(patch: { models_dir?: string; idle_unload_min?: number }): Promise<{ models_dir: string; idle_unload_min: number }>;
export function modelsTry(prompt: string, maxTokens?: number): Promise<GenerateResult>;
export function curatorList(): Promise<{ detected: AgentCli[]; selected: AgentId | null }>;
export function curatorSet(agent: AgentId | null): Promise<{ selected: AgentId | null }>;
export function curatorTest(): Promise<{ reply: string; ms: number }>;
```

- [ ] Bridge: whitelist test asserts every `MODEL_ADMIN_OPS` name is known and `admin.models.try` gets the 120 s deadline; integration test in `tests/bridge.rs` drives `admin.models.status` against a real daemon and expects `runtime.state.state == "idle"`.
- [ ] `Models.tsx` sections exactly as the spec's "/models screen" list (Runtime card, Library table, Catalog, Try box). Polling: `modelsStatus` `refetchInterval` 2 000 ms while any job is `running` or runtime `loading`, else 10 000 ms. Download button → `modelsDownload` → progress bar from the matching job (`bytes_done / bytes_total`), Cancel → `modelsDownloadCancel`. Two-tap Delete reuses the `ConfirmButton` pattern — move `ConfirmButton` and `FailureNote` from `Settings.tsx` into `frontend/src/components/ui/ConfirmButton.tsx` / `FailureNote.tsx` (same code, exported) so both screens import them; `Settings.tsx` imports them back (Settings tests unchanged).
- [ ] Copy in Pam's voice (serif): empty library → "No weights on the shelf yet. Pick a model from the catalog below and I'll fetch and verify it."; `test_only` badge sentence → "wiring checks only — never a tier default"; idle runtime → "Nothing loaded. Memory is yours until a job or a click needs the model."
- [ ] `Models.test.tsx` (vi.mock `../lib/ipc`): idle state renders the Pam sentence and a disabled Try box; loaded state shows id, quant, tokens/sec with `font-display`; library row for a `test_only` entry shows the badge and a disabled "Set default" with the floor reason; catalog hides presets with `fits_host: false` and shows a check for `installed`; a running download job renders a progress bar with the percentage and a Cancel that calls `modelsDownloadCancel(job.id)`; Try success renders text + tokens/sec; Try refusal renders `FailureNote` with the cause.
- [ ] `SettingsModels.tsx`: tier selects (engine-class only enabled; `test_only` options disabled with the sentence), curator radio list + Test button + result, models dir input with Apply, idle unload number input. `SettingsModels.test.tsx`: select change calls `modelsDefaultsSet("heavy", id)`; `test_only` option disabled; curator radio calls `curatorSet`; Test renders reply + ms; empty detected list names the four CLIs.
- [ ] Sidebar: `NavLink to="/models"`; `NavLink` `to` union gains `"/models"`; shell test asserts four links and one "soon" (Flows).
- [ ] Gate + visual check in the fixture browser (`npm --prefix frontend run dev`, open `/models` and `/settings`, both themes × both modes, screenshot each) — attach the four screenshots to the PR. Commit `feat(gui): models screen, settings models section, bridge ops (#37)`.

---

### Task 8 (ptrack #16): integrate and verify (coordinator)

- [ ] Fresh `main`: `tools/check.sh` green; `cargo tree -e normal,build | grep -E '^(cc|cmake|onig_sys|esaxx-rs) '` empty.
- [ ] Bench: download Qwen3-0.6B Q8_0 through the GUI paste-URL path (`https://huggingface.co/unsloth/Qwen3-0.6B-GGUF/resolve/main/Qwen3-0.6B-Q8_0.gguf`, vendor `qwen`); library shows `test only`; Load; Try "Say hello in five words." → text + tokens/sec; `Set default` refused `below_floor`; `PAM_BENCH_MODEL=~/llm/qwen/Qwen3-0.6B-Q8_0.gguf cargo test -p pam_model --test bench -- --nocapture` passes.
- [ ] Resume proof: start the catalog download of Q6_K (the owner's existing `~/llm/qwen/.Qwen3-Coder-30B-A3B-Instruct-Q6_K.gguf.pam-model.part` at ~5.3 GB) and confirm the job's `bytes_done` starts above 5 GB; cancel after a minute (owner decides when to finish it).
- [ ] Production binary: `npm --prefix frontend run gui:build`, launch `target/release/pam gui` against a scratch `PAM_BASE_DIR` with no dev server; `/models` renders; `pam status` prints the `model:` line.
- [ ] Audit: `assert_invariant_clean` style query on the scratch store (`terminal_requests_missing_audit`) is empty.
- [ ] `ptrack task done 16 --summary …`, `ptrack plan done 3`, act on the CHECKPOINT block, `ptrack summary set`.
