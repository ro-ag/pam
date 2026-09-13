# The llama.cpp engine as a pinned external binary

Status: decision and acquisition contract, 2026-09-13 (plan 36). The user
switched local inference from the in-process candle runtime to llama.cpp,
delivered as the upstream GitHub release binaries. PAM's own build stays pure
Rust; the engine is a separate, pinned, digest-verified process that PAM
installs, supervises and talks to over a private socket. Companion to
[model admission and qualification](2026-09-10-model-admission-and-qualification.md).

## Why

- candle 0.9.2 loads only the `qwen3` and `qwen3moe` GGUF architectures, and
  newer candle drags a C `tokenizers` build into PAM. llama.cpp already runs
  gpt-oss, Qwen3-Coder-Next, Qwen3.6/3.8 and every new family, with Metal on
  Apple Silicon.
- Measured on this host (M4 Max, Metal, Qwen3-Coder-30B-A3B Q4_K_M): the
  release `llama-server` answers a bounded trap question in 0.6 s at
  101 tokens/s where candle on CPU took about 26 s.
- Linking llama.cpp (any `llama-cpp-*` crate) would compile C++ with cmake
  inside PAM's build. Running the upstream binary keeps the no-C rule for
  PAM's own dependency graph and gives every CI target a matching asset.

## Pinning (`pam_model::engine`)

| constant | value |
| --- | --- |
| `ENGINE_TAG` | `b10938` |
| `ENGINE_BUILD` | `10938` (what `llama-server --version` must report) |
| assets | one per target: macos-arm64, macos-x64, ubuntu-x64, ubuntu-arm64, win-cpu-x64, win-cpu-arm64 |
| digest | the `sha256:` the GitHub release API publishes for each asset |

Targets map from `std::env::consts::{OS, ARCH}`; anything else reports
`unsupported_target` and local inference is unavailable there. Bumping the
engine is a visible commit that changes the tag and all six digests together.

## Acquisition

1. The archive is fetched with the same resumable curl transfer models use
   (`pam_model::download`), which refuses a digest or size mismatch before the
   file lands. Cancellation keeps the part file for a resume.
2. The archive is unpacked into a private scratch directory by the operating
   system's own `tar` (`/usr/bin/tar`; `%SystemRoot%\System32\tar.exe` on
   Windows, which reads the zip assets too), never by a compression crate.
3. The unpacked `llama-server` runs `--version` with a scrubbed environment and
   must print `(build <ENGINE_BUILD>,`; anything else is discarded.
4. The release directory moves to `<base>/engine/llama-<tag>/` and
   `<base>/engine/.pam-engine.json` records tag, build, target, asset, digest,
   size, the version line and the install time. The archive is removed.

`status()` reads files only and reports `not_installed`, `manifest_invalid`,
`stale_release`, `server_missing` or `installed`; it never runs a process.

## Daemon surface

- `admin.models.engine.status` → the status above plus the pinned tag and
  target name. Read-only.
- `admin.models.engine.install { confirm: true }` → installs the pinned
  release and answers with the status. Without `confirm` it refuses
  (`invalid_admin_args`), so no listing or probe ever starts a download. The
  GUI bridge gives it the long (120 s) deadline.
- The engine root is the daemon's base directory (`~/.pam` by default), set
  on the model service at start; tests fall back to a private directory
  beside their models.

Evidence: the opt-in test `engine::tests::the_pinned_release_installs_on_this_host`
installed the real macOS arm64 asset on 2026-09-13 (digest `69f236c8…`,
version line `version: 0.4.0-dev (build 10938, commit f1e44dcc1)`).

## Next (plan 36)

- Supervisor (#149): spawn `llama-server` on a private Unix socket
  (`--host <run>/engine.sock`) with `--api-key`, `--no-webui`, `--jinja`,
  `--reasoning-budget 0` for bounded tasks, context and prediction bounds from
  the admission envelope, one loaded model at a time; health, load, unload,
  crash recovery; loopback TCP with the api-key only where a Unix socket is
  unavailable.
- API routing (#150): `generate_bounded`, diagnosis and summaries go through
  `/v1/chat/completions` on that socket; the GGUF chat template owns framing.
- Requalification (#151): the frozen capability bench and the #139 sequence on
  llama.cpp for Qwen3-Coder-30B-A3B, gpt-oss-20b and Qwen3-Coder-Next.
- Readiness (#152): engine state in the CLI and the Models page; candle stays
  only until parity, then is removed.
