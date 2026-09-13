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

## Supervisor (`pam_model::engine_server`, #149)

`EngineServer` runs one `llama-server` for one model:

- Spawned with a scrubbed environment (only `LD_LIBRARY_PATH` to its own
  directory on Linux, `SystemRoot` on Windows), stdin/stdout/stderr closed, the
  server log under the engine directory, and `kill_on_drop`.
- Arguments: `-m <gguf> --host <endpoint> [--port N] --no-webui --jinja -np 1
  -c <context> --reasoning-budget <n> --log-file <log> [-t threads] [-ngl
  layers] --api-key <fresh key>`. The GGUF's own chat template owns framing;
  the reasoning budget is 0 for bounded tasks.
- Endpoint: the private Unix socket `<run>/engine.sock` where the platform has
  them; a free loopback TCP port on Windows. Either way the per-load API key
  (SHA-256 over the model path, pid, time and 32 bytes of OS entropy) gates the
  peer and never leaves the process.
- Load polls `/health` until `{"status":"ok"}`, refuses with the log tail when
  the process exits first, and times out on the load deadline; `/props`
  supplies `build_info`. Unload kills the process and removes the socket.
- Generation: `/apply-template` then `/tokenize` count the framed prompt and
  refuse above the caller's input limit before any decoding; then one
  non-streaming `/v1/chat/completions` with `max_tokens`, `temperature` and
  `stop`. A cancel drops the connection, which stops decoding on the server.
  Results carry the server's token counts and timings.
- Transport: `pam_model::engine_http`, a minimal HTTP/1.1 client (one request
  per connection, JSON bodies, 4 MiB response cap, no redirects).

Evidence: `tests/engine_server.rs` drives the supervisor against the shipped
fake server binary (`pam-fake-llama-server`) for load, bounds, cancel, unload,
early exit and health timeout; `tests/engine_live.rs` runs on every CI target
with `PAM_ENGINE_LIVE=1`: it installs the pinned release from GitHub, fetches
the 1.2 MB `tinyllamas/stories260K.gguf` (digest pinned), loads it and asks for
one bounded completion — the Windows check runs there, over loopback TCP.
On this host the real engine loads that model in about 0.2 s (13 s on first
launch after extraction) and answers in under 20 ms.

## Next (plan 36)
- API routing (#150): `generate_bounded`, diagnosis and summaries go through
  `/v1/chat/completions` on that socket; the GGUF chat template owns framing.
- Requalification (#151): the frozen capability bench and the #139 sequence on
  llama.cpp for Qwen3-Coder-30B-A3B, gpt-oss-20b and Qwen3-Coder-Next.
- Readiness (#152): engine state in the CLI and the Models page; candle stays
  only until parity, then is removed.
