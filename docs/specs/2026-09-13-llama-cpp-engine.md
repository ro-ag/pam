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

## Routing (`pam_daemon::model_service`, #150)

When `engine::status(base).installed` is true the model service routes every
weight-holding operation to the supervisor and keeps the in-process runtime
idle; when the engine is absent nothing changes. Concretely:

- `ensure_loaded` unloads any candle model first (one copy of the weights),
  then loads the registry entry into `llama-server` unless it is already the
  loaded one, and answers a `LoadedModel` whose `device` is `llama.cpp`.
- `generate_bounded` (diagnosis, summaries) and `generate_diagnostic`
  (`admin.models.try`) run the same `GenerateRequest` through the engine and
  return the runtime-shaped `GenerateResult` (server token counts and timings),
  so no caller changes. The engine's prompt count enforces the caller's
  `input_limit` before decoding.
- `unload_all` (behind `admin.models.unload`) stops the engine process and the
  runtime. `status()` gains an `engine` block: installed, expected tag, cause,
  and the loaded engine model.
- One completion may take at most 15 minutes end to end.

Evidence: `model_service_test::an_installed_engine_takes_over_load_generate_status_and_unload`
installs the fake server as the pinned release and proves load, echo
completion, the prompt limit, the idle candle runtime and unload.

## Requalification on the engine (#151)

`crates/pam_model/tests/capability_bench.rs` takes `PAM_BENCH_BACKEND=llama`
with `PAM_BENCH_ENGINE_SERVER=<llama-server>` (optional
`PAM_BENCH_ENGINE_GPU_LAYERS`, `PAM_BENCH_ENGINE_REASONING_BUDGET`); the
candle backends stay for comparison. Under the engine the GGUF's own template
frames requests, so the candle-side template classification is skipped. The
supervisor sends `cache_prompt: false` and a fixed seed so warm repeats stay
bit-identical, which the bench asserts. First record:
[2026-09-13-llama-engine-screen](../benchmarks/2026-09-13-llama-engine-screen/record.json)
— coder 0.853 / 7 false passes at warm p95 671 ms, gpt-oss-20b 0.867 / 3 false
passes at 574 ms; the latency gate is met, the accuracy gates are not, and every
remaining false pass is an abstention-trap variant.

## Readiness in the GUI (#152)

The Models page carries an "Inference engine" card above the compressor card.
It reads `admin.models.engine.status` every 10 s and says exactly what the
manifest says: installed (tag, target, version line, digest prefix), not
installed, stale release (installed tag versus the pinned one), broken install
(server missing or manifest invalid) or no release for this platform. One
explicit click on "Install engine" / "Reinstall engine" calls
`admin.models.engine.install { confirm: true }`; the button is disabled while
installing, failures render with the daemon's cause, detail and recovery, and
nothing is ever installed by a poll or by navigating. The runtime card shows
the model the engine holds (id, context, build) with an "engine" badge, or
"Engine ready, nothing loaded" when the engine is installed and idle; the
candle badges remain for hosts without an engine.

## Next (plan 36)
- API routing (#150): `generate_bounded`, diagnosis and summaries go through
  `/v1/chat/completions` on that socket; the GGUF chat template owns framing.
- Requalification (#151): the frozen capability bench and the #139 sequence on
  llama.cpp for Qwen3-Coder-30B-A3B, gpt-oss-20b and Qwen3-Coder-Next.
- Readiness (#152): engine state in the CLI and the Models page; candle stays
  only until parity, then is removed.
