# Model layer — design

Status: approved by owner (brainstorming session, 2026-09-01)
Plan: ptrack #3 "Model layer: llama.cpp runtime adapter + vendor agent CLIs"
Umbrella vision: `docs/vision.md` (goal 1, "Local models first-class")
Spine contracts this builds on: `docs/specs/2026-09-01-spine-design.md`

## Scope

The model layer gives the daemon a local inference engine and the human a
complete GUI surface to manage it: a curated catalog, assisted GGUF
download, a registry of weights on disk, an in-process runtime with load /
unload / generate, per-job-tier defaults, and detection of the vendor agent
CLIs already installed on the machine (the "curator" tier). Every piece
degrades gracefully without a model — nothing in PAM breaks when no weights
exist.

Out of scope here (later plans consume this layer): log summarization
(plan #4), Ask Pam (plan #7), catalog curation flows, any agent-facing
capability that spends tokens. Plan #3 ships no new `pam` subcommand.

## Decisions (owner-approved)

- **Runtime: candle, pure Rust, in-process** (like pam-old's in-process
  llama.cpp, without the C++). `candle-core`, `candle-nn`,
  `candle-transformers` pinned `=0.9.2`: that release carries
  `quantized_qwen3` and `quantized_qwen3_moe` and has **no** `tokenizers`
  dependency. `candle-core >= 0.10` depends unconditionally on
  `tokenizers` with the `onig` feature (Oniguruma, compiled C via `cc`),
  which the C-free rule forbids. `tokenizers` is used directly with
  `default-features = false, features = ["fancy-regex"]` (pure Rust;
  the `esaxx-rs` C++ path stays off). Metal on macOS (`objc2-metal`, Rust
  bindings, no C compile), CPU everywhere else. CUDA needs `nvcc` and is
  not shipped.
- **Download: system `curl` as a child process.** Hugging Face needs
  HTTPS; every pure-Rust TLS stack either compiles C (`ring`, `aws-lc`)
  or is alpha (`rustls-rustcrypto`). macOS, Windows 10+, and mainstream
  Linux ship `curl`. Integrity is PAM's job, not curl's: SHA-256 and size
  are verified in Rust after the transfer. A missing `curl` is a legible
  refusal naming the binary and how to install it.
- **Model floor: 18 GB. The catalog never offers anything smaller.**
  The engine class is Qwen3-Coder-30B-A3B (MoE, 3B active — fast on
  Apple Silicon). Smallest offered quant: Q4_K_M at 18.56 GB. Any model
  under the floor is class `test_only`: it can be loaded and prompted
  from the GUI to prove wiring, but it is **refused as a tier default**
  and never serves a job. The micro model used by the bench test
  (Qwen3-0.6B Q8_0, 639 MB) is exactly that — wiring proof, banned as
  engine.
- **Job tiers: `light` and `heavy`.** `light` = classification, short
  Ask Pam answers; `heavy` = summaries, briefs. Each tier has a default
  model setting. Fallback: `heavy` → `light` → none (deterministic path).
  Both may point at the same model.
- **Curator tier = installed vendor agent CLIs** (claude, codex, copilot,
  gemini), invoked non-interactively, riding the user's subscription.
  PAM holds no API keys. Plan #3 detects, lets the human pick, and tests
  the pick; the flows that use the curator arrive with the catalog work.
- **Administration is GUI-only** (spine decision): every model operation
  is an `admin.models.*` / `admin.curator.*` op. Agents cannot download,
  delete, load, or reconfigure models. The `status` capability grows a
  read-only `model` block so agents (and the CLI) can see what is loaded.
- **Sidecar compatibility with pam-old.** The download checkpoint files
  keep pam-old's names and JSON fields, so the owner's two existing
  partial downloads under `~/llm/qwen` resume instead of restarting.
- **CI arrives with this plan** (owner request): linux amd64 full gate,
  then linux arm64, macOS arm64, windows amd64, windows arm64 gated
  behind it. Release packaging stays in plan #9.

## Crate: `pam_model`

Pure Rust library, no daemon knowledge. Modules, each with a sibling
`_test.rs`:

### `gguf`

Bounded header parser (adopted from pam-old's hardening): magic `GGUF`,
version 2 or 3, tensor and metadata-KV counts, alignment (power of two,
≤ 4096), per-tensor offsets and overlap checks, hard caps
(`GGUF_MAX_HEADER_BYTES = 256 MiB`, string ≤ 256 MiB, tensor name ≤ 127
bytes). Produces `GgufInfo { architecture, parameter_count, quant_label,
context_length, expert_count, tokenizer_metadata }`. `quant_label` is
derived from the dominant tensor dtype (`Q4_K_M`, `Q8_0`, …). Only the
header is read; never the tensor data.

### `catalog`

Static `CATALOG: &[Preset]`. `Preset { id, label, vendor, file_name,
url, size_bytes, sha256, license_id, license_url, quant, params_label,
min_host_ram_bytes }`. Entries:

| id | quant | bytes | sha256 (prefix) | needs RAM |
| --- | --- | --- | --- | --- |
| `qwen3-coder-30b-a3b-q4_k_m` | Q4_K_M | 18 556 689 568 | `fadc3e5f…` | 32 GB |
| `qwen3-coder-30b-a3b-q5_k_m` | Q5_K_M | 21 725 584 544 | `4b78837b…` | 32 GB |
| `qwen3-coder-30b-a3b-q6_k` | Q6_K | 25 092 535 456 | `100b5121…` | 48 GB |
| `qwen3-coder-30b-a3b-q8_0` | Q8_0 | 32 483 935 392 | `4ff1cff6…` | 64 GB |

Source: `https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/resolve/main/<file>`,
license Apache-2.0. Only K-quants and Q8_0 are listed — candle's
quantized kernels do not cover IQ/UD formats. `MODEL_FLOOR_BYTES =
18_000_000_000`; a unit test asserts every preset is ≥ floor.
`Preset::fits_host(total_ram)` compares `min_host_ram_bytes`; the GUI
hides (does not merely disable) entries that do not fit.

### `registry`

Models dir default `~/llm`, layout `~/llm/<vendor>/<file>.gguf`
(owner's existing layout). `scan(dir)` walks two levels, opens every
`.gguf` through `gguf`, and yields `ModelEntry { id, vendor, path,
size_bytes, info, class, verified }`. `id` = `<vendor>/<file-stem>`.
`class` = `Engine` when `size_bytes >= MODEL_FLOOR_BYTES`, else
`TestOnly`. `verified` is `Some(sha256)` when a verification ran and the
digest matched a catalog preset or the download checkpoint; a model the
human copied in by hand is `unverified` until `verify` runs (digest
recorded, compared to catalog when the file name matches a preset).
`verify(path)` streams SHA-256 in 1 MiB chunks. `delete(entry)` refuses
anything outside the models dir, and refuses while the model is loaded
or downloading.

### `download`

`Downloader::start(job: DownloadRequest) -> DownloadHandle`.
`DownloadRequest { url, dest, expected_size, expected_sha256 }` — from
a catalog preset, or from a pasted URL (then size/sha256 are unknown
and the result is `unverified`, class by size).

Sidecars next to `dest`, names and fields identical to pam-old:
`.<file>.pam-model.part` (partial bytes), `.<file>.pam-model.json`
(`schema_version: 1, canonical_source, expected_digest ("sha256:…"),
expected_size_bytes, license_digest, etag`), `.<file>.pam-model.lock`
(advisory lock, refuses a concurrent download of the same file).
`license_digest` is kept for field compatibility and written as the
SHA-256 of the license identifier string.

Transfer: `curl --fail --location --silent --show-error --continue-at -
--etag-save <json-tmp> --output <part> <url>` spawned with
`tokio::process`, stdout/stderr bounded. A checkpoint whose
`canonical_source` or `expected_digest` differ from the request is a
`checkpoint_conflict` refusal (never silently reused). Progress =
`part` file size polled every 500 ms, exposed as `{ bytes, total?,
pct? }`. Cancel kills the child; the `part` stays for resume. After
exit 0: size check (when expected), SHA-256 check (when expected), then
atomic rename `part → dest` (refusing to replace an existing file),
sidecars removed. A digest mismatch deletes the `part` and reports
`digest_mismatch` with both digests. curl's own failure exit codes map
to `download_failed` with curl's stderr tail as detail.

`which curl` runs once per download; absence is `curl_missing` with a
recovery line per platform.

Tests: a tokio TCP HTTP/1.1 test server in the sibling test file serving
a synthetic file with `Range` / `206` support, driven by the real
`curl` on the machine (every CI runner ships curl). Covers full
transfer, resume from a partial, digest mismatch, cancel-and-resume,
checkpoint conflict.

### `tokenizer`

Builds a `tokenizers::Tokenizer` from GGUF metadata
(`tokenizer.ggml.model = gpt2`, `tokens`, `merges`, `token_type`,
`bos/eos_token_id`, `pre = qwen2`): byte-level BPE with the Qwen
pre-tokenizer split pattern, special tokens registered as added tokens.
This is a port of candle 0.11's `quantized/tokenizer.rs` (Apache-2.0,
attributed in the module docs) so the model stays **one file** — no
`tokenizer.json` side download. Chat formatting uses the Qwen3 ChatML
template (`<|im_start|>role\n…<|im_end|>`), hard-coded for the
`qwen3`/`qwen3moe` architectures; other architectures are refused at
load with `unsupported_architecture`.

### `runtime`

`Runtime` owns one dedicated OS thread (`pam-model`) that holds the
loaded weights; the async side talks to it over a bounded
`std::sync::mpsc` command channel, so generation is strictly serialized
(a second caller waits in the queue; the daemon's own per-repo lanes
already serialize callers above this). Commands: `Load { entry }`,
`Unload`, `Generate { request, cancel: watch, progress: mpsc }`,
`Snapshot`.

Load: `gguf_file::Content::read`, dispatch on `general.architecture`
(`qwen3` → `quantized_qwen3::ModelWeights`, `qwen3moe` →
`quantized_qwen3_moe::GGUFQWenMoE`), device = Metal on macOS else CPU,
tokenizer from metadata. Load progress is reported as phases
(`reading_header`, `mapping_tensors`, `ready`) — candle does not expose
per-tensor progress. Failures are `load_failed` with candle's message.

Generate: `GenerateRequest { system?, prompt, max_tokens, temperature,
stop: Vec<String> }`. Sampling via `candle_transformers::generation::
LogitsProcessor`. Emits tokens as they decode; honors the cancel watch
between tokens; stops on EOS, a stop string, or `max_tokens`. Returns
`GenerateResult { text, prompt_tokens, completion_tokens,
prompt_ms, decode_ms, tokens_per_sec }`.

Snapshot: `RuntimeSnapshot { state: Idle | Loading { phase } | Loaded
{ id, quant, context_length, weight_bytes, device, loaded_at,
last_used_at, last_tokens_per_sec }, busy: bool }`. `weight_bytes` =
file size (the mapped footprint); KV cache is reported as
`context_length` only — no invented byte figures.

Idle unload: the service (below) unloads after `model.idle_unload_min`
minutes without a generate (default 10, 0 = never). Memory returns to
the developer without a click.

Context: fixed 8192 tokens for plan #3 (pam-old's figure); prompts over
budget are refused `prompt_too_long` with the counts.

### `curator`

`detect(path_env) -> Vec<AgentCli>`: looks for `claude`, `codex`,
`copilot`, `gemini` executables on `PATH`, canonicalized, regular and
executable; runs `<cli> --version` with a 5 s deadline and captures the
first line. `AgentCli { id, path, version: Option<String> }`.
`invoke(cli, prompt, deadline) -> Result<String>`: non-interactive,
tool-free, single-turn contract per CLI (claude: `--print
--output-format text --max-turns 1 --tools ""`; codex: `exec --skip-git-repo-check`
reading stdin; copilot: `-p <prompt> --allow-tool ""`; gemini:
`--prompt <prompt>`), stdin/stdout bounded (256 KiB), cwd = a fresh
empty temp dir, `PATH` pinned. Exact flags per CLI are verified against
the installed binaries during implementation and recorded in the module
docs; an unknown CLI version that rejects the flags fails legibly with
the CLI's stderr. The daemon keeps the pick in setting `curator.agent`;
the test op sends "Reply with the single word OK." and reports the
answer and the round-trip time.

## Daemon integration (`pam_daemon`)

### `ModelService`

One long-lived task owning `pam_model::Runtime`, the active
`Downloader` handles, and the settings it reads:

| setting key | value | default |
| --- | --- | --- |
| `model.models_dir` | path string | `~/llm` |
| `model.default.light` | model id or null | null |
| `model.default.heavy` | model id or null | null |
| `model.idle_unload_min` | integer | 10 |
| `curator.agent` | `claude` \| `codex` \| `copilot` \| `gemini` \| null | null |

`ModelService::generate(tier, request)` is the daemon-internal API later
plans call: resolves the tier default (with the heavy→light fallback),
lazily loads it if the runtime is idle or holds another model (strict
old-before-new swap, in-flight generation on the outgoing model is
cancelled and reported), then generates. With no default configured it
returns `Err(ModelUnavailable::NoDefault)` so callers take their
deterministic path. `DaemonHandle::models()` exposes the service to the
GUI plumbing and tests.

### Store: `model_job` (migration 3)

```sql
CREATE TABLE model_job (
    id          TEXT PRIMARY KEY,      -- job_<ulid>
    kind        TEXT NOT NULL CHECK (kind IN ('download','verify')),
    model_id    TEXT NOT NULL,
    source      TEXT,                  -- url for downloads
    state       TEXT NOT NULL CHECK (state IN ('running','done','failed','cancelled')),
    bytes_done  INTEGER NOT NULL DEFAULT 0,
    bytes_total INTEGER,
    detail      TEXT,                  -- failure cause/detail json
    created_ts  INTEGER NOT NULL,
    updated_ts  INTEGER NOT NULL
);
```

Long-running work is not a request (admin ops answer synchronously),
so its history lives here: the GUI shows it, and a `running` job found
at boot is marked `failed` with cause `daemon_restart` (its `part` file
still resumes on the next download request). Every `admin.models.*` op
remains a request row + audit row exactly like today's admin ops; a
download's *start* is the audited human action, its completion is a job
row plus a tracing line.

### Admin ops

All under the existing `AdminService` dispatch, tripwire, deadline, and
audit rules. Bodies are JSON; refusals carry `cause` + `recovery`.

| op | args | body |
| --- | --- | --- |
| `admin.models.list` | — | `{ models: [ModelEntry…], models_dir }` (registry scan) |
| `admin.models.catalog` | — | `{ presets: [Preset + fits_host + installed…], host_ram_bytes, floor_bytes }` |
| `admin.models.download` | `{ preset_id }` or `{ url, vendor }` | `{ job_id }`; refuses `already_downloading`, `already_installed`, `curl_missing`, `below_floor_url` never (URL downloads are allowed; class decides) |
| `admin.models.download.cancel` | `{ job_id }` | `{ job_id, cancelled: true }` |
| `admin.models.delete` | `{ model_id }` | `{ deleted: true }`; refuses `model_loaded`, `outside_models_dir`, `download_in_progress`; clears a tier default that pointed at it |
| `admin.models.verify` | `{ model_id }` | `{ job_id }` (streams SHA-256 in the service; result on the job row and the entry) |
| `admin.models.load` | `{ model_id }` | `{ state }`; refuses `unsupported_architecture`, `load_failed`, `unknown_model` |
| `admin.models.unload` | — | `{ state: "idle" }` |
| `admin.models.status` | — | `{ runtime: RuntimeSnapshot, jobs: [running + last 20], defaults: { light, heavy }, idle_unload_min }` |
| `admin.models.defaults.set` | `{ tier, model_id \| null }` | `{ tier, model_id }`; refuses `below_floor` for a `test_only` model, `unknown_model` |
| `admin.models.settings.set` | `{ models_dir?, idle_unload_min? }` | echo; `models_dir` must exist and be a directory |
| `admin.models.try` | `{ prompt, max_tokens? }` | `GenerateResult`; refuses `no_model_loaded`, `prompt_too_long`, `busy` |
| `admin.curator.list` | — | `{ detected: [AgentCli…], selected }` |
| `admin.curator.set` | `{ agent \| null }` | `{ selected }`; refuses `not_detected` |
| `admin.curator.test` | — | `{ reply, ms }`; refuses `no_curator`, `curator_failed` |

`admin.models.try` runs within the admin deadline (the bridge raises it
to 120 s for this op) and is explicitly a wiring/diagnostic surface —
it works on `test_only` models too, because that is its purpose.

### `status` capability

Gains `"model": { "state": "idle"|"loading"|"loaded", "id": …,
"tokens_per_sec": …, "defaults": { "light": …, "heavy": … } }`. The CLI's
`pam status` summary prints one extra line (`model: idle` /
`model: qwen/… loaded`).

## GUI (`pam_gui` + frontend)

### Bridge

`ADMIN_OPS` whitelist grows by the ops above. `admin_call` keeps its
30 s deadline except `admin.models.try` (120 s). No new commands: the
host RAM figure comes from the daemon (`sysinfo` is already a
dependency), not from the webview.

### `/models` screen (replaces the sidebar "soon" placeholder)

One scrollable column, same Section/Panel furniture as Settings:

1. **Runtime card** — state badge (idle / loading phase / loaded),
   loaded model id + quant + context, weight footprint, device
   (Metal/CPU), last tokens/sec as a display-face number, Load (select
   from installed engine-class models) / Unload buttons, "idle unload in
   N min" caption. Polls `admin.models.status` every 2 s while a job or
   load is in flight, 10 s otherwise.
2. **Library table** — installed models: id, quant, size, class badge
   (`engine` success / `test only` neutral with the sentence "wiring
   checks only — never a tier default"), verified badge, actions:
   Load, Set as light/heavy default (disabled with reason for
   `test_only`), Verify, two-tap Delete. Empty state in Pam's voice.
3. **Catalog** — presets that fit host RAM, each a card with quant,
   size, RAM need, license link, Download button → progress bar
   (bytes/total/pct) with Cancel; `installed` cards show a check
   instead. Below: paste-URL download (URL + vendor field) with the
   honest note that pasted files are unverified until their digest
   is known.
4. **Try box** — textarea + max tokens + Run; renders the reply in mono
   with prompt/completion tokens and tokens/sec; refusals in the
   standard FailureNote. Disabled with reason when nothing is loaded.

### Settings → Models section

- Tier defaults: two selects (light / heavy) over engine-class installed
  models plus "none (deterministic)"; `test_only` entries appear
  disabled with the floor sentence.
- Curator: radio list of detected CLIs with version, "none" option,
  Test button showing reply + ms; empty state says which CLIs PAM looks
  for and that none was found on PATH.
- Models dir (text + validation feedback) and idle unload minutes.

The "no model available" inline banner above the composer belongs to
the Ask Pam composer and ships with plan #7 (deferral, recorded here).

## Error legibility

Every refusal cause above carries a recovery sentence pointing at the
GUI screen or the concrete fix (`curl_missing` → install command per
platform; `below_floor` → the floor figure and the catalog; `busy` →
"another generation is running; retry"; `unsupported_architecture` →
the supported list). Runtime failures never panic the daemon: the model
thread catches candle errors and reports them; a panic in the model
thread is caught at the channel (`RecvError`), the runtime resets to
idle with cause `runtime_crashed`, and the daemon keeps serving.

## Testing

- Unit (sibling files): gguf parser on synthetic headers (valid v2/v3,
  bad magic, absurd counts, overlapping tensors); catalog invariants
  (floor, unique ids, sha256 shape); registry scan + class on a temp
  dir; download suite against the local range server with real curl;
  tokenizer round-trip on a tiny synthetic GGUF vocab; curator
  detection on an injected PATH with fake executables (Unix) and
  `.cmd` shims (Windows); service tier fallback logic.
- Bench (opt-in): `PAM_BENCH_MODEL=<path to Qwen3-0.6B-Q8_0.gguf>`
  loads through the real runtime, generates 32 tokens, asserts
  non-empty text and `tokens_per_sec > 0`. Skips (does not fail) when
  the variable is unset. Run locally on the owner's machine for the
  plan checkpoint; never in CI.
- Integration (`pam_testkit`): admin ops through a real daemon — list
  on an empty dir, defaults.set refusing a `test_only` fixture,
  download of a fixture from the local range server end to end
  (job row `done`, file verified), status `model` block, audit
  invariant clean.
- Bridge tests: whitelist covers the new ops; `admin.models.try`
  deadline.
- Frontend (vitest): Models screen states (idle/loading/loaded, empty
  library, catalog filtered by RAM, download progress, try box
  success/refusal), Settings Models section (tier select disables
  `test_only`, curator radio/test), design-contract suite unchanged.
- Checkpoint (task #16): production `gui-embed` binary against a scratch
  base dir, download the micro model through the GUI, load, try,
  set-default refused as `below_floor`, resume one of the owner's
  existing `~/llm/qwen` partials, audit invariant clean.

## CI (`.github/workflows/ci.yml`)

Triggers: `pull_request` to `main`, `push` to `main`, tags `v*`.
`concurrency: ci-${{ github.ref }}` with cancel-in-progress. Path filter
ignores `docs/**` and `*.md`.

1. `gate` on `ubuntu-24.04`: rust-cache + npm cache, apt webkit2gtk /
   libsoup / gtk dev packages for tauri, then `tools/check.sh` (the whole
   local gate: fmt, clippy, tests, lint, build, vitest).
2. `needs: gate`, matrix `cargo test --workspace` on `ubuntu-24.04-arm`,
   `macos-15` (arm64, plus `npm run build` + `cargo build --release -p
   pam --features gui-embed` to prove the embedded binary links),
   `windows-2025` (amd64), `windows-11-arm`. All public-repo runners.

No release job — plan #9.

## Deferred (recorded, not built now)

- Per-tensor load progress (candle exposes none).
- Context length as a setting (fixed 8192 now).
- CUDA / Vulkan acceleration on Linux and Windows (C toolchains).
- Curator use beyond detection + test (catalog curation flows).
- "No model" composer banner (plan #7).
