# Stack decisions

Status: proposed foundation; versions are pinned only when implementation lands.

## Recommendation

| Concern | Choice | Why | Guardrail |
| --- | --- | --- | --- |
| Repository license | Apache-2.0 | Permissive for corporate adoption, with explicit patent and contribution terms. | Preserve required notices and inventory dependency and model licenses. |
| Language | Rust 2024 edition | One native binary, strong type boundaries, predictable resource use, and good macOS/Linux/Windows reach. | Keep unsafe code isolated to audited FFI adapters. |
| Async runtime | Tokio | Matches the selected ZeroMQ implementation and connector ecosystem. | Blocking database, process, and model work use bounded workers. |
| CLI | clap | Mature derive-based command contract and shell completion support. | Domain operations do not depend on CLI types. |
| Desktop UI | Tauri 2.11.5 + React 19 + TypeScript | Preserves a small Rust authority boundary while providing the cross-platform layout, accessibility tree, and interaction fidelity the GPUI spike could not deliver. | Keep Tauri commands typed and narrow; no shell/fs/http plugins or credentials in frontend DTOs. |
| IPC | zeromq 0.6 Router/Dealer | Native Rust, Tokio, local IPC on every supported OS, multiplexed clients, and no required `libzmq`. | Own the versioned protocol and transport conformance tests. |
| Encoding | Serde + MessagePack | Compact typed envelopes without inventing a serializer. | Explicit limits, schema versions, unknown-field behavior, and golden fixtures. |
| Durable state | SQLite via rusqlite with bundled SQLite | Transactional queues and audit state in a user-local deployment. | WAL mode, migrations, bounded DB worker, backups, and corruption tests. |
| Evidence | Content-addressed files + SQLite metadata | Avoids bloating IPC/database while retaining exact proof. | Checksums, ownership, retention, redaction, size limits, atomic writes. |
| Prompt compression | Deterministic compactor first; LLMLingua-2 mBERT as a measured future option | Keeps exact source spans authoritative while allowing a later small extractive semantic stage. | Load on demand in a separately measured phase; require unload proof, fresh Qwen admission, code/log retention tests, and a Rust-compatible implementation before promotion. |
| Local inference | `llama-cpp-4` 0.6.0 behind `ModelRuntime` | Direct in-process llama.cpp, GGUF support, and Apple Silicon Metal acceleration without an HTTP sidecar. | Pin wrapper/sys and upstream llama.cpp revisions; keep FFI and model-specific types inside `pam_model`. |
| Model acquisition | Hugging Face-compatible catalog/import | Lets users choose location and weights; no bundled payload. | License notice, size/memory estimate, resumable download, checksum, explicit consent. |
| HTTP | reqwest + rustls + rustls-platform-verifier | Async connectors with native trust behavior for corporate CAs on macOS/Windows. | Proxy/CA diagnostics, destination policy, timeouts, retry budgets, response limits. |
| Secrets | keyring-core + platform backends | Native Keychain/Credential Manager/Secret Service behavior. | Store opaque tokens only; never log or return connector credentials. |
| Configuration | TOML + Serde; platform directories crate | Human-reviewable flow/project configuration and correct OS paths. | Strict schemas, safe defaults, atomic updates, no secrets in TOML. |
| Observability | tracing | Structured daemon spans and correlation IDs. | Local by default, redaction at source, no telemetry without opt-in. |
| Planning continuity | ptrack adapter | Existing purpose-built durable goal/plan/task companion. | Use supported CLI/protocol; never couple to the ptrack database. |

## Why Tauri replaced the GPUI spike

The GPUI spike proved the Rust-side state boundaries but failed the approved
visual contract, did not expose the control center through a platform
accessibility tree, and made the requested five-target preview matrix costly.
Tauri keeps `pam_gui` independent of the webview shell: Rust owns credentials,
project authority, daemon protocol, evidence bounds, and stale-operation fences;
React owns presentation and interaction. Electron remains unnecessary because
Tauri reuses the operating system webview and bundles the existing Rust helper.

## Why application-level queues, not a ZeroMQ queue

ZeroMQ routes live messages; it is not PAM's durable source of truth. Project
ordering, retries, leases, cancellation, event replay, and idempotency belong in
the SQLite-backed scheduler. A daemon restart may disconnect sockets without
losing or duplicating accepted work.

## llama.cpp integration decision gate

The first runtime adapter uses `llama-cpp-4` 0.6.0 with default features
disabled and only static Metal enabled. The binding remains isolated behind a
model-neutral contract because its recent release still carries maintenance,
native-abort, and packaging risk. The measured Mac spike records:

- universal/aarch64 build and codesigning behavior;
- Metal startup and first-token latency;
- resident memory for one recommended Qwen GGUF;
- cancellation and concurrent request behavior;
- grammar/structured output support;
- model unload/reload safety;
- binary size and license inventory.

The available M4 Max/64 GiB host passed the static aarch64 Metal, development
signing, linkage, startup, first-token, and host-memory gates. Qwen3.6 Q4_K_S
remains calibration history; the production Qwen3-Coder-30B-A3B-Instruct
Q4_K_S profile passed the 20 GB model-allocation ceiling at 8,192 context
tokens. M1 Pro with 32 GB memory is the minimum supported Mac; host-specific
admission is mandatory, and M1 Pro speed remains unmeasured.
Universal model packaging remains intentionally out of scope. The desktop
control center targets Linux and Windows on arm64/amd64 and macOS 12+ on arm64.
The macOS CI package is Developer-ID-signed, notarized, stapled, and
Gatekeeper-validated without exposing repository credentials. PAM will use bounded chunk-boundary
cancellation and a serialized worker instead of the binding's unsafe abort
callback. See `docs/benchmarks/llama-cpp-macos.md` for commands, measurements,
limitations, and the fallback criteria. The preview uses the embedded adapter
only: no separately installed model server, HTTP listener, or subprocess is
part of the runtime path.

## Reference model policy

PAM maintains explicit digest-bound model capability profiles. The first
production profile is Qwen3-Coder-30B-A3B-Instruct Q4_K_S at 8,192 context,
documented in `docs/model-memory.md`; it is text-only, supports only
non-thinking mode, and uses the model card's recommended sampling parameters.
The adapter admits it only after checking weights, context, compute, calibrated
contingency, operating-system and PAM reserves, live pressure and swap trend,
and the 20 GB model-allocation ceiling. Other artifacts and quantizations
require their own exact projection, calibration, and focused quality suite; M4
timings are not presented as M1 Pro measurements.

The user chooses the download directory. If they do not, PAM proposes:

```text
~/llm/<vendor>/<model-name>.<extension>
```

`pam_model` now implements exact-hash local import and resumable HTTPS
acquisition with artifact-bound license consent, strict user-owned paths,
bounded GGUF structure validation, manual redirect policy, and atomic
no-replace publication. Schema v7 records only the verified path, hash,
bounded GGUF metadata, license snapshot, and sanitized source identity;
weights remain user-owned and are never committed, synchronized, or included
in releases. See `docs/model-acquisition.md` for the security and recovery
contract.

## Proposed workspace boundaries

```text
crates/
  pam_cli          command parsing and terminal presentation
  pam_daemon       composition root and lifecycle
  pam_gui          Tauri-independent desktop authority and DTO boundary
  pam_core         IDs, requests, results, state machines
  pam_protocol     versioned envelopes and transport contracts
  pam_store        SQLite and evidence storage
  pam_flow         definitions, validation, execution
  pam_policy       capabilities, approvals, redaction
  pam_compact      deterministic evidence reduction
  pam_model        runtime contract and llama.cpp adapter
  pam_connectors   connector capability interfaces
  pam_platform     paths, IPC, credentials, service lifecycle
src-tauri/         thin typed Tauri 2 shell and platform packaging
frontend/          React presentation, interactions, and visual states
```

This is a dependency-boundary proposal, not permission to create every crate on
day one. The first vertical slice should start with the fewest crates that keep
daemon, protocol, and core free of UI/platform coupling; split only when a
boundary is proven.

## Validation strategy

- Portable format, lint, unit, and contract tests run cheaply on Linux.
- Linux frontend/Rust validation is the cheap gate for every desktop package.
- Windows arm64/amd64 and Linux arm64/amd64 packages run on native GitHub
  runners after that gate; macOS arm64 signing and notarization is gated to
  approved PRs and `main`.
- Protocol and flow schemas use golden fixtures. Queue recovery uses crash/fault
  tests. Redaction and capability policy use adversarial cases.
- Rust tests live in sibling test files rather than inline test modules, matching
  the repository's working agreement.

## Open decisions

- Release and long-term distribution policy beyond CI-retained preview
  artifacts; no tag, release, or public upload is implied by the package jobs.
- MessagePack library and evolution rules after protocol fixture spike.
- Whether a later model-sharing slice needs another authenticated PAM protocol
  operation; an HTTP/OpenAI-compatible listener is intentionally out of scope.
