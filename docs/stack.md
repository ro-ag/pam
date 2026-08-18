# Stack decisions

Status: proposed foundation; versions are pinned only when implementation lands.

## Recommendation

| Concern | Choice | Why | Guardrail |
| --- | --- | --- | --- |
| Repository license | Apache-2.0 | Permissive for corporate adoption, with explicit patent and contribution terms. | Preserve required notices and inventory dependency and model licenses. |
| Language | Rust 2024 edition | One native binary, strong type boundaries, predictable resource use, and good macOS/Linux/Windows reach. | Keep unsafe code isolated to audited FFI adapters. |
| Async runtime | Tokio | Matches the selected ZeroMQ implementation and connector ecosystem. | Blocking database, process, and model work use bounded workers. |
| CLI | clap | Mature derive-based command contract and shell completion support. | Domain operations do not depend on CLI types. |
| Native UI | GPUI 0.2.x | The requested Zed stack, GPU-native, and already exercised in a serious editor. | Pin exact revisions, isolate `pam_gui`, and keep a daemon-first fallback because the public API is young. |
| IPC | zeromq 0.6 Router/Dealer | Native Rust, Tokio, Unix IPC, multiplexed clients, and no required `libzmq`. | Own the versioned protocol; transport fallback and conformance tests are mandatory. |
| Encoding | Serde + MessagePack | Compact typed envelopes without inventing a serializer. | Explicit limits, schema versions, unknown-field behavior, and golden fixtures. |
| Durable state | SQLite via rusqlite with bundled SQLite | Transactional queues and audit state in a user-local deployment. | WAL mode, migrations, bounded DB worker, backups, and corruption tests. |
| Evidence | Content-addressed files + SQLite metadata | Avoids bloating IPC/database while retaining exact proof. | Checksums, ownership, retention, redaction, size limits, atomic writes. |
| Local inference | llama.cpp behind `ModelRuntime` | GGUF ecosystem and first-class Apple Silicon Metal support. | Benchmark binding options; do not expose FFI or model-specific types to core crates. |
| Model acquisition | Hugging Face-compatible catalog/import | Lets users choose location and weights; no bundled payload. | License notice, size/memory estimate, resumable download, checksum, explicit consent. |
| HTTP | reqwest + rustls + rustls-platform-verifier | Async connectors with native trust behavior for corporate CAs on macOS/Windows. | Proxy/CA diagnostics, destination policy, timeouts, retry budgets, response limits. |
| Secrets | keyring-core + platform backends | Native Keychain/Credential Manager/Secret Service behavior. | Store opaque tokens only; never log or return connector credentials. |
| Configuration | TOML + Serde; platform directories crate | Human-reviewable flow/project configuration and correct OS paths. | Strict schemas, safe defaults, atomic updates, no secrets in TOML. |
| Observability | tracing | Structured daemon spans and correlation IDs. | Local by default, redaction at source, no telemetry without opt-in. |
| Planning continuity | ptrack adapter | Existing purpose-built durable goal/plan/task companion. | Use supported CLI/protocol; never couple to the ptrack database. |

## Why not Tauri or Electron first

Tauri would make cross-platform settings screens faster, and Electron would
offer the largest UI ecosystem. Neither is the requested product character:
PAM should feel like a native operations companion and share the rendering
approach of Zed. GPUI earns the first spike because the user explicitly chose
that family and macOS is the first delivery. The daemon/client boundary keeps a
future secondary UI possible if GPUI portability or accessibility becomes a
release blocker.

## Why application-level queues, not a ZeroMQ queue

ZeroMQ routes live messages; it is not PAM's durable source of truth. Project
ordering, retries, leases, cancellation, event replay, and idempotency belong in
the SQLite-backed scheduler. A daemon restart may disconnect sockets without
losing or duplicating accepted work.

## llama.cpp integration decision gate

The Rust binding layer is deliberately not final. `llama-cpp-4` 0.6 is a current
candidate with Metal support and safe wrappers, but its recent release raises
maintenance and packaging risk. Before the runtime scaffold commits to it, a
time-boxed Mac spike must measure:

- universal/aarch64 build and codesigning behavior;
- Metal startup and first-token latency;
- resident memory for one recommended Qwen GGUF;
- cancellation and concurrent request behavior;
- grammar/structured output support;
- model unload/reload safety;
- binary size and license inventory.

If the binding fails the gate, keep the same `ModelRuntime` contract and compare
a minimal maintained C-ABI wrapper. Running a separately installed model server
can be supported as an adapter, but does not replace the one-binary embedded
goal.

## Reference model policy

PAM maintains model capability profiles rather than hard-coding one weight.
Qwen3.6-35B-A3B GGUF is an initial coding/agent candidate for the target M1 Mac
with 32 GB RAM. The setup UI should recommend quantization only after estimating
weights, KV cache, context, and operating-system headroom. A Q4 variant may fit
but must be proven on the actual target; smaller quantizations are offered with
an explicit quality trade-off.

The user chooses the download directory. If they do not, PAM proposes:

```text
~/llm/<vendor>/<model-name>.<extension>
```

PAM records paths, hashes, model metadata, and licenses, but weights remain
user-owned and are never committed, synchronized, or included in releases.

## Proposed workspace boundaries

```text
crates/
  pam_cli          command parsing and terminal presentation
  pam_daemon       composition root and lifecycle
  pam_gui          GPUI application
  pam_core         IDs, requests, results, state machines
  pam_protocol     versioned envelopes and transport contracts
  pam_store        SQLite and evidence storage
  pam_flow         definitions, validation, execution
  pam_policy       capabilities, approvals, redaction
  pam_compact      deterministic evidence reduction
  pam_model        runtime contract and llama.cpp adapter
  pam_connectors   connector capability interfaces
  pam_platform     paths, IPC, credentials, service lifecycle
```

This is a dependency-boundary proposal, not permission to create every crate on
day one. The first vertical slice should start with the fewest crates that keep
daemon, protocol, and core free of UI/platform coupling; split only when a
boundary is proven.

## Validation strategy

- Portable format, lint, unit, and contract tests run cheaply on Linux.
- macOS is added for GPUI, Keychain, Unix IPC, Metal, signing, and packaging only
  after Linux checks pass.
- Windows is added for protocol/path compile checks before its native transport
  milestone and for full integration only when the implementation exists.
- Protocol and flow schemas use golden fixtures. Queue recovery uses crash/fault
  tests. Redaction and capability policy use adversarial cases.
- Rust tests live in sibling test files rather than inline test modules, matching
  the repository's working agreement.

## Open decisions

- Minimum supported macOS version and signing/notarization identity.
- MessagePack library and evolution rules after protocol fixture spike.
- Exact llama.cpp binding after the measured Mac spike.
- Whether the OpenAI-compatible local API ships in the first preview or the
  following model-sharing slice.
