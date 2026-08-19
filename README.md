# PAM

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

PAM is Baywatch for developers and AI agents working inside corporate
environments: always on watch, confident, and ready with the verified project
story. It keeps durable context, turns noisy evidence into compact answers,
safely brokers approved tools, and runs repeatable flows without sending the
developer's workspace to a hosted control plane.

PAM is designed as one Rust binary with three faces:

```text
pam                         # client mode (default)
pam daemon                  # local background service
pam gui                     # native control center; can start/stop the daemon
pam flow run "release check"
```

The first delivery targets Apple Silicon Macs. Linux and Windows remain
architectural constraints from the first commit rather than ports deferred
until the end.

## Why PAM

Coding agents are capable, but corporate development work is fragmented across
build logs, Git, CI, SonarQube, Jira, Confluence, credentials, policy prompts,
and restrictive sandboxes. Agents also lose useful context when conversations
are compacted or restarted. PAM sits locally between agents and those systems,
preserving verified continuity and returning small, evidence-backed results.

PAM should help an agent answer:

- What project am I acting on, and what work is already in flight?
- What actually failed, where is the evidence, and what can PAM safely fix?
- Which action requires human approval?
- What changed, how was it verified, and what remains unresolved?

## Product shape

- **Local first:** state, logs, policy, and model weights stay under the user's
  control by default.
- **Durable per-project queues:** callers share one project timeline without
  racing or repeating expensive work.
- **Safe capability bridge:** callers receive narrowly scoped access rather
  than inheriting every credential on the machine.
- **Compact evidence:** deterministic log reduction comes before optional local
  model summarization; original evidence is always addressable.
- **Flows:** developers compose auditable sequences in the GUI or as files and
  run them with `pam flow run "name"`.
- **Local inference:** PAM integrates with `llama.cpp`, helps acquire compatible
  models, and never ships model weights. The default model location is
  `~/llm/<vendor>/<model-name>.<extension>` unless the user chooses another.
- **Companion continuity:** PAM can cooperate with tools such as `ptrack`
  through supported interfaces instead of taking ownership of their storage.

## Current status

The product foundation, walking skeleton, durable project-continuity, and local
trust-and-policy slices are complete. The pinned Rust workspace builds one
`pam` executable with client, daemon, status, brief, wait, result, evidence,
caller, access, approval, network-diagnostics, audit-export, retention, and
GUI-shell modes. The daemon durably schedules per-project work in SQLite,
recovers leases after restart, replays ordered events, retains exact
content-addressed evidence, and obtains project context from `ptrack` only
through its supported JSON CLI. The workspace also contains a tested,
deterministic log compactor and a bounded, directly embedded llama.cpp runtime
behind the existing authenticated PAM protocol; compactor integration remains
future work. LLMLingua-2 is recorded as a possible staged semantic compressor,
but is not integrated; it may load on demand and unload before the selected
model. The 20 GB ceiling applies to the active Qwen profile, not installed
tools. The model path is text-only, English-first, and intended for coding
plus Python/SQL data analysis. It does not expose an HTTP model endpoint.

Production requests authenticate a registered, revocable caller whose secret is
kept in the operating system's native credential store. Project policy is
default-deny with explicit-deny precedence and exact-effect, one-time approvals.
Native-trust network diagnostics expose only sanitized configuration facts;
audit export is project-scoped and redacted; evidence and audit retention are
explicit, bounded, and crash-recoverable. Model registration verifies exact
user-owned bytes and license consent; model loading is disabled unless the
daemon receives `--model VENDOR/NAME`, then fails closed on the 20 GB profile,
fresh memory pressure, swap trend, Metal working set, and OS/PAM reserves.
Flows, connectors, service-manager integration, peer-credential transport
hardening, and the full GPUI control center remain later roadmap slices. PAC
evaluation and live managed enterprise CA/proxy behavior are not claimed; no
managed-environment interviews or workflow observations have been conducted.

Initialize the CLI caller and grant only the capabilities needed for the
current project:

```sh
cargo run -p pam_cli -- caller register
cargo run -p pam_cli -- access grant daemon.status --resource daemon
cargo run -p pam_cli -- access grant brief.read
```

Run the daemon from an initialized project in one terminal:

```sh
cargo run -p pam_cli -- daemon
```

```sh
cargo run -p pam_cli -- status
cargo run -p pam_cli -- brief
```

The first supported embedded model profile is the user-owned
Qwen3-Coder-30B-A3B-Instruct Q4_K_S artifact documented in
`docs/model-memory.md`. Register its exact bytes and accepted license snapshot;
if policy denies the import, run the exact recovery grant printed by PAM and
retry the same command:

```sh
cargo run -p pam_cli -- model import \
  qwen/qwen3-coder-30b-a3b-instruct-q4-k-s \
  --path /absolute/path/to/Qwen3-Coder-30B-A3B-Instruct-Q4_K_S.gguf \
  --digest sha256:56a7d00783419bcb0ae566253c371bcb3678261bb79881a553539f5679864db4 \
  --size-bytes 17456012448 \
  --license-id Apache-2.0 \
  --license-url https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct/blob/b2cff646eb4bb1d68355c01b18ae02e7cf42d120/LICENSE \
  --license-notice-digest sha256:832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e \
  --accept-license
```

Start the daemon with that profile and invoke it over PAM's authenticated local
protocol. The first generation is default-denied until its printed exact-effect
grant is added; retry the identical request after granting it.

Terminal 1:

```sh
cargo run -p pam_cli -- daemon \
  --model qwen/qwen3-coder-30b-a3b-instruct-q4-k-s
```

Terminal 2:

```sh
cargo run -p pam_cli -- model generate \
  qwen/qwen3-coder-30b-a3b-instruct-q4-k-s \
  'Explain this Rust compiler error and propose the smallest safe fix.' \
  --tokens 256
```

The daemon runs in the foreground and shuts down cleanly on Ctrl-C. If an
interrupted daemon leaves stale local endpoint state, recover it explicitly
with `cargo run -p pam_cli -- daemon --recover`. The native GUI boundary is
available as `cargo run -p pam_cli -- gui`; the production GPUI surface lands
in the native-control-center roadmap slice. `pam brief` requires `ptrack` to be
installed and initialized for that exact project root; otherwise it reports the
source as unavailable. Durable request observers use `pam wait <request-id>` and
`pam result <request-id>`. A brief's exact source can be inspected with
`pam evidence show <evidence-handle>` or written byte-for-byte with
`--raw`/`--output`.

If policy returns an approval challenge, decide it and retry that same
operation with the explicit one-time receipt:

```sh
cargo run -p pam_cli -- approval approve <approval-id>
cargo run -p pam_cli -- status --approval-id <approval-id>
```

`--approval-id <ID>` is available on the single-request `status`, `brief`,
`wait`, `result`, and `network diagnostics` commands. The receipt is attached
only to the command that explicitly supplies it; PAM does not read approval
authority from the environment.

`evidence show` deliberately does not accept an approval receipt. One evidence
download spans an inspection request followed by one or more bounded range-read
requests, while a one-time receipt authorizes exactly one protocol request and
cannot be reused across that sequence. A protocol client may retry the exact
challenged evidence request with its receipt.

## Security model

Local endpoint reachability is not authorization: callers authenticate, policy
is evaluated for the exact project/capability/resource, and required approvals
are consumed transactionally immediately before dispatch. PAM nevertheless
relies on the operating-system account and per-user data-directory protections
for local administrative CLI operations and direct database access; an
untrusted process with unrestricted execution as that same user is inside the
current administrative trust boundary.

See the [local daemon threat model](docs/security/local-daemon-threat-model.md)
for assets, actors, trust boundaries, current mitigations, planned hardening,
residual risks, severity calibration, and a test-linked validation matrix.

Local quality gates match the portable Linux checks:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

The prototype translates the approved "Project Current" direction into a
responsive, interactive screen with project switching, daemon control, agent
handoff, evidence inspection, and flow/access states:

```sh
cd prototype
npm install
npm run dev
```

See the [prototype visual QA](prototype/design-qa.md) for the source target and
comparison evidence. The prototype is a design contract; production UI remains
native GPUI.

Read next:

- [Product brief](docs/product-brief.md)
- [Research synthesis](docs/research.md)
- [Architecture](docs/architecture.md)
- [Local daemon threat model](docs/security/local-daemon-threat-model.md)
- [Stack decisions](docs/stack.md)
- [Roadmap](docs/roadmap.md)

## Contributing

The design is intentionally open before implementation hardens it. Please start
with the product brief and roadmap, then open an issue describing the user
problem, expected evidence, and security boundary. PAM is licensed under the
[Apache License 2.0](LICENSE). By contributing, you agree that your contributions
will be licensed under the same terms.
