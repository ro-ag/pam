# PAM

PAM is a local lifeguard for developers and AI agents working inside corporate
environments. It keeps durable project context, turns noisy evidence into
compact answers, safely brokers approved tools, and runs repeatable flows
without sending the developer's workspace to a hosted control plane.

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

PAM is in product-foundation stage. The repository currently contains the
research, product contract, architecture, implementation roadmap, and a cheap
CI baseline. Runtime scaffolding follows after the first native UI direction is
selected and the highest-risk technical spikes are resolved.

Read next:

- [Product brief](docs/product-brief.md)
- [Research synthesis](docs/research.md)
- [Architecture](docs/architecture.md)
- [Stack decisions](docs/stack.md)
- [Roadmap](docs/roadmap.md)

## Contributing

The design is intentionally open before implementation hardens it. Please start
with the product brief and roadmap, then open an issue describing the user
problem, expected evidence, and security boundary. A project license has not
yet been selected; until one is added, normal copyright restrictions apply.
