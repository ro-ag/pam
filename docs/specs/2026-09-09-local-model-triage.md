# Local-model triage: what the small model does for the big one

Status: draft for review · Owner decisions captured 2026-09-09 · ptrack plan 30, task #103

## The claim

The local model is not a small chat assistant. It is a **stateless worker that
stands outside the agent's sandbox, holds the connector credentials, and sits
next to the evidence**. Those three facts — not its reasoning quality — are
what it sells to a frontier model.

It earns its place by doing five things:

1. **Route** — turn "something is wrong with the Jenkins job" into the right
   connector calls, in order, with the right arguments. Classification over a
   closed set, not reasoning. The frontier agent cannot make these calls at all
   from inside a sandbox.
2. **Pre-digest** — take evidence far too long to send anywhere (a 40 MB build
   log, 400 Sonar issues) and return only the part that decides the answer.
3. **Classify** — answer bounded questions into a closed answer set: infra or
   code, new debt or pre-existing, same flake as last night or new.
4. **Escalate honestly** — "I cannot tell, here are the 3 KB that matter,
   already fetched" is a first-class outcome, not a failure.
5. **Watch** — run on every merge, every night, every push. A frontier model
   cannot afford that cadence. A local one is free, and frequency is where it
   wins outright.

What it must never do: open-ended reasoning, writing fixes, or anything whose
wrongness is both expensive and unverifiable.

## Owner decisions

- **Stateless per step.** Every model call is one-shot: a fixed task prompt, a
  bounded evidence slice, a declared answer set. No conversation, no carried
  transcript. A watch that runs for six hours makes N independent calls and
  grows nothing.
- **Not a chat.** No composer, no follow-ups, no memory of what was asked
  before. The unit of work is a task with a verdict.
- **The long log never reaches the model whole.** `pam_compact` reduces it
  deterministically first; the model reads what survived and picks what
  decided it.

## Why stateless matters beyond tidiness

The context window in this build is 8192 tokens. A conversational design spends
it on history; a stateless one spends all of it on evidence. It also means a
step can be retried, reordered, or run a thousand times without drift, and two
runs over the same evidence produce the same verdict.

## Security stance: this model reads hostile text

Build logs, Jira comments and PR descriptions are attacker-writable, and this
is the model with connector access. Therefore:

- **Model output is never an instruction.** It selects from a declared answer
  set. An answer outside that set is a refusal, not a passthrough.
- **Model output never becomes an argv, a connector argument, or a URL.** Flow
  branching may read the verdict; nothing composes a call from model text.
- Evidence handles are minted by the daemon, never by the model.

The typed-verdict contract is a security boundary first and an ergonomic choice
second.

## The three call kinds

Every call returns the same envelope:

```json
{
  "answer": "infra",
  "confidence": "high",
  "evidence": ["ev_01J...", "ev_01J..."],
  "escalate": false,
  "note": "runner lost connection at 14:02; no test ever started"
}
```

- `digest` — long evidence in, the decisive records and identifiers out
  (stage, first failing test, exit code, the one stack frame that matters).
- `classify` — one answer from `answers:` declared in the YAML, plus
  confidence.
- `check` — a yes/no gate with a reason, for "did the Sonar gate pass, and if
  not, why".

`note` is length-capped. `escalate: true` means the frontier agent should look;
the handles are already fetched and compacted, so it starts narrowed.

## Flow surface

Two additions to `pam_flow::schema`:

```yaml
# a model step: reads evidence a previous step produced
- id: triage
  model: classify
  from: build-log            # the step whose evidence to read
  answers: [infra, code, flake, config]
  needs: [build-log]

# a watch step: poll a connector call until a predicate or a deadline
- id: wait-jenkins
  connector: jenkins
  call: build
  with: { job: "${inputs.job}", sha: "${steps.land.result.sha}" }
  until: { result: finished }
  every: 30s
  deadline: 45m
```

Polling is model-free — it is a connector call and a predicate. The model is
called only when the state settles.

Branching reads the verdict:

```yaml
when: { verdict: { step: triage, is: code } }
```

## The flow the owner described

`land-watch`: monitor the landing, wait for Jenkins, check what Sonar said.

1. `wait_for` GitHub: the PR merges → carries the merge SHA
2. `wait_for` Jenkins: the build for that SHA finishes
3. on failure → `digest` the build log → `classify` infra | code | flake
4. `wait_for` Sonar: the gate for that SHA publishes
5. on gate failure → `digest` the issues → `classify` new-debt | pre-existing
6. one verdict card

Each of steps 3 and 5 is a fresh model call over its own evidence. Nothing
carries between them but a small typed value.

## What the frontier agent receives

One card, roughly twenty lines: state, cause class, identifiers, suggested next
action, evidence handles, escalate flag. Not a transcript, not a log, not
prose about a log. If it disagrees, it pulls exact bytes by handle.

## What already exists

- `pam_compact` — deterministic reduction with a byte-exact map back to source
  (`crates/pam_compact/src/compact.rs`), wired into every flow step
  (`log_service.rs:279`).
- `OutputPolicy::Summarize` — a per-step model summary with honest
  `model_skipped` reporting (`flow_service.rs:1603`).
- Connectors, evidence handles, approvals, retry with backoff.

## What is missing

- `Action` has no model step (`schema.rs:104`), so a flow cannot ask a bounded
  question or branch on the answer.
- No answer-set constraint, no confidence, no escalate signal — today the model
  returns prose.
- No polling: `Retry` retries a *failure* (`schema.rs:240`); waiting for a
  remote state to settle is a different thing and has no expression.
- No run-level verdict card.

## Build order

1. The verdict envelope and the answer-set constraint, with a refusal when the
   model answers outside the set. Provable without any flow changes.
2. `model:` step kind (`digest`, `classify`, `check`) reading a prior step's
   evidence.
3. `when: { verdict: ... }` branching.
4. `until:` / `every:` / `deadline:` polling.
5. `land-watch` and a rewritten `ci-failure-triage` as starter flows.
6. The verdict card in the GUI and as the `flow.run` result the agent reads.
