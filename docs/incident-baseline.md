# Deterministic investigation baseline

Task #136 freezes 60 original synthetic screening incidents in
[`fixtures/incidents/v1`](../fixtures/incidents/v1/manifest.json): ten each for
Git, lint, tests, builds, Sonar and publishing. Publishing/JFrog observations are
offline examples; they do not establish an implemented publishing capability.

Each case has an immutable source snapshot, exact target, observable status,
separate expected interpretation, unique decisive quotes and a family ID.
Independent agents reviewed the labels, corrected unsupported causes and removed
answer annotations from the model-visible source. This is **agent-adjudicated
synthetic screening**, not human-adjudicated production evidence. These families
cannot later count as independent held-out qualification incidents.

The manifest pins the bytes and SHA-256 of both the source and case metadata.
The loader refuses changed hashes, duplicate sources/families, oversized files,
unreviewed labels and descriptive case identifiers in model input. A manifest
refresh is a deliberate reviewed dataset change; tests never regenerate it.

## Three distinct measurements

| Measurement | What actually runs | What it does not establish |
| --- | --- | --- |
| 60-case screening preparation | The production `LogService` redaction, deterministic compaction and evidence storage, twice per frozen case | Connector execution, model accuracy or frontier resolution |
| Development broker replay | Real test daemon and public flow/evidence routes, six connectors, a strict 13-request synthetic HTTP transcript, exact identities and authorized paging | Live enterprise compatibility or held-out incident quality |
| Derived 40 MB stress | One screening incident surrounded by generated unique long progress records, through the same production preparation path | Another independent incident, realistic log-frequency distributions or model fit |

The first screening replay retained all 212 declared decisive quotes. Its 49,550
source bytes became 50,708 compact-view bytes: these inputs are short, and status
footers add bytes. There is no demonstrated compression benefit for this set.

The derived stress source is exactly 40,000,000 bytes. It reduced to 42,411 bytes
of compact text and retained its four decisive quotes. Initial preparation took
about 14 seconds in an unoptimized test build on the 64 GB development host.
This is a phase timing under ambient load, not a p95 latency or 32 GB result.
Even a roughly 99.9% byte reduction does not establish model fit: the result is
approximately 10,603 **estimated** tokens before task framing. Admission must
use the actual candidate tokenizer, framing, output reserve and measured memory
envelope. Do not lower evidence-retention requirements merely to fit a model.

## Replay

Run Cargo exclusively; do not run a second build in another worktree.

```sh
PAM_INCIDENT_REPORT=/tmp/pam-screening.json cargo test -p pam_daemon --test incident_replay
PAM_INCIDENT_BROKER_REPORT=/tmp/pam-broker.json cargo test -p pam_daemon --test incident_broker_baseline
PAM_INCIDENT_STRESS_REPORT=/tmp/pam-stress.json cargo test -p pam_daemon --test incident_replay -- --ignored
```

The stress measurement is opt-in and is excluded from the normal gate. Report
files contain only the synthetic fixture data. The offline report identifies
the source, manifest, code and configuration hashes and compares two identical
content/provenance replays. Timings are recorded separately from content equality.
The broker report records response-body bytes, public-response bytes and observed
requests; these are not TLS wire-byte measurements.

The `model_input` object deliberately excludes gold labels, descriptive case and
family IDs, review notes, and the evaluator's explanatory status basis. It includes
the task, requested target, observed status and final redacted compact evidence.
Retention is measured on that final evidence, with source-span coverage reported
separately. Normalized mappings remain `covering_record`; a synthetic exit footer
is not a source quotation. Missed facts must remain visible in results, not be
injected back into the input using the expected answer.

Frontier tokens, correction turns, avoided access attempts and realized savings
remain `null`/`not_measured`. A later paired agent experiment must measure correct
resolution and count its additional reads and corrections. Corpus freezing and
successful replay therefore complete the reproducible preparation baseline, not
the separate qualification or benefit gates. Follow the
[model qualification contract](specs/2026-09-10-model-admission-and-qualification.md)
for the 500 ordinary plus 100 hostile held-out cases and resource requirements.

## Extending the corpus

Keep development examples, screening families, derived stress variants and future
qualification families distinct. Preserve source authenticity and review history.
Changes to evidence or labels require a new review and manifest digest; adding
paraphrases or retries does not increase the independent incident count. Do not
copy private logs into this corpus or export them for frontier replay without the
required authorization. Existing synthetic fixture labels confer no live scope.
