# Microsoft evidence compression

In **Models → Catalog**, install the Microsoft evidence compressor, then enable
it for summaries. Installation uses the existing download jobs and pinned
SHA-256 checks. Reinstall preserves the previous assets as `.replaced-*` files.
Asset presence is displayed separately from integrity: each inference verifies
all three pinned assets again. The setting defaults off.

PAM runs Microsoft's Apache-2.0
[LLMLingua-2 BERT classifier](https://huggingface.co/microsoft/llmlingua-2-bert-base-multilingual-cased-meetingbank)
through its existing Candle dependencies. This is token scoring followed by
PAM's whole-record selection policy, not an exact port of Microsoft's word
removal algorithm. Original records and omission markers preserve diagnostic
syntax. Selection is experimental, not evidence of troubleshooting accuracy.

For log steps with `output: summarize`, the path is original evidence →
deterministic compaction → optional Microsoft record selection → bounded
summary. Original and deterministic evidence remain available after every
skip. Semantic evidence stores the selected text, retained UTF-8 byte spans,
input digest, and model revision; its offsets refer to the compact rendering,
which links back to original evidence. Summary metadata links its selected
input. With no configured investigator, PAM skips the extra classifier work.

Admission limits are 64 KiB and 8,192 classifier input tokens, with inference
windows of at most 510 content tokens. Summary selection allows 6,000 bytes;
the investigator's exact tokenizer additionally enforces a 2,048-token prefill
limit, including its prompt template. Required records that cannot fit cause
a skip. PAM never silently substitutes head/tail truncation for a summary.

Inputs already within the byte budget bypass the classifier.

The classifier needs at least 2 GiB of available memory at admission. A single
worker unloads the investigator before loading the classifier; operations are
serialized. The caller requests cancellation after 30 seconds. Cancellation
is checked during reads and between inference windows, so that deadline is
not a hard limit on worker termination. CPU, memory pressure, missing assets,
or an unavailable/busy investigator preserve deterministic results.

The [Jenkins investigation flow](jenkins-investigation.md) separately collects
structured Pipeline observations without a model. Its JSON evidence does not
pass through the log-summary compressor. It retains bounded node logs and
explicit coverage gaps; it does not claim to have determined the root cause.
Other existing adapters remain Jira Data Center, Confluence Cloud, SharePoint
365, GitHub, and SonarQube. This change adds no new connector permissions.

Run the opt-in real-classifier smoke test with the pinned assets installed:

```sh
PAM_COMPRESSION_MODEL_DIR=/path/to/microsoft/llmlingua-2 \
  cargo test -p pam_model --test compression -- --ignored --nocapture
```

The test checks actual inference, output budget, exact source spans, and
retention of a recovered publish error plus an unresolved quality-gate
failure. It is a wiring test. Qualification still requires labeled enterprise
builds and comparison against deterministic evidence alone, as described in
the model admission specification.

Measured smoke result on the development workstation (September 10, 2026):
1,017 → 459 tokens; 4,350 → 1,753 bytes; 70.88 seconds with an unoptimized
CPU build. `/usr/bin/time` reported approximately 1.61 GB maximum resident
set size for the test command. This exceeds the runtime's 30-second caller
budget; optimized latency has not been qualified. The smoke intentionally
calls the classifier directly to prove inference and source mapping.

## Optimized follow-up smoke

Three release-build runs on the 64 GiB M4 Max took 2.501, 2.412 and 2.383
seconds for the same synthetic fixture, retaining its required facts and reducing
1,017 tokens to 459. Maximum RSS ranged from 1.589 to 1.604 decimal GB.
The earlier 70.88-second debug timing is not a release latency estimate.
[Recorded measurements](benchmarks/2026-09-10-compressor/release-smoke.json)
include the source revision and limitations. This supports further evaluation,
not default enablement: one protected-fact fixture, three ambient-load runs and
warmed file caches cannot establish log fidelity, p95 latency or frontier savings.

## Held-out qualification and sequence measurement (task 140)

September 12, 2026, release build, pinned assets, 64 GiB M4 Max (not a 32 GB
measurement). [Compressor record](benchmarks/2026-09-12-compression-qualification/compressor.json)
and [sequence record](benchmarks/2026-09-12-compression-qualification/sequence.json).

Held-out authored families (disjoint from the dev records) at the product
selection budget, gated per class:

- Proven classes — identifiers, numbers, operators, retry boundaries, cleanup
  boundaries, parallel branches, multibyte spans, and a 21 KB near-cap record —
  retained 21 of 21 decisive facts. Wall time 3.9–4.6 s per 8–9.5 KB record and
  8.2 s at 21 KB, inside the 30-second caller budget; steady-state peak RSS
  about 1.68 GB.
- Restricted classes — decisive facts anchored outside the retention keyword
  net (for example a negation line with no `error`/`failed`-family keyword) —
  are not dependable: the qualification run lost
  `deploy did not start: manifest rejected by admission` at the product budget.
  Those classes stay excluded from any enablement.
- Failure paths hold: missing or tampered assets refuse on size and SHA-256
  before any inference, cancellation lands mid-verification in about 0.4 s,
  inputs over 64 KiB or 8,192 tokens refuse before inference, and a
  within-budget record is returned unchanged.

The full sequence — compressor, fresh-admission investigator load, then the
structured investigator on the real Qwen3-14B artifact (CPU) — measured the
compression arm against deterministic-only preparation:

- Oversized evidence (framed 3,736–4,569 tokens against the 2,048-token
  envelope) cannot be investigated deterministically; the runtime refuses and
  the run escalates. Compressed to 3,600 bytes it fits (1,941/1,983 prompt
  tokens) and the model reached the gold hypothesis (infra, code) with every
  citation quote verbatim in the evidence it was given.
- The within-envelope packet diagnosed directly at 1,165 prompt tokens with no
  compressor involvement — no benefit class below the selection budget.
- On every arm, compressed or not, the shipped citation contract refused the
  verdict on byte offsets (`quote_mismatch` / `offset_out_of_range`): the model
  supplies verbatim quotes but cannot count bytes. The product path therefore
  escalated honestly for this artifact at measurement time, independent of
  compression. Repaired 2026-09-12 (ptrack issue #25): the daemon now resolves
  citation offsets host-side from the verbatim quote before the byte-exact
  check; see the prompts spec's implementation status.

Decision: compression stays off by default. Proven input classes are
keyword-anchored decisive facts in 8–64 KB evidence; non-keyword-anchored
facts are restricted out. The citation-offset gap that also blocked enablement
was closed by host-side quote-to-offset resolution (issue #25); enablement now
waits only on the #108 capability gates and the #123 publication.
