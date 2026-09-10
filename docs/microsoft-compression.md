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
