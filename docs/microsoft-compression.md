# Microsoft evidence compression (removed)

Removed 2026-09-13 (plan 37), alongside the in-process candle runtime. PAM's
local inference now runs only through the pinned `llama.cpp` release (see
[the llama.cpp engine spec](specs/2026-09-13-llama-cpp-engine.md)); the
Microsoft LLMLingua-2 BERT classifier this document described was a candle
model and had no equivalent on the engine path, so record selection over log
summaries was dropped rather than ported. Log summaries now go straight from
deterministic compaction to the bounded model summary, with no optional
semantic-selection step in between.

This file is kept so existing links resolve. The qualification records this
feature was measured against remain under `docs/benchmarks/` —
[2026-09-10-compressor](benchmarks/2026-09-10-compressor/) and
[2026-09-12-compression-qualification](benchmarks/2026-09-12-compression-qualification/)
— as a historical record of what was measured and why enablement never
shipped.
