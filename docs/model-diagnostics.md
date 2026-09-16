# Model diagnostics and attribution

The Models screen is a wiring check. A successful answer establishes that the
reported artifact generated that answer; it does not establish troubleshooting
accuracy, safe resource limits, or task qualification.

`admin.models.try` requires an explicit installed `model_id`, a prompt and an
optional output-token limit. An optional `timeout_ms` is bounded to 1–120,000 ms;
Ask sends its shorter waiting deadline to the server. Load the intended artifact explicitly first. A
missing model refuses `unknown_model`; an unloaded or different resident model
refuses `model_not_loaded` (naming what is loaded, if anything); a busy runtime
refuses `runtime_busy`. A diagnostic request never loads a model, swaps the
current model or chooses a tier fallback: the daemon compares the requested
entry (id and path) against what the engine holds at execution, rather than
trusting a previously observed status snapshot. A deadline that drops the
request also clears the runtime's `busy` flag, so idle unload proceeds as usual.

A successful response includes `requested_model_id` and the actual worker-owned
`model` identity (`id`, `architecture`, `quant`, `device`, `weight_bytes`), alongside
the generation measurements. `diagnostic_only: true` and
`qualification: "not_assessed"` prevent a successful smoke test from becoming a
qualification claim. Weight bytes are artifact size, not runtime memory usage.
A registry verification digest is not proof that the same bytes were freshly
hashed when this worker loaded them. Diagnostics select that loaded snapshot;
an external replacement of a file is not a request to reload it. Changing the
configured registry directory unloads the old selection under the same operation
reservation, preventing identical IDs in different directories from being confused.

Ask PAM remains deterministic by default. Optional rephrasing only uses the
configured light model when that exact artifact is already loaded and available.
The returned identity must match the request and existing factual checks must
pass before a rewrite receives attribution. Disabled rewriting makes no inference
call. Any refusal, timeout, identity mismatch or rejected rewrite leaves the
original deterministic answer available without model attribution.

Daemon model operations serialize access to the runtime. A dropped diagnostic
request signals cancellation instead of leaving a never-fired cancellation watch.
This is cooperative cancellation: an individual Candle forward pass cannot be
interrupted, and current whole-prompt prefill can delay acknowledgment. The
separate inference-envelope task must measure and bound that delay before
qualification. Do not promise immediate cancellation or infer memory admission
from a token limit.

See the [qualification contract](specs/2026-09-10-model-admission-and-qualification.md)
and [screening baseline](incident-baseline.md). Diagnostics stay on the GUI admin
surface; this adds no agent administration permission or conversational product.
