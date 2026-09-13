# Opt-in model resource screening

> Historical: the candle memory model this document describes was removed
> 2026-09-13 (plan 37) along with `tests/resource_screen.rs`. Local inference
> now runs only through the pinned llama.cpp engine (see
> [the llama.cpp engine spec](specs/2026-09-13-llama-cpp-engine.md)), whose
> resident-memory shape differs from what is measured below.

`crates/pam_model/tests/resource_screen.rs` exercises the production GGUF registry,
tokenizer and Candle runtime. It downloads nothing and adds no dependencies.
Ordinary tests skip it. Results are resource observations, not model qualification,
incident accuracy, or proof that a model fits a 32 GB workstation.

## Required inputs

Set these environment variables for one local artifact at a time:

- `PAM_SCREEN_MODEL`: absolute path in the registry's `<directory>/<vendor>/<file>.gguf` layout.
- `PAM_SCREEN_SHA256` and `PAM_SCREEN_BYTES`: independently obtained expected
  artifact digest and exact byte size. The harness hashes the actual file before
  loading and refuses a mismatch. Accepted size is 9–14 decimal GB.
- `PAM_SCREEN_REVISION`: pinned artifact repository revision.
- `PAM_SCREEN_LICENSE_SHA256`: pinned license digest. This is recorded as declared;
  the harness does **not** download or verify the license text.
- `PAM_SCREEN_BACKEND`: exactly `cpu` or `metal`; no automatic backend fallback.
- `PAM_SCREEN_HOST_LABEL`: actual hardware, memory and workload label, for example
  `M4 Max / 64 GiB / capped screening / editor+browser workload`.

Use the exact artifact and license pins in the model admission specification and
ptrack task #137. Keep the artifact unchanged during the run. A repository revision
label alone is not byte verification; the actual GGUF digest is checked separately.

## Build and supervise separately

Build first, with the project's normal single-Cargo-slot discipline:

```sh
cargo test --release -p pam_model --test resource_screen --no-run
```

Use the executable path printed by Cargo as `PAM_SCREEN_BIN`. Run the binary
rather than timing Cargo's build. On macOS, record system state before and after:

```sh
vm_stat
sysctl vm.swapusage
/usr/bin/time -l "$PAM_SCREEN_BIN" --ignored --nocapture --test-threads=1
vm_stat
sysctl vm.swapusage
```

The macOS stdlib-only supervisor is the supported bounded measurement wrapper:

```sh
python3 tools/screen-model.py --binary "$PAM_SCREEN_BIN" --output-dir /absolute/new/screen-run
python3 tools/screen_model_test.py
```

The output directory must not already exist. It contains `measurements.jsonl`,
`stdout.log` and `stderr.log`; each stream is capped at 16 MiB. The wrapper accepts
only an already-built executable named `resource_screen-<hex>` and supplies the
fixed ignored-test arguments. Filename validation is a misuse guard, not proof
that the executable is trustworthy. Use the binary from the preceding build.
Required artifact environment variables are inherited; the supervisor does not
print them or download weights.

It samples child RSS (`ps`, KiB converted to bytes), child `phys_footprint`
(`footprint -p`, the metric macOS uses for pressure and jetsam), system pressure
(`kern.memorystatus_vm_pressure_level`) and cumulative `vm_stat` swapouts at a
0.5-second target cadence. Probe latency adds to that interval; timestamps record
the actual cadence. It terminates on sampled RSS above 16 GiB, pressure other than
normal (`1`), additional system swapout pages, unavailable measurements or a
20-minute deadline. After termination it waits up to five seconds before killing
and reaping the child. These are **sampled soft stops**, not OS hard memory caps;
a rapid allocation spike can occur between samples. An existing 1 GiB swap
allocation is not an added-swapout failure. Swapouts and pressure include ambient
activity and cannot be attributed exclusively to PAM.

Final measurements include maximum sampled RSS, child exit code, stop reason and
native `getrusage(RUSAGE_CHILDREN).ru_maxrss`, explicitly in macOS bytes. That
native high-water value includes measurement subprocesses and is not a delta or
sum. RSS is not total Metal/unified-memory allocation; virtual size is not resident
usage. The two-second identity and post-unload windows support phase comparison.
A successful process exit does not establish returned GPU memory, normal pressure
between samples, p95 latency or model quality. Collect paired timings of the same
representative developer workload with and without the model. A 64 GiB host
remains a 64 GiB measurement; the 16 GiB RSS threshold does not emulate a 32 GiB
machine or qualify its memory fit.

## Interpretation

Each `PAM_RESOURCE_SCREEN ` line contains a bounded JSON object. Framed prompt
length is counted with production `chatml`, GGUF tokenizer and BOS handling.
The harness chooses a synthetic prompt at or below each 512/1024/2048-token cap;
it reports the **actual** length and asserts production generation agrees.
Lengths may fall short of their cap. Output reserve is 64 tokens, greedy sampling.
Output digests support repeatability comparison without printing model prose.

The first call at each length and its warm repeat are recorded separately. Only
the first call after load is cold with respect to this runtime; hashing and prior
loads warm OS caches. This does not measure a physically cold file cache, and two
samples do not establish p95 latency. Repeat supervised fresh-process runs when
estimating distributions and retain every failure.

The cancellation probe requests up to 1024 output tokens and signals after 100 ms
if generation is still pending. It records whether the signal was sent, the
outcome and signal-to-return latency. An early completion is not proof of working
cancellation. The signal's inference phase is unknown. Production prefill is a
single forward call, so a timeout/cancel cannot preempt that call; the external
supervisor is essential. Recovery requires an identical subsequent greedy result.
Unload completion alone does not prove memory returned to the OS.

Framing is derived per artifact at load from the chat template the file itself
declares (`tokenizer.chat_template`): instruct templates carrying the Qwen3
`enable_thinking` branch run thinking-disabled (the empty think block is
appended), Coder-family templates end at the assistant newline, and anything
else is refused rather than guessed. The screen records the derived framing as
`template` with `template_qualified` true only when the file declared a
template PAM recognised. Behavioural proof for a pinned artifact — generated
output contains no think block and temperature-0 repeats match — is a separate
opt-in run: `crates/pam_model/tests/framing_verification.rs`. There is no fresh
daemon working-set admission in this direct runtime path. Record
OS/architecture, backend, GGUF architecture/quantization and source revision of
the PAM checkout with the results. A successful screen on a 64 GiB host remains
a 64 GiB measurement, even when its workload is capped. Run the independent
incident benchmark only after resource and template limitations have been
adjudicated.

## First screened artifact

The pinned dense `Qwen3-14B-Q5_K_M` GGUF (10,514,569,568 bytes, SHA256
`e7c9aba1…d08e3e31`, verified locally before the run) was screened twice per
backend in release builds on an M4 Max with 64 GiB. Full measurements and the
raw supervisor sample streams are in
[the screening record](benchmarks/2026-09-10-model-screen/screen.json).

Both backends exceeded the 16 GiB sampled ceiling and every run was terminated,
so **no true peak working set was established for either backend** — each figure
below is a lower bound taken mid-climb.

Metal never finished loading. Two runs stopped at 25.9 s and 23.1 s with peak
sampled resident sets of 17.53 GB and 18.35 GB, emitting no load time, prefill,
decode or unload measurement at all. For a 10.51 GB artifact that is over 1.75×
artifact bytes in host RSS alone, and resident set is not the Metal footprint.

CPU loaded in 1.9 s and generated, which is the first actual Candle
compatibility evidence for this artifact: it reports architecture `qwen3`,
quantization `Q5_K_M` and context length 8192. Decoding is deterministic at
temperature 0 — warm repeats and both independent processes produced identical
output digests at 509 and 1019 framed tokens. Resident set was about 1.5×
artifact bytes after load, then climbed monotonically from about 16.0 GB to
about 17.2 GB across the 2048-token phase without returning, which is where both
runs were terminated. Prefill is roughly linear at about 11.3 tokens per second:
44 s at 509 framed tokens and 90 s at 1019, making a 512-token frame cost about
54 s end to end. Pressure stayed normal and no swapout pages were added in any
run on this host.

### Resident set is not an overstatement

The supervisor now samples `phys_footprint` — the metric macOS itself uses for
pressure and jetsam — alongside `ps` RSS, and stops on either. This was added to
test whether RSS was inflating the figures by counting clean file-backed pages
from the mapped GGUF, which the kernel can evict for free.

It is not. `phys_footprint` tracks RSS within about 0.4 GB across the whole run
and peaks **higher** on both backends — CPU 17.18 GB against RSS 17.16 GB, Metal
19.33 GB against RSS 18.73 GB — because it excludes clean file-backed pages and
includes compressed ones. The working set is real anonymous memory: weights are
materialized rather than mapped, and the ceiling breach is genuine demand.

The margin over artifact bytes is large and backend-dependent: roughly 4.5 GB on
CPU and over 8.8 GB on Metal for the same 10.51 GB file. Weight bytes therefore
underestimate demand, which is the eligibility question raised in issue #12.

### Where the working set goes

The artifact's own GGUF header accounts for nearly all of the gap. Tensor
payload is 10.509 GB, and candle reads each tensor into an owned buffer rather
than mapping it, so all of it becomes dirty anonymous memory. On top of that
`token_embd.weight` — 5,120 x 151,936 at Q5_K, 0.535 GB on disk — is
**dequantized to F32 at load**, which is 3.112 GB of new memory, and the
quantized source tensor stays alive alongside the F32 copy until model
construction returns.

| Component | Bytes |
| --- | --- |
| Tensor payload read into owned buffers | 10.509 GB |
| `token_embd.weight` dequantized to F32 | 3.112 GB |
| Quantized embedding retained during load | 0.535 GB |
| Accounted total during load | 14.156 GB |

Measured `phys_footprint` after load was 15.03 GB, leaving about 0.9 GB for
allocator retention, the transient per-tensor double buffer, and the
152,000-entry tokenizer vocabulary. The steady-state prediction once model
construction returns — 10.509 + 3.112, about 13.6 GB — matches the 13.91 GB dip
the CPU run actually recorded at 77.5 s.

Embeddings are **not** tied in this artifact: `output.weight` is present
separately as Q6_K (0.638 GB) and is kept quantized, so a duplicated embedding
is not part of the total. The F32 embedding copy alone is about 22% of the
working set; keeping it at F16 would return roughly 1.6 GB, and keeping it
quantized roughly 2.6 GB. That has not been attempted or measured.

### Corrections found while measuring

Three defects in the measurement chain were found and fixed; the figures above
are the corrected ones.

**Metal prefill timing was fabricated, in production code.** `prompt_ms` stopped
its clock immediately after the forward pass, but Metal only *enqueues* GPU
work there, so the reported prefill was enqueue latency — 6 to 11 ms for a
1000-token prompt — and its real cost silently reappeared inside `decode_ms`.
That figure is returned in `GenerateResult` and shown by diagnostics, so the GUI
was reporting a fake prefill time. The device is now synchronized before the
clock stops: 509 framed tokens cost 1,487 ms and 1,019 cost 3,094 ms, which is
about 342 tokens per second against CPU's 11.3.

**`phys_footprint` readings carried false precision.** `footprint -p` rounds
large processes to whole GB, so early readings were exact whole GiB values
dressed up with two decimals. The probe now uses `footprint -j`, which is
byte-exact and also exposes `phys_footprint_peak` — a kernel high-water mark
that, unlike a sampled maximum, cannot miss a transient between samples.

**The record was lost exactly when a run was most extreme.** A child inside an
uninterruptible GPU call survived both signals, and the unhandled second `wait`
raised, killing the supervisor before it wrote its `finished` record.
`terminate` no longer raises and the record reports `child_reaped`.

A fourth problem followed from the third: the soft stop tested only the current
sampled footprint, so an allocation that spiked and subsided between samples
never triggered it — under a 48 GiB ceiling the kernel high-water mark reached
58.09 GB. The stop now tests the kernel peak as well.

### Metal's constraint is the transient, not the steady state

Once loaded, Metal settles near 17.7 GB resident, close to CPU. But transient
GPU allocations during generation grow with prompt length and are invisible to
RSS: while RSS stayed flat at 17.68 GB, the kernel high-water mark climbed to
58.09 GB on a 64 GiB host.

That number is **an upper bound on what this host permitted, not a prediction of
demand on a smaller one**. With 64 GiB available the allocator and the Metal
driver take what is there: transient buffers are allocated and cached because
there is headroom, the compressor stays lazy, and purgeable GPU memory is never
reclaimed. A 32 GB machine would be forced into different behaviour long before
58 GB — earlier compression, earlier eviction of purgeable buffers, allocation
failure, or differently sized driver caches. Which of those happens cannot be
determined from this host, so no statement about whether the artifact fits a
32 GB machine follows from these runs, in either direction.

The same caveat applies more weakly to the CPU figures. Anonymous dirty memory
must be backed somewhere, so the 19.17 GB peak transfers better than a GPU
transient does — but under a 32 GB budget compression and swap would engage
earlier and change the timings, so it is still not a 32 GB measurement.

Whether `phys_footprint` attributing unified-memory GPU allocations this way
reflects pressure identically to anonymous CPU memory has also not been
independently confirmed.

Those raised-ceiling runs are not routine: they pushed this host into heavy
swapping, growing swap from 1.03 GB used of a 2 GB file to 15.1 GB of a 16 GB
file. Do not repeat them without cause.

### The complete CPU run

Raising the per-phase limit to 6 minutes let one run finish every phase for the
first time on either backend: exit 0 after 1,119 s at a 22 GiB ceiling, with
pressure normal and no swapouts added.

| Framed tokens | Prefill | Decode (64 tokens) |
| --- | --- | --- |
| 509 | 44,391 / 44,188 ms | 9,155 / 9,208 ms |
| 1,019 | 89,407 / 89,287 ms | 11,340 / 11,265 ms |
| 2,045 | 185,741 / 185,231 ms | 15,715 / 15,702 ms |

A 2048-token prompt therefore costs over three minutes of prefill on CPU. The
widest phase also sets the peak: 19.17 GB resident and a 19.24 GB kernel
footprint, against the 17.53 GB a run reached when it stopped after 1,024
tokens. Any envelope taken from a narrower phase understates the real one.

**Cancellation is not bounded.** The probe signalled after 100 ms; the call
returned 185,050 ms later — the entire prefill — with `worker_preemption_proven`
false and the phase at signal not observable. The prose limitation recorded for
task #100 is now quantified: a caller who cancels a 2048-token CPU request waits
over three minutes. Recovery after cancel did succeed, with the same token count
and valid output.

**Unload does not return the working set.** It reports success in 64 ms, but
external sampling shows resident memory holding near 17.8 GB for the remaining
ten seconds — essentially the whole working set. Allocator retention could
account for part of it, though large tensor allocations would normally be
unmapped on free, so this needs a dedicated check before it is settled. As it
stands, `idle_unload_min` would report a model unloaded while returning nothing
the machine can use.

Metal still has none of these four measurements: its transient GPU allocation
stops a run before the 2048-token phase is reached.

What this does **not** establish: any 32 GB claim, the 2048-token envelope,
cancellation, recovery or unload behaviour on either backend, answer quality
under the correct non-thinking framing, or a p95 latency. The challenger
`Qwen3-Coder-30B-A3B-Instruct-Q3_K_S` artifact has not been downloaded or
screened.
