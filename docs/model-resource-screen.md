# Opt-in model resource screening

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

It samples child RSS (`ps`, KiB converted to bytes), system pressure
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

The template is explicitly **unqualified**: current production ChatML is used
without adding a harness-only non-thinking template. There is no fresh daemon
working-set admission in this direct runtime path. Record OS/architecture, backend,
GGUF architecture/quantization and source revision of the PAM checkout with the
results. A successful screen on a 64 GiB host remains a 64 GiB measurement, even
when its workload is capped. Run the independent incident benchmark only after
resource and template limitations have been adjudicated.

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

What this does **not** establish: any 32 GB claim, the 2048-token envelope,
cancellation, recovery or unload behaviour on either backend, answer quality
under the correct non-thinking framing, or a p95 latency. The challenger
`Qwen3-Coder-30B-A3B-Instruct-Q3_K_S` artifact has not been downloaded or
screened.
