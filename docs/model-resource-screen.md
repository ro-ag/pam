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

Put an external wall-time/process supervisor around this invocation. For example,
a stdlib Python supervisor can enforce a 20-minute process limit:

```sh
python3 - <<'PY'
import os, subprocess
process = subprocess.Popen([os.environ['PAM_SCREEN_BIN'], '--ignored', '--nocapture', '--test-threads=1'])
try:
    raise SystemExit(process.wait(timeout=1200))
except subprocess.TimeoutExpired:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    raise SystemExit('screen process exceeded external time limit')
PY
```

For detailed memory supervision, sample the printed PID with macOS `ps -o rss=`
throughout the run and correlate timestamps with the JSON phase markers. Record
Activity Monitor memory pressure and interval `vm_stat` swapout deltas alongside
it. RSS/max RSS is not total Metal/unified-memory allocation; VM size is not
resident usage. The two-second identity and post-unload windows allow sampling
before loading and after unloading. Before/after swap totals alone cannot prove
that pressure remained normal throughout the run. No memory or slowdown claim is
made by the harness itself. Collect paired timings of the same representative
developer workload with and without the model under the same conditions.

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
