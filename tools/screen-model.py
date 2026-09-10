#!/usr/bin/env python3
"""macOS sampled soft-stop supervision; RSS is not total Metal memory."""
import argparse
import json
import os
from pathlib import Path
import re
import resource
import selectors
import subprocess
import sys
import time

RSS_LIMIT = 16 * 1024**3
FOOTPRINT_LIMIT = 16 * 1024**3
# Widest budget the supervisor will accept. Raising the ceiling produces an
# honest measurement of THIS host, never a smaller-host admission decision.
MAX_LIMIT = 48 * 1024**3
MIN_LIMIT = 1024**3
OUTPUT_LIMIT = 16 * 1024**2
DEADLINE = 1200
INTERVAL = 0.5
FOOTPRINT_UNITS = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}


def command(argv):
    return subprocess.check_output(argv, timeout=2, stderr=subprocess.DEVNULL,
                                   env={"PATH": "/usr/bin:/bin:/usr/sbin", "LC_ALL": "C"},
                                   text=True)


def host_sample():
    pressure = int(command(["/usr/sbin/sysctl", "-n", "kern.memorystatus_vm_pressure_level"]))
    vm = command(["/usr/bin/vm_stat"])
    pages = re.search(r"page size of (\d+) bytes", vm)
    swaps = re.search(r"^Swapouts:\s+(\d+)\.", vm, re.M)
    if not pages or not swaps:
        raise ValueError("unrecognized vm_stat format")
    return {"pressure": pressure, "swapout_pages": int(swaps[1]),
            "page_bytes": int(pages[1])}


def parse_footprint(payload):
    """Exact byte figures from `footprint -j`. The text output rounds large
    processes to whole GB, which silently fabricates precision, so the JSON
    form is the only usable source. `phys_footprint_peak` is the kernel's own
    high-water mark: unlike a sampled maximum it cannot miss a transient
    between samples, which matters because GPU allocations spike and subside
    inside one interval."""
    processes = payload.get("processes") if isinstance(payload, dict) else None
    if not processes or not isinstance(processes, list):
        raise ValueError("unrecognized footprint json")
    auxiliary = processes[0].get("auxiliary")
    if not isinstance(auxiliary, dict):
        raise ValueError("footprint json has no auxiliary data")
    current = auxiliary.get("phys_footprint")
    peak = auxiliary.get("phys_footprint_peak")
    if not isinstance(current, int) or not isinstance(peak, int):
        raise ValueError("footprint json has no integer phys_footprint")
    return current, peak


def read_footprint(pid, scratch):
    subprocess.run(["/usr/bin/footprint", "-j", str(scratch), "-p", str(pid)],
                   timeout=5, check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL,
                   env={"PATH": "/usr/bin:/bin:/usr/sbin", "LC_ALL": "C"})
    with open(scratch, encoding="utf-8") as handle:
        return parse_footprint(json.load(handle))


def stop_reason(sample, baseline, elapsed, limits=None):
    rss_limit, footprint_limit = limits or (RSS_LIMIT, FOOTPRINT_LIMIT)
    if elapsed >= DEADLINE:
        return "deadline"
    if sample["rss_bytes"] > rss_limit:
        return "sampled_rss_limit"
    if sample.get("phys_footprint_bytes", 0) > footprint_limit:
        return "sampled_footprint_limit"
    # The sampled value can sit under the ceiling while a GPU allocation spiked
    # over it between samples; the kernel's high-water mark is what actually
    # happened, so the ceiling binds only if it is checked too.
    if sample.get("phys_footprint_peak_bytes", 0) > footprint_limit:
        return "peak_footprint_limit"
    if sample["pressure"] != 1:
        return "system_pressure"
    if sample["swapout_pages"] > baseline["swapout_pages"]:
        return "added_system_swapouts"
    return None


def terminate(child):
    """Never raise. A child inside an uninterruptible GPU call can outlive both
    signals, and losing the measurement record is worse than leaving a reap to
    the OS - the record is the whole point of the run."""
    if child.poll() is None:
        for signal_child in (child.terminate, child.kill):
            try:
                signal_child()
                child.wait(timeout=5)
                return True
            except subprocess.TimeoutExpired:
                continue
            except OSError:
                return False
        return False
    return True


def validate_binary(raw):
    path = Path(raw).resolve(strict=True)
    if not re.fullmatch(r"resource_screen-[0-9a-f]+", path.name):
        raise ValueError("expected an already-built resource_screen-<hex> test binary")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("test binary must be an executable regular file")
    return path


def supervise(binary, destination, limits=None):
    limits = limits or (RSS_LIMIT, FOOTPRINT_LIMIT)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    start = time.monotonic()
    child = None
    maximum = 0
    peak_footprint = 0
    reason = None
    counts = {"stdout": 0, "stderr": 0}
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    scratch = destination.joinpath("footprint.json")
    with (destination.joinpath("measurements.jsonl").open("x") as journal,
          destination.joinpath("stdout.log").open("xb") as stdout,
          destination.joinpath("stderr.log").open("xb") as stderr,
          selectors.DefaultSelector() as selector):
        def emit(kind, **fields):
            record = {"schema_version": 1, "kind": kind, "unix_seconds": time.time(),
                      "elapsed_seconds": round(time.monotonic() - start, 3), **fields}
            encoded = json.dumps(record, separators=(",", ":"))
            if len(encoded.encode()) > 16384:
                raise ValueError("measurement record too large")
            journal.write(encoded + "\n")
            journal.flush()

        try:
            baseline = host_sample()
            emit("baseline", **baseline, rss_limit_bytes=limits[0],
                 phys_footprint_limit_bytes=limits[1],
                 limits_are_default=limits == (RSS_LIMIT, FOOTPRINT_LIMIT),
                 deadline_seconds=DEADLINE, sample_interval_seconds=INTERVAL,
                 macos_version=command(["/usr/bin/sw_vers", "-productVersion"]).strip(),
                 host_memory_bytes=int(command(["/usr/sbin/sysctl", "-n", "hw.memsize"])),
                 attribution="ambient system activity cannot be attributed to PAM",
                 cap="sampled soft stop, not an OS hard cap", rss_is_metal_total=False,
                 footprint_excludes_clean_file_pages_and_includes_compressed=True)
            if baseline["pressure"] != 1:
                reason = "baseline_system_pressure"
                return 1
            child = subprocess.Popen([str(binary), "--ignored", "--nocapture", "--test-threads=1"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for stream, name, sink in [(child.stdout, "stdout", stdout), (child.stderr, "stderr", stderr)]:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, (name, sink))
            emit("started", pid=child.pid, binary=str(binary))
            next_sample = time.monotonic()
            while child.poll() is None:
                now = time.monotonic()
                if now - start >= DEADLINE:
                    reason = "deadline"
                    break
                if now >= next_sample:
                    state = host_sample()
                    try:
                        rss = command(["/bin/ps", "-o", "rss=", "-p", str(child.pid)]).strip()
                    except subprocess.CalledProcessError:
                        if child.poll() is not None:
                            break
                        raise
                    state["rss_bytes"] = int(rss) * 1024  # ps RSS is KiB on macOS.
                    try:
                        current, kernel_peak = read_footprint(child.pid, scratch)
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                            OSError, ValueError):
                        if child.poll() is not None:
                            break
                        raise
                    state["phys_footprint_bytes"] = current
                    state["phys_footprint_peak_bytes"] = kernel_peak
                    maximum = max(maximum, state["rss_bytes"])
                    peak_footprint = max(peak_footprint, kernel_peak)
                    emit("sample", **state,
                         added_swapout_pages=max(0, state["swapout_pages"] - baseline["swapout_pages"]))
                    reason = stop_reason(state, baseline, time.monotonic() - start, limits)
                    if reason:
                        break
                    next_sample = time.monotonic() + INTERVAL
                for key, _ in selector.select(timeout=0.05):
                    name, sink = key.data
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = OUTPUT_LIMIT - counts[name]
                    sink.write(data[:remaining])
                    counts[name] += min(len(data), remaining)
                    if len(data) > remaining:
                        reason = "output_limit"
                        break
                if reason:
                    break
            if not reason:
                child.wait()
        except (OSError, ValueError, subprocess.SubprocessError):
            # Do not emit arbitrary environment/command text into the measurements.
            reason = "supervision_or_measurement_failed"
        finally:
            if child is not None:
                reaped = terminate(child)
                # Drain only bounded bytes already buffered after the child exits.
                for key in list(selector.get_map().values()):
                    name, sink = key.data
                    while counts[name] < OUTPUT_LIMIT:
                        try:
                            data = os.read(key.fileobj.fileno(), min(65536, OUTPUT_LIMIT - counts[name]))
                        except BlockingIOError:
                            break
                        if not data:
                            break
                        sink.write(data)
                        counts[name] += len(data)
                    if counts[name] == OUTPUT_LIMIT:
                        try:
                            if os.read(key.fileobj.fileno(), 1):
                                reason = "output_limit"
                        except BlockingIOError:
                            pass
                    key.fileobj.close()
            emit("finished", reason=reason, exit_code=None if child is None else child.returncode,
                 child_reaped=child is None or reaped,
                 max_sampled_rss_bytes=maximum,
                 max_phys_footprint_bytes=peak_footprint,
                 phys_footprint_peak_source="kernel high-water mark, not a sampled maximum",
                 output_bytes=counts,
                 children_ru_maxrss=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
                 children_ru_maxrss_before=usage_before, ru_maxrss_units="bytes_on_macos",
                 ru_maxrss_scope="all supervisor children including measurement commands",
                 qualification="not_assessed")
    return 1 if reason or child is None else child.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="already-built resource_screen-<hex> executable")
    parser.add_argument("--output-dir", required=True, help="new directory; existing paths are refused")
    parser.add_argument("--rss-limit-bytes", type=int, default=RSS_LIMIT,
                        help="sampled RSS soft stop; default 16 GiB")
    parser.add_argument("--phys-footprint-limit-bytes", type=int, default=FOOTPRINT_LIMIT,
                        help="sampled phys_footprint soft stop; default 16 GiB")
    args = parser.parse_args()
    limits = (args.rss_limit_bytes, args.phys_footprint_limit_bytes)
    if not all(MIN_LIMIT <= limit <= MAX_LIMIT for limit in limits):
        parser.error(f"memory limits must be between {MIN_LIMIT} and {MAX_LIMIT} bytes")
    if sys.platform != "darwin":
        parser.error("macOS only: measurement units and pressure probes are platform-specific")
    try:
        return supervise(validate_binary(args.binary), Path(args.output_dir), limits)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
