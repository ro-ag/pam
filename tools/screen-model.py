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
OUTPUT_LIMIT = 16 * 1024**2
DEADLINE = 1200
INTERVAL = 0.5


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


def stop_reason(sample, baseline, elapsed):
    if elapsed >= DEADLINE:
        return "deadline"
    if sample["rss_bytes"] > RSS_LIMIT:
        return "sampled_rss_limit"
    if sample["pressure"] != 1:
        return "system_pressure"
    if sample["swapout_pages"] > baseline["swapout_pages"]:
        return "added_system_swapouts"
    return None


def terminate(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)


def validate_binary(raw):
    path = Path(raw).resolve(strict=True)
    if not re.fullmatch(r"resource_screen-[0-9a-f]+", path.name):
        raise ValueError("expected an already-built resource_screen-<hex> test binary")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("test binary must be an executable regular file")
    return path


def supervise(binary, destination):
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    start = time.monotonic()
    child = None
    maximum = 0
    reason = None
    counts = {"stdout": 0, "stderr": 0}
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
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
            emit("baseline", **baseline, rss_limit_bytes=RSS_LIMIT,
                 deadline_seconds=DEADLINE, sample_interval_seconds=INTERVAL,
                 macos_version=command(["/usr/bin/sw_vers", "-productVersion"]).strip(),
                 host_memory_bytes=int(command(["/usr/sbin/sysctl", "-n", "hw.memsize"])),
                 attribution="ambient system activity cannot be attributed to PAM",
                 cap="sampled soft stop, not an OS hard cap", rss_is_metal_total=False)
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
                    maximum = max(maximum, state["rss_bytes"])
                    emit("sample", **state,
                         added_swapout_pages=max(0, state["swapout_pages"] - baseline["swapout_pages"]))
                    reason = stop_reason(state, baseline, time.monotonic() - start)
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
                terminate(child)
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
                 max_sampled_rss_bytes=maximum, output_bytes=counts,
                 children_ru_maxrss=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
                 children_ru_maxrss_before=usage_before, ru_maxrss_units="bytes_on_macos",
                 ru_maxrss_scope="all supervisor children including measurement commands",
                 qualification="not_assessed")
    return 1 if reason or child is None else child.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="already-built resource_screen-<hex> executable")
    parser.add_argument("--output-dir", required=True, help="new directory; existing paths are refused")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("macOS only: measurement units and pressure probes are platform-specific")
    try:
        return supervise(validate_binary(args.binary), Path(args.output_dir))
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
