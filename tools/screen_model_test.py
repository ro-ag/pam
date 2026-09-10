"""Synthetic supervision checks; never load weights or invoke the model harness."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("screen_model", Path(__file__).with_name("screen-model.py"))
screen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(screen)


class SupervisionTests(unittest.TestCase):
    def test_existing_swap_is_not_added_swap(self):
        baseline = {"swapout_pages": 65536}
        sample = {"swapout_pages": 65536, "pressure": 1, "rss_bytes": 1024}
        self.assertIsNone(screen.stop_reason(sample, baseline, 1))
        sample["swapout_pages"] += 1
        self.assertEqual(screen.stop_reason(sample, baseline, 1), "added_system_swapouts")

    def test_footprint_json_gives_exact_bytes_and_the_kernel_peak(self):
        # The text output rounds large processes to whole GB; only the JSON
        # form is byte-exact, and its peak is a kernel high-water mark that a
        # sampled maximum can miss between intervals.
        payload = {"processes": [{"auxiliary": {"phys_footprint": 15032385536,
                                                "phys_footprint_peak": 42949672961}}]}
        self.assertEqual(screen.parse_footprint(payload), (15032385536, 42949672961))
        for bad in ({}, {"processes": []}, {"processes": [{}]},
                    {"processes": [{"auxiliary": {"phys_footprint": "15 GB"}}]},
                    {"processes": [{"auxiliary": {"phys_footprint": 1}}]}):
            with self.assertRaises(ValueError):
                screen.parse_footprint(bad)

    def test_footprint_over_the_limit_stops_the_run_even_when_rss_fits(self):
        # phys_footprint counts compressed pages that ps RSS does not, so it can
        # cross the ceiling first; a missing reading must never imply zero.
        sample = {"swapout_pages": 0, "pressure": 1, "rss_bytes": 1024,
                  "phys_footprint_bytes": screen.FOOTPRINT_LIMIT}
        self.assertIsNone(screen.stop_reason(sample, sample, 1))
        sample["phys_footprint_bytes"] += 1
        self.assertEqual(screen.stop_reason(sample, sample, 1), "sampled_footprint_limit")
        del sample["phys_footprint_bytes"]
        self.assertIsNone(screen.stop_reason(sample, sample, 1))

    def test_explicit_limits_override_the_default_ceiling(self):
        # A raised ceiling measures this host honestly; it never becomes a
        # smaller-host admission decision, so the run records which was used.
        sample = {"swapout_pages": 0, "pressure": 1,
                  "rss_bytes": screen.RSS_LIMIT + 1, "phys_footprint_bytes": 1024}
        self.assertEqual(screen.stop_reason(sample, sample, 1), "sampled_rss_limit")
        raised = (screen.RSS_LIMIT * 2, screen.FOOTPRINT_LIMIT * 2)
        self.assertIsNone(screen.stop_reason(sample, sample, 1, raised))
        sample["rss_bytes"] = raised[0] + 1
        self.assertEqual(screen.stop_reason(sample, sample, 1, raised), "sampled_rss_limit")

    def test_limit_bounds_are_enforced(self):
        self.assertLess(screen.MIN_LIMIT, screen.RSS_LIMIT)
        self.assertLess(screen.RSS_LIMIT, screen.MAX_LIMIT)
        for bad in (screen.MIN_LIMIT - 1, screen.MAX_LIMIT + 1, 0, -1):
            self.assertFalse(screen.MIN_LIMIT <= bad <= screen.MAX_LIMIT)

    def test_terminate_never_raises_when_a_child_cannot_be_reaped(self):
        # Losing the measurement record is worse than leaving a reap to the OS.
        class Stubborn:
            returncode = None

            def __init__(self):
                self.signals = []

            def poll(self):
                return None

            def terminate(self):
                self.signals.append("terminate")

            def kill(self):
                self.signals.append("kill")

            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired("child", timeout)

        child = Stubborn()
        self.assertFalse(screen.terminate(child))
        self.assertEqual(child.signals, ["terminate", "kill"])

    def test_kernel_peak_over_the_ceiling_stops_a_run_the_sampled_value_missed(self):
        # Observed for real: a 48 GiB ceiling did not bind while the kernel
        # high-water mark reached 58 GB, because the spike fell between samples.
        sample = {"swapout_pages": 0, "pressure": 1, "rss_bytes": 1024,
                  "phys_footprint_bytes": 1024,
                  "phys_footprint_peak_bytes": screen.FOOTPRINT_LIMIT + 1}
        self.assertEqual(screen.stop_reason(sample, sample, 1), "peak_footprint_limit")
        sample["phys_footprint_peak_bytes"] = screen.FOOTPRINT_LIMIT
        self.assertIsNone(screen.stop_reason(sample, sample, 1))

    def test_stop_thresholds(self):
        sample = {"swapout_pages": 0, "pressure": 1, "rss_bytes": screen.RSS_LIMIT}
        self.assertIsNone(screen.stop_reason(sample, sample, 1))
        sample["rss_bytes"] += 1
        self.assertEqual(screen.stop_reason(sample, sample, 1), "sampled_rss_limit")
        sample["rss_bytes"] = 1
        sample["pressure"] = 2
        self.assertEqual(screen.stop_reason(sample, sample, 1), "system_pressure")
        self.assertEqual(screen.stop_reason(sample, sample, screen.DEADLINE), "deadline")

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileExistsError):
                screen.supervise(Path("unused"), Path(directory))

    def test_child_is_reaped(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            screen.terminate(child)
            self.assertIsNotNone(child.poll())
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


if __name__ == "__main__":
    unittest.main()
