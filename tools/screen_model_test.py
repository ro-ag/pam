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

    def test_footprint_is_parsed_with_its_unit_and_refused_when_unrecognized(self):
        report = "Auxiliary data:\n    phys_footprint: 15,032,385 KB\n    phys_footprint_peak: 16 GB\n"
        self.assertEqual(screen.parse_footprint(report), 15_032_385 * 1024)
        self.assertEqual(screen.parse_footprint("  phys_footprint: 1.5 GB\n"), int(1.5 * 1024**3))
        for bad in ("phys_footprint: 12 QB\n", "phys_footprint_peak: 12 GB\n", "nothing here"):
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
