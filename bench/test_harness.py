#!/usr/bin/env python3
"""Tests for the parts of the harness that must not be wrong.

The sanity assertion is the only thing standing between a broken measurement
and a slide, so it needs a test that proves it fires. Percentiles need one
because an off-by-one in a percentile is invisible in the output.

Run: python3 bench/test_harness.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Measurement, check_sanity, parse_pgbench_logs, percentile  # noqa: E402


def meas(config: str, workload: str, p50_us: float) -> Measurement:
    # A flat distribution, so every percentile equals p50_us.
    return Measurement(config, workload, 1, 8, 120, tps=1000.0,
                       latencies_us=[p50_us] * 100)


class TestPercentile(unittest.TestCase):
    def test_nearest_rank_returns_an_observed_value(self):
        v = [float(i) for i in range(1, 101)]
        # Nearest-rank never interpolates, so the answer is always a sample.
        for q in (50, 95, 99):
            self.assertIn(percentile(v, q), v)

    def test_known_values(self):
        v = [float(i) for i in range(1, 101)]
        self.assertEqual(percentile(v, 50), 50.0)
        self.assertEqual(percentile(v, 99), 99.0)
        self.assertEqual(percentile(v, 100), 100.0)

    def test_single_sample(self):
        self.assertEqual(percentile([7.0], 99), 7.0)

    def test_empty_is_nan_not_a_crash(self):
        self.assertNotEqual(percentile([], 50), percentile([], 50))  # NaN


class TestSanityAssertion(unittest.TestCase):
    """A proxy cannot be faster than what it forwards to."""

    NOISE = {"select": {"p50_spread_ms": 0.010}}

    def build(self, **p50_ms) -> dict:
        return {(name, "select"): [meas(name, "select", v * 1000.0)]
                for name, v in p50_ms.items()}

    def test_a_plausible_ordering_passes(self):
        r = self.build(direct=0.25, haproxy=0.50, prism_plain=0.75,
                       prism_tls=0.90, pgbouncer=0.73)
        self.assertEqual(check_sanity(r, self.NOISE), [])

    def test_a_proxy_faster_than_its_backend_fails(self):
        # prism_plain sits behind haproxy and cannot beat it.
        r = self.build(direct=0.25, haproxy=0.50, prism_plain=0.30,
                       prism_tls=0.90, pgbouncer=0.73)
        failures = check_sanity(r, self.NOISE)
        self.assertTrue(failures, "a faster-than-its-backend result was accepted")
        self.assertIn("prism_plain", failures[0])
        self.assertIn("haproxy", failures[0])

    def test_haproxy_faster_than_direct_fails(self):
        r = self.build(direct=0.50, haproxy=0.25)
        self.assertTrue(check_sanity(r, self.NOISE))

    def test_tls_faster_than_plaintext_fails(self):
        # Not a topology relationship, but TLS does strictly more work.
        r = self.build(direct=0.25, haproxy=0.50, prism_plain=0.90, prism_tls=0.60)
        failures = check_sanity(r, self.NOISE)
        self.assertTrue(failures)
        self.assertIn("prism_tls", failures[0])

    def test_a_difference_inside_the_noise_floor_is_not_a_failure(self):
        # 0.005 ms faster, noise floor is 0.010 ms. Not a claim either way.
        r = self.build(direct=0.250, haproxy=0.245)
        self.assertEqual(check_sanity(r, self.NOISE), [])

    def test_a_difference_just_outside_the_noise_floor_is_a_failure(self):
        r = self.build(direct=0.250, haproxy=0.235)
        self.assertTrue(check_sanity(r, self.NOISE))

    def test_missing_configurations_are_skipped_not_assumed(self):
        r = self.build(direct=0.25)
        self.assertEqual(check_sanity(r, self.NOISE), [])

    def test_a_zero_noise_floor_still_works(self):
        r = self.build(direct=0.50, haproxy=0.49)
        self.assertTrue(check_sanity(r, {"select": {"p50_spread_ms": 0.0}}))


class TestLogParsing(unittest.TestCase):
    def test_latency_comes_from_the_third_field(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            # client_id transaction_no time script_no time_epoch time_us
            (p / "run.123").write_text(
                "0 1 1234 0 1700000000 500000\n"
                "0 2 5678 0 1700000000 600000\n"
            )
            self.assertEqual(parse_pgbench_logs(p, "run"), [1234.0, 5678.0])

    def test_malformed_lines_are_skipped(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "run.1").write_text("garbage\n0 1 900 0 1 2\n\n0 2 x 0 1 2\n")
            self.assertEqual(parse_pgbench_logs(p, "run"), [900.0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
