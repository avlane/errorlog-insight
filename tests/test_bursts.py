import unittest
from datetime import datetime, timedelta

from errorlog_insight.bursts import BurstConfig, detect_bursts, find_bursts
from errorlog_insight.classify import classify
from errorlog_insight.reader import read_entries
from tests.helpers import fixture

T0 = datetime(2022, 8, 1, 12, 0, 0)


def at(*seconds):
    return [T0 + timedelta(seconds=s) for s in seconds]


class DetectTests(unittest.TestCase):
    def test_quiet_log_has_no_burst(self):
        self.assertEqual(detect_bursts(at(0, 600, 1200, 1800)), [])

    def test_spike_after_quiet_period(self):
        stamps = at(0, 1000) + at(*[3600 + i for i in range(8)])
        (burst,) = detect_bursts(stamps, key="x")
        self.assertEqual(burst.count, 8)
        self.assertEqual(burst.peak, 8)
        self.assertEqual(burst.start, datetime(2022, 8, 1, 13, 0))
        self.assertEqual(burst.end, datetime(2022, 8, 1, 13, 1))
        self.assertEqual(burst.key, "x")

    def test_below_min_count_is_ignored(self):
        self.assertEqual(detect_bursts(at(0, 1, 2, 3)), [])

    def test_steady_rate_is_not_a_burst(self):
        # six events every minute for an hour: the baseline already is six per bucket
        stamps = at(*[m * 60 + k for m in range(60) for k in range(6)])
        bursts = detect_bursts(stamps)
        self.assertTrue(all(b.start < T0 + timedelta(minutes=2) for b in bursts))

    def test_adjacent_buckets_merge(self):
        stamps = at(*([3600 + i for i in range(6)] + [3660 + i for i in range(9)]))
        (burst,) = detect_bursts(stamps)
        self.assertEqual(burst.count, 15)
        self.assertEqual(burst.peak, 9)
        self.assertEqual(burst.end, datetime(2022, 8, 1, 13, 2))

    def test_separate_bursts(self):
        stamps = at(*([100 + i for i in range(6)] + [7200 + i for i in range(6)]))
        self.assertEqual(len(detect_bursts(stamps)), 2)

    def test_factor_and_window_are_configurable(self):
        stamps = at(*([i * 60 for i in range(30)] + [1800 + i for i in range(5)]))
        self.assertEqual(len(detect_bursts(stamps, BurstConfig(factor=3.0))), 1)
        self.assertEqual(detect_bursts(stamps, BurstConfig(factor=10.0)), [])


class FindingBurstTests(unittest.TestCase):
    def test_login_failures_burst(self):
        findings = classify(read_entries(fixture("login_failures.log")))
        bursts = find_bursts(findings)
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0].key, "18456")
        self.assertEqual(bursts[0].count, 6)

    def test_info_findings_are_ignored(self):
        findings = classify(read_entries(fixture("startup_2019.log")))
        self.assertEqual(find_bursts(findings), [])


if __name__ == "__main__":
    unittest.main()
