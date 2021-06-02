import unittest

from errorlog_insight.classify import classify
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class SchedulerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = classify(read_entries(fixture("nonyielding.log")))

    def test_count_and_codes(self):
        self.assertEqual([f.code for f in self.findings], ["17883", "17883", "17884", "17884", "17883"])

    def test_cpu_bound_worker(self):
        f = self.findings[0]
        self.assertEqual(f.details["scheduler"], 3)
        self.assertEqual(f.details["pattern"], "cpu-bound")
        self.assertEqual(f.details["interval_ms"], 70030)
        self.assertEqual(f.severity, "error")

    def test_long_interval_is_critical(self):
        self.assertEqual(self.findings[1].severity, "critical")

    def test_stalled_worker_blames_something_outside_sql(self):
        f = self.findings[4]
        self.assertEqual(f.details["pattern"], "stalled")
        self.assertIn("outside SQL Server", f.advice)

    def test_starvation(self):
        f = self.findings[2]
        self.assertEqual(f.details["seconds"], 60)
        self.assertEqual(f.details["system_idle"], 92)
        self.assertEqual(self.findings[3].details["seconds"], 120)


if __name__ == "__main__":
    unittest.main()
