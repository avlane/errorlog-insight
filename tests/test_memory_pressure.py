import unittest

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class MemoryPressureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("memory_pressure.log"))
        cls.findings = classify(cls.entries)

    def test_sequence(self):
        self.assertEqual([f.code for f in self.findings], ["17890"] * 3 + ["8645", "8645", "701"])

    def test_paged_out_details(self):
        f = self.findings[1]
        self.assertEqual(f.details["duration_seconds"], 301)
        self.assertEqual(f.details["working_set_kb"], 9437184)
        self.assertEqual(f.details["committed_kb"], 25165824)
        self.assertEqual(f.details["memory_utilization"], 37)

    def test_severity_follows_utilization_and_duration(self):
        self.assertEqual([f.severity for f in self.findings[:3]], ["warning", "error", "error"])

    def test_grant_timeout(self):
        f = self.findings[3]
        self.assertEqual(f.details["pool"], "default")
        self.assertEqual(f.details["pool_id"], 2)
        self.assertEqual(f.details["error_state"], 1)

    def test_old_wording_without_pool(self):
        from datetime import datetime
        from errorlog_insight.model import Entry
        e = Entry(datetime(2024, 1, 9), "spid55", "A timeout occurred while waiting for memory resources to execute the query. Rerun the query.")
        (f,) = classify([e])
        self.assertIsNone(f.details["pool"])

    def test_nothing_left_over(self):
        self.assertEqual(unclassified(self.entries, self.findings), [])


if __name__ == "__main__":
    unittest.main()
