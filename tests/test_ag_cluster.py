import unittest

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class ClusterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("ag_lease.log"))
        cls.findings = classify(cls.entries)

    def test_sequence(self):
        self.assertEqual([f.code for f in self.findings], ["17883", "19407", "19421", "19421", "41005"])

    def test_lease_expired_is_critical(self):
        f = self.findings[1]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.details["ag"], "AG_Sales")
        self.assertEqual(f.details["error_severity"], 16)
        self.assertIn("17883", f.advice)

    def test_renewal_failure(self):
        f = self.findings[2]
        self.assertEqual(f.severity, "error")
        self.assertEqual(f.details["because"], "the existing lease is no longer valid")

    def test_quorum_loss(self):
        self.assertEqual(self.findings[4].severity, "critical")
        self.assertIn("witness", self.findings[4].advice)

    def test_nothing_left_over(self):
        self.assertEqual(unclassified(self.entries, self.findings), [])


if __name__ == "__main__":
    unittest.main()
