import unittest

from errorlog_insight.classify import classify
from errorlog_insight.insights import find_insights, of_code, server_of
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


def findings_of(*pairs):
    out = []
    for label, name in pairs:
        out.extend(classify(read_entries(fixture(name), replica=label)))
    return out


class IoMaintenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = findings_of(("SQLPROD01", "insight_io.log"))
        cls.insights = find_insights(cls.findings)

    def test_two_overlaps_found(self):
        self.assertEqual([i.code for i in self.insights], ["io-during-checkdb", "io-during-snapshot"])

    def test_checkdb_overlap(self):
        i = self.insights[0]
        self.assertEqual(i.severity, "error")   # a 30 second stall
        self.assertEqual(i.confidence, "high")
        self.assertIn("DBCC consistency checking was running on Sales", i.title)
        self.assertEqual([f.code for f in i.evidence], ["833", "833", "checkdb"])
        self.assertIn("quiet period", i.advice)

    def test_snapshot_overlap(self):
        i = self.insights[1]
        self.assertEqual(i.severity, "warning")
        self.assertIn("a snapshot backup froze I/O on Sales", i.title)
        self.assertEqual([f.code for f in i.evidence], ["833", "io-frozen"])

    def test_unrelated_stall_is_not_explained(self):
        stalls = of_code(self.findings, "833")
        explained = {id(f) for i in self.insights for f in i.evidence}
        self.assertEqual([f.entry.timestamp.hour for f in stalls if id(f) not in explained], [5])

    def test_other_server_does_not_explain_it(self):
        mixed = findings_of(("SQLPROD01", "io_stalls.log"), ("SQLDR02", "insight_io.log"))
        for f in mixed:
            if f.entry.replica == "SQLDR02" and f.code != "833":
                f.entry.replica = "SQLDR03"
        self.assertEqual(find_insights(mixed), [])

    def test_server_of_falls_back_to_the_file(self):
        f = classify(read_entries(fixture("insight_io.log")))[0]
        self.assertTrue(server_of(f).endswith("insight_io.log"))

    def test_no_insights_for_quiet_logs(self):
        self.assertEqual(find_insights(findings_of(("A", "noise.log"), ("A", "startup_2019.log"))), [])


if __name__ == "__main__":
    unittest.main()
