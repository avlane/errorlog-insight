import unittest

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class CheckdbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("checkdb.log"))
        cls.findings = classify(cls.entries)

    def test_sequence(self):
        self.assertEqual([f.code for f in self.findings], ["17573", "checkdb", "checkdb", "checkdb", "checkdb"])

    def test_clean_run(self):
        f = self.findings[1]
        self.assertEqual(f.severity, "info")
        self.assertEqual(f.details["target"], "Sales")
        self.assertEqual(f.details["elapsed_seconds"], 12 * 60 + 33)
        self.assertEqual(f.details["user"], "CONTOSO\\svc_sqlagent")
        self.assertIsNone(f.details["options"])

    def test_errors_found(self):
        f = self.findings[2]
        self.assertEqual(f.severity, "critical")
        self.assertEqual((f.details["errors_found"], f.details["errors_repaired"]), (3, 0))
        self.assertEqual(f.details["options"], "no_infomsgs")
        self.assertIn("NO_INFOMSGS", f.advice)

    def test_repair_mode(self):
        f = self.findings[3]
        self.assertTrue(f.details["repair_mode"])
        self.assertEqual(f.details["arguments"], ["repair_allow_data_loss"])
        self.assertIn("last good backup", f.advice)

    def test_checktable_target(self):
        f = self.findings[4]
        self.assertEqual(f.details["command"], "CHECKTABLE")
        self.assertEqual(f.details["target"], "Sales.dbo.Orders")

    def test_nothing_left_over(self):
        self.assertEqual(unclassified(self.entries, self.findings), [])


if __name__ == "__main__":
    unittest.main()
