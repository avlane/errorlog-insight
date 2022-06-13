import unittest

from errorlog_insight.classify import classify
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class DataMovementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = classify(read_entries(fixture("ag_datamovement.log")))

    def test_sequence(self):
        self.assertEqual([f.code for f in self.findings],
                         ["35264", "35264", "35265", "35265", "35264", "35265", "35264"])

    def test_system_suspend_from_redo(self):
        f = self.findings[0]
        self.assertEqual(f.details["database"], "Sales")
        self.assertEqual(f.details["reason"], "SUSPEND_FROM_REDO")
        self.assertEqual(f.details["source_id"], 2)
        self.assertFalse(f.details["by_user"])
        self.assertEqual(f.severity, "error")
        self.assertIn("redo thread", f.advice)

    def test_user_suspend_is_only_a_warning(self):
        f = self.findings[4]
        self.assertTrue(f.details["by_user"])
        self.assertEqual(f.severity, "warning")
        self.assertIn("HADR SUSPEND", f.advice)

    def test_partner_suspend(self):
        f = self.findings[6]
        self.assertEqual(f.details["reason"], "SUSPEND_FROM_PARTNER")
        self.assertEqual(f.details["database"], "Reporting")

    def test_resume(self):
        f = self.findings[2]
        self.assertEqual(f.severity, "info")
        self.assertEqual(f.details["database"], "Sales")


if __name__ == "__main__":
    unittest.main()
