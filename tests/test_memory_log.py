import unittest

from errorlog_insight.classify import classify
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class MemoryAndLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = classify(read_entries(fixture("memory_logfull.log")))

    def test_codes_in_order(self):
        self.assertEqual([f.code for f in self.findings],
                         ["701", "701", "802", "9002", "9002", "9002", "9002"])

    def test_701_details(self):
        f = self.findings[0]
        self.assertEqual(f.details["pool"], "default")
        self.assertEqual(f.details["error_state"], 123)
        self.assertEqual(f.severity, "error")

    def test_802_has_state(self):
        self.assertEqual(self.findings[2].details["error_state"], 20)

    def test_log_full_reuse_wait(self):
        waits = [f.details["log_reuse_wait"] for f in self.findings[3:]]
        self.assertEqual(waits, ["ACTIVE_TRANSACTION", "LOG_BACKUP", None, "AVAILABILITY_REPLICA"])

    def test_log_full_is_critical_with_specific_advice(self):
        f = self.findings[3]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.details["database"], "Sales")
        self.assertIn("DBCC OPENTRAN", f.advice)

    def test_old_message_form_gets_default_advice(self):
        f = self.findings[5]
        self.assertEqual(f.details["database"], "Staging")
        self.assertIn("log_reuse_wait_desc", f.advice)
        self.assertEqual(f.title, "Transaction log of Staging is full")


if __name__ == "__main__":
    unittest.main()
