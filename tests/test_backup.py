import unittest

from errorlog_insight.classify import classify
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class BackupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = classify(read_entries(fixture("backup_failures.log")))

    def codes(self):
        return [f.code for f in self.findings]

    def test_sequence(self):
        self.assertEqual(self.codes(), ["18204", "3041", "3201", "3041", "18264", "18265",
                                        "18204", "3041", "4208"])

    def test_network_path_error(self):
        f = self.findings[0]
        self.assertEqual(f.details["os_error"], 53)
        self.assertTrue(f.details["network"])
        self.assertIn("file server", f.advice)

    def test_failed_backup_database_and_kind(self):
        self.assertEqual(self.findings[1].details["database"], "Sales")
        self.assertEqual(self.findings[1].details["kind"], "database")
        self.assertEqual(self.findings[3].details["kind"], "log")
        self.assertEqual(self.findings[3].details["database"], "Reporting")

    def test_bracketed_name_and_options(self):
        f = self.findings[7]
        self.assertEqual(f.details["database"], "Archive")
        self.assertEqual(f.details["command"], "BACKUP DATABASE [Archive] WITH COPY_ONLY")

    def test_access_denied(self):
        f = self.findings[2]
        self.assertEqual(f.details["os_error"], 5)
        self.assertFalse(f.details["network"])
        self.assertIn("write permission", f.advice)

    def test_success_messages_are_info(self):
        ok = self.findings[4]
        self.assertEqual(ok.severity, "info")
        self.assertEqual(ok.details["pages"], 412876)
        log = self.findings[5]
        self.assertEqual(log.details["kind"], "log")
        self.assertIsNone(log.details["pages"])

    def test_disk_full(self):
        self.assertEqual(self.findings[6].details["os_error"], 112)


if __name__ == "__main__":
    unittest.main()
