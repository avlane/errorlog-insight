import unittest

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class CorruptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("corruption.log"))
        cls.findings = classify(cls.entries)

    def test_sequence_and_severity(self):
        self.assertEqual([f.code for f in self.findings], ["825", "824", "823", "824"])
        self.assertEqual([f.severity for f in self.findings], ["error", "critical", "critical", "critical"])

    def test_checksum_error(self):
        f = self.findings[1]
        self.assertEqual(f.details["kind"], "incorrect checksum")
        self.assertEqual(f.details["detail"], "expected: 0x1a2b3c4d; actual: 0x5e6f7a8b")
        self.assertEqual((f.details["file_id"], f.details["page"], f.details["database_id"]), (1, 123456, 5))
        self.assertEqual(f.details["operation"], "read")
        self.assertEqual(f.details["path"], "E:\\SQLData\\Sales_Data1.mdf")
        self.assertEqual(f.details["error_severity"], 24)

    def test_torn_page_on_write(self):
        f = self.findings[3]
        self.assertEqual(f.details["kind"], "torn page")
        self.assertEqual(f.details["operation"], "write")
        self.assertEqual(f.details["database_id"], 7)

    def test_os_error(self):
        f = self.findings[2]
        self.assertEqual(f.details["os_error"], 1117)
        self.assertIn("I/O device error", f.details["os_error_text"])
        self.assertIn("DBCC CHECKDB", f.advice)

    def test_retry(self):
        f = self.findings[0]
        self.assertEqual(f.details["failures"], 1)
        self.assertEqual(f.details["kind"], "incorrect checksum")
        self.assertIn("failing hardware", f.advice)

    def test_nothing_left_over(self):
        self.assertEqual(unclassified(self.entries, self.findings), [])


if __name__ == "__main__":
    unittest.main()
