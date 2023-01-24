import unittest

from errorlog_insight.classify import classify
from errorlog_insight.rules.io import volume_of
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class IoStallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = classify(read_entries(fixture("io_stalls.log")))

    def test_only_stall_messages_are_classified(self):
        self.assertEqual(len(self.findings), 7)
        self.assertTrue(all(f.code == "833" for f in self.findings))

    def test_extracts_file_database_and_duration(self):
        first = self.findings[0]
        self.assertEqual(first.details["file"], "E:\\SQLData\\Sales_Data1.mdf")
        self.assertEqual(first.details["database"], "Sales")
        self.assertEqual(first.details["database_id"], 5)
        self.assertEqual(first.details["seconds"], 15)
        self.assertEqual(first.details["count"], 3)
        self.assertEqual(first.details["offset"], "0x000000a1c60000")

    def test_severity_grows_with_duration(self):
        severities = [f.severity for f in self.findings[:5]]
        self.assertEqual(severities, ["warning", "warning", "warning", "error", "error"])

    def test_log_file_is_labelled(self):
        log = self.findings[2]
        self.assertEqual(log.details["file_kind"], "log")
        self.assertEqual(log.details["volume"], "F:")
        self.assertIn("commits", log.advice)

    def test_network_share(self):
        last = self.findings[-1]
        self.assertTrue(last.details["network"])
        self.assertEqual(last.details["volume"], "\\\\FILESRV01\\SQLData")

    def test_volume_of(self):
        self.assertEqual(volume_of("e:\\data\\x.mdf"), "E:")
        self.assertEqual(volume_of("\\\\nas\\share\\dir\\x.ndf"), "\\\\nas\\share")


if __name__ == "__main__":
    unittest.main()
