import unittest

from errorlog_insight.classify import classify
from errorlog_insight.rules.io import volume_of
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class IoStallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.all_findings = classify(read_entries(fixture("io_stalls.log")))
        cls.findings = [f for f in cls.all_findings if f.code == "833"]

    def test_stall_messages_are_classified(self):
        self.assertEqual(len(self.findings), 7)

    def test_flushcache_and_snapshot_freeze_are_classified_too(self):
        self.assertEqual([f.code for f in self.all_findings if f.code != "833"],
                         ["io-frozen", "io-resumed", "flushcache", "flushcache"])

    def test_flushcache_details(self):
        slow, quick = [f for f in self.all_findings if f.code == "flushcache"]
        self.assertEqual(slow.details["buffers"], 150321)
        self.assertEqual(slow.details["milliseconds"], 71530)
        self.assertEqual(slow.details["throughput_mb_per_sec"], 16.42)
        self.assertEqual(slow.details["avg_write_latency_ms"], 1)
        self.assertEqual(slow.severity, "warning")
        self.assertIn("833", slow.advice)
        self.assertEqual(quick.severity, "info")

    def test_freeze_and_resume(self):
        frozen, resumed = [f for f in self.all_findings if f.code in ("io-frozen", "io-resumed")]
        self.assertEqual(frozen.details["database"], "Sales")
        self.assertEqual(resumed.details["database"], "Sales")
        self.assertLess(frozen.entry.timestamp, resumed.entry.timestamp)

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
