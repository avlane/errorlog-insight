import unittest

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.reader import read_entries
from errorlog_insight.rules.io import volume_of
from errorlog_insight.serverinfo import collect_server_info, describe
from errorlog_insight.summaries import io_summary
from tests.helpers import fixture


class LinuxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("linux_server.log"), replica="SQLLX01")
        cls.findings = classify(cls.entries)

    def by_code(self, code):
        return [f for f in self.findings if f.code == code]

    def test_banner_on_linux(self):
        (startup,) = self.by_code("startup")
        self.assertEqual(startup.details["version_year"], 2022)
        self.assertEqual(startup.details["build"], "16.0.4085.2")
        self.assertEqual(startup.details["edition"], "Developer Edition (64-bit)")
        self.assertEqual(startup.details["os"], "Linux (Ubuntu 22.04.3 LTS) <X64>")

    def test_server_info(self):
        (info,) = collect_server_info(self.entries)
        self.assertEqual(info["platform"], "linux")
        self.assertEqual(info["utc_offset_minutes"], 0)
        self.assertTrue(info["virtual"])
        self.assertIn("Linux (Ubuntu 22.04.3 LTS)", describe(info))

    def test_windows_platform(self):
        (info,) = collect_server_info(read_entries(fixture("startup_2019.log")))
        self.assertEqual(info["platform"], "windows")

    def test_startup_parameters_use_posix_paths(self):
        (params,) = self.by_code("startup-params")
        self.assertIn("-d/var/opt/mssql/data/master.mdf", params.details["parameters"])

    def test_volume_is_the_directory(self):
        self.assertEqual(volume_of("/var/opt/mssql/data/Sales.mdf"), "/var/opt/mssql/data")
        self.assertEqual(volume_of("/Sales.mdf"), "/")
        self.assertEqual(volume_of("E:\\SQLData\\x.mdf"), "E:")

    def test_io_stalls_on_posix_paths(self):
        stalls = self.by_code("833")
        self.assertEqual({f.details["volume"] for f in stalls}, {"/var/opt/mssql/data"})
        self.assertEqual([f.details["file_kind"] for f in stalls], ["data", "log"])
        self.assertFalse(stalls[0].details["network"])
        rows = io_summary(self.findings)
        self.assertEqual(len(rows), 2)

    def test_backup_errors_use_errno_meanings(self):
        full, log = self.by_code("3201")
        self.assertEqual(full.details["os_error"], 28)
        self.assertIn("No space left on device", full.advice)
        self.assertIn("mssql user needs write access", log.advice)
        self.assertNotIn("Windows error", full.advice + log.advice)

    def test_windows_error_numbers_keep_their_windows_meaning(self):
        windows = [f for f in classify(read_entries(fixture("backup_failures.log"))) if f.code == "3201"]
        self.assertIn("Access denied", windows[0].advice)

    def test_dump_path_on_linux(self):
        (dump,) = self.by_code("stackdump")
        self.assertEqual(dump.details["file"], "/var/opt/mssql/log/SQLDump0001.txt")
        self.assertIn("SQLDump0001.txt", dump.title)

    def test_nothing_left_over_except_plain_lines(self):
        left = [e.text for e in unclassified(self.entries, self.findings)]
        self.assertTrue(all(t.startswith(("UTC adjustment", "(c)", "All rights", "Server process ID",
                                          "Logging SQL Server", "SQL Server detected", "Detected",
                                          "System Manufacturer", "Authentication mode")) for t in left), left)


if __name__ == "__main__":
    unittest.main()
