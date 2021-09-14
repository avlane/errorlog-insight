import unittest

from errorlog_insight.classify import classify
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


def findings_of(name):
    return classify(read_entries(fixture(name)))


class StartupTests(unittest.TestCase):
    def test_startup_sequence(self):
        findings = findings_of("startup_2019.log")
        self.assertEqual([f.code for f in findings], ["startup", "recovery", "ready"])

    def test_banner_details(self):
        banner = findings_of("startup_2019.log")[0]
        self.assertEqual(banner.details["version_year"], 2019)
        self.assertEqual(banner.details["level"], "RTM-CU8")
        self.assertEqual(banner.details["kb"], "KB4577194")
        self.assertEqual(banner.details["build"], "15.0.4073.23")
        self.assertEqual(banner.details["edition"], "Enterprise Edition (64-bit)")
        self.assertTrue(banner.details["os"].startswith("Windows Server 2019"))

    def test_recovery_progress(self):
        recovery = findings_of("startup_2019.log")[1]
        self.assertEqual(recovery.details["database"], "Sales")
        self.assertEqual(recovery.details["percent"], 45)
        self.assertEqual(recovery.details["seconds_remaining"], 4)


class ShutdownTests(unittest.TestCase):
    def test_shutdowns_and_cycle(self):
        findings = findings_of("shutdown.log")
        self.assertEqual([f.code for f in findings], ["shutdown", "shutdown", "cycled"])
        self.assertEqual(findings[0].details["how"], "service control manager")
        self.assertEqual(findings[1].details["how"], "system shutdown")
        self.assertTrue(all(f.severity == "info" for f in findings))

    def test_noise_is_not_classified(self):
        self.assertEqual(findings_of("noise.log"), [])


if __name__ == "__main__":
    unittest.main()
