import unittest

from errorlog_insight.classify import classify
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


def findings_of(name):
    return classify(read_entries(fixture(name)))


class StartupTests(unittest.TestCase):
    def test_startup_sequence(self):
        findings = findings_of("startup_2019.log")
        self.assertEqual([f.code for f in findings],
                         ["startup", "startup-params", "startup-params", "recovery", "ready"])

    def test_banner_details(self):
        banner = findings_of("startup_2019.log")[0]
        self.assertEqual(banner.details["version_year"], 2019)
        self.assertEqual(banner.details["level"], "RTM-CU8")
        self.assertEqual(banner.details["kb"], "KB4577194")
        self.assertEqual(banner.details["build"], "15.0.4073.23")
        self.assertEqual(banner.details["edition"], "Enterprise Edition (64-bit)")
        self.assertTrue(banner.details["os"].startswith("Windows Server 2019"))

    def test_recovery_progress(self):
        recovery = next(f for f in findings_of("startup_2019.log") if f.code == "recovery")
        self.assertEqual(recovery.details["database"], "Sales")
        self.assertEqual(recovery.details["percent"], 45)
        self.assertEqual(recovery.details["seconds_remaining"], 4)


class StartupParameterTests(unittest.TestCase):
    def test_registry_and_command_line(self):
        params = [f for f in findings_of("startup_single_user.log") if f.code == "startup-params"]
        self.assertEqual([p.details["source"] for p in params], ["Registry startup parameters", "Command Line Startup Parameters"])
        registry, command = params
        self.assertEqual(registry.details["trace_flags"], [1118, 3226])
        self.assertIn("-T1118", registry.details["parameters"])
        self.assertTrue(registry.details["parameters"][0].startswith("-dC:\\Program Files"))
        self.assertFalse(registry.details["single_user"])
        self.assertEqual(command.details["parameters"], ["-sMSSQLSERVER", "-mSQLCMD", "-f"])
        self.assertTrue(command.details["single_user"])
        self.assertTrue(command.details["minimal_configuration"])
        self.assertIn("single-user", command.details["options"]["m"])

    def test_ordinary_startup_has_no_special_options(self):
        command = [f for f in findings_of("startup_2019.log") if f.code == "startup-params"][1]
        self.assertEqual(command.details["parameters"], ["-sMSSQLSERVER"])
        self.assertFalse(command.details["single_user"])

    def test_parse_startup_parameters(self):
        from errorlog_insight.rules.lifecycle import parse_startup_parameters
        text = 'Command Line Startup Parameters:\n\t -c\n\t -T3608\n\t -g512\n\t not a flag'
        self.assertEqual(parse_startup_parameters(text), [("c", ""), ("T", "3608"), ("g", "512")])


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
