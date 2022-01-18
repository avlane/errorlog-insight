import io
import json
import unittest

from errorlog_insight.cli import main
from tests.helpers import fixture


def run(*names, extra=()):
    out = io.StringIO()
    code = main([fixture(n) for n in names] + list(extra), out=out)
    return code, out.getvalue()


class CliTests(unittest.TestCase):
    def test_summary_of_one_file(self):
        code, text = run("io_stalls.log")
        self.assertEqual(code, 0)
        self.assertIn("Findings: 7", text)
        self.assertIn("Slow I/O (833)", text)
        self.assertIn("x7", text)

    def test_most_severe_first(self):
        _, text = run("io_stalls.log")
        first = text.split("Most severe")[1].splitlines()[1]
        self.assertTrue(first.strip().startswith("[ERROR]"))

    def test_multiple_files(self):
        _, text = run("login_failures.log", "io_stalls.log")
        self.assertIn("Login failures", text)
        self.assertIn("Slow I/O (833)", text)
        self.assertIn("Findings: 22", text)

    def test_nothing_recognised(self):
        _, text = run("noise.log")
        self.assertIn("Nothing recognised.", text)

    def test_period_line(self):
        _, text = run("login_failures.log")
        self.assertIn("2021-03-02 07:55:10 .. 2021-03-02 15:18:33", text)


class OptionTests(unittest.TestCase):
    def test_json_output(self):
        code, text = run("io_stalls.log", extra=["--json"])
        doc = json.loads(text)
        self.assertEqual(code, 0)
        self.assertEqual(doc["entries"], 11)
        self.assertEqual(len(doc["findings"]), 7)
        first = doc["findings"][0]
        self.assertEqual(first["code"], "833")
        self.assertEqual(first["details"]["database"], "Sales")
        self.assertEqual(first["timestamp"], "2021-04-06T02:14:11.120")
        self.assertEqual(doc["period"]["first"], "2021-04-06T01:00:00.120")

    def test_json_for_empty_log(self):
        _, text = run("noise.log", extra=["--json"])
        doc = json.loads(text)
        self.assertEqual(doc["findings"], [])

    def test_min_severity_hides_info(self):
        _, text = run("startup_2019.log", extra=["--min-severity", "warning"])
        self.assertIn("Nothing recognised.", text)
        _, text = run("startup_2019.log")
        self.assertIn("Ready for connections", text)

    def test_min_severity_error_keeps_only_errors(self):
        _, text = run("io_stalls.log", extra=["--json", "--min-severity", "error"])
        severities = {f["severity"] for f in json.loads(text)["findings"]}
        self.assertEqual(severities, {"error"})


if __name__ == "__main__":
    unittest.main()
