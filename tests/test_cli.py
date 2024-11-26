import contextlib
import io
import json
import os
import tempfile
import unittest

from errorlog_insight.cli import main
from tests.helpers import fixture
from tools.encode_log import encode


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

    def test_unrecognised_section(self):
        _, text = run("noise.log")
        self.assertIn("Unrecognised messages (10 entries, 8 templates)", text)
        self.assertIn("x2    Configuration option '<STR>' changed from <NUM> to <NUM>.", text)

    def test_unrecognised_section_shows_when_and_where(self):
        _, text = run("noise.log")
        section = text.split("Unrecognised messages")[1].splitlines()
        # x2 "Using ..." messages from spid53 and spid57
        self.assertIn("2021-09-14 06:10:44 .. 06:12:01  spid53, spid57", section[2])
        self.assertIn("2021-09-14 07:00:00 .. 07:00:00  spid62", text)
        self.assertIn("2021-09-14 06:00:02  Server\n", text)

    def test_top_limits_templates(self):
        _, text = run("noise.log", extra=["--top", "3"])
        self.assertIn("... and 5 more templates", text)

    def test_burst_section(self):
        _, text = run("login_failures.log")
        self.assertIn("Bursts (well above the recent rate)", text)
        self.assertIn("18456", text.split("Bursts")[1])

    def test_burst_json_and_threshold(self):
        _, text = run("login_failures.log", extra=["--json"])
        self.assertEqual(json.loads(text)["bursts"][0]["count"], 6)
        _, text = run("login_failures.log", extra=["--json", "--burst-min", "7"])
        self.assertEqual(json.loads(text)["bursts"], [])

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

    def test_schema_header(self):
        _, text = run("io_stalls.log", extra=["--json"])
        doc = json.loads(text)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["tool"]["name"], "errorlog-insight")
        self.assertRegex(doc["tool"]["version"], r"^\d+\.\d+\.\d+$")

    def test_documented_keys_match_the_output(self):
        _, text = run("login_failures.log", "ag_primary.log", extra=["--json"])
        doc = json.loads(text)
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "json-format.md")
        with open(path, encoding="utf-8") as f:
            documented = f.read()
        for key in doc:
            self.assertIn("`%s`" % key, documented)
        for key in doc["findings"][0]:
            self.assertIn('"%s"' % key, documented)

    def test_json_for_empty_log(self):
        _, text = run("noise.log", extra=["--json"])
        doc = json.loads(text)
        self.assertEqual(doc["findings"], [])
        self.assertEqual(doc["unrecognised"][0]["count"], 2)
        self.assertEqual(doc["unrecognised"][0]["variants"], 1)
        self.assertEqual(len(doc["unrecognised"]), 8)

    def test_min_severity_hides_info(self):
        _, text = run("startup_2019.log", extra=["--min-severity", "warning"])
        self.assertIn("Nothing recognised.", text)
        _, text = run("startup_2019.log")
        self.assertIn("Ready for connections", text)

    def test_min_severity_error_keeps_only_errors(self):
        _, text = run("io_stalls.log", extra=["--json", "--min-severity", "error"])
        severities = {f["severity"] for f in json.loads(text)["findings"]}
        self.assertEqual(severities, {"error"})


class EntryPointTests(unittest.TestCase):
    def test_console_script_target_exists(self):
        from errorlog_insight import cli
        self.assertTrue(callable(cli.console_main))

    def test_package_version_is_declared(self):
        import errorlog_insight
        self.assertRegex(errorlog_insight.__version__, r"^\d+\.\d+\.\d+$")

    def test_version_flag(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("errorlog-insight", out.getvalue())


class FormatTests(unittest.TestCase):
    def test_format_option(self):
        _, text = run("noise.log", extra=["--format", "json"])
        self.assertEqual(json.loads(text)["schema_version"], 1)
        _, text = run("noise.log", extra=["--format", "html"])
        self.assertTrue(text.startswith("<!doctype html>"))
        _, text = run("noise.log", extra=["--format", "text"])
        self.assertTrue(text.startswith("errorlog-insight report"))

    def test_aliases_still_work(self):
        _, text = run("noise.log", extra=["--json"])
        self.assertIn("schema_version", text)
        _, text = run("noise.log", extra=["--html"])
        self.assertTrue(text.startswith("<!doctype html>"))

    def test_extension_picks_the_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, expected in (("r.json", "{"), ("r.html", "<!doctype html>"), ("r.HTM", "<!doctype html>"),
                                   ("r.txt", "errorlog-insight report"), ("r", "errorlog-insight report")):
                target = os.path.join(tmp, name)
                main([fixture("noise.log"), "-o", target])
                with open(target, encoding="utf-8") as f:
                    self.assertTrue(f.read().startswith(expected), name)

    def test_explicit_format_beats_the_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "r.json")
            main([fixture("noise.log"), "-o", target, "--format", "html"])
            with open(target, encoding="utf-8") as f:
                self.assertTrue(f.read().startswith("<!doctype html>"))

    def test_unknown_format_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main([fixture("noise.log"), "--format", "xml"], out=io.StringIO())


class OutputFileTests(unittest.TestCase):
    def make_log(self, directory, text):
        path = os.path.join(directory, "ERRORLOG")
        with open(path, "wb") as f:
            f.write(encode(text))
        return path

    def test_output_file_is_utf8(self):
        line = ("2023-04-18 10:00:00.10 Logon       Login failed for user 'Jos\u00e9'. "
                "Reason: Could not find a login matching the name provided. [CLIENT: 10.0.0.1]\n")
        with tempfile.TemporaryDirectory() as tmp:
            log = self.make_log(tmp, line)
            target = os.path.join(tmp, "report.txt")
            out = io.StringIO()
            code = main([log, "-o", target], out=out)
            self.assertEqual(code, 0)
            self.assertEqual(out.getvalue(), "")
            with open(target, "rb") as f:
                data = f.read()
        self.assertIn("Jos\u00e9".encode("utf-8"), data)
        self.assertNotIn(b"\r\n", data)

    def test_output_file_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "report.html")
            main([fixture("io_stalls.log"), "--html", "--output", target])
            with open(target, encoding="utf-8") as f:
                self.assertTrue(f.read().startswith("<!doctype html>"))


if __name__ == "__main__":
    unittest.main()
