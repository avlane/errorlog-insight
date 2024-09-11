import contextlib
import io
import json
import unittest
from datetime import datetime

from errorlog_insight.cli import main
from errorlog_insight.model import Entry
from errorlog_insight.timefilter import in_window, parse_when
from tests.helpers import fixture


def entry(hour, minute=0):
    return Entry(datetime(2024, 9, 10, hour, minute), "spid5s", "x")


class ParseTests(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(parse_when("2024-09-10"), datetime(2024, 9, 10))
        self.assertEqual(parse_when("2024-09-10 08:30"), datetime(2024, 9, 10, 8, 30))
        self.assertEqual(parse_when("2024-09-10T08:30:15"), datetime(2024, 9, 10, 8, 30, 15))

    def test_garbage(self):
        for bad in ("yesterday", "10/09/2024", "2024-13-01", ""):
            with self.assertRaises(ValueError, msg=bad):
                parse_when(bad)


class WindowTests(unittest.TestCase):
    def setUp(self):
        self.entries = [entry(7), entry(8), entry(9), entry(10)]

    def test_no_bounds_keeps_everything(self):
        self.assertEqual(in_window(self.entries), self.entries)

    def test_since_is_inclusive_and_until_exclusive(self):
        kept = in_window(self.entries, datetime(2024, 9, 10, 8), datetime(2024, 9, 10, 10))
        self.assertEqual([e.timestamp.hour for e in kept], [8, 9])

    def test_one_sided(self):
        self.assertEqual(len(in_window(self.entries, since=datetime(2024, 9, 10, 9))), 2)
        self.assertEqual(len(in_window(self.entries, until=datetime(2024, 9, 10, 9))), 2)

    def test_reversed_window(self):
        with self.assertRaises(ValueError):
            in_window(self.entries, datetime(2024, 9, 10, 9), datetime(2024, 9, 10, 8))


class CliWindowTests(unittest.TestCase):
    def run_cli(self, *extra):
        out = io.StringIO()
        code = main([fixture("login_failures.log"), "--json"] + list(extra), out=out)
        return code, out.getvalue()

    def test_since_and_until_limit_findings(self):
        _, text = self.run_cli("--since", "2021-03-02 09:00", "--until", "2021-03-02 11:00")
        doc = json.loads(text)
        users = [f["details"]["user"] for f in doc["findings"]]
        self.assertEqual(users, ["reports", "CONTOSO\\jdoe", "appsvc", "etl_loader"])
        self.assertEqual(doc["entries"], 8)

    def test_window_drops_bursts_outside_it(self):
        _, text = self.run_cli("--since", "2021-03-02 09:00")
        self.assertEqual(json.loads(text)["bursts"], [])

    def test_bad_values_exit_2(self):
        for extra in (["--since", "soon"], ["--since", "2021-03-03", "--until", "2021-03-02"]):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code, _ = self.run_cli(*extra)
            self.assertEqual(code, 2, extra)
            self.assertIn("errorlog-insight:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
