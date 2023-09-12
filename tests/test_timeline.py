import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import timedelta

from errorlog_insight.classify import classify
from errorlog_insight.cli import main
from errorlog_insight.reader import read_entries
from errorlog_insight.timeline import (
    apply_offset, default_label, merge_entries, merge_findings, parse_offset, parse_source, timeline_lines)
from tests.helpers import fixture


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.primary = read_entries(fixture("ag_primary.log"), replica="SQLPROD01")
        self.secondary = read_entries(fixture("ag_secondary.log"), replica="SQLDR02")

    def test_entries_interleave_by_time(self):
        merged = merge_entries(self.primary, self.secondary)
        self.assertEqual(len(merged), len(self.primary) + len(self.secondary))
        stamps = [e.timestamp for e in merged]
        self.assertEqual(stamps, sorted(stamps))
        self.assertEqual([e.replica for e in merged[:3]], ["SQLDR02", "SQLPROD01", "SQLPROD01"])

    def test_ties_keep_file_order(self):
        merged = merge_entries(self.primary, self.primary)
        self.assertEqual(merged[0].lineno, merged[1].lineno)
        self.assertIs(merged[0], self.primary[0])

    def test_findings_merge(self):
        findings = classify(self.primary) + classify(self.secondary)
        merged = merge_findings(findings)
        self.assertEqual(merged[0].entry.replica, "SQLDR02")
        self.assertEqual([f.entry.timestamp for f in merged], sorted(f.entry.timestamp for f in findings))

    def test_timeline_lines(self):
        lines = timeline_lines(classify(self.primary) + classify(self.secondary))
        self.assertEqual(len(lines), 12)
        self.assertIn("SQLDR02", lines[0])
        self.assertIn("preparing to become primary", lines[0])
        self.assertTrue(lines[0].startswith("2022-05-10 21:59:59.80"))

    def test_default_label(self):
        self.assertEqual(default_label("/var/log/SQLDR02.log"), "SQLDR02")
        self.assertEqual(default_label("ERRORLOG.1"), "ERRORLOG")


class SourceLabelTests(unittest.TestCase):
    def test_plain_path(self):
        self.assertEqual(parse_source("logs/ERRORLOG.1"), ("ERRORLOG", "logs/ERRORLOG.1"))

    def test_label_equals_path(self):
        self.assertEqual(parse_source("SQLDR02=logs/dr02/ERRORLOG"), ("SQLDR02", "logs/dr02/ERRORLOG"))

    def test_windows_drive_is_not_a_label(self):
        self.assertEqual(parse_source("C:\\logs\\ERRORLOG"), ("ERRORLOG", "C:\\logs\\ERRORLOG"))

    def test_existing_file_with_equals_sign_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a=b.log")
            open(path, "w").close()
            self.assertEqual(parse_source(path)[1], path)


class OffsetTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_offset("SQLDR02=+2s"), ("SQLDR02", timedelta(seconds=2)))
        self.assertEqual(parse_offset("SQLDR02=-1.5m"), ("SQLDR02", timedelta(seconds=-90)))
        self.assertEqual(parse_offset("a-b.c=+250ms"), ("a-b.c", timedelta(milliseconds=250)))
        self.assertEqual(parse_offset("x=+1h")[1], timedelta(hours=1))
        self.assertEqual(parse_offset("x=-3")[1], timedelta(seconds=-3))

    def test_parse_errors(self):
        for bad in ("SQLDR02", "SQLDR02=2s", "SQLDR02=+s", "=+2s", "SQLDR02=+2d"):
            with self.assertRaises(ValueError, msg=bad):
                parse_offset(bad)

    def test_apply_offset(self):
        entries = read_entries(fixture("ag_secondary.log"))
        first = entries[0].timestamp
        apply_offset(entries, timedelta(seconds=5))
        self.assertEqual(entries[0].timestamp, first + timedelta(seconds=5))

    def test_offset_reorders_the_merged_timeline(self):
        def first_label(*extra):
            out = io.StringIO()
            main(["SQLPROD01=" + fixture("ag_primary.log"), "SQLDR02=" + fixture("ag_secondary.log"),
                  "--timeline"] + list(extra), out=out)
            return out.getvalue().split("\nTimeline\n")[1].splitlines()[0]
        self.assertIn("SQLDR02", first_label())
        self.assertIn("SQLPROD01", first_label("--offset", "SQLDR02=+3s"))

    def test_bad_offsets_exit_2(self):
        for extra in (["--offset", "nonsense"], ["--offset", "OTHER=+1s"]):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = main([fixture("ag_primary.log")] + extra, out=io.StringIO())
            self.assertEqual(code, 2, extra)
            self.assertIn("errorlog-insight:", err.getvalue())


class CliTimelineTests(unittest.TestCase):
    def run_cli(self, *extra):
        out = io.StringIO()
        main([fixture("ag_primary.log"), fixture("ag_secondary.log")] + list(extra), out=out)
        return out.getvalue()

    def test_timeline_section(self):
        text = self.run_cli("--timeline")
        self.assertIn("\nTimeline\n", text)
        section = text.split("\nTimeline\n")[1].splitlines()
        self.assertIn("ag_secondary", section[0])
        self.assertIn("ag_primary", section[1])

    def test_labels_name_the_replicas(self):
        out = io.StringIO()
        main(["SQLPROD01=" + fixture("ag_primary.log"), "SQLDR02=" + fixture("ag_secondary.log"), "--timeline"], out=out)
        section = out.getvalue().split("\nTimeline\n")[1].splitlines()
        self.assertIn("SQLDR02", section[0])
        self.assertIn("SQLPROD01", section[1])
        self.assertNotIn("ag_primary", "\n".join(section))
        self.assertIn("[SQLDR02] AG_Sales: preparing to become primary", out.getvalue())

    def test_no_timeline_by_default(self):
        self.assertNotIn("\nTimeline\n", self.run_cli())

    def test_json_findings_are_merged_and_labelled(self):
        out = io.StringIO()
        main([fixture("ag_primary.log"), fixture("ag_secondary.log"), "--json"], out=out)
        findings = json.loads(out.getvalue())["findings"]
        self.assertEqual(findings[0]["replica"], "ag_secondary")
        self.assertEqual([f["timestamp"] for f in findings], sorted(f["timestamp"] for f in findings))


if __name__ == "__main__":
    unittest.main()
