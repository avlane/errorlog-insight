import io
import json
import unittest

from errorlog_insight.classify import classify
from errorlog_insight.cli import main
from errorlog_insight.reader import read_entries
from errorlog_insight.timeline import default_label, merge_entries, merge_findings, timeline_lines
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
