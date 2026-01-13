import io
import json
import os
import tempfile
import unittest

from errorlog_insight.baseline import BaselineError, make_baseline, read_baseline, write_baseline
from errorlog_insight.classify import classify, unclassified
from errorlog_insight.cli import main
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


def analyse(*names):
    entries = []
    for n in names:
        entries.extend(read_entries(fixture(n)))
    findings = classify(entries)
    return entries, findings, unclassified(entries, findings)


class MakeBaselineTests(unittest.TestCase):
    def test_counts_and_templates(self):
        entries, findings, unknown = analyse("io_stalls.log", "noise.log")
        b = make_baseline(entries, findings, unknown, ["a.log", "b.log"])
        self.assertEqual(b["schema_version"], 1)
        self.assertEqual(b["codes"]["833"], 7)
        self.assertEqual(b["codes"]["flushcache"], 2)
        self.assertEqual(len(b["templates"]), 8)
        counts = sorted(t["count"] for t in b["templates"].values())
        self.assertEqual(counts, [1, 1, 1, 1, 1, 1, 2, 2])
        self.assertEqual(b["source"]["files"], ["a.log", "b.log"])
        self.assertEqual(b["source"]["entries"], 21)
        self.assertEqual(b["source"]["first"], "2021-04-06T01:00:00.120")

    def test_template_ids_are_the_report_ids(self):
        from errorlog_insight.cluster import cluster_entries
        entries, findings, unknown = analyse("noise.log")
        b = make_baseline(entries, findings, unknown)
        self.assertEqual(set(b["templates"]), {c.id for c in cluster_entries(unknown)})

    def test_empty_log(self):
        b = make_baseline([], [], [])
        self.assertEqual((b["codes"], b["templates"], b["source"]["first"]), ({}, {}, None))

    def test_round_trip(self):
        entries, findings, unknown = analyse("noise.log")
        b = make_baseline(entries, findings, unknown)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "base.json")
            write_baseline(path, b)
            self.assertEqual(read_baseline(path), b)

    def test_unreadable_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(BaselineError):
                read_baseline(os.path.join(tmp, "missing.json"))
            bad = os.path.join(tmp, "bad.json")
            with open(bad, "w") as f:
                f.write("{not json")
            with self.assertRaises(BaselineError):
                read_baseline(bad)


class CliTests(unittest.TestCase):
    def test_save_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "base.json")
            out = io.StringIO()
            main([fixture("io_stalls.log"), fixture("noise.log"), "--save-baseline", path], out=out)
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        self.assertEqual(data["codes"]["833"], 7)
        self.assertIn("errorlog-insight report", out.getvalue())   # the normal report is still written

    def test_baseline_ignores_the_severity_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "base.json")
            main([fixture("io_stalls.log"), "--min-severity", "critical", "--save-baseline", path], out=io.StringIO())
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        self.assertEqual(data["codes"]["833"], 7)


if __name__ == "__main__":
    unittest.main()
