import contextlib
import io
import json
import os
import tempfile
import unittest

from errorlog_insight.baseline import BaselineError, compare, make_baseline, read_baseline, write_baseline
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


class CompareTests(unittest.TestCase):
    def baseline_of(self, *names):
        entries, findings, unknown = analyse(*names)
        return make_baseline(entries, findings, unknown)

    def compare_with(self, base_names, now_names):
        base = self.baseline_of(*base_names)
        _, findings, unknown = analyse(*now_names)
        return compare(base, findings, unknown)

    def test_same_log_has_nothing_new(self):
        c = self.compare_with(["noise.log", "io_stalls.log"], ["noise.log", "io_stalls.log"])
        self.assertEqual((c["new_codes"], c["increased"], c["new_templates"]), ([], [], []))
        self.assertEqual(c["known_templates"], 8)

    def test_new_finding_types_and_templates(self):
        c = self.compare_with(["noise.log"], ["noise.log", "io_stalls.log", "template_burst.log"])
        self.assertEqual({x["code"] for x in c["new_codes"]}, {"833", "flushcache", "io-frozen", "io-resumed"})
        self.assertEqual([t.template for t in c["new_templates"]],
                         ["Unable to contact the licensing service at <IP>. Retry <NUM> of <NUM> failed.",
                          "Starting up database '<STR>'."])
        self.assertEqual(c["known_templates"], 8)

    def test_increase_needs_a_factor_of_three_and_five_events(self):
        c = self.compare_with(["login_failures.log"], ["login_failures.log", "login_patterns.log"])
        (inc,) = [x for x in c["increased"] if x["code"] == "18456"]
        self.assertEqual((inc["before"], inc["now"]), (15, 76))
        c = self.compare_with(["login_patterns.log"], ["login_patterns.log", "login_failures.log"])
        self.assertEqual(c["increased"], [])   # 61 -> 76 is not three times as many

    def test_small_numbers_are_not_an_increase(self):
        c = self.compare_with(["backup_failures.log"], ["backup_failures.log", "backup_failures.log"])
        self.assertEqual(c["increased"], [])

    def test_a_baseline_from_other_grouping_rules_only_compares_codes(self):
        base = self.baseline_of("noise.log")
        base["template_scheme"] = 0
        _, findings, unknown = analyse("noise.log", "io_stalls.log")
        c = compare(base, findings, unknown)
        self.assertFalse(c["templates_compared"])
        self.assertEqual(c["new_templates"], [])
        self.assertEqual({x["code"] for x in c["new_codes"]}, {"833", "flushcache", "io-frozen", "io-resumed"})

    def test_newer_baseline_format_is_refused(self):
        base = self.baseline_of("noise.log")
        base["schema_version"] = 2
        with self.assertRaises(BaselineError) as ctx:
            compare(base, [], [])
        self.assertIn("newer errorlog-insight", str(ctx.exception))

    def test_schema_version_is_required(self):
        base = self.baseline_of("noise.log")
        del base["schema_version"]
        with self.assertRaises(BaselineError):
            compare(base, [], [])
        base["schema_version"] = True
        with self.assertRaises(BaselineError):
            compare(base, [], [])

    def test_the_scheme_is_saved(self):
        from errorlog_insight.cluster import TEMPLATE_SCHEME
        self.assertEqual(self.baseline_of("noise.log")["template_scheme"], TEMPLATE_SCHEME)

    def test_invalid_baseline(self):
        with self.assertRaises(BaselineError):
            compare({"codes": []}, [], [])
        with self.assertRaises(BaselineError):
            compare([], [], [])


class CliCompareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = os.path.join(self.tmp.name, "base.json")
        main([fixture("noise.log"), "--save-baseline", self.base], out=io.StringIO())

    def run_cli(self, *args):
        out = io.StringIO()
        code = main(list(args), out=out)
        return code, out.getvalue()

    def test_text_section(self):
        _, text = self.run_cli(fixture("noise.log"), fixture("template_burst.log"), "--baseline", self.base)
        section = text.split("New since the baseline")[1].split("\n\n")[0]
        self.assertIn("(2021-09-14 to 2021-09-14)", text)
        self.assertIn("new message x12 [error?] Unable to contact the licensing service at <IP>.", section)
        self.assertIn("new message x8 Starting up database '<STR>'.", section)   # info-level: no guess shown
        self.assertNotIn("Software Usage Metrics", section)                        # already in the baseline

    def test_nothing_new(self):
        _, text = self.run_cli(fixture("noise.log"), "--baseline", self.base)
        self.assertIn("Nothing new: 8 known message group(s).", text)

    def test_json_and_html(self):
        _, text = self.run_cli(fixture("noise.log"), fixture("io_stalls.log"), "--baseline", self.base, "--json")
        doc = json.loads(text)
        self.assertEqual({c["code"] for c in doc["comparison"]["new_codes"]}, {"833", "flushcache", "io-frozen", "io-resumed"})
        self.assertEqual(doc["comparison"]["known_templates"], 8)
        _, text = self.run_cli(fixture("noise.log"), fixture("io_stalls.log"), "--baseline", self.base, "--html")
        self.assertIn("<h2>New since the baseline</h2>", text)
        self.assertIn("new finding type", text)

    def test_no_baseline_no_section(self):
        _, text = self.run_cli(fixture("noise.log"))
        self.assertNotIn("New since", text)
        _, text = self.run_cli(fixture("noise.log"), "--json")
        self.assertIsNone(json.loads(text)["comparison"])

    def test_old_scheme_is_explained_in_all_formats(self):
        with open(self.base, encoding="utf-8") as f:
            data = json.load(f)
        data["template_scheme"] = 0
        with open(self.base, "w", encoding="utf-8") as f:
            json.dump(data, f)
        _, text = self.run_cli(fixture("noise.log"), "--baseline", self.base)
        self.assertIn("different message grouping rules", text)
        self.assertNotIn("Nothing new", text)
        _, text = self.run_cli(fixture("noise.log"), "--baseline", self.base, "--json")
        self.assertFalse(json.loads(text)["comparison"]["templates_compared"])
        _, text = self.run_cli(fixture("noise.log"), "--baseline", self.base, "--html")
        self.assertIn("different message grouping rules", text)

    def test_bad_baseline_exits_2(self):
        bad = os.path.join(self.tmp.name, "bad.json")
        with open(bad, "w") as f:
            f.write("[1, 2]")
        for path in (bad, os.path.join(self.tmp.name, "missing.json")):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code, _ = self.run_cli(fixture("noise.log"), "--baseline", path)
            self.assertEqual(code, 2)
            self.assertIn("errorlog-insight:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
