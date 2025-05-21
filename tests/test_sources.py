import io
import json
import os
import shutil
import tempfile
import unittest

from errorlog_insight.classify import classify
from errorlog_insight.cli import main
from errorlog_insight.reader import read_entries
from errorlog_insight.sources import (
    drop_duplicate_entries, drop_duplicate_findings, expand_sources, natural_key)
from tests.helpers import fixture


class ExpandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name in ("ERRORLOG", "ERRORLOG.1", "ERRORLOG.2", "ERRORLOG.10", "other.txt"):
            shutil.copy(fixture("noise.log"), os.path.join(self.tmp.name, name))

    def path(self, name):
        return os.path.join(self.tmp.name, name)

    def test_natural_order(self):
        self.assertEqual(sorted(["ERRORLOG.10", "ERRORLOG.2", "ERRORLOG.1", "ERRORLOG"], key=natural_key),
                         ["ERRORLOG", "ERRORLOG.1", "ERRORLOG.2", "ERRORLOG.10"])

    def test_glob_expands_in_natural_order(self):
        found = expand_sources([self.path("ERRORLOG*")])
        self.assertEqual([os.path.basename(p) for _, p in found],
                         ["ERRORLOG", "ERRORLOG.1", "ERRORLOG.2", "ERRORLOG.10"])
        self.assertEqual({label for label, _ in found}, {"ERRORLOG"})

    def test_label_applies_to_every_match(self):
        found = expand_sources(["SQLDR02=" + self.path("ERRORLOG*")])
        self.assertEqual({label for label, _ in found}, {"SQLDR02"})
        self.assertEqual(len(found), 4)

    def test_plain_paths_pass_through(self):
        self.assertEqual(expand_sources([self.path("other.txt")]), [("other", self.path("other.txt"))])

    def test_pattern_without_matches_is_kept_for_the_error_message(self):
        self.assertEqual(expand_sources([self.path("nothing*")]), [("nothing*", self.path("nothing*"))])

    def test_square_brackets_work_as_patterns(self):
        found = expand_sources([self.path("ERRORLOG.[12]")])
        self.assertEqual([os.path.basename(p) for _, p in found], ["ERRORLOG.1", "ERRORLOG.2"])


class DuplicateTests(unittest.TestCase):
    def test_same_file_twice(self):
        entries = read_entries(fixture("noise.log"), replica="A") + read_entries(fixture("noise.log"), replica="A")
        self.assertEqual(len(drop_duplicate_entries(entries)), 10)

    def test_same_text_on_different_servers_is_kept(self):
        entries = read_entries(fixture("noise.log"), replica="A") + read_entries(fixture("noise.log"), replica="B")
        self.assertEqual(len(drop_duplicate_entries(entries)), 20)

    def test_findings(self):
        findings = classify(read_entries(fixture("io_stalls.log"), replica="A")) * 2
        self.assertEqual(len(drop_duplicate_findings(findings)), 11)


class CliTests(unittest.TestCase):
    def test_a_copy_of_the_log_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "io_stalls.log")
            shutil.copy(fixture("io_stalls.log"), copy)
            out_one, out_two = io.StringIO(), io.StringIO()
            main([fixture("io_stalls.log"), "--json"], out=out_one)
            main([fixture("io_stalls.log"), copy, "--json"], out=out_two)
        one, two = json.loads(out_one.getvalue()), json.loads(out_two.getvalue())
        self.assertEqual(two["entries"], one["entries"])
        self.assertEqual(len(two["findings"]), len(one["findings"]))

    def test_glob_on_the_command_line(self):
        pattern = os.path.join(os.path.dirname(fixture("ag_primary.log")), "ag_[ps]*ary.log")
        out = io.StringIO()
        main([pattern, "--json"], out=out)
        doc = json.loads(out.getvalue())
        self.assertEqual(len(doc["files"]), 2)
        self.assertEqual(doc["entries"], 12)

    def test_offset_applies_to_every_file_with_the_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            for n in ("a.log", "b.log"):
                shutil.copy(fixture("ag_primary.log"), os.path.join(tmp, n))
            out = io.StringIO()
            main(["X=" + os.path.join(tmp, "*.log"), "--offset", "X=+1h", "--json"], out=out)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc["period"]["first"][:13], "2022-05-10T23")   # 22:00 + 1 h


if __name__ == "__main__":
    unittest.main()
