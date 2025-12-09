import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime

from errorlog_insight.classify import classify
from errorlog_insight.cli import main
from errorlog_insight.config import ConfigError, load_settings
from errorlog_insight.customrules import RuleError, make_rule, rules_from_config
from errorlog_insight.model import Entry
from tests.helpers import fixture

TOML = """\
[[rule]]
name = "Licence server"
pattern = 'Unable to contact the licensing service at (?P<host>[\\d.]+)'
severity = "error"
title = "Licence server {host} unreachable"
advice = "Check the licence server and the firewall."

[[rule]]
name = "Noisy job"
pattern = "job 'nightly etl' started"
ignore_case = true
severity = "info"
"""

INI = """\
[rule:Licence server]
pattern = Unable to contact the licensing service at (?P<host>[\\d.]+)
severity = error
title = Licence server {host} unreachable (100%% sure)
advice = Check the licence server and the firewall.
"""


def entry(text):
    return Entry(datetime(2025, 12, 9, 10, 0), "spid5s", text)


def write(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


class MakeRuleTests(unittest.TestCase):
    def test_named_groups_become_details_and_fill_the_title(self):
        rule = make_rule({"name": "Licence", "pattern": r"service at (?P<host>\d+\.\d+\.\d+\.\d+)", "severity": "error",
                          "title": "Licence {host} down", "advice": "Look."})
        f = rule(entry("Unable to contact the licensing service at 10.1.1.4. Retry 3 of 20 failed."), None)
        self.assertEqual(f.details, {"host": "10.1.1.4"})
        self.assertEqual(f.title, "Licence 10.1.1.4 down")
        self.assertEqual((f.severity, f.advice, f.category), ("error", "Look.", "custom"))
        self.assertEqual(f.code, "custom:licence")

    def test_no_match_no_finding(self):
        rule = make_rule({"name": "x", "pattern": "needle"})
        self.assertIsNone(rule(entry("hay"), None))

    def test_defaults(self):
        f = make_rule({"name": "Plain", "pattern": "x"})(entry("an x"), None)
        self.assertEqual((f.severity, f.title), ("warning", "Plain"))

    def test_unmatched_placeholder_is_left_visible(self):
        f = make_rule({"name": "x", "pattern": "x", "title": "Seen {nothing}"})(entry("x"), None)
        self.assertEqual(f.title, "Seen {nothing}")

    def test_optional_group_that_did_not_match_is_not_a_detail(self):
        f = make_rule({"name": "x", "pattern": "a(?P<b>b)?"})(entry("a"), None)
        self.assertEqual(f.details, {})

    def test_explicit_code(self):
        f = make_rule({"name": "x", "pattern": "x", "code": "lic"})(entry("x"), None)
        self.assertEqual(f.code, "lic")

    def test_ignore_case(self):
        rule = make_rule({"name": "x", "pattern": "needle", "ignore_case": "yes"})
        self.assertIsNotNone(rule(entry("A NEEDLE here"), None))

    def test_bad_rules(self):
        for spec in ({}, {"name": "x"}, {"name": "x", "pattern": "("}, {"name": "x", "pattern": "x", "severity": "loud"},
                     {"name": "x", "pattern": "x", "colour": "red"}):
            with self.assertRaises(RuleError, msg=spec):
                make_rule(spec)


class ConfigTests(unittest.TestCase):
    def test_toml_rules(self):
        try:
            import tomllib  # noqa: F401
        except ImportError:
            self.skipTest("TOML needs Python 3.11+")
        with tempfile.TemporaryDirectory() as tmp:
            settings = load_settings(write(tmp, "eli.toml", TOML))
        self.assertEqual(len(settings.custom_rules), 2)

    def test_ini_rules_with_percent_in_the_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = load_settings(write(tmp, "eli.ini", INI))
        (rule,) = settings.custom_rules
        f = rule(entry("Unable to contact the licensing service at 10.1.1.4"), None)
        self.assertEqual(f.title, "Licence server 10.1.1.4 unreachable (100%% sure)")

    def test_rule_errors_are_config_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                load_settings(write(tmp, "eli.ini", "[rule:bad]\npattern = (\n"))

    def test_rules_from_config_accepts_one_table(self):
        self.assertEqual(len(rules_from_config({"rule": {"name": "x", "pattern": "x"}})), 1)


class EndToEndTests(unittest.TestCase):
    def test_custom_rule_findings_appear_in_the_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write(tmp, "eli.ini", "[rule:Config change]\npattern = Configuration option '(?P<option>[^']+)' changed from (?P<old>\\d+) to (?P<new>\\d+)\n"
                                         "severity = warning\ntitle = {option}: {old} -> {new}\n")
            out = io.StringIO()
            main([fixture("noise.log"), "--config", cfg, "--json"], out=out)
            doc = json.loads(out.getvalue())
            titles = [f["title"] for f in doc["findings"]]
            self.assertEqual(titles, ["max degree of parallelism: 0 -> 4", "cost threshold for parallelism: 5 -> 50"])
            self.assertEqual(doc["findings"][0]["code"], "custom:config-change")
            self.assertEqual(len(doc["unrecognised"]), 7)
            out = io.StringIO()
            main([fixture("noise.log"), "--config", cfg], out=out)
        self.assertIn("Config change", out.getvalue())

    def test_bad_rule_in_the_config_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write(tmp, "eli.ini", "[rule:bad]\nseverity = error\n")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = main([fixture("noise.log"), "--config", cfg], out=io.StringIO())
        self.assertEqual(code, 2)
        self.assertIn("needs a pattern", err.getvalue())

    def test_classify_without_extra_rules_is_unchanged(self):
        self.assertEqual(classify([entry("Configuration option 'x' changed from 0 to 4. Run the RECONFIGURE statement to install.")]), [])


if __name__ == "__main__":
    unittest.main()
