import io
import json
import unittest

from errorlog_insight.cli import main
from tests.helpers import fixture


def run(*names, extra=()):
    out = io.StringIO()
    main([fixture(n) for n in names] + list(extra), out=out)
    return out.getvalue()


class InsightSectionTests(unittest.TestCase):
    def test_section_comes_first_and_lists_evidence(self):
        text = run("insight_io.log")
        self.assertIn("Insights (most important first)", text)
        self.assertLess(text.index("Insights (most important first)"), text.index("Findings by type"))
        self.assertIn("[ERROR, high confidence] Slow I/O on E:\\SQLData\\Sales_Data1.mdf overlaps maintenance: "
                      "DBCC consistency checking was running on Sales", text)
        self.assertIn("      3 finding(s), 2025-01-21 03:05:30 .. 03:12:44", text)
        self.assertIn("-> CHECKDB reads every page", text)

    def test_most_important_first(self):
        text = run("insight_logfull.log", "insight_io.log")
        section = text.split("Findings by type")[0]
        self.assertLess(section.index("CRITICAL"), section.index("[ERROR"))
        self.assertLess(section.index("[ERROR"), section.index("[WARNING"))

    def test_no_insights_flag(self):
        self.assertNotIn("Insights", run("insight_io.log", extra=["--no-insights"]))

    def test_nothing_to_say_no_section(self):
        self.assertNotIn("Insights", run("noise.log", "startup_2019.log"))

    def test_min_severity_applies_to_insights(self):
        text = run("insight_io.log", extra=["--min-severity", "error"])
        self.assertIn("DBCC consistency checking", text)
        self.assertNotIn("a snapshot backup froze", text)

    def test_insights_survive_when_their_findings_are_filtered(self):
        # the evidence is info/warning level, but the insight is an error
        text = run("insight_nonyield.log", extra=["--min-severity", "error"])
        self.assertIn("stalled while storage was reporting slow I/O", text)


class InsightOutputTests(unittest.TestCase):
    def test_json(self):
        doc = json.loads(run("insight_io.log", extra=["--json"]))
        first = doc["insights"][0]
        self.assertEqual(first["code"], "io-during-checkdb")
        self.assertEqual(first["severity"], "error")
        self.assertEqual(first["confidence"], "high")
        self.assertEqual(first["start"], "2025-01-21T03:05:30.450")
        self.assertEqual([e["code"] for e in first["evidence"]], ["833", "833", "checkdb"])
        self.assertEqual(first["evidence"][0]["line"], 4)
        self.assertIn("quiet period", first["advice"])

    def test_json_without_insights(self):
        doc = json.loads(run("insight_io.log", extra=["--json", "--no-insights"]))
        self.assertEqual(doc["insights"], [])

    def test_html(self):
        text = run("insight_io.log", extra=["--html"])
        self.assertIn("<h2>Insights</h2>", text)
        self.assertLess(text.index("<h2>Insights</h2>"), text.index("<h2>Findings by type</h2>"))
        self.assertIn("high confidence, 2025-01-21 03:05:30 to 2025-01-21 03:12:44", text)
        self.assertIn("DBCC CHECKDB of Sales found no errors", text)

    def test_html_escapes_evidence(self):
        from datetime import datetime
        from errorlog_insight.htmlreport import render_html
        from errorlog_insight.insights import Insight
        from errorlog_insight.model import Entry, Finding
        f = Finding(Entry(datetime(2025, 5, 6), "x", "y", replica="<b>S</b>"), "topic", "c", "info", "<i>bad</i>")
        text = render_html([], [], insights=[Insight("x", "<u>heading</u>", "info", "low", [f], "<s>a</s>")])
        self.assertNotIn("<i>bad", text)
        self.assertIn("&lt;i&gt;bad&lt;/i&gt;", text)
        self.assertIn("&lt;u&gt;heading&lt;/u&gt;", text)
        self.assertIn("&lt;b&gt;S&lt;/b&gt;", text)


if __name__ == "__main__":
    unittest.main()
