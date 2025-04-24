import io
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


if __name__ == "__main__":
    unittest.main()
