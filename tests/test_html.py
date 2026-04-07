import io
import re
import unittest
from datetime import datetime
from html.parser import HTMLParser

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.cli import main
from errorlog_insight.report.htmlout import activity_svg, esc, render_html
from errorlog_insight.model import Entry
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "script":
            self.scripts += 1


def render(*names):
    entries = []
    for n in names:
        entries.extend(read_entries(fixture(n)))
    findings = classify(entries)
    return render_html(entries, findings, names, unknown=unclassified(entries, findings))


class HtmlTests(unittest.TestCase):
    def test_document_shell(self):
        text = render("io_stalls.log")
        self.assertTrue(text.startswith("<!doctype html>"))
        self.assertIn("<title>errorlog-insight report</title>", text)
        self.assertIn('<meta name="viewport"', text)

    def test_parses_and_has_no_scripts(self):
        parser = Collector()
        parser.feed(render("io_stalls.log", "deadlock_1222.log"))
        self.assertEqual(parser.scripts, 0)
        self.assertIn("details", parser.tags)
        self.assertIn("table", parser.tags)

    def test_no_external_resources(self):
        text = render("io_stalls.log")
        self.assertNotRegex(text, r"(src|href)=")

    def test_findings_with_severity_classes(self):
        text = render("io_stalls.log")
        self.assertIn('<details class="sev-error">', text)
        self.assertIn("I/O stall: 12 request(s) over 45 s", text)

    def test_details_are_listed(self):
        text = render("backup_failures.log")
        self.assertIn("<dt>os_error</dt><dd>53</dd>", text)

    def test_user_controlled_text_is_escaped(self):
        entry = Entry(datetime(2023, 3, 28, 10, 0), "Logon",
                      "Login failed for user '<script>alert(1)</script>'. Reason: Could not find a login matching the name provided. [CLIENT: 10.0.0.1]")
        findings = classify([entry])
        text = render_html([entry], findings)
        self.assertNotIn("<script>alert", text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", text)

    def test_unrecognised_templates_are_escaped(self):
        entry = Entry(datetime(2023, 3, 28, 10, 0), "spid5s", "Something <b>odd</b> happened here today")
        text = render_html([entry], [], unknown=[entry])
        self.assertIn("&lt;b&gt;odd&lt;/b&gt;", text)

    def test_severity_filters_are_pure_css(self):
        text = render("io_stalls.log")
        for name in ("info", "warning", "error", "critical"):
            self.assertIn('<input type="checkbox" id="show-%s" checked>' % name, text)
            self.assertIn("#show-%s:not(:checked) ~ .findings details.sev-%s { display: none; }" % (name, name), text)
        self.assertIn('<label for="show-error" class="sev-error">error</label>', text)
        self.assertEqual(text.count('<div class="findings">'), 1)

    def test_filter_inputs_come_before_the_findings(self):
        text = render("io_stalls.log")
        self.assertLess(text.index('id="show-info"'), text.index('<div class="findings">'))
        self.assertLess(text.index('<div class="filters"'), text.index('<div class="findings">'))

    def test_activity_chart(self):
        text = render("io_stalls.log", "login_failures.log")
        self.assertIn("<h2>Activity</h2>", text)
        self.assertIn('<svg class="activity"', text)
        self.assertIn('class="bar-error"', text)
        self.assertIn("2021-03-02 07:55:10", text)

    def test_activity_bars_are_scaled_to_the_busiest_period(self):
        entries = read_entries(fixture("login_failures.log"))
        svg = activity_svg(classify(entries), buckets=10)
        heights = [float(h) for h in re.findall(r'<rect[^>]* height="([\d.]+)"', svg)]
        self.assertEqual(max(heights), 70.0)
        self.assertGreaterEqual(min(heights), 3.0)

    def test_activity_chart_skipped_for_a_single_instant(self):
        entry = Entry(datetime(2024, 8, 20, 10, 0), "Logon",
                      "Login failed for user 'a'. Reason: Password did not match that for the login provided. [CLIENT: 1.1.1.1]")
        findings = classify([entry])
        self.assertEqual(activity_svg(findings), "")
        self.assertNotIn("<h2>Activity</h2>", render_html([entry], findings))

    def test_activity_chart_has_no_scripts_or_external_references(self):
        svg = activity_svg(classify(read_entries(fixture("io_stalls.log"))))
        self.assertNotIn("<script", svg)
        self.assertNotIn("href", svg)

    def test_long_reports_show_only_the_worst_findings(self):
        entries = read_entries(fixture("login_patterns.log"))
        findings = classify(entries)
        self.assertGreater(len(findings), 50)
        text = render_html(entries, findings, html_limit=10)
        self.assertEqual(text.count('<details class="sev-'), 10)
        self.assertIn("%d more finding(s)" % (len(findings) - 10), text)
        self.assertIn("Login failures by client", text)       # the summaries still use every finding

    def test_limit_zero_shows_everything(self):
        entries = read_entries(fixture("login_patterns.log"))
        findings = classify(entries)
        text = render_html(entries, findings, html_limit=0)
        self.assertEqual(text.count('<details class="sev-'), len(findings))
        self.assertNotIn("more finding(s)", text)

    def test_default_limit_is_500(self):
        from errorlog_insight.report.htmlout import DEFAULT_HTML_LIMIT
        self.assertEqual(DEFAULT_HTML_LIMIT, 500)

    def test_cli_option(self):
        out = io.StringIO()
        main([fixture("login_patterns.log"), "--html", "--html-limit", "5", "--no-insights"], out=out)
        self.assertEqual(out.getvalue().count('<details class="sev-'), 5)

    def test_empty_report(self):
        text = render("noise.log")
        self.assertIn("Nothing recognised.", text)
        self.assertIn("Unrecognised messages", text)

    def test_cli_flag(self):
        out = io.StringIO()
        main([fixture("login_failures.log"), "--html"], out=out)
        self.assertTrue(out.getvalue().startswith("<!doctype html>"))
        self.assertIn("Bursts", out.getvalue())

    def test_esc_handles_none(self):
        self.assertEqual(esc(None), "")
        self.assertEqual(esc('a"b'), "a&quot;b")


if __name__ == "__main__":
    unittest.main()
