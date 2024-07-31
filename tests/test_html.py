import io
import unittest
from datetime import datetime
from html.parser import HTMLParser

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.cli import main
from errorlog_insight.htmlreport import esc, render_html
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
