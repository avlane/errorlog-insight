import io
import unittest

from errorlog_insight.cli import main, text_width
from errorlog_insight.report import wrap_report
from tests.helpers import fixture


class WrapTests(unittest.TestCase):
    def test_short_lines_are_untouched(self):
        self.assertEqual(wrap_report("one\n  two\n", 40), "one\n  two\n")

    def test_zero_or_negative_width_means_no_wrapping(self):
        text = "word " * 50
        self.assertEqual(wrap_report(text, 0), text)
        self.assertEqual(wrap_report(text, -5), text)

    def test_long_line_wraps_with_a_deeper_indent(self):
        text = "  [ERROR] 2026-05-28 10:00:00  " + "word " * 12
        lines = wrap_report(text, 40).split("\n")
        self.assertGreater(len(lines), 1)
        self.assertTrue(all(len(l) <= 40 for l in lines))
        self.assertTrue(all(l.startswith("      ") for l in lines[1:]))     # indent 2 + 4

    def test_advice_lines_line_up_under_the_arrow_text(self):
        text = "      -> " + "advice " * 12
        lines = wrap_report(text, 40).split("\n")
        self.assertEqual(lines[0][:9], "      -> ")
        self.assertTrue(all(l.startswith("         ") for l in lines[1:]))   # indent 6 + 3
        self.assertFalse(lines[1].startswith("          "))

    def test_a_word_longer_than_the_width_is_not_broken(self):
        text = "  " + "x" * 80
        self.assertEqual(wrap_report(text, 40), text)

    def test_wrapping_loses_no_words(self):
        text = "  " + " ".join("w%d" % i for i in range(60))
        self.assertEqual(wrap_report(text, 30).split(), text.split())


class CliWidthTests(unittest.TestCase):
    def report(self, *extra):
        out = io.StringIO()
        main([fixture("ag_lease_failover.log")] + list(extra), out=out)
        return out.getvalue()

    def test_default_is_not_wrapped_when_not_a_terminal(self):
        self.assertTrue(any(len(l) > 150 for l in self.report().splitlines()))

    def test_width_option(self):
        # --redact so the input path (one unbreakable word) is not in the report
        self.assertTrue(all(len(l) <= 80 for l in self.report("--width", "80", "--redact").splitlines()))

    def test_width_zero(self):
        self.assertTrue(any(len(l) > 150 for l in self.report("--width", "0").splitlines()))

    def test_json_and_html_are_never_wrapped(self):
        self.assertEqual(self.report("--json", "--width", "30"), self.report("--json"))
        self.assertEqual(self.report("--html", "--width", "30"), self.report("--html"))

    def test_text_width_rules(self):
        class Args:
            width = None
            output = None

        class Tty(io.StringIO):
            def isatty(self):
                return True

        args = Args()
        self.assertEqual(text_width(args, io.StringIO()), 0)
        self.assertGreater(text_width(args, Tty()), 0)
        args.output = "file.txt"
        self.assertEqual(text_width(args, Tty()), 0)
        args.width = 72
        self.assertEqual(text_width(args, io.StringIO()), 72)


if __name__ == "__main__":
    unittest.main()
