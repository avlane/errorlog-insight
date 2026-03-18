import contextlib
import io
import unittest

from errorlog_insight.cli import main
from tests.helpers import fixture


def code_for(*args):
    return main(list(args), out=io.StringIO())


class FailOnTests(unittest.TestCase):
    def test_default_is_zero_whatever_is_found(self):
        self.assertEqual(code_for(fixture("stackdump.log")), 0)

    def test_critical_finding_trips_every_threshold(self):
        for level in ("info", "warning", "error", "critical"):
            self.assertEqual(code_for(fixture("stackdump.log"), "--fail-on", level), 1, level)

    def test_threshold_above_the_worst_finding(self):
        # io_stalls: the worst is an error
        self.assertEqual(code_for(fixture("io_stalls.log"), "--fail-on", "error"), 1)
        self.assertEqual(code_for(fixture("io_stalls.log"), "--fail-on", "critical"), 0)

    def test_info_only_log(self):
        self.assertEqual(code_for(fixture("startup_2019.log"), "--fail-on", "info"), 1)
        self.assertEqual(code_for(fixture("startup_2019.log"), "--fail-on", "warning"), 0)

    def test_no_findings_at_all(self):
        self.assertEqual(code_for(fixture("noise.log"), "--fail-on", "info"), 0)

    def test_min_severity_hides_findings_from_the_report_but_not_from_fail_on(self):
        out = io.StringIO()
        code = main([fixture("stackdump.log"), "--min-severity", "critical", "--fail-on", "error"], out=out)
        self.assertEqual(code, 1)

    def test_since_until_decide_what_counts(self):
        code = code_for(fixture("stackdump.log"), "--since", "2022-03-08 16:00", "--fail-on", "critical")
        self.assertEqual(code, 0)   # the access violation was at 11:42, the later dump is only an error

    def test_report_is_still_written(self):
        out = io.StringIO()
        main([fixture("stackdump.log"), "--fail-on", "critical"], out=out)
        self.assertIn("errorlog-insight report", out.getvalue())

    def test_bad_severity_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            code_for(fixture("noise.log"), "--fail-on", "fatal")
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
