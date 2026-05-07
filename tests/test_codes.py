import contextlib
import io
import os
import unittest

from errorlog_insight.classify import LABELS, classify
from errorlog_insight.cli import code_sort_key, list_codes, main
from errorlog_insight.reader import read_entries
from tests.helpers import FIXTURES, fixture


def codes_in_fixtures():
    codes = set()
    for name in os.listdir(FIXTURES):
        if name.endswith((".log", ".tsv", ".csv")):
            codes |= {f.code for f in classify(read_entries(fixture(name)))}
    return codes


class CodeTests(unittest.TestCase):
    def test_every_code_a_fixture_produces_has_a_name(self):
        self.assertEqual(sorted(codes_in_fixtures() - set(LABELS)), [])

    def test_every_named_code_is_exercised_by_a_fixture(self):
        # a rule without a fixture is a rule without a test
        self.assertEqual(sorted(set(LABELS) - codes_in_fixtures()), [])

    def test_list_codes_output(self):
        out = io.StringIO()
        self.assertEqual(main(["--list-codes"], out=out), 0)
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), len(LABELS))
        self.assertTrue(lines[0].startswith("701 "))
        self.assertRegex(out.getvalue(), r"(?m)^18456 +Login failures$")
        numeric = [l.split()[0] for l in lines if l.split()[0].isdigit()]
        self.assertEqual(numeric, sorted(numeric, key=int))
        self.assertTrue(lines[-1].split()[0][0].isalpha())    # named codes come last

    def test_sort_key(self):
        self.assertEqual(sorted(["traceflag", "833", "18456", "ag-transition", "9002"], key=code_sort_key),
                         ["833", "9002", "18456", "ag-transition", "traceflag"])

    def test_files_are_required_otherwise(self):
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as ctx:
            main([], out=io.StringIO())
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("no input files", err.getvalue())

    def test_list_codes_text_matches_the_function(self):
        out = io.StringIO()
        main(["--list-codes"], out=out)
        self.assertEqual(out.getvalue(), list_codes())


if __name__ == "__main__":
    unittest.main()
