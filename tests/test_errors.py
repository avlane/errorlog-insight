import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest

from errorlog_insight.cli import main
from tests.helpers import fixture


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(err):
        code = main(list(args), out=out)
    return code, out.getvalue(), err.getvalue()


class InputErrorTests(unittest.TestCase):
    def test_missing_file(self):
        code, out, err = run(os.path.join(tempfile.gettempdir(), "no-such-errorlog-xyz"))
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("errorlog-insight: cannot read", err)
        self.assertIn("no-such-errorlog-xyz", err)
        self.assertIn("No such file or directory", err)

    def test_wildcard_without_matches_names_the_pattern(self):
        code, _, err = run(os.path.join(tempfile.gettempdir(), "no-such-dir-xyz", "ERRORLOG*"))
        self.assertEqual(code, 2)
        self.assertIn("ERRORLOG*", err)

    def test_directory_instead_of_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run(tmp)
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    @unittest.skipIf(sys.platform == "win32" or os.geteuid() == 0, "permissions do not apply")
    def test_unreadable_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ERRORLOG")
            with open(path, "wb") as f:
                f.write(b"x")
            os.chmod(path, 0)
            try:
                code, _, err = run(path)
            finally:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        self.assertEqual(code, 2)
        self.assertIn("Permission denied", err)

    def test_saved_grid_with_an_unreadable_date(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "grid.csv")
            with open(path, "w", encoding="utf-8") as f:
                f.write("Date,Source,Message\n2. 3. 2021 8:14,Logon,hello\n")
            code, _, err = run(path)
        self.assertEqual(code, 2)
        self.assertIn("grid.csv: unrecognised date in saved grid", err)

    def test_one_bad_file_stops_the_run(self):
        code, out, _ = run(fixture("noise.log"), os.path.join(tempfile.gettempdir(), "no-such-errorlog-xyz"))
        self.assertEqual(code, 2)
        self.assertEqual(out, "")

    def test_a_file_that_is_not_an_errorlog_gives_an_empty_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "notes.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("just some notes\nnothing like a log\n")
            code, out, _ = run(path)
        self.assertEqual(code, 0)
        self.assertIn("Entries:  0", out)

    def test_no_arguments(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
            main([], out=io.StringIO())
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
