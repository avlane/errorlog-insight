import io
import unittest

from errorlog_insight.cli import main
from tests.helpers import fixture


def run(*names):
    out = io.StringIO()
    code = main([fixture(n) for n in names], out=out)
    return code, out.getvalue()


class CliTests(unittest.TestCase):
    def test_summary_of_one_file(self):
        code, text = run("io_stalls.log")
        self.assertEqual(code, 0)
        self.assertIn("Findings: 7", text)
        self.assertIn("Slow I/O (833)", text)
        self.assertIn("x7", text)

    def test_most_severe_first(self):
        _, text = run("io_stalls.log")
        first = text.split("Most severe")[1].splitlines()[1]
        self.assertTrue(first.strip().startswith("[ERROR]"))

    def test_multiple_files(self):
        _, text = run("login_failures.log", "io_stalls.log")
        self.assertIn("Login failures", text)
        self.assertIn("Slow I/O (833)", text)
        self.assertIn("Findings: 22", text)

    def test_nothing_recognised(self):
        _, text = run("noise.log")
        self.assertIn("Nothing recognised.", text)

    def test_period_line(self):
        _, text = run("login_failures.log")
        self.assertIn("2021-03-02 07:55:10 .. 2021-03-02 15:18:33", text)


if __name__ == "__main__":
    unittest.main()
