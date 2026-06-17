import json
import os
import subprocess
import sys
import unittest

from tests.helpers import FIXTURES

ROOT = os.path.dirname(os.path.dirname(FIXTURES))


def all_fixtures():
    return [os.path.join("tests", "fixtures", n) for n in sorted(os.listdir(FIXTURES))
            if n.endswith((".log", ".tsv", ".csv"))]


def run(fmt, seed, *extra):
    env = dict(os.environ, PYTHONHASHSEED=str(seed), PYTHONIOENCODING="utf-8")
    done = subprocess.run([sys.executable, "-m", "errorlog_insight"] + all_fixtures() + ["--format", fmt] + list(extra),
                          cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return done


class DeterminismTests(unittest.TestCase):
    def test_the_same_report_whatever_the_hash_seed(self):
        """Sets and dicts must never leak their iteration order into a report."""
        for fmt in ("text", "json", "html"):
            outputs = {run(fmt, seed, "--redact").stdout for seed in (0, 1, 2, 3)}
            self.assertEqual(len(outputs), 1, fmt)

    def test_every_fixture_in_every_format_in_one_run(self):
        for fmt in ("text", "json", "html"):
            done = run(fmt, 0)
            self.assertEqual(done.returncode, 0, done.stderr.decode("utf-8", "replace")[-500:])
            self.assertEqual(done.stderr, b"")
            self.assertGreater(len(done.stdout), 1000)

    def test_json_from_all_fixtures_is_valid_and_complete(self):
        doc = json.loads(run("json", 0).stdout.decode("utf-8"))
        self.assertEqual(len(doc["files"]), len(all_fixtures()))
        self.assertGreater(len(doc["findings"]), 200)
        self.assertGreater(len(doc["incidents"]), 3)
        self.assertGreater(len(doc["insights"]), 10)
        self.assertEqual(doc["schema_version"], 1)

    def test_each_fixture_alone_does_not_crash(self):
        from errorlog_insight.cli import main
        import io
        for path in all_fixtures():
            for fmt in ("text", "json", "html"):
                out = io.StringIO()
                code = main([os.path.join(ROOT, path), "--format", fmt], out=out)
                self.assertEqual(code, 0, (path, fmt))
                self.assertTrue(out.getvalue(), (path, fmt))


if __name__ == "__main__":
    unittest.main()
