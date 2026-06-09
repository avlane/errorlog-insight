import contextlib
import io
import json
import unittest

from errorlog_insight.cli import main
from errorlog_insight.config import ConfigError, load_settings
from tests.helpers import fixture


def bursts(*extra):
    out = io.StringIO()
    main([fixture("login_failures.log"), "--json"] + list(extra), out=out)
    return json.loads(out.getvalue())["bursts"]


class BurstOptionTests(unittest.TestCase):
    def test_default_finds_the_guessing_burst(self):
        (b,) = bursts()
        self.assertEqual(b["count"], 6)

    def test_wider_buckets_merge_more_events(self):
        # six failures within seven seconds, plus four more the same hour: a 10 minute bucket sees more
        found = bursts("--bucket-seconds", "600")
        self.assertEqual(found[0]["count"], 6)
        self.assertEqual(found[0]["start"], "2021-03-02T08:10:00.000")
        self.assertEqual(found[0]["end"], "2021-03-02T08:20:00.000")

    def test_one_second_buckets_split_the_burst(self):
        found = bursts("--bucket-seconds", "1", "--burst-min", "3")
        self.assertTrue(all(b["count"] < 6 for b in found))

    def test_values_below_one_are_refused(self):
        for flag in ("--burst-window", "--bucket-seconds", "--burst-min"):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = main([fixture("noise.log"), flag, "0"], out=io.StringIO())
            self.assertEqual(code, 2, flag)
            self.assertIn("must be at least 1", err.getvalue())

    def test_load_settings(self):
        s = load_settings(burst_window=12, bucket_seconds=300)
        self.assertEqual((s.bursts.window, s.bursts.bucket_seconds), (12, 300))
        with self.assertRaises(ConfigError):
            load_settings(burst_factor=-1)

    def test_flag_beats_config(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "eli.ini")
            with open(path, "w") as f:
                f.write("[bursts]\nbucket_seconds = 300\nwindow = 10\n")
            s = load_settings(path, bucket_seconds=60)
        self.assertEqual((s.bursts.bucket_seconds, s.bursts.window), (60, 10))


if __name__ == "__main__":
    unittest.main()
