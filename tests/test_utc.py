import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from errorlog_insight.cli import main
from tests.helpers import fixture


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(err):
        code = main(list(args) + ["--json"], out=out)
    return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()


class UtcTests(unittest.TestCase):
    def test_utc_adjustment_is_applied(self):
        _, doc, err = run(fixture("startup_2019.log"), "--utc")
        # the log says UTC adjustment: -5:00, so local 06:00:01 is 11:00:01 UTC
        self.assertEqual(doc["period"]["first"], "2021-03-01T11:00:01.250")
        self.assertEqual(err, "")

    def test_without_the_flag_times_stay_local(self):
        _, doc, _ = run(fixture("startup_2019.log"))
        self.assertEqual(doc["period"]["first"], "2021-03-01T06:00:01.250")

    def test_server_without_a_startup_banner_is_left_alone_with_a_warning(self):
        _, doc, err = run("A=" + fixture("startup_2019.log"), "B=" + fixture("noise.log"), "--utc")
        self.assertIn("no UTC adjustment line for B", err)
        self.assertEqual(doc["period"]["first"], "2021-03-01T11:00:01.250")
        self.assertEqual(doc["period"]["last"], "2021-09-14T07:00:00.070")

    def test_rotated_archive_uses_the_offset_of_its_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(fixture("startup_2019.log"), os.path.join(tmp, "ERRORLOG"))
            shutil.copy(fixture("noise.log"), os.path.join(tmp, "ERRORLOG.1"))
            _, doc, err = run("SQLPROD01=" + os.path.join(tmp, "ERRORLOG*"), "--utc")
        self.assertEqual(err, "")
        self.assertEqual(doc["period"]["last"], "2021-09-14T12:00:00.070")   # 07:00 local + 5 h

    def test_window_applies_to_the_converted_times(self):
        _, doc, _ = run(fixture("startup_2019.log"), "--utc", "--since", "2021-03-01 11:00:05")
        self.assertEqual(doc["period"]["first"][:19], "2021-03-01T11:00:07")

    def test_offset_is_applied_before_utc(self):
        _, doc, _ = run("A=" + fixture("startup_2019.log"), "--utc", "--offset", "A=+1h")
        self.assertEqual(doc["period"]["first"], "2021-03-01T12:00:01.250")

    def test_unknown_offset_label_still_exits_2(self):
        code, doc, err = run(fixture("startup_2019.log"), "--offset", "Z=+1s")
        self.assertEqual(code, 2)
        self.assertIn("--offset names no input file: Z", err)


if __name__ == "__main__":
    unittest.main()
