import contextlib
import io
import json
import os
import tempfile
import unittest

from errorlog_insight.cli import main
from errorlog_insight.config import ConfigError, load_settings, read_config, settings_from_config
from tests.helpers import fixture

INI = """\
[report]
top = 3
min_severity = warning

[bursts]
min = 8
factor = 4.5
"""

TOML = """\
[report]
top = 3
min_severity = "warning"

[bursts]
min = 8
factor = 4.5
window = 15
"""


def write(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


class SettingsTests(unittest.TestCase):
    def test_defaults(self):
        s = load_settings()
        self.assertEqual((s.top, s.min_severity, s.bursts.min_count, s.bursts.factor), (10, "info", 5, 3.0))

    def test_ini_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = load_settings(write(tmp, "eli.ini", INI))
        self.assertEqual((s.top, s.min_severity, s.bursts.min_count, s.bursts.factor), (3, "warning", 8, 4.5))

    def test_toml_file(self):
        try:
            import tomllib  # noqa: F401
        except ImportError:
            self.skipTest("TOML needs Python 3.11+")
        with tempfile.TemporaryDirectory() as tmp:
            s = load_settings(write(tmp, "eli.toml", TOML))
        self.assertEqual((s.top, s.bursts.min_count, s.bursts.window), (3, 8, 15))

    def test_command_line_beats_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = load_settings(write(tmp, "eli.ini", INI), top=20, burst_min=2)
        self.assertEqual((s.top, s.bursts.min_count, s.bursts.factor), (20, 2, 4.5))

    def test_unknown_key_and_section(self):
        with self.assertRaises(ConfigError):
            settings_from_config({"report": {"limit": "3"}})
        with self.assertRaises(ConfigError):
            settings_from_config({"colour": {}})

    def test_bad_values(self):
        with self.assertRaises(ConfigError):
            settings_from_config({"report": {"top": "many"}})
        with self.assertRaises(ConfigError):
            settings_from_config({"bursts": {"min": "0"}})
        with self.assertRaises(ConfigError):
            settings_from_config({"report": {"min_severity": "loud"}})

    def test_missing_file(self):
        with self.assertRaises(ConfigError):
            read_config("/nonexistent/eli.ini")


class CliConfigTests(unittest.TestCase):
    def test_config_changes_burst_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write(tmp, "eli.ini", "[bursts]\nmin = 7\n")
            out = io.StringIO()
            main([fixture("login_failures.log"), "--json", "--config", cfg], out=out)
        self.assertEqual(json.loads(out.getvalue())["bursts"], [])

    def test_bad_config_exits_with_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write(tmp, "eli.ini", "[report]\ntop = lots\n")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = main([fixture("noise.log"), "--config", cfg], out=io.StringIO())
        self.assertEqual(code, 2)
        self.assertIn("top must be a number", err.getvalue())


if __name__ == "__main__":
    unittest.main()
