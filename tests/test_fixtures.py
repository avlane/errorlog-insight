import os
import unittest

from tests.helpers import FIXTURES
from tools.encode_log import encode


class FixtureSyncTests(unittest.TestCase):
    """The .log fixtures must be exact encodings of their readable sources."""

    def test_logs_match_sources(self):
        src_dir = os.path.join(FIXTURES, "src")
        names = [n for n in os.listdir(src_dir) if n.endswith(".txt")]
        self.assertTrue(names)
        for name in names:
            with open(os.path.join(src_dir, name), encoding="utf-8", newline="") as f:
                expected = encode(f.read())
            log = os.path.join(FIXTURES, name[:-4] + ".log")
            with open(log, "rb") as f:
                self.assertEqual(f.read(), expected, name)


if __name__ == "__main__":
    unittest.main()
