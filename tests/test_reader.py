import unittest
from datetime import datetime

from errorlog_insight.reader import decode, parse_entries, read_entries
from tests.helpers import fixture


class ReaderTests(unittest.TestCase):
    def test_reads_utf16_file(self):
        entries = read_entries(fixture("startup_2019.log"))
        self.assertEqual(entries[0].timestamp, datetime(2021, 3, 1, 6, 0, 1, 250000))
        self.assertEqual(entries[0].process, "Server")
        self.assertTrue(entries[0].text.startswith("Microsoft SQL Server 2019"))

    def test_banner_is_one_multiline_entry(self):
        entries = read_entries(fixture("startup_2019.log"))
        banner = entries[0]
        self.assertEqual(len(banner.text.splitlines()), 4)
        self.assertIn("Enterprise Edition (64-bit)", banner.text)
        self.assertEqual(entries[1].text, "UTC adjustment: -5:00")

    def test_entry_count_and_last_entry(self):
        entries = read_entries(fixture("startup_2019.log"))
        self.assertEqual(len(entries), 24)
        self.assertIn("ready for client connections", entries[-1].text)
        self.assertEqual(entries[-1].process, "spid6s")

    def test_line_numbers_are_physical(self):
        entries = read_entries(fixture("startup_2019.log"))
        self.assertEqual(entries[0].lineno, 1)
        self.assertEqual(entries[1].lineno, 6)

    def test_decode_requires_bom_for_utf16(self):
        raw = b"\xff\xfe" + "2021-01-01 00:00:00.00 Server x".encode("utf-16-le")
        self.assertTrue(decode(raw).startswith("2021-01-01"))

    def test_parse_entries_ignores_leading_junk(self):
        entries = parse_entries("junk before\n2021-01-01 00:00:00.10 spid5s      hello\n")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].text, "hello")


if __name__ == "__main__":
    unittest.main()
