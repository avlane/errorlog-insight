import unittest
from datetime import datetime

from errorlog_insight.reader import decode, parse_entries, parse_readerrorlog, read_entries
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

    def test_decode_with_bom(self):
        raw = b"\xff\xfe" + "2021-01-01 00:00:00.00 Server x".encode("utf-16-le")
        self.assertTrue(decode(raw).startswith("2021-01-01"))

    def test_decode_utf16_without_bom(self):
        raw = "2021-01-01 00:00:00.00 Server x\r\n".encode("utf-16-le")
        self.assertTrue(decode(raw).startswith("2021-01-01"))

    def test_decode_truncated_utf16(self):
        # a copy taken while SQL Server was mid-write can end on half a character
        raw = b"\xff\xfe" + "2021-01-01 00:00:00.00 Server hello".encode("utf-16-le") + b"\x41"
        self.assertTrue(decode(raw).endswith("hello"))

    def test_decode_big_endian_bom(self):
        raw = b"\xfe\xff" + "2021-01-01 00:00:00.00 Server x".encode("utf-16-be")
        self.assertIn("Server x", decode(raw))

    def test_decode_utf8_and_legacy_code_page(self):
        self.assertEqual(decode(b"\xef\xbb\xbfabc"), "abc")
        self.assertEqual(decode("caf\u00e9".encode("cp1252")), "caf\u00e9")

    def test_crlf_and_stray_nul_bytes(self):
        text = "2021-01-01 00:00:00.00 Server a\x00b\r\n\tcontinued\r\n2021-01-01 00:00:01.00 spid5s      c\r\n"
        entries = parse_entries(text)
        self.assertEqual([e.text for e in entries], ["ab\n\tcontinued", "c"])

    def test_parse_entries_ignores_leading_junk(self):
        entries = parse_entries("junk before\n2021-01-01 00:00:00.10 spid5s      hello\n")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].text, "hello")


class ReaderrorlogTests(unittest.TestCase):
    def test_reads_tab_separated_output(self):
        entries = read_entries(fixture("sp_readerrorlog.tsv"))
        self.assertEqual(len(entries), 5)
        self.assertEqual(entries[0].process, "Logon")
        self.assertEqual(entries[0].timestamp, datetime(2021, 3, 2, 8, 14, 22, 350000))

    def test_quoted_multiline_text_is_kept(self):
        entries = read_entries(fixture("sp_readerrorlog.tsv"))
        banner = entries[2]
        self.assertEqual(len(banner.text.splitlines()), 4)
        self.assertIn("Enterprise Edition", banner.text)

    def test_embedded_quotes(self):
        entries = read_entries(fixture("sp_readerrorlog.tsv"))
        self.assertEqual(entries[3].text, 'Using "dbghelp.dll" version "4.0.5"')

    def test_rejects_missing_header(self):
        with self.assertRaises(ValueError):
            parse_readerrorlog("Date\tProc\tText\n")


if __name__ == "__main__":
    unittest.main()
