import unittest
from datetime import datetime

from errorlog_insight.reader import decode, parse_entries, parse_grid_date, parse_readerrorlog, read_entries
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


class DamagedLineTests(unittest.TestCase):
    def test_an_impossible_date_is_not_an_entry_start(self):
        text = ("2026-03-26 10:00:00.10 spid5s      first\n"
                "2026-02-30 10:00:01.10 spid5s      not a real day\n"
                "2026-03-26 25:00:00.10 spid5s      not a real hour\n"
                "2026-03-26 10:00:02.10 spid6s      second\n")
        entries = parse_entries(text)
        self.assertEqual([e.text for e in entries],
                         ["first\n2026-02-30 10:00:01.10 spid5s      not a real day\n"
                          "2026-03-26 25:00:00.10 spid5s      not a real hour", "second"])

    def test_a_damaged_first_line_is_ignored(self):
        entries = parse_entries("2026-02-30 10:00:01.10 spid5s      bad\n2026-03-26 10:00:02.10 spid6s      good\n")
        self.assertEqual([e.text for e in entries], ["good"])

    def test_three_digit_fractions(self):
        (e,) = parse_entries("2026-03-26 10:00:02.123 spid6s      x\n")
        self.assertEqual(e.timestamp.microsecond, 123000)


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


class LogViewerExportTests(unittest.TestCase):
    def test_comma_separated_newest_first_export(self):
        entries = read_entries(fixture("log_viewer_export.csv"))
        self.assertEqual(len(entries), 5)
        stamps = [e.timestamp for e in entries]
        self.assertEqual(stamps, sorted(stamps))
        self.assertEqual(entries[0].timestamp, datetime(2021, 3, 1, 23, 59, 58))
        self.assertEqual(entries[-1].process, "Backup")

    def test_same_second_entries_keep_log_order(self):
        entries = read_entries(fixture("log_viewer_export.csv"))
        self.assertTrue(entries[1].text.startswith("Error: 18456"))
        self.assertTrue(entries[2].text.startswith("Login failed"))

    def test_multiline_message(self):
        banner = read_entries(fixture("log_viewer_export.csv"))[3]
        self.assertEqual(len(banner.text.splitlines()), 4)

    def test_am_pm_dates(self):
        self.assertEqual(parse_grid_date("3/2/2021 8:20:12 AM"), datetime(2021, 3, 2, 8, 20, 12))
        self.assertEqual(parse_grid_date("3/2/2021 8:20:12 PM"), datetime(2021, 3, 2, 20, 20, 12))
        self.assertEqual(parse_grid_date("03/02/2021 20:20:12"), datetime(2021, 3, 2, 20, 20, 12))

    def test_iso_dates_with_fraction(self):
        self.assertEqual(parse_grid_date("2021-03-02 08:14:22.350"), datetime(2021, 3, 2, 8, 14, 22, 350000))
        self.assertEqual(parse_grid_date("2021-03-02 08:14:22"), datetime(2021, 3, 2, 8, 14, 22))

    def test_unknown_date_format(self):
        with self.assertRaises(ValueError):
            parse_grid_date("2. 3. 2021 8:14")

    def test_classification_works_on_exports(self):
        from errorlog_insight.classify import classify
        findings = classify(read_entries(fixture("log_viewer_export.csv")))
        self.assertEqual([f.code for f in findings], ["18456", "startup", "18264"])
        self.assertEqual(findings[0].details["state"], 8)


if __name__ == "__main__":
    unittest.main()
