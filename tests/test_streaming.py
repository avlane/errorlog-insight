import os
import tempfile
import types
import unittest

from errorlog_insight.reader import decode, iter_entries, parse_entries, read_entries
from tests.helpers import FIXTURES, fixture


def same(a, b):
    return [(e.timestamp, e.process, e.text, e.lineno) for e in a] == [(e.timestamp, e.process, e.text, e.lineno) for e in b]


class StreamingTests(unittest.TestCase):
    def test_iter_entries_is_lazy(self):
        gen = iter_entries(fixture("startup_2019.log"))
        self.assertIsInstance(gen, types.GeneratorType)
        first = next(gen)
        self.assertEqual(first.process, "Server")

    def test_streaming_matches_whole_file_parsing_for_every_log_fixture(self):
        names = [n for n in os.listdir(FIXTURES) if n.endswith(".log")]
        self.assertGreater(len(names), 10)
        for name in names:
            with open(fixture(name), "rb") as f:
                expected = parse_entries(decode(f.read()))
            self.assertTrue(same(read_entries(fixture(name)), expected), name)

    def test_large_file(self):
        line = "2024-10-29 10:%02d:%02d.%02d spid%ds     Starting up database 'Db%d'.\r\n"
        text = "".join(line % (i // 60 % 60, i % 60, i % 90, i % 7, i % 1000) for i in range(30000))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ERRORLOG")
            with open(path, "wb") as f:
                f.write(b"\xff\xfe" + text.encode("utf-16-le"))
            count = sum(1 for _ in iter_entries(path))
        self.assertEqual(count, 30000)

    def write(self, data):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = os.path.join(self.tmp.name, "ERRORLOG")
        with open(path, "wb") as f:
            f.write(data)
        return path

    def test_utf16_without_bom(self):
        path = self.write("2024-10-29 10:00:00.10 Server      hello\r\n2024-10-29 10:00:01.10 Server      bye\r\n".encode("utf-16-le"))
        self.assertEqual([e.text for e in read_entries(path)], ["hello", "bye"])

    def test_utf16_big_endian(self):
        path = self.write(b"\xfe\xff" + "2024-10-29 10:00:00.10 Server      hello\r\n".encode("utf-16-be"))
        self.assertEqual([e.text for e in read_entries(path)], ["hello"])

    def test_utf8_with_bom(self):
        path = self.write(b"\xef\xbb\xbf" + "2024-10-29 10:00:00.10 Server      café\n".encode("utf-8"))
        self.assertEqual(read_entries(path)[0].text, "café")

    def test_cp1252(self):
        path = self.write("2024-10-29 10:00:00.10 Server      café au lait\n".encode("cp1252"))
        self.assertEqual(read_entries(path)[0].text, "café au lait")

    def test_file_cut_in_the_middle_of_a_character(self):
        data = b"\xff\xfe" + "2024-10-29 10:00:00.10 Server      hello\r\n2024-10-29 10:00:01.10 Server      cut".encode("utf-16-le") + b"\x41"
        entries = read_entries(self.write(data))
        self.assertEqual(len(entries), 2)
        self.assertTrue(entries[1].text.startswith("cut"))

    def test_grid_files_still_work(self):
        entries = list(iter_entries(fixture("log_viewer_export.csv")))
        self.assertEqual(len(entries), 5)
        self.assertEqual(len(list(iter_entries(fixture("sp_readerrorlog.tsv")))), 5)

    def test_empty_file(self):
        self.assertEqual(read_entries(self.write(b"")), [])

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            read_entries(os.path.join(FIXTURES, "no-such-file.log"))


if __name__ == "__main__":
    unittest.main()
