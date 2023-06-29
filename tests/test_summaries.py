import io
import json
import unittest

from errorlog_insight.classify import classify
from errorlog_insight.cli import main
from errorlog_insight.reader import read_entries
from errorlog_insight.summaries import io_summary
from tests.helpers import fixture


class IoSummaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = io_summary(classify(read_entries(fixture("io_stalls.log"))))

    def test_one_row_per_file_worst_first(self):
        self.assertEqual([r["file"] for r in self.rows], [
            "E:\\SQLData\\Sales_Data1.mdf",
            "\\\\FILESRV01\\SQLData\\Archive_2019.ndf",   # 15 s like the rest, but 4 requests
            "F:\\SQLLogs\\Sales_log.ldf",
            "T:\\TempDB\\tempdev2.ndf",
        ])

    def test_data_file_totals(self):
        r = self.rows[0]
        self.assertEqual(r["messages"], 4)
        self.assertEqual(r["requests"], 3 + 7 + 7 + 12)
        self.assertEqual(r["max_seconds"], 45)
        self.assertEqual(r["episodes"], 1)
        self.assertEqual(r["database"], "Sales")

    def test_quiet_gap_starts_a_new_episode(self):
        from datetime import datetime
        from errorlog_insight.model import Entry
        from errorlog_insight.rules.io import io_stall

        def stall(minute):
            text = ("SQL Server has encountered 1 occurrence(s) of I/O requests taking longer than 15 seconds to "
                    "complete on file [E:\\d.mdf] in database [Sales] (5).  The OS file handle is 0x00000000000009C4.  "
                    "The offset of the latest long I/O is: 0x000000a1c60000")
            e = Entry(datetime(2023, 6, 27, 1, minute), "spid22s", text)
            return io_stall(e, None)

        rows = io_summary([stall(0), stall(5), stall(40), stall(42)])
        self.assertEqual(rows[0]["episodes"], 2)

    def test_no_io_findings_no_rows(self):
        self.assertEqual(io_summary(classify(read_entries(fixture("noise.log")))), [])


class ReportTests(unittest.TestCase):
    def test_text_section(self):
        out = io.StringIO()
        main([fixture("io_stalls.log")], out=out)
        text = out.getvalue()
        self.assertIn("Slow I/O by file", text)
        self.assertIn("E:\\SQLData\\Sales_Data1.mdf (Sales, data)  worst 45 s, 29 requests in 4 message(s)", text)

    def test_json_summary(self):
        out = io.StringIO()
        main([fixture("io_stalls.log"), "--json"], out=out)
        rows = json.loads(out.getvalue())["summaries"]["io"]
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["first"], "2021-04-06T02:14:11.120")

    def test_html_section(self):
        out = io.StringIO()
        main([fixture("io_stalls.log"), "--html"], out=out)
        self.assertIn("<h2>Slow I/O by file</h2>", out.getvalue())


if __name__ == "__main__":
    unittest.main()
