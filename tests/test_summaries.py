import io
import json
import unittest

from errorlog_insight.classify import classify
from errorlog_insight.cli import main
from errorlog_insight.reader import read_entries
from errorlog_insight.summaries import io_summary, login_summary, login_summary
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


class LoginSummaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = login_summary(classify(read_entries(fixture("login_patterns.log"))))
        cls.by_client = {r["client"]: r for r in cls.rows}

    def test_patterns(self):
        patterns = {c: r["pattern"] for c, r in self.by_client.items()}
        self.assertEqual(patterns, {
            "10.20.8.15": "password guessing",
            "203.0.113.45": "many users tried",
            "10.20.4.50": "repeating client",
            "10.20.8.19": "occasional",
        })

    def test_worst_first(self):
        self.assertEqual([r["pattern"] for r in self.rows],
                         ["password guessing", "many users tried", "repeating client", "occasional"])

    def test_many_users_row(self):
        r = self.by_client["203.0.113.45"]
        self.assertEqual(r["failures"], 12)
        self.assertEqual(r["users"], ["admin", "backup", "sa", "sql", "test", "user1"])
        self.assertEqual(r["states"], {5: 10, 8: 2})

    def test_repeating_client_is_database_state(self):
        r = self.by_client["10.20.4.50"]
        self.assertEqual(r["failures"], 40)
        self.assertEqual(r["states"], {38: 40})

    def test_two_typos_are_just_occasional(self):
        self.assertEqual(self.by_client["10.20.8.19"]["failures"], 2)

    def test_spread_out_wrong_passwords_are_not_guessing(self):
        from datetime import datetime, timedelta
        from errorlog_insight.model import Entry
        entries = [Entry(datetime(2023, 7, 18, 8, 0) + timedelta(minutes=30 * i), "Logon",
                         "Login failed for user 'bob'. Reason: Password did not match that for the login provided. [CLIENT: 10.1.1.1]")
                   for i in range(6)]
        (row,) = login_summary(classify(entries))
        self.assertEqual(row["pattern"], "occasional")

    def test_cli_sections(self):
        out = io.StringIO()
        main([fixture("login_patterns.log")], out=out)
        text = out.getvalue()
        self.assertIn("Login failures by client", text)
        self.assertIn("203.0.113.45", text)
        self.assertIn("many users tried", text)
        self.assertIn("admin, backup, sa +3 more", text)
        out = io.StringIO()
        main([fixture("login_patterns.log"), "--html"], out=out)
        self.assertIn("<h2>Login failures by client</h2>", out.getvalue())


if __name__ == "__main__":
    unittest.main()
