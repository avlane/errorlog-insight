import io
import json
import unittest
from datetime import datetime

from errorlog_insight.cli import main
from errorlog_insight.model import Entry
from errorlog_insight.reader import read_entries
from errorlog_insight.serverinfo import collect_server_info, describe
from tests.helpers import fixture


class ServerInfoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.starts = collect_server_info(read_entries(fixture("startup_2019.log"), replica="SQLPROD01"))

    def test_one_start(self):
        self.assertEqual(len(self.starts), 1)
        self.assertEqual(self.starts[0]["server"], "SQLPROD01")
        self.assertEqual(self.starts[0]["started"], datetime(2021, 3, 1, 6, 0, 1, 250000))

    def test_version_and_edition(self):
        info = self.starts[0]
        self.assertEqual((info["version_year"], info["level"], info["build"]), (2019, "RTM-CU8", "15.0.4073.23"))
        self.assertEqual(info["edition"], "Enterprise Edition (64-bit)")

    def test_hardware(self):
        info = self.starts[0]
        self.assertEqual(info["logical_processors"], 8)
        self.assertEqual(info["sockets"], 2)
        self.assertEqual(info["memory_mb"], 65535)
        self.assertTrue(info["virtual"])
        self.assertEqual(info["model"], "VMware7,1")

    def test_settings(self):
        info = self.starts[0]
        self.assertEqual(info["authentication"], "mixed")
        self.assertEqual(info["service_account"], "CONTOSO\\svc_sqlprod")
        self.assertEqual(info["utc_offset_minutes"], -300)
        self.assertEqual(info["collation"], "SQL_Latin1_General_CP1_CI_AS")
        self.assertEqual(info["process_id"], 4184)

    def test_description(self):
        self.assertEqual(
            describe(self.starts[0]),
            "SQL Server 2019 RTM-CU8 (15.0.4073.23), Enterprise Edition, Windows Server 2019 Standard 10.0, "
            "8 logical CPUs, 64 GB RAM, mixed authentication, virtual machine")

    def test_two_starts_and_two_servers(self):
        entries = read_entries(fixture("startup_2019.log"), replica="A") + read_entries(fixture("startup_2019.log"), replica="B")
        for e in entries[24:]:
            e.timestamp = e.timestamp.replace(day=9)
        starts = collect_server_info(entries)
        self.assertEqual([(s["server"], s["started"].day) for s in starts], [("A", 1), ("B", 9)])

    def test_next_banner_ends_the_previous_start(self):
        banner = ("Microsoft SQL Server 2022 (RTM-CU4) (KB5026717) - 16.0.4045.3 (X64) \n\tMay 2 2023 \n"
                  "\tEnterprise Edition (64-bit) on Windows Server 2022 Standard 10.0 <X64>")
        entries = [Entry(datetime(2023, 6, 1, 6, 0, 0), "Server", banner, replica="S"),
                   Entry(datetime(2023, 6, 1, 6, 0, 5), "Server", "Microsoft SQL Server 2022 (RTM-CU4) (KB5026717) - 16.0.4045.3 (X64)", replica="S"),
                   Entry(datetime(2023, 6, 1, 6, 0, 6), "Server", "Detected 32768 MB of RAM. This is an informational message; no user action is required.", replica="S")]
        starts = collect_server_info(entries)
        self.assertEqual(len(starts), 2)
        self.assertNotIn("memory_mb", starts[0])
        self.assertEqual(starts[1]["memory_mb"], 32768)

    def test_logs_without_a_banner(self):
        self.assertEqual(collect_server_info(read_entries(fixture("noise.log"))), [])

    def test_positive_utc_offset_and_physical_machine(self):
        text = [("Microsoft SQL Server 2017 (RTM-CU22) (KB4577467) - 14.0.3356.20 (X64) \n\tEnterprise Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64>"),
                "UTC adjustment: 5:30", "System Manufacturer: 'Dell Inc.', System Model: 'PowerEdge R740'."]
        entries = [Entry(datetime(2023, 6, 1, 6, 0, i), "Server", t, replica="S") for i, t in enumerate(text)]
        info = collect_server_info(entries)[0]
        self.assertEqual(info["utc_offset_minutes"], 330)
        self.assertFalse(info["virtual"])


class ReportTests(unittest.TestCase):
    def test_text_json_html(self):
        out = io.StringIO()
        main(["SQLPROD01=" + fixture("startup_2019.log")], out=out)
        self.assertIn("Servers (one line per start in the logs)", out.getvalue())
        self.assertIn("2021-03-01 06:00:01  SQLPROD01  SQL Server 2019 RTM-CU8", out.getvalue())
        out = io.StringIO()
        main(["SQLPROD01=" + fixture("startup_2019.log"), "--json"], out=out)
        server = json.loads(out.getvalue())["servers"][0]
        self.assertEqual(server["started"], "2021-03-01T06:00:01.250")
        self.assertEqual(server["logical_processors"], 8)
        out = io.StringIO()
        main(["SQLPROD01=" + fixture("startup_2019.log"), "--html"], out=out)
        self.assertIn("<h2>Servers</h2>", out.getvalue())


if __name__ == "__main__":
    unittest.main()
