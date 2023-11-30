import io
import json
import unittest
from datetime import datetime, timedelta

from errorlog_insight.classify import classify
from errorlog_insight.cli import main
from errorlog_insight.incidents import find_incidents
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


def findings(*pairs):
    out = []
    for label, name in pairs:
        out.extend(classify(read_entries(fixture(name), replica=label)))
    return out


class IncidentTests(unittest.TestCase):
    def test_planned_failover_across_two_servers(self):
        (inc,) = find_incidents(findings(("SQLPROD01", "ag_primary.log"), ("SQLDR02", "ag_secondary.log")))
        self.assertEqual(inc["kind"], "planned failover")
        self.assertEqual(inc["old_primary"], "SQLPROD01")
        self.assertEqual(inc["new_primary"], "SQLDR02")
        self.assertEqual(inc["databases"], ["Reporting", "Sales"])
        self.assertEqual(inc["ags"], ["AG_Sales"])
        self.assertEqual(inc["replicas"], ["SQLDR02", "SQLPROD01"])
        self.assertEqual(inc["events"], 12)
        self.assertEqual(inc["no_primary_seconds"], 1.1)
        self.assertEqual(inc["start"], datetime(2022, 5, 10, 21, 59, 59, 800000))

    def test_one_server_only_still_finds_the_incident(self):
        (inc,) = find_incidents(findings(("SQLPROD01", "ag_primary.log")))
        self.assertEqual(inc["old_primary"], "SQLPROD01")
        self.assertIsNone(inc["new_primary"])
        self.assertIsNone(inc["no_primary_seconds"])
        self.assertEqual(inc["kind"], "planned failover")

    def test_unplanned_failover_and_rejoin_are_separate_incidents(self):
        incidents = find_incidents(findings(
            ("SQLPROD01", "ag_unplanned_old_primary.log"), ("SQLDR02", "ag_unplanned_new_primary.log")))
        self.assertEqual([i["kind"] for i in incidents],
                         ["unplanned failover", "replica rejoined", "role activity"])
        first = incidents[0]
        self.assertEqual(first["no_primary_seconds"], 14.59)
        self.assertEqual((first["old_primary"], first["new_primary"]), ("SQLPROD01", "SQLDR02"))
        self.assertEqual(incidents[1]["replicas"], ["SQLPROD01"])

    def test_failed_failover(self):
        (inc,) = find_incidents(findings(("SQLDR02", "ag_failed_failover.log")))
        self.assertEqual(inc["kind"], "failed failover")
        self.assertEqual(inc["ags"], ["AG_Sales"])

    def test_gap_parameter_splits_incidents(self):
        fs = findings(("SQLPROD01", "ag_primary.log"), ("SQLDR02", "ag_secondary.log"))
        self.assertEqual(len(find_incidents(fs, gap=timedelta(milliseconds=100))), 9)

    def test_clock_skew_shows_up_as_negative_gap(self):
        old = findings(("SQLPROD01", "ag_primary.log"))
        new = classify(read_entries(fixture("ag_secondary.log"), replica="SQLDR02"))
        for f in new:
            for e in f.entries:
                e.timestamp -= timedelta(seconds=30)
        (inc,) = find_incidents(old + new)
        self.assertTrue(inc["clock_skew_suspected"])
        self.assertLess(inc["no_primary_seconds"], 0)

    def test_nothing_to_report(self):
        self.assertEqual(find_incidents(findings(("A", "noise.log"), ("A", "io_stalls.log"))), [])


class IncidentReportTests(unittest.TestCase):
    def run_cli(self, *extra):
        out = io.StringIO()
        main(["SQLPROD01=" + fixture("ag_primary.log"), "SQLDR02=" + fixture("ag_secondary.log")] + list(extra), out=out)
        return out.getvalue()

    def test_text_section(self):
        text = self.run_cli()
        self.assertIn("Availability group incidents", text)
        self.assertIn("2022-05-10 21:59:59 .. 22:00:04  planned failover   AG_Sales  SQLPROD01 -> SQLDR02  no primary for 1.1 s", text)
        self.assertIn("databases: Reporting, Sales", text)

    def test_incidents_survive_the_severity_filter(self):
        text = self.run_cli("--min-severity", "warning")
        self.assertIn("planned failover", text)

    def test_json(self):
        doc = json.loads(self.run_cli("--json"))
        self.assertEqual(doc["incidents"][0]["new_primary"], "SQLDR02")
        self.assertEqual(doc["incidents"][0]["start"], "2022-05-10T21:59:59.800")

    def test_html(self):
        text = self.run_cli("--html")
        self.assertIn("<h2>Availability group incidents</h2>", text)
        self.assertIn("<td>planned failover</td>", text)

    def test_skew_hint(self):
        text = self.run_cli("--offset", "SQLDR02=-30s")
        self.assertIn("clocks differ, try --offset", text)


if __name__ == "__main__":
    unittest.main()
