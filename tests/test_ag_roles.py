import unittest

from errorlog_insight.classify import classify
from errorlog_insight.model import Entry
from errorlog_insight.reader import read_entries
from tests.helpers import fixture
from datetime import datetime


def findings_of(name):
    return classify(read_entries(fixture(name)))


class RoleTests(unittest.TestCase):
    def test_old_primary_goes_to_secondary(self):
        findings = findings_of("ag_primary.log")
        self.assertEqual([f.code for f in findings],
                         ["ag-transition", "19406", "1480", "1480", "19406", "1480", "1480"])
        self.assertEqual(findings[0].details["role"], "resolving")
        self.assertEqual((findings[2].details["old_role"], findings[2].details["new_role"]), ("PRIMARY", "RESOLVING"))
        self.assertEqual(findings[2].details["database"], "Sales")
        self.assertTrue(findings[2].details["planned"])
        self.assertEqual(findings[5].details["new_role"], "SECONDARY")

    def test_new_primary(self):
        findings = findings_of("ag_secondary.log")
        self.assertEqual(findings[0].details["role"], "primary")
        self.assertEqual(findings[1].details["new_state"], "PRIMARY_PENDING")
        self.assertEqual(findings[-1].details["new_state"], "PRIMARY_NORMAL")
        self.assertEqual(findings[-1].details["ag"], "AG_Sales")

    def test_planned_failover_is_info(self):
        for name in ("ag_primary.log", "ag_secondary.log"):
            self.assertTrue(all(f.severity == "info" for f in findings_of(name)), name)

    def test_unplanned_resolving_is_a_warning(self):
        text = ('The availability group database "Sales" is changing roles from "PRIMARY" to "RESOLVING" because '
                'the mirroring session or availability group failed over due to automatic failover. '
                'This is an informational message only. No user action is required.')
        (f,) = classify([Entry(datetime(2022, 5, 17, 3, 12), "spid30s", text)])
        self.assertEqual(f.severity, "warning")
        self.assertFalse(f.details["planned"])
        self.assertIn("quorum", f.advice)

    def test_replica_state_not_user_initiated(self):
        text = ("The state of the local availability replica in availability group 'AG_Sales' has changed from "
                "'PRIMARY_NORMAL' to 'RESOLVING_NORMAL'.  The state changed because the lease expired.  "
                "For more information, see the SQL Server error log, Windows Server Failover Clustering (WSFC) "
                "log, or WSFC management console.")
        (f,) = classify([Entry(datetime(2022, 5, 17, 3, 12), "spid30s", text)])
        self.assertEqual(f.severity, "warning")
        self.assertFalse(f.details["user_initiated"])


if __name__ == "__main__":
    unittest.main()
