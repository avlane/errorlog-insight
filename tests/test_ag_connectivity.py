import unittest

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class ConnectivityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("ag_connectivity.log"))
        cls.findings = classify(cls.entries)

    def test_sequence(self):
        self.assertEqual([f.code for f in self.findings],
                         ["1479", "1479", "35206", "35201", "35201", "35202"])

    def test_mirroring_timeout(self):
        f = self.findings[0]
        self.assertEqual(f.details["endpoint"], "TCP://SQLDR02.contoso.local:5022")
        self.assertEqual(f.details["database"], "Sales")
        self.assertEqual(f.details["seconds"], 10)
        self.assertEqual(f.details["error_severity"], 16)
        self.assertIn("5022", f.advice)

    def test_replica_ids_are_normalised(self):
        f = self.findings[2]
        self.assertEqual(f.details["replica"], "SQLDR02")
        self.assertEqual(f.details["replica_id"], "7F8A2D11-3C4B-4E5F-9A60-1B2C3D4E5F60")
        self.assertEqual(f.severity, "warning")

    def test_connect_timeout_mentions_the_endpoint(self):
        self.assertIn("mirroring endpoint", self.findings[3].advice)

    def test_connection_established(self):
        f = self.findings[5]
        self.assertEqual(f.severity, "info")
        self.assertEqual((f.details["ag"], f.details["from"], f.details["to"]), ("AG_Sales", "SQLPROD01", "SQLDR02"))

    def test_nothing_left_over(self):
        self.assertEqual(unclassified(self.entries, self.findings), [])


if __name__ == "__main__":
    unittest.main()
