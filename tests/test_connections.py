import unittest

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class ConnectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("connections.log"))
        cls.findings = classify(cls.entries)

    def test_sequence(self):
        self.assertEqual([f.code for f in self.findings], ["17806"] * 4 + ["18452", "17187"])

    def test_sspi_details(self):
        f = self.findings[0]
        self.assertEqual(f.details["status"], "0x80090311")
        self.assertEqual(f.details["state"], 14)
        self.assertEqual(f.details["client"], "10.20.8.19")
        self.assertEqual(f.details["error_severity"], 20)
        self.assertEqual(f.details["windows_text"], "No authority could be contacted for authentication.")
        self.assertIn("domain controller", f.advice)

    def test_other_status_codes(self):
        self.assertIn("clock", self.findings[2].advice)
        self.assertEqual(self.findings[3].details["meaning"], "the target principal name is incorrect")
        self.assertIn("SPN", self.findings[3].advice)

    def test_unknown_status(self):
        from datetime import datetime
        from errorlog_insight.model import Entry
        e = Entry(datetime(2024, 3, 12), "Logon",
                  "SSPI handshake failed with error code 0x8009ffff, state 1 while establishing a connection with "
                  "integrated security; the connection has been closed. Reason: AcceptSecurityContext failed.  [CLIENT: 1.2.3.4]")
        (f,) = classify([e])
        self.assertEqual(f.details["meaning"], "unrecognised SSPI status")
        self.assertEqual(f.details["client"], "1.2.3.4")

    def test_untrusted_domain_and_not_ready(self):
        self.assertEqual(self.findings[4].details["client"], "10.20.9.14")
        self.assertEqual(self.findings[5].details["client"], "10.20.8.19")

    def test_nothing_left_over(self):
        self.assertEqual(unclassified(self.entries, self.findings), [])


if __name__ == "__main__":
    unittest.main()
