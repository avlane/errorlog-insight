import unittest

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class TraceFlagTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("traceflags.log"))
        cls.findings = classify(cls.entries)

    def test_all_messages_found(self):
        self.assertEqual(len(self.findings), 6)
        self.assertTrue(all(f.code == "traceflag" for f in self.findings))

    def test_deadlock_flag(self):
        f = self.findings[0]
        self.assertEqual(f.details["flags"], [1222])
        self.assertEqual(f.details["action"], "on")
        self.assertEqual(f.details["spid"], 53)
        self.assertEqual(f.details["meaning"], {"1222": "write the deadlock graph to the error log"})
        self.assertEqual(f.title, "Trace flag 1222 turned on (spid 53)")

    def test_off_and_unknown_flags(self):
        self.assertEqual(self.findings[2].details["action"], "off")
        self.assertEqual(self.findings[4].details["meaning"]["9999"], "not in the built-in list")

    def test_noisy_flag_advice_only_when_turned_on(self):
        self.assertIn("error log until it is turned off", self.findings[1].advice)
        self.assertEqual(self.findings[2].advice, "")

    def test_several_flags_in_one_message(self):
        from datetime import datetime
        from errorlog_insight.model import Entry
        e = Entry(datetime(2024, 12, 3), "spid55", "DBCC TRACEON 1118, 2371, server process ID (SPID) 55. This is an informational message only; no user action is required.")
        (f,) = classify([e])
        self.assertEqual(f.details["flags"], [1118, 2371])

    def test_nothing_left_over(self):
        self.assertEqual(unclassified(self.entries, self.findings), [])


if __name__ == "__main__":
    unittest.main()
