import unittest

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class StackDumpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("stackdump.log"))
        cls.findings = classify(cls.entries)

    def test_findings_in_order(self):
        self.assertEqual([f.code for f in self.findings],
                         ["stackdump", "17310", "17066", "stackdump", "stackdump"])

    def test_exception_dump(self):
        f = self.findings[0]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.details["kind"], "exception")
        self.assertEqual(f.details["exception_code"], "c0000005")
        self.assertEqual(f.details["exception_name"], "EXCEPTION_ACCESS_VIOLATION")
        self.assertEqual(f.details["spid"], 61)
        self.assertEqual(f.details["signature"], "0x000000000000A2D1")
        self.assertEqual(f.details["modules"], ["sqllang", "sqlmin", "KERNEL32"])
        self.assertTrue(f.details["file"].endswith("SQLDump0007.txt"))

    def test_input_buffer_is_joined(self):
        buf = self.findings[0].details["input_buffer"]
        self.assertTrue(buf.startswith("SELECT o.OrderID"))
        self.assertTrue(buf.endswith("GROUP BY o.OrderID"))
        self.assertNotIn("*", buf)

    def test_dump_covers_all_its_lines(self):
        self.assertEqual(len(self.findings[0].entries), 24)

    def test_fatal_session_message(self):
        self.assertEqual(self.findings[1].details["spid"], 61)
        self.assertEqual(self.findings[1].severity, "critical")

    def test_assertion_message_and_dump(self):
        message, dump = self.findings[2], self.findings[3]
        self.assertEqual(message.details["file"], "lockmgr.cpp")
        self.assertEqual(message.details["line"], 1234)
        self.assertEqual(message.details["expression"], "lockCount > 0")
        self.assertEqual(dump.details["kind"], "assertion")
        self.assertEqual(dump.details["location"], "lockmgr.cpp:1234")
        self.assertEqual(dump.details["expression"], "lockCount > 0")
        self.assertEqual(dump.details["spid"], 74)

    def test_non_yielding_dump_is_separate_from_previous_dump(self):
        f = self.findings[4]
        self.assertEqual(f.details["kind"], "non-yielding")
        self.assertEqual(f.details["spid"], 6120)
        self.assertEqual(f.severity, "error")

    def test_only_unrelated_line_is_left_over(self):
        left = unclassified(self.entries, self.findings)
        self.assertEqual(len(left), 1)
        self.assertIn("xp_msver", left[0].text)


if __name__ == "__main__":
    unittest.main()
