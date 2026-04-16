import unittest

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class AutogrowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("autogrow.log"))
        cls.findings = classify(cls.entries)

    def test_sequence(self):
        self.assertEqual([f.code for f in self.findings], ["5145"] * 4 + ["5144"] + ["5145"] * 2)

    def test_details(self):
        f = self.findings[1]
        self.assertEqual((f.details["file"], f.details["database"], f.details["milliseconds"]),
                         ("Sales_log", "Sales", 12500))
        self.assertEqual(f.details["error_severity"], 10)

    def test_only_long_growths_are_warnings(self):
        self.assertEqual([f.severity for f in self.findings if f.code == "5145"],
                         ["info", "info", "warning", "info", "warning", "info"])
        self.assertIn("fixed growth in MB", self.findings[2].advice)
        self.assertEqual(self.findings[0].advice, "")

    def test_cancelled_growth_is_an_error(self):
        f = self.findings[4]
        self.assertEqual(f.severity, "error")
        self.assertEqual(f.details["database"], "Reporting")
        self.assertIn("gave up after 30.5 s", f.title)

    def test_nothing_left_over(self):
        self.assertEqual(unclassified(self.entries, self.findings), [])


if __name__ == "__main__":
    unittest.main()
