import os
import typing
import unittest

import errorlog_insight
from errorlog_insight.classify import classify
from errorlog_insight.incidents import find_incidents
from errorlog_insight.insights import Insight, find_insights
from errorlog_insight.model import Entry, Finding
from errorlog_insight.reader import iter_entries, read_entries

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TypingTests(unittest.TestCase):
    def test_the_package_is_marked_typed(self):
        self.assertTrue(os.path.exists(os.path.join(os.path.dirname(errorlog_insight.__file__), "py.typed")))
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn('errorlog_insight = ["py.typed"]', text)

    def test_model_annotations_resolve(self):
        hints = typing.get_type_hints(Finding)
        self.assertEqual(hints["entry"], Entry)
        self.assertEqual(hints["covered"], list[Entry])
        self.assertEqual(typing.get_type_hints(Entry)["lineno"], int)
        self.assertEqual(typing.get_type_hints(Insight)["evidence"], list[Finding])

    def test_public_function_annotations_resolve(self):
        for fn in (classify, find_incidents, find_insights, read_entries, iter_entries):
            self.assertIn("return", typing.get_type_hints(fn), fn.__name__)

    def test_slots_keep_the_objects_small(self):
        entry = Entry.__new__(Entry)
        self.assertFalse(hasattr(entry, "__dict__"))
        self.assertFalse(hasattr(Finding.__new__(Finding), "__dict__"))


if __name__ == "__main__":
    unittest.main()
