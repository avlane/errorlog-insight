import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINK_RE = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")


def documents():
    yield os.path.join(ROOT, "README.md")
    docs = os.path.join(ROOT, "docs")
    for name in sorted(os.listdir(docs)):
        if name.endswith(".md"):
            yield os.path.join(docs, name)


class DocumentTests(unittest.TestCase):
    def test_relative_links_point_at_files_that_exist(self):
        checked = 0
        for path in documents():
            with open(path, encoding="utf-8") as f:
                text = f.read()
            for target in LINK_RE.findall(text):
                if "://" in target:
                    continue
                checked += 1
                self.assertTrue(os.path.exists(os.path.join(os.path.dirname(path), target)),
                                "%s links to %s" % (os.path.basename(path), target))
        self.assertGreater(checked, 4)

    def test_every_documented_option_exists(self):
        from errorlog_insight.cli import build_parser
        options = {opt for action in build_parser()._actions for opt in action.option_strings}
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            text = f.read()
        for flag in set(re.findall(r"^\* `(--[a-z-]+)", text, re.M)):
            self.assertIn(flag, options)


if __name__ == "__main__":
    unittest.main()
