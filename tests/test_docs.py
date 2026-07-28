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

    def readme(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            return f.read()

    def parser_options(self):
        from errorlog_insight.cli import build_parser
        return {opt for action in build_parser()._actions for opt in action.option_strings if opt.startswith("--")}

    def test_every_documented_option_exists(self):
        documented = set(re.findall(r"`(--[a-z][a-z-]*)", self.readme()))
        self.assertGreater(len(documented), 20)
        self.assertEqual(sorted(documented - self.parser_options()), [])

    def test_every_option_is_documented(self):
        text = self.readme()
        missing = [opt for opt in sorted(self.parser_options()) if opt not in ("--help", "--version") and "`%s" % opt not in text]
        self.assertEqual(missing, [])


class ClassifierDocTests(unittest.TestCase):
    def test_every_finding_code_is_in_the_classifier_reference(self):
        from errorlog_insight.classify import LABELS
        with open(os.path.join(ROOT, "docs", "classifiers.md"), encoding="utf-8") as f:
            text = f.read()
        missing = [c for c in sorted(LABELS) if not re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(c), text)]
        self.assertEqual(missing, [])


class ChangelogTests(unittest.TestCase):
    def test_latest_entry_is_the_package_version(self):
        import errorlog_insight
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
            headings = re.findall(r"^## (\d+\.\d+(?:\.\d+)?)", f.read(), re.M)
        self.assertEqual(headings[0], errorlog_insight.__version__)


class SampleOutputTests(unittest.TestCase):
    def test_sample_output_is_current(self):
        from tools.make_sample import TARGET, render
        with open(TARGET, encoding="utf-8") as f:
            self.assertEqual(f.read(), render(), "docs/sample-output.txt is out of date: run python3 tools/make_sample.py")

    def test_render_does_not_depend_on_the_working_directory(self):
        import tempfile
        from tools.make_sample import render
        before = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                text = render()
            finally:
                os.chdir(before)
        self.assertEqual(os.getcwd(), before)
        self.assertIn("Availability group incidents", text)


if __name__ == "__main__":
    unittest.main()
