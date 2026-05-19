"""Regenerate docs/sample-output.txt from the fixtures.

    python3 tools/make_sample.py

The sample shows a lease expiry after a non-yielding scheduler, on one server, with the
wording the tool really prints. tests/test_docs.py fails when the file is out of date.
"""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARGUMENTS = ["SQLPROD01=tests/fixtures/ag_lease_failover.log", "--timeline"]
TARGET = os.path.join(ROOT, "docs", "sample-output.txt")


def render():
    """The report for ARGUMENTS, run from the repository root so the paths are relative."""
    sys.path.insert(0, ROOT)
    from errorlog_insight.cli import main

    previous = os.getcwd()
    os.chdir(ROOT)
    try:
        out = io.StringIO()
        main(ARGUMENTS, out=out)
    finally:
        os.chdir(previous)
    return "$ errorlog-insight %s\n\n%s" % (" ".join(ARGUMENTS), out.getvalue())


if __name__ == "__main__":
    with open(TARGET, "w", encoding="utf-8", newline="\n") as f:
        f.write(render())
    print("wrote", TARGET)
