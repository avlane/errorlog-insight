"""Damaged logs must produce a report, never a traceback.

The fixtures are shuffled, truncated and mutated with a fixed seed, so a failure can be reproduced by
the seed in the message. A few cases found this way are kept as ordinary tests below.
"""
import contextlib
import glob
import io
import os
import random
import tempfile
import unittest
from datetime import datetime, timedelta

from errorlog_insight.classify import classify
from errorlog_insight.cli import main
from errorlog_insight.insights import find_insights
from errorlog_insight.model import Entry
from tests.helpers import FIXTURES
from tools.encode_log import encode

SEEDS = range(40)


def source_lines():
    lines = []
    for path in sorted(glob.glob(os.path.join(FIXTURES, "src", "*.txt"))):
        with open(path, encoding="utf-8") as f:
            lines.extend(l for l in f.read().split("\n") if l)
    return lines


def mutate(lines, seed):
    rng = random.Random(seed)
    sample = rng.sample(lines, rng.choice([5, 30, 120, 300]))
    out = []
    for line in sample:
        roll = rng.random()
        if roll < 0.1:
            line = line[:rng.randint(0, len(line))]
        elif roll < 0.2:
            line = line.replace("'", "").replace("(", "")
        elif roll < 0.25:
            line = line.upper()
        elif roll < 0.3:
            line = line + " " + line[24:60]
        elif roll < 0.33:
            line = line.replace("=", " ")
        out.append(line)
    if rng.random() < 0.5:
        out.sort()
    return "\n".join(out) + "\n"


class FuzzTests(unittest.TestCase):
    def test_mutated_fixtures_always_give_a_report(self):
        lines = source_lines()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ERRORLOG")
            for seed in SEEDS:
                with open(path, "wb") as f:
                    f.write(encode(mutate(lines, seed)))
                for fmt in ("text", "json", "html"):
                    out = io.StringIO()
                    with contextlib.redirect_stderr(io.StringIO()):
                        try:
                            code = main([path, "--format", fmt, "--timeline", "--utc"], out=out)
                        except Exception as exc:     # report which input broke
                            self.fail("seed %d, %s: %s: %s" % (seed, fmt, type(exc).__name__, exc))
                    self.assertEqual(code, 0, (seed, fmt))
                    self.assertTrue(out.getvalue(), (seed, fmt))


def entries(*lines, process="spid17s"):
    start = datetime(2026, 7, 7, 9, 0, 0)
    return [Entry(start + timedelta(milliseconds=10 * i), process, text) for i, text in enumerate(lines)]


class FoundByFuzzingTests(unittest.TestCase):
    def test_parallel_deadlock_cut_off_before_its_processes(self):
        graph = entries("deadlock-list", "resource-list",
                        "exchangeEvent id=Pipe1 WaitType=e_waitPipeGetRow nodeId=3",
                        "owner-list", "owner event=e_waitNone id=process1",
                        "waiter-list", "waiter event=e_waitPipeGetRow id=process2")
        (finding,) = classify(graph)
        self.assertEqual(finding.code, "1222")
        self.assertTrue(finding.details["parallel"])
        self.assertIn("cut off", finding.title)
        self.assertEqual(find_insights([finding]), [])

    def test_lock_deadlock_with_no_processes_at_all(self):
        graph = entries("deadlock-list", "resource-list",
                        "keylock hobtid=1 dbid=5 objectname=Sales.dbo.T indexname=PK id=lock1 mode=X",
                        "owner-list", "owner id=process1 mode=X")
        (finding,) = classify(graph)
        self.assertEqual(finding.title, "Deadlock on Sales.dbo.T")

    def test_a_graph_that_is_only_its_first_line(self):
        (finding,) = classify(entries("deadlock-list"))
        self.assertEqual(finding.title, "Deadlock on unknown objects")


if __name__ == "__main__":
    unittest.main()
