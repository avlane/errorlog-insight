import unittest

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.deadlock import collect_block, parse_block
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class ParallelDeadlockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("deadlock_parallel.log"))
        cls.dl = parse_block(cls.entries[:collect_block(cls.entries, 0)])
        cls.findings = classify(cls.entries)

    def test_exchange_resources(self):
        self.assertEqual([r.kind for r in self.dl.resources], ["exchangeEvent", "exchangeEvent"])
        self.assertEqual(self.dl.resources[0].attrs["WaitType"], "e_waitPipeGetRow")
        self.assertEqual(self.dl.resources[0].owners, [("process1e8f3c8c8", "e_waitNone")])
        self.assertEqual(self.dl.resources[0].waiters, [("process1e8f3d468", "e_waitPipeGetRow")])

    def test_workers_share_a_spid(self):
        coordinator = self.dl.process("process1e8f3d468")
        worker = self.dl.process("process1e8f3c8c8")
        self.assertEqual((coordinator.spid, coordinator.ecid), (72, 0))
        self.assertEqual((worker.spid, worker.ecid), (72, 3))

    def test_edges_form_a_cycle(self):
        pairs = {(w, o) for w, o, _ in self.dl.edges()}
        self.assertEqual(pairs, {("process1e8f3d468", "process1e8f3c8c8"), ("process1e8f3c8c8", "process1e8f3d468")})

    def test_finding(self):
        (f,) = self.findings
        self.assertEqual(f.code, "1222")
        self.assertTrue(f.details["parallel"])
        self.assertEqual(f.details["objects"], [])
        self.assertIn("Parallel query deadlocked with itself: spid 72", f.title)
        self.assertIn("MAXDOP", f.advice)
        self.assertNotIn("READ_COMMITTED_SNAPSHOT", f.advice)
        self.assertEqual([p["ecid"] for p in f.details["processes"]], [0, 3])

    def test_lock_deadlocks_are_not_parallel(self):
        findings = classify(read_entries(fixture("deadlock_1222.log")))
        self.assertFalse(any(f.details["parallel"] for f in findings))
        self.assertIn("READ_COMMITTED_SNAPSHOT", findings[0].advice)

    def test_everything_covered(self):
        self.assertEqual(unclassified(self.entries, self.findings), [])


if __name__ == "__main__":
    unittest.main()
