import unittest
from datetime import datetime, timedelta

from errorlog_insight.classify import classify
from errorlog_insight.deadlock import collect_block, parse_attrs, parse_block
from errorlog_insight.model import Entry
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


class AttrTests(unittest.TestCase):
    def test_values_with_spaces(self):
        attrs = parse_attrs("id=p1 waitresource=KEY: 5:72057594043432960 (a1b2c3d4e5f6) "
                            "waittime=4120 isolationlevel=read committed (2) xactid=1830021")
        self.assertEqual(attrs["waitresource"], "KEY: 5:72057594043432960 (a1b2c3d4e5f6)")
        self.assertEqual(attrs["isolationlevel"], "read committed (2)")
        self.assertEqual(attrs["waittime"], "4120")

    def test_backslash_login(self):
        self.assertEqual(parse_attrs("loginname=CONTOSO\\kwong isolationlevel=x")["loginname"], "CONTOSO\\kwong")


class DeadlockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_entries(fixture("deadlock_1222.log"))
        cls.findings = classify(cls.entries)

    def test_two_deadlocks_found_and_noise_skipped(self):
        self.assertEqual([f.code for f in self.findings], ["1222", "1222"])
        # the xp_instance_regread line and the READ_COMMITTED_SNAPSHOT line are not part of a graph
        self.assertEqual(len(self.findings), 2)

    def test_block_boundaries(self):
        start = next(i for i, e in enumerate(self.entries) if e.text == "deadlock-list")
        end = collect_block(self.entries, start)
        self.assertEqual(self.entries[end].process, "spid57")
        dl = parse_block(self.entries[start:end])
        self.assertEqual(len(dl.processes), 2)
        self.assertEqual(len(dl.resources), 2)

    def test_key_lock_graph(self):
        start = next(i for i, e in enumerate(self.entries) if e.text == "deadlock-list")
        dl = parse_block(self.entries[start:collect_block(self.entries, start)])
        self.assertEqual(dl.victims, ["process1e8f3c8c8"])
        victim = dl.process("process1e8f3c8c8")
        self.assertEqual(victim.spid, 57)
        self.assertEqual(victim.procedure, "Sales.dbo.usp_UpdateOrderStatus")
        self.assertIn("UPDATE dbo.Orders SET Status", victim.statement)
        other = dl.process("process1e8f3d468")
        self.assertEqual(other.host, "WEB04")
        self.assertEqual(other.wait_resource, "KEY: 5:72057594043498496 (5d2e1c8a90b4)")
        edges = [(w, o, r.object_name) for w, o, r in dl.edges()]
        self.assertIn(("process1e8f3d468", "process1e8f3c8c8", "Sales.dbo.OrderLines"), edges)
        self.assertIn(("process1e8f3c8c8", "process1e8f3d468", "Sales.dbo.Orders"), edges)

    def test_finding_for_key_lock_deadlock(self):
        f = self.findings[0]
        self.assertEqual(f.severity, "error")
        self.assertEqual(f.details["objects"], ["Sales.dbo.OrderLines", "Sales.dbo.Orders"])
        self.assertEqual(f.details["lock_kinds"], ["keylock"])
        self.assertEqual(f.details["victims"][0]["spid"], 57)
        self.assertIn("opposite orders", f.advice)
        self.assertIn("READ_COMMITTED_SNAPSHOT", f.advice)
        self.assertIn("victim spid 57", f.title)

    def test_page_and_rid_lock_deadlock(self):
        f = self.findings[1]
        self.assertEqual(f.details["lock_kinds"], ["pagelock", "ridlock"])
        self.assertEqual(f.details["victims"][0]["login"], "CONTOSO\\kwong")
        self.assertEqual(f.details["victims"][0]["host"], "DBA-WS01")
        self.assertIn("missing index", f.advice)


def synthetic(lines, process="spid17s", start=datetime(2024, 4, 16, 9, 0, 0)):
    return [Entry(start + timedelta(milliseconds=10 * i), process, text) for i, text in enumerate(lines)]


GRAPH = [
    "deadlock-list",
    "victim-list",
    "victimProcess id=processA",
    "victimProcess id=processB",
    "process-list",
    "process id=processA spid=51 ecid=0 clientapp=app1 isolationlevel=serializable (4) currentdbname=Sales",
    "executionStack",
    "frame procname=Sales.dbo.p1 line=3 stmtstart=0 stmtend=10 sqlhandle=0x01",
    "UPDATE t SET x = 1",
    "process id=processB spid=52 ecid=0 clientapp=app2 isolationlevel=serializable (4) currentdbname=Sales",
    "resource-list",
    "objectlock lockPartition=0 objid=1 subresource=FULL dbid=5 objectname=Sales.dbo.T id=lock1 mode=X",
    "owner-list",
    "owner id=processA mode=X",
    "waiter-list",
    "waiter id=processB mode=X requestType=wait",
]


class BlockEdgeTests(unittest.TestCase):
    def test_block_stops_at_a_line_that_is_not_part_of_the_graph(self):
        entries = synthetic(GRAPH + ["Some later message from the same spid"])
        self.assertEqual(collect_block(entries, 0), len(GRAPH))

    def test_block_runs_to_the_end_of_the_list(self):
        entries = synthetic(GRAPH)
        self.assertEqual(collect_block(entries, 0), len(GRAPH))

    def test_statement_text_before_the_resource_list_is_still_part_of_the_graph(self):
        entries = synthetic(GRAPH)
        dl = parse_block(entries)
        self.assertEqual(dl.process("processA").statement, "UPDATE t SET x = 1")

    def test_victim_list_with_two_victims(self):
        dl = parse_block(synthetic(GRAPH))
        self.assertEqual(dl.victims, ["processA", "processB"])
        self.assertEqual(dl.resources[0].kind, "objectlock")

    def test_long_statements_are_shortened_in_the_finding(self):
        lines = list(GRAPH)
        lines[8] = "UPDATE t SET x = '" + "y" * 2000 + "'"
        (f,) = classify(synthetic(lines))
        statement = f.details["victims"][0]["statement"]
        self.assertEqual(len(statement), 403)
        self.assertTrue(statement.endswith("..."))

    def test_second_graph_from_the_same_spid_starts_a_new_block(self):
        entries = synthetic(GRAPH + GRAPH)
        self.assertEqual(len(classify(entries)), 2)


if __name__ == "__main__":
    unittest.main()
