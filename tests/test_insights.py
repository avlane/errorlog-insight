import unittest

from errorlog_insight.classify import classify
from errorlog_insight.insights import find_insights, of_code, server_of
from errorlog_insight.reader import read_entries
from tests.helpers import fixture


def findings_of(*pairs):
    out = []
    for label, name in pairs:
        out.extend(classify(read_entries(fixture(name), replica=label)))
    return out


class IoMaintenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = findings_of(("SQLPROD01", "insight_io.log"))
        cls.insights = find_insights(cls.findings)

    def test_two_overlaps_found(self):
        self.assertEqual([i.code for i in self.insights], ["io-during-checkdb", "io-during-snapshot"])

    def test_checkdb_overlap(self):
        i = self.insights[0]
        self.assertEqual(i.severity, "error")   # a 30 second stall
        self.assertEqual(i.confidence, "high")
        self.assertIn("DBCC consistency checking was running on Sales", i.title)
        self.assertEqual([f.code for f in i.evidence], ["833", "833", "checkdb"])
        self.assertIn("quiet period", i.advice)

    def test_snapshot_overlap(self):
        i = self.insights[1]
        self.assertEqual(i.severity, "warning")
        self.assertIn("a snapshot backup froze I/O on Sales", i.title)
        self.assertEqual([f.code for f in i.evidence], ["833", "io-frozen"])

    def test_unrelated_stall_is_not_explained(self):
        stalls = of_code(self.findings, "833")
        explained = {id(f) for i in self.insights for f in i.evidence}
        self.assertEqual([f.entry.timestamp.hour for f in stalls if id(f) not in explained], [5])

    def test_other_server_does_not_explain_it(self):
        mixed = findings_of(("SQLPROD01", "io_stalls.log"), ("SQLDR02", "insight_io.log"))
        for f in mixed:
            if f.entry.replica == "SQLDR02" and f.code != "833":
                f.entry.replica = "SQLDR03"
        self.assertEqual(find_insights(mixed), [])

    def test_server_of_falls_back_to_the_file(self):
        f = classify(read_entries(fixture("insight_io.log")))[0]
        self.assertTrue(server_of(f).endswith("insight_io.log"))

    def test_no_insights_for_quiet_logs(self):
        self.assertEqual(find_insights(findings_of(("A", "noise.log"), ("A", "startup_2019.log"))), [])


class LogFullTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.insights = [i for i in find_insights(findings_of(("SQLPROD01", "insight_logfull.log")))
                        if i.code.startswith("logfull")]

    def test_one_insight_per_log_that_waits_for_a_backup(self):
        self.assertEqual(sorted(i.code for i in self.insights), ["logfull-backups-failing", "logfull-no-backups"])

    def test_failing_backups_are_the_evidence(self):
        i = next(i for i in self.insights if i.code == "logfull-backups-failing")
        self.assertEqual(i.severity, "critical")
        self.assertEqual(i.confidence, "high")
        self.assertIn("log of Sales is full because log backups have been failing", i.title)
        self.assertIn("There is not enough space on the disk.", i.title)
        self.assertEqual(sorted(f.code for f in i.evidence), ["18204"] * 3 + ["3041"] * 3 + ["9002"])
        self.assertIn("Growing the log file only delays", i.advice)

    def test_no_failures_means_a_missing_job(self):
        i = next(i for i in self.insights if i.code == "logfull-no-backups")
        self.assertIn("Reporting", i.title)
        self.assertEqual(i.confidence, "medium")
        self.assertEqual([f.code for f in i.evidence], ["9002"])

    def test_other_reuse_waits_are_left_alone(self):
        titles = " ".join(i.title for i in self.insights)
        self.assertNotIn("Staging", titles)

    def test_failures_on_another_server_do_not_count(self):
        findings = findings_of(("SQLPROD01", "insight_logfull.log"))
        for f in findings:
            if f.code == "3041":
                f.entry.replica = "SQLDR02"
        codes = [i.code for i in find_insights(findings) if i.code.startswith("logfull")]
        self.assertEqual(codes, ["logfull-no-backups", "logfull-no-backups"])

    def test_old_failures_do_not_count(self):
        from datetime import timedelta
        findings = findings_of(("SQLPROD01", "insight_logfull.log"))
        for f in findings:
            if f.code in ("3041", "18204"):
                for e in f.entries:
                    e.timestamp -= timedelta(hours=9)
        codes = [i.code for i in find_insights(findings) if i.code.startswith("logfull")]
        self.assertEqual(codes, ["logfull-no-backups", "logfull-no-backups"])


class NonYieldingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = findings_of(("SQLPROD01", "insight_nonyield.log"))
        cls.insights = find_insights(cls.findings)

    def test_two_explained_stalls(self):
        self.assertEqual(sorted(i.code for i in self.insights), ["stall-from-paged-out-memory", "stall-with-slow-io"])

    def test_paged_out_memory(self):
        i = next(i for i in self.insights if i.code == "stall-from-paged-out-memory")
        self.assertEqual(i.confidence, "high")
        self.assertEqual([f.code for f in i.evidence], ["17890", "17883"])
        self.assertIn("lock pages in memory", i.advice)
        self.assertIn("Scheduler 5", i.title)

    def test_slow_io(self):
        i = next(i for i in self.insights if i.code == "stall-with-slow-io")
        self.assertEqual(i.confidence, "medium")
        self.assertIn("E:", i.advice)
        self.assertEqual([f.code for f in i.evidence], ["833", "17883"])

    def test_stall_without_a_nearby_cause_is_not_explained(self):
        late = [f for f in self.findings if f.code == "17883" and f.entry.timestamp.hour == 15]
        self.assertEqual(len(late), 1)
        explained = {id(f) for i in self.insights for f in i.evidence}
        self.assertNotIn(id(late[0]), explained)

    def test_cpu_bound_stall_next_to_slow_io_is_left_alone(self):
        findings = findings_of(("SQLPROD01", "insight_nonyield.log"))
        for f in findings:
            if f.code == "17883":
                f.details["pattern"] = "cpu-bound"
        self.assertEqual([i.code for i in find_insights(findings)], ["stall-from-paged-out-memory"])
        self.assertEqual(find_insights(findings)[0].confidence, "medium")


class SuspendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.insights = find_insights(findings_of(("SQLDR02", "insight_ag_suspend.log")))

    def by_code(self, code):
        return [i for i in self.insights if i.code == code]

    def test_what_was_found(self):
        self.assertEqual(sorted(i.code for i in self.insights),
                         ["suspend-after-local-error", "suspend-after-local-error",
                          "suspend-not-resumed", "suspend-not-resumed"])

    def test_log_full_on_the_secondary(self):
        i = next(i for i in self.by_code("suspend-after-local-error") if "Reporting" in i.title)
        self.assertEqual(i.confidence, "high")
        self.assertIn("error 9002 on SQLDR02", i.title)
        self.assertEqual([f.code for f in i.evidence], ["9002", "35264"])
        self.assertIn("SET HADR RESUME", i.advice)

    def test_corruption_on_the_secondary_is_only_medium(self):
        i = next(i for i in self.by_code("suspend-after-local-error") if "Sales" in i.title)
        self.assertEqual(i.confidence, "medium")
        self.assertIn("824", i.title)

    def test_not_resumed(self):
        titles = {i.title: i for i in self.by_code("suspend-not-resumed")}
        self.assertEqual(len(titles), 2)
        reporting = next(i for t, i in titles.items() if "Reporting" in t)
        staging = next(i for t, i in titles.items() if "Staging" in t)
        self.assertEqual(reporting.severity, "error")
        self.assertEqual(staging.severity, "warning")
        self.assertIn("A person suspended it", staging.advice)

    def test_sales_was_resumed(self):
        self.assertFalse(any("Sales" in i.title for i in self.by_code("suspend-not-resumed")))

    def test_user_suspend_is_not_blamed_on_a_local_error(self):
        self.assertFalse(any("Staging" in i.title for i in self.by_code("suspend-after-local-error")))


class FlappingTests(unittest.TestCase):
    def test_four_failovers_in_forty_minutes(self):
        insights = find_insights(findings_of(("SQLPROD01", "insight_ag_flap.log")))
        (flap,) = [i for i in insights if i.code == "ag-flapping"]
        self.assertEqual(flap.severity, "critical")
        self.assertEqual(flap.confidence, "high")
        self.assertEqual(flap.title, "AG_Sales failed over 4 times between 02:00 and 02:41 (4 unplanned)")
        self.assertEqual(len(flap.evidence), 8)
        self.assertTrue(all(f.code == "1480" for f in flap.evidence))
        self.assertIn("lease", flap.advice)

    def test_one_failover_is_not_flapping(self):
        found = find_insights(findings_of(("SQLPROD01", "ag_primary.log"), ("SQLDR02", "ag_secondary.log")))
        self.assertEqual([i for i in found if i.code == "ag-flapping"], [])

    def test_failovers_far_apart_are_not_flapping(self):
        from datetime import timedelta
        findings = findings_of(("SQLPROD01", "insight_ag_flap.log"))
        for n, f in enumerate(findings):
            for e in f.entries:
                e.timestamp += timedelta(hours=3 * (n // 4))
        self.assertEqual([i for i in find_insights(findings) if i.code == "ag-flapping"], [])

    def test_planned_flapping_is_only_an_error(self):
        findings = findings_of(("SQLPROD01", "insight_ag_flap.log"))
        for f in findings:
            if f.code == "1480":
                f.details["planned"] = True
            if f.code == "19406":
                f.details["user_initiated"] = True
        (flap,) = [i for i in find_insights(findings) if i.code == "ag-flapping"]
        self.assertEqual(flap.severity, "error")
        self.assertIn("(0 unplanned)", flap.title)


class LoginInsightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.insights = [i for i in find_insights(findings_of(("SQLPROD01", "login_patterns.log")))
                        if i.code.startswith("login")]

    def test_one_insight_per_suspicious_client(self):
        self.assertEqual(sorted(i.code for i in self.insights), ["login-guessing", "login-spray", "login-stale-client"])

    def test_guessing(self):
        i = next(i for i in self.insights if i.code == "login-guessing")
        self.assertEqual(i.title, "10.20.8.15 tried wrong passwords 7 times for reports")
        self.assertEqual(i.severity, "error")
        self.assertEqual(len(i.evidence), 7)

    def test_spray_names_the_logins(self):
        i = next(i for i in self.insights if i.code == "login-spray")
        self.assertIn("203.0.113.45 tried 6 different logins", i.title)
        self.assertIn("sa is disabled", i.advice)

    def test_stale_service_explains_the_state(self):
        i = next(i for i in self.insights if i.code == "login-stale-client")
        self.assertIn("10.20.4.50 has failed to log in 40 times over 3.3 hours (state 38)", i.title)
        self.assertEqual(i.severity, "warning")
        self.assertIn("database named in the connection string cannot be opened", i.advice)
        self.assertEqual(len(i.evidence), 40)

    def test_guessing_against_sa_is_called_out(self):
        findings = findings_of(("SQLPROD01", "login_failures.log"))
        (guess,) = [i for i in find_insights(findings) if i.code == "login-guessing"]
        self.assertTrue(guess.title.endswith("(including sa)"))

    def test_occasional_failures_are_not_insights(self):
        self.assertEqual([i for i in find_insights(findings_of(("A", "backup_failures.log"))) if i.code.startswith("login")], [])


def startup_findings(year, level, when):
    from datetime import datetime
    from errorlog_insight.model import Entry
    text = ("Microsoft SQL Server %d (%s) (KB4577194) - 15.0.4073.23 (X64) \n\tEnterprise Edition (64-bit) on "
            "Windows Server 2019 Standard 10.0 <X64>" % (year, level))
    return classify([Entry(datetime(*when), "Server", text, replica="S")])


class SupportTests(unittest.TestCase):
    def codes(self, year, level, when):
        return [i.code for i in find_insights(startup_findings(year, level, when)) if i.code.startswith("version")]

    def test_out_of_support_when_it_started(self):
        self.assertEqual(self.codes(2014, "SP3-CU4", (2024, 8, 1, 6, 0)), ["version-unsupported"])

    def test_the_same_version_was_fine_earlier(self):
        self.assertEqual(self.codes(2014, "SP3-CU4", (2024, 6, 1, 6, 0)), ["version-ending"])

    def test_far_from_the_end(self):
        self.assertEqual(self.codes(2019, "RTM-CU8", (2021, 3, 1, 6, 0)), [])

    def test_last_day_still_counts_as_supported(self):
        self.assertEqual(self.codes(2012, "SP4", (2022, 7, 12, 6, 0)), ["version-ending"])

    def test_rtm_without_cumulative_update(self):
        self.assertEqual(self.codes(2022, "RTM", (2023, 1, 5, 6, 0)), ["version-rtm"])

    def test_unlisted_versions_are_not_judged(self):
        self.assertEqual(self.codes(2005, "SP4", (2024, 8, 1, 6, 0)), [])

    def test_details(self):
        (i,) = [i for i in find_insights(startup_findings(2014, "SP3", (2024, 8, 1, 6, 0))) if i.code == "version-unsupported"]
        self.assertEqual(i.severity, "error")
        self.assertIn("extended support ended 2024-07-09", i.title)
        self.assertEqual(i.evidence[0].code, "startup")


class StartupOptionTests(unittest.TestCase):
    def test_single_user_and_minimal_configuration(self):
        insights = find_insights(findings_of(("SQLPROD01", "startup_single_user.log")))
        codes = sorted(i.code for i in insights if i.code.startswith("startup"))
        self.assertEqual(codes, ["startup-minimal-config", "startup-single-user"])
        single = next(i for i in insights if i.code == "startup-single-user")
        self.assertEqual(single.title, "SQLPROD01 was started in single-user mode (-m)")
        self.assertEqual(single.severity, "warning")
        self.assertEqual(single.evidence[0].code, "startup-params")

    def test_normal_startup_is_quiet(self):
        insights = find_insights(findings_of(("SQLPROD01", "startup_2019.log")))
        self.assertEqual([i for i in insights if i.code.startswith("startup")], [])


if __name__ == "__main__":
    unittest.main()
