import unittest
from datetime import datetime

from errorlog_insight.classify import classify, unclassified
from errorlog_insight.cluster import cluster_entries, mask, similarity, template_id
from errorlog_insight.model import Entry
from errorlog_insight.reader import parse_entries, read_entries
from tests.helpers import fixture


def entry(text, minute=0, process="spid10s"):
    return Entry(datetime(2022, 1, 1, 12, minute, 0), process, text)


class MaskTests(unittest.TestCase):
    def test_numbers_and_quotes(self):
        self.assertEqual(mask("Starting up database 'Sales'."), "Starting up database '<STR>'.")
        self.assertEqual(mask("Server process ID is 4184."), "Server process ID is <NUM>.")

    def test_addresses_guids_and_hex(self):
        text = "Connection from 10.20.4.77:49152 handle 0x00000A84 id 6f9619ff-8b86-d011-b42d-00c04fc964ff"
        self.assertEqual(mask(text), "Connection from <IP> handle <HEX> id <GUID>")

    def test_paths(self):
        self.assertEqual(mask("Opened C:\\Data\\x.mdf ok"), "Opened <PATH> ok")
        self.assertEqual(mask("Opened \\\\FILESRV01\\Share\\x.bak ok"), "Opened <PATH> ok")

    def test_sids_accounts_dates_and_times(self):
        text = "Mapped S-1-5-21-3623811015-3361044348-30300820-1013 for CONTOSO\\jdoe at 2024-11-12 10:11:12.345"
        self.assertEqual(mask(text), "Mapped <SID> for <ACCOUNT> at <DATE> <TIME>")

    def test_lsns_and_spids(self):
        self.assertEqual(mask("Log restored to 00000a2b:00001c3d:0001 and 120987:44321:37 by spid57s"),
                         "Log restored to <LSN> and <LSN> by <SPID>")

    def test_a_clock_time_is_not_an_lsn(self):
        self.assertEqual(mask("Started at 10:11:12"), "Started at <TIME>")

    def test_unc_path_is_not_taken_for_an_account(self):
        self.assertEqual(mask("Backup to \\\\FILESRV01\\Share\\a.bak by CONTOSO\\svc_sql"), "Backup to <PATH> by <ACCOUNT>")

    def test_only_first_line_is_used(self):
        self.assertEqual(mask("FlushCache: cleaned up 5 bufs\n\t\t\taverage throughput: 1 MB/sec"),
                         "FlushCache: cleaned up <NUM> bufs")


class ClusterTests(unittest.TestCase):
    def test_same_template_one_cluster(self):
        entries = [entry("Starting up database 'A'.", 1), entry("Starting up database 'B'.", 5),
                   entry("Something else 7", 2)]
        clusters = cluster_entries(entries)
        self.assertEqual(len(clusters), 2)
        self.assertEqual(clusters[0].template, "Starting up database '<STR>'.")
        self.assertEqual(clusters[0].count, 2)
        self.assertEqual(clusters[0].first_seen.minute, 1)
        self.assertEqual(clusters[0].last_seen.minute, 5)

    def test_unrecognised_entries_skip_classified_ones_and_headers(self):
        entries = read_entries(fixture("login_failures.log")) + read_entries(fixture("noise.log"))
        findings = classify(entries)
        unknown = unclassified(entries, findings)
        self.assertEqual(len(unknown), 10)
        self.assertTrue(all(e.process != "Logon" for e in unknown))

    def test_deadlock_block_is_fully_covered(self):
        entries = read_entries(fixture("deadlock_1222.log"))
        unknown = unclassified(entries, classify(entries))
        self.assertEqual(len(unknown), 2)

    def test_noise_templates(self):
        clusters = cluster_entries(read_entries(fixture("noise.log")))
        templates = {c.template for c in clusters}
        self.assertIn("Configuration option '<STR>' changed from <NUM> to <NUM>. Run the RECONFIGURE statement to install.",
                      templates)
        counts = {c.template: c.count for c in clusters}
        self.assertEqual(max(counts.values()), 2)


class SimilarityTests(unittest.TestCase):
    OPTION = "Setting database option %s to %s for database '%s'."

    def test_similar_templates_merge(self):
        entries = [
            entry(self.OPTION % ("RECOVERY", "SIMPLE", "Staging"), 1),
            entry(self.OPTION % ("READ_COMMITTED_SNAPSHOT", "ON", "Reporting"), 2),
            entry(self.OPTION % ("RECOVERY", "FULL", "Sales"), 3),
        ]
        (cluster,) = cluster_entries(entries)
        self.assertEqual(cluster.template, "Setting database option <*> to <*> for database '<STR>'.")
        self.assertEqual(cluster.count, 3)
        self.assertEqual(cluster.variants, 3)
        self.assertEqual(cluster.first_seen.minute, 1)
        self.assertEqual(cluster.last_seen.minute, 3)

    def test_different_lengths_do_not_merge(self):
        entries = [entry("Backup of the log started now"), entry("Backup of the log started now again")]
        self.assertEqual(len(cluster_entries(entries)), 2)

    def test_different_first_word_does_not_merge(self):
        entries = [entry("Starting the replica manager for group one"), entry("Stopping the replica manager for group one")]
        self.assertEqual(len(cluster_entries(entries)), 2)

    def test_short_messages_only_merge_when_identical(self):
        entries = [entry("Resumed database Sales"), entry("Resumed database Staging")]
        self.assertEqual(len(cluster_entries(entries)), 2)

    def test_threshold_parameter(self):
        entries = [entry("Moved file alpha to disk one for user bob"), entry("Moved file gamma to disk two for user sue")]
        self.assertEqual(len(cluster_entries(entries, threshold=0.7)), 2)
        self.assertEqual(len(cluster_entries(entries, threshold=0.5)), 1)

    def test_versions_are_masked(self):
        self.assertEqual(mask("CLR version v4.0.30319 loaded"), "CLR version <VER> loaded")

    def test_similarity_helper(self):
        self.assertEqual(similarity(["a", "b"], ["a", "c"]), 0.5)
        self.assertEqual(similarity(["a", "<*>"], ["a", "c"]), 1.0)
        self.assertEqual(similarity(["a"], ["a", "b"]), 0.0)


class TemplateIdTests(unittest.TestCase):
    def test_id_is_stable_and_short(self):
        self.assertEqual(template_id("Starting up database '<STR>'."), template_id("Starting up database '<STR>'."))
        self.assertRegex(template_id("anything"), r"^[0-9a-f]{8}$")

    def test_known_value(self):
        # pinned so a change of the hash (which would invalidate saved ids) is noticed
        self.assertEqual(template_id("Starting up database '<STR>'."), "669b9531")

    def test_different_templates_differ(self):
        self.assertNotEqual(template_id("a b c d"), template_id("a b c e"))

    def test_cluster_id_follows_its_template(self):
        (c,) = cluster_entries([entry("Starting up database 'A'.")])
        self.assertEqual(c.id, template_id(c.template))

    def test_same_message_in_two_runs_has_the_same_id(self):
        one = cluster_entries([entry("Starting up database 'A'.", 1)])[0]
        two = cluster_entries([entry("Starting up database 'B'.", 9), entry("Other thing happened here now", 3)])
        self.assertIn(one.id, [c.id for c in two])


if __name__ == "__main__":
    unittest.main()
