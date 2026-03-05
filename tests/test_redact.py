import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime

from errorlog_insight.cli import main
from errorlog_insight.model import Entry
from errorlog_insight.redact import Redactor
from tests.helpers import fixture


def entry(text, replica="SQLPROD01", source="logs/prod/ERRORLOG"):
    return Entry(datetime(2026, 2, 24, 10, 0), "spid5s", text, source=source, replica=replica)


class TextTests(unittest.TestCase):
    def setUp(self):
        self.r = Redactor()
        self.r.learn([], ["SQLPROD01", "SQLDR02"])

    def test_ip_addresses_get_documentation_addresses_consistently(self):
        a = self.r.text("client 10.20.4.77 and 10.20.4.31 and again 10.20.4.77")
        self.assertEqual(a, "client 192.0.2.1 and 192.0.2.2 and again 192.0.2.1")

    def test_version_numbers_are_not_ip_addresses(self):
        self.assertEqual(self.r.text("build 15.0.4073.23 and 16.0.4045.3"), "build 15.0.4073.23 and 16.0.4045.3")
        self.assertEqual(self.r.text("not an address 300.1.1.1"), "not an address 300.1.1.1")

    def test_ip_pool_wraps_into_other_documentation_ranges(self):
        r = Redactor()
        first_block = [r.ip("10.0.%d.%d" % (i // 250, i % 250 + 1)) for i in range(251)]
        self.assertEqual(first_block[0], "192.0.2.1")
        self.assertEqual(first_block[249], "192.0.2.250")
        self.assertEqual(first_block[250], "198.51.100.1")

    def test_domain_accounts(self):
        t = self.r.text("executed by CONTOSO\\kwong and CONTOSO\\svc_sql, then FABRIKAM\\kwong")
        self.assertEqual(t, "executed by DOMAIN1\\user-1 and DOMAIN1\\user-2, then DOMAIN2\\user-1")

    def test_builtin_accounts_and_paths_are_kept(self):
        t = "NT AUTHORITY\\SYSTEM wrote C:\\Windows\\Microsoft.NET\\Framework64\\x.dll"
        self.assertEqual(self.r.text(t), t)

    def test_sql_logins(self):
        self.assertEqual(self.r.text("Login failed for user 'bob'. Login failed for user 'sa'. Login failed for user 'Bob'."),
                         "Login failed for user 'login-1'. Login failed for user 'sa'. Login failed for user 'login-1'.")
        self.assertEqual(self.r.text("Login failed for user 'CONTOSO\\jdoe'."), "Login failed for user 'DOMAIN1\\user-1'.")

    def test_unc_paths_keep_everything_but_the_server(self):
        self.assertEqual(self.r.text("device '\\\\FILESRV01\\SQLBackups\\Sales\\x.bak'"),
                         "device '\\\\server-3\\SQLBackups\\Sales\\x.bak'")

    def test_known_server_names_in_free_text(self):
        t = self.r.text("replica 'SQLDR02' with id [AB] to sqlprod01.contoso.local, and SQLDR02PLUS stays")
        self.assertEqual(t, "replica 'server-1' with id [AB] to server-2, and SQLDR02PLUS stays")

    def test_endpoint_and_graph_attributes(self):
        t = self.r.text('timed out "TCP://SQLDR02.contoso.local:5022" hostname=WEB03 loginname=CONTOSO\\svc_portal loginname=sa')
        self.assertEqual(t, 'timed out "TCP://server-1:5022" hostname=server-3 loginname=DOMAIN1\\user-1 loginname=sa')

    def test_server_name_line_teaches_the_names(self):
        r = Redactor()
        r.learn([entry("Server name is 'SQLX01'. This is an informational message only.")], [])
        self.assertEqual(r.text("backup of SQLX01 done"), "backup of server-1 done")


class EntryTests(unittest.TestCase):
    def test_entries_are_changed_in_place_with_matching_pseudonyms(self):
        r = Redactor()
        entries = [entry("from 10.1.1.1", "SQLPROD01", "a/ERRORLOG"), entry("from 10.1.1.1", "SQLDR02", "b/ERRORLOG")]
        r.learn(entries, ["SQLPROD01", "SQLDR02"])
        r.entries(entries)
        self.assertEqual([e.text for e in entries], ["from 192.0.2.1", "from 192.0.2.1"])
        self.assertEqual([e.replica for e in entries], ["server-2", "server-1"])   # numbered in name order
        self.assertEqual([e.source for e in entries], ["file-1", "file-2"])


SENSITIVE = ("CONTOSO", "svc_portal", "jdoe", "kwong", "10.20.", "203.0.113.4", "FILESRV01", "SQLDR02", "SQLPROD01",
             "WEB03", "WEB04", "DBA-WS01", "ETL01", "/tests/fixtures", "tests/fixtures")


def run(args):
    out = io.StringIO()
    main(args + ["--redact"], out=out)
    return out.getvalue()


class CliTests(unittest.TestCase):
    FILES = ["SQLPROD01=" + fixture("login_patterns.log"), "SQLDR02=" + fixture("deadlock_1222.log"),
             "SQLPROD01=" + fixture("ag_connectivity.log"), "SQLDR02=" + fixture("backup_failures.log"),
             "SQLDR02=" + fixture("ag_secondary.log"), "SQLDR02=" + fixture("startup_2019.log"),
             "SQLDR02=" + fixture("login_failures.log")]

    def check(self, text):
        for needle in SENSITIVE:
            self.assertNotIn(needle, text, needle)

    def test_text_json_and_html_contain_none_of_the_original_values(self):
        for extra in ([], ["--json"], ["--html"], ["--timeline"]):
            self.check(run(self.FILES + extra))

    def test_analysis_still_works_on_redacted_text(self):
        doc = json.loads(run(self.FILES + ["--json"]))
        codes = {f["code"] for f in doc["findings"]}
        self.assertTrue({"18456", "1222", "1479", "3041"} <= codes)
        clients = {r["client"] for r in doc["summaries"]["logins"]}
        self.assertTrue(all(c.startswith(("192.0.2.", "198.51.100.")) or c.startswith("<") for c in clients), clients)
        spray = [r for r in doc["summaries"]["logins"] if r["pattern"] == "many users tried"]
        self.assertEqual(len(spray), 1)

    def test_same_value_gets_the_same_pseudonym_in_every_file(self):
        doc = json.loads(run(self.FILES[:1] + [self.FILES[6]] + ["--json"]))
        clients = [r["client"] for r in doc["summaries"]["logins"]]
        self.assertEqual(len(clients), len(set(clients)))   # 10.20.4.50 etc. appear in two files, one row each

    def test_files_are_listed_as_file_numbers(self):
        doc = json.loads(run(self.FILES + ["--json"]))
        self.assertEqual(doc["files"], ["file-%d" % i for i in range(1, len(self.FILES) + 1)])
        self.assertTrue(all(f["replica"].startswith("server-") for f in doc["findings"]))

    def test_without_the_flag_nothing_is_changed(self):
        out = io.StringIO()
        main([fixture("login_patterns.log"), "--json"], out=out)
        self.assertIn("10.20.4.50", out.getvalue())


class MappingTests(unittest.TestCase):
    def test_mapping_reverses_every_kind(self):
        r = Redactor()
        entries = [entry("Login failed for user 'Bob'. Reason: x. [CLIENT: 10.20.4.77]", "SQLPROD01", "a/ERRORLOG"),
                   entry("done by CONTOSO\\kwong via \\\\FILESRV01\\share", "SQLDR02", "b/ERRORLOG")]
        r.learn(entries, ["SQLPROD01", "SQLDR02"])
        r.entries(entries)
        m = r.mapping()
        self.assertEqual(m["ip"], {"192.0.2.1": "10.20.4.77"})
        self.assertEqual(m["login"], {"login-1": "Bob"})
        self.assertEqual(m["domain"], {"DOMAIN1": "CONTOSO"})
        self.assertEqual(m["account"], {"user-1": "kwong"})
        self.assertEqual(m["server"], {"server-1": "SQLDR02", "server-2": "SQLPROD01", "server-3": "FILESRV01"})
        self.assertEqual(m["file"], {"file-1": "a/ERRORLOG", "file-2": "b/ERRORLOG"})

    def test_cli_writes_a_private_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "map.json")
            main([fixture("login_failures.log"), "--redact", "--redact-map", path], out=io.StringIO())
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(data["ip"]["192.0.2.1"], "10.20.4.31")
        self.assertIn("jdoe", data["account"].values())
        self.assertEqual(data["file"], {"file-1": fixture("login_failures.log")})
        if os.name == "posix":
            self.assertEqual(mode, 0o600)

    def test_an_existing_wide_open_file_is_tightened(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "map.json")
            with open(path, "w") as f:
                f.write("old")
            os.chmod(path, 0o644)
            main([fixture("noise.log"), "--redact", "--redact-map", path], out=io.StringIO())
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_map_without_redact_is_an_error(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main([fixture("noise.log"), "--redact-map", "x.json"], out=io.StringIO())
        self.assertEqual(code, 2)
        self.assertIn("needs --redact", err.getvalue())


if __name__ == "__main__":
    unittest.main()
