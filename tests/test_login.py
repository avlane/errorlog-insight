import collections
import unittest

from errorlog_insight.classify import classify
from errorlog_insight.rules.login import decode_login_state, guess_state_from_reason
from errorlog_insight.reader import parse_entries, read_entries
from tests.helpers import fixture


class LoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = classify(read_entries(fixture("login_failures.log")))

    def test_one_finding_per_failed_login(self):
        self.assertEqual(len(self.findings), 15)
        self.assertTrue(all(f.code == "18456" for f in self.findings))

    def test_states_come_from_error_header(self):
        states = collections.Counter(f.details["state"] for f in self.findings)
        self.assertEqual(states[8], 6)
        self.assertEqual(states[5], 1)
        self.assertEqual(states[38], 1)

    def test_decoded_cause(self):
        by_user = {f.details["user"]: f for f in self.findings}
        disabled = by_user["reports"]
        self.assertEqual(disabled.details["state"], 7)
        self.assertIn("disabled", disabled.details["cause"])
        self.assertEqual(disabled.details["client"], "10.20.8.15")

    def test_domain_user_and_client(self):
        by_user = {f.details["user"]: f for f in self.findings}
        self.assertIn("CONTOSO\\jdoe", by_user)
        self.assertEqual(by_user["CONTOSO\\jdoe"].details["kind"], "authorization")

    def test_state_1_has_no_reason(self):
        by_user = {f.details["user"]: f for f in self.findings}
        mystery = by_user["mystery"]
        self.assertIsNone(mystery.details["reason"])
        self.assertEqual(mystery.details["kind"], "unknown")

    def test_state_guessed_from_reason_without_header(self):
        entries = parse_entries(
            "2021-03-02 08:14:22.35 Logon       Login failed for user 'bob'. "
            "Reason: Password did not match that for the login provided. [CLIENT: 10.0.0.9]\n"
        )
        (finding,) = classify(entries)
        self.assertEqual(finding.details["state"], 8)

    def test_header_from_other_process_is_ignored(self):
        entries = parse_entries(
            "2021-03-02 08:14:22.35 spid9s      Error: 18456, Severity: 14, State: 5.\n"
            "2021-03-02 08:14:22.36 Logon       Login failed for user 'bob'. "
            "Reason: Password did not match that for the login provided. [CLIENT: 10.0.0.9]\n"
        )
        (finding,) = classify(entries)
        self.assertEqual(finding.details["state"], 8)

    def test_unknown_state(self):
        kind, cause, _ = decode_login_state(99)
        self.assertEqual(kind, "unknown")
        self.assertIn("99", cause)
        self.assertIsNone(guess_state_from_reason("something new"))


if __name__ == "__main__":
    unittest.main()
