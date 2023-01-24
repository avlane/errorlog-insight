"""Failed logins: error 18456."""
import re

from ..model import Finding
from ..registry import LABELS, rule

LABELS.update({
    "18456": "Login failures",
})

LOGIN_FAILED_RE = re.compile(
    r"^Login failed for user '(?P<user>(?:[^']|'')*)'\."
    r"(?: Reason: (?P<reason>.*?))?"
    r"(?: \[CLIENT: (?P<client>[^\]]*)\])?\s*$",
    re.S,
)

# state -> (kind, cause, advice)
LOGIN_STATES = {
    1: ("unknown", "Error information withheld from the client and the log.",
        "Check the server for a later entry, or raise the trace flag that exposes the state; "
        "state 1 hides the real cause."),
    2: ("credentials", "The user id is not valid.",
        "Check the login name the application sends."),
    5: ("credentials", "The login name does not exist on this server.",
        "Create the login, or fix the connection string (stale server alias or old account)."),
    6: ("credentials", "A Windows account name was used with SQL Server authentication.",
        "Use Integrated Security / Trusted_Connection instead of a SQL user and password."),
    7: ("credentials", "The login is disabled.",
        "Enable the login if it is still needed, or retire the application using it."),
    8: ("credentials", "The password did not match the one stored for the login.",
        "Update the password in the application, or check for a brute-force attempt if the user is sa."),
    9: ("credentials", "The password is invalid.",
        "Reset the password."),
    11: ("authorization", "The login is valid but server access failed (no CONNECT SQL permission or token check failed).",
         "Check that the login has CONNECT SQL permission and that the domain controller is reachable."),
    12: ("authorization", "The login is valid but the server access check failed.",
         "Check CONNECT SQL permission and group membership for the Windows account."),
    13: ("server", "The SQL Server service is paused.",
         "Resume the service."),
    16: ("database", "The target database is not accessible to the login.",
         "Check the database state and the user mapping."),
    18: ("credentials", "The password must be changed before the login can connect.",
         "Change the password or clear the MUST_CHANGE flag."),
    23: ("server", "The server is shutting down or not accepting connections.",
         "Wait for startup to finish."),
    38: ("database", "The database named in the connection string cannot be opened.",
         "Check that the database exists, is online, and the login can reach it."),
    40: ("database", "The login's default database cannot be opened.",
         "Change the default database of the login or bring the database online."),
    46: ("database", "The database requested by the login cannot be opened.",
         "Check the database name and that the login has a user in it."),
    58: ("config", "SQL authentication was used but the server accepts Windows authentication only.",
         "Switch the client to Windows authentication or enable mixed mode (needs a restart)."),
}

# The reason text is enough to guess the state when the "Error:" header entry is missing
# (for example in a filtered sp_readerrorlog result).
REASON_HINTS = (
    ("Password did not match", 8),
    ("Could not find a login", 5),
    ("Account is disabled", 7),
    ("Attempting to use an NT account name", 6),
    ("Token-based server access validation", 11),
    ("Login-based server access validation", 12),
    ("Failed to open the explicitly specified database", 38),
    ("Failed to open the database specified in the login properties", 40),
    ("must be changed", 18),
    ("Server is configured for Windows authentication only", 58),
)


def decode_login_state(state):
    return LOGIN_STATES.get(state, ("unknown", "State %s is not in the decoder table." % state, ""))


def guess_state_from_reason(reason):
    for needle, state in REASON_HINTS:
        if needle in (reason or ""):
            return state
    return None


@rule
def login_failed(entry, ctx):
    m = LOGIN_FAILED_RE.match(entry.text)
    if not m:
        return None
    header = ctx.header_for(entry, 18456)
    state = header[1] if header else guess_state_from_reason(m.group("reason"))
    kind, cause, advice = decode_login_state(state)
    details = {
        "user": m.group("user").replace("''", "'"),
        "reason": m.group("reason"),
        "client": m.group("client"),
        "state": state,
        "kind": kind,
        "cause": cause,
    }
    return Finding(entry, "login", "18456", "warning",
                   "Login failed for %s: %s" % (details["user"], cause), details, advice)
