"""Rule-based classification of ERRORLOG entries.

Rules are plain functions registered with @rule. Each receives the entry and a
Context (which remembers the "Error: N, Severity: S, State: X." header that
SQL Server writes as a separate entry just before the message text) and
returns a Finding or None. The first rule that returns a Finding wins.
"""
import re

from .model import Finding

RULES = []

# Human-readable name per message number / pseudo code, used by the reports.
LABELS = {
    "18456": "Login failures",
    "833": "Slow I/O (833)",
    "17883": "Non-yielding (17883)",
    "17884": "Worker starvation (17884)",
}

ERROR_HEADER_RE = re.compile(r"^Error: (\d+), Severity: (\d+), State: (\d+)\.")
HEADER_WINDOW_SECONDS = 5


def rule(fn):
    RULES.append(fn)
    return fn


class Context:
    """State carried from one entry to the next while classifying a log."""

    def __init__(self):
        self.header = None  # (entry, number, severity, state)

    def observe(self, entry):
        m = ERROR_HEADER_RE.match(entry.first_line)
        if m:
            self.header = (entry, int(m.group(1)), int(m.group(2)), int(m.group(3)))

    def header_for(self, entry, number):
        """Return (severity, state) of the matching Error: header, if there is one."""
        if self.header is None:
            return None
        head, num, severity, state = self.header
        if num != number:
            return None
        if head.process != entry.process:
            return None
        if abs((entry.timestamp - head.timestamp).total_seconds()) > HEADER_WINDOW_SECONDS:
            return None
        return severity, state


def classify(entries):
    """Run every rule over the entries and return the findings in log order."""
    ctx = Context()
    findings = []
    for entry in entries:
        ctx.observe(entry)
        for fn in RULES:
            finding = fn(entry, ctx)
            if finding is not None:
                findings.append(finding)
                break
    return findings


# ---------------------------------------------------------------------------
# 18456: login failed
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 833: I/O requests taking longer than 15 seconds
# ---------------------------------------------------------------------------

IO_STALL_RE = re.compile(
    r"SQL Server has encountered (?P<count>\d+) occurrence\(s\) of I/O requests taking longer than "
    r"(?P<seconds>\d+) seconds to complete on file \[(?P<file>.+?)\] in database \[(?P<db>.+?)\] "
    r"\((?P<dbid>\d+)\)\.\s+The OS file handle is (?P<handle>0x[0-9A-Fa-f]+)\.\s+"
    r"The offset of the latest long I/O is: (?P<offset>0x[0-9A-Fa-f]+)"
)


def volume_of(path):
    """Drive letter ('E:') or UNC share ('\\\\FILESRV01\\SQLData') of a Windows path."""
    if path.startswith("\\\\"):
        parts = path.split("\\")
        return "\\\\" + "\\".join(parts[2:4])
    return path[:2].upper()


def file_kind(path):
    lowered = path.lower()
    if lowered.endswith(".ldf"):
        return "log"
    return "data"


def io_stall_severity(seconds):
    if seconds >= 60:
        return "critical"
    if seconds >= 30:
        return "error"
    return "warning"


@rule
def io_stall(entry, ctx):
    m = IO_STALL_RE.search(entry.text)
    if not m:
        return None
    path = m.group("file")
    seconds = int(m.group("seconds"))
    volume = volume_of(path)
    kind = file_kind(path)
    details = {
        "count": int(m.group("count")),
        "seconds": seconds,
        "file": path,
        "volume": volume,
        "file_kind": kind,
        "database": m.group("db"),
        "database_id": int(m.group("dbid")),
        "handle": m.group("handle"),
        "offset": m.group("offset"),
        "network": path.startswith("\\\\"),
    }
    if details["network"]:
        advice = "The file lives on a network share; check the SMB path, the file server and NIC errors."
    elif kind == "log":
        advice = ("Log writes are stalling, so commits stall too. Check latency on %s and whether a "
                  "filter driver or antivirus is scanning the log." % volume)
    else:
        advice = ("Check storage latency on %s (perfmon Avg. Disk sec/Read and sec/Write) and what else "
                  "uses the LUN at this time: backups, CHECKDB, a snapshot." % volume)
    title = "I/O stall: %d request(s) over %d s on %s (%s)" % (
        details["count"], seconds, path, details["database"])
    return Finding(entry, "io", "833", io_stall_severity(seconds), title, details, advice)


# ---------------------------------------------------------------------------
# 17883 / 17884: non-yielding schedulers and worker starvation
# ---------------------------------------------------------------------------

NON_YIELDING_RE = re.compile(
    r"Process (?P<spid>\d+:\d+:\d+) \((?P<thread>0x[0-9A-Fa-f]+)\) Worker (?P<worker>0x[0-9A-Fa-f]+) "
    r"appears to be non-yielding on Scheduler (?P<scheduler>\d+)\. "
    r"Thread creation time: (?P<created>\d+)\. "
    r"Approx Thread CPU Used: kernel (?P<kernel>\d+) ms, user (?P<user>\d+) ms\. "
    r"Process Utilization (?P<util>\d+)%\. System Idle (?P<idle>\d+)%\. Interval: (?P<interval>\d+) ms\."
)

STARVATION_RE = re.compile(
    r"New queries assigned to process on Node (?P<node>\d+) have not been picked up by a worker thread "
    r"in the last (?P<seconds>\d+) seconds\..*?"
    r"SQL Process Utilization: (?P<util>\d+)%\. System Idle: (?P<idle>\d+)%\.",
    re.S,
)


@rule
def non_yielding(entry, ctx):
    m = NON_YIELDING_RE.search(entry.text)
    if not m:
        return None
    kernel, user = int(m.group("kernel")), int(m.group("user"))
    interval = int(m.group("interval"))
    cpu_ms = kernel + user
    cpu_share = cpu_ms / interval if interval else 0.0
    if cpu_share >= 0.7:
        pattern = "cpu-bound"
        advice = ("The worker burned CPU the whole time without yielding: look for a runaway scan or "
                  "loop, a CLR or regex-heavy function, or a bug fixed in a later cumulative update.")
    elif cpu_share <= 0.1:
        pattern = "stalled"
        advice = ("The worker used almost no CPU while it held the scheduler, so it was waiting outside "
                  "SQL Server: preemptive calls (linked server, extended procedure), paging, a driver "
                  "or antivirus. Check what else happened at this time.")
    else:
        pattern = "mixed"
        advice = "Partly running and partly waiting; correlate with stack dumps and memory messages."
    details = {
        "scheduler": int(m.group("scheduler")),
        "worker": m.group("worker"),
        "kernel_ms": kernel,
        "user_ms": user,
        "interval_ms": interval,
        "cpu_share": round(cpu_share, 2),
        "process_utilization": int(m.group("util")),
        "system_idle": int(m.group("idle")),
        "pattern": pattern,
    }
    severity = "critical" if interval >= 120000 else "error"
    title = "Scheduler %d non-yielding for %.0f s (%s)" % (details["scheduler"], interval / 1000.0, pattern)
    return Finding(entry, "scheduler", "17883", severity, title, details, advice)


@rule
def worker_starvation(entry, ctx):
    m = STARVATION_RE.search(entry.text)
    if not m:
        return None
    seconds = int(m.group("seconds"))
    details = {
        "node": int(m.group("node")),
        "seconds": seconds,
        "process_utilization": int(m.group("util")),
        "system_idle": int(m.group("idle")),
    }
    advice = ("No worker thread was free. Check for a blocking chain holding many workers, THREADPOOL "
              "waits, and whether max worker threads is sensible for the core count.")
    severity = "critical" if seconds >= 180 else "error"
    title = "New queries waited %d s for a worker thread" % seconds
    return Finding(entry, "scheduler", "17884", severity, title, details, advice)
