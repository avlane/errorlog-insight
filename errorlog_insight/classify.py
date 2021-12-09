"""Rule-based classification of ERRORLOG entries.

Rules are plain functions registered with @rule. Each receives the entry and a
Context (which remembers the "Error: N, Severity: S, State: X." header that
SQL Server writes as a separate entry just before the message text) and
returns a Finding or None. The first rule that returns a Finding wins.
"""
import re

from . import deadlock as deadlock_graph
from .model import Finding

RULES = []

# Human-readable name per message number / pseudo code, used by the reports.
LABELS = {
    "18456": "Login failures",
    "833": "Slow I/O (833)",
    "17883": "Non-yielding (17883)",
    "17884": "Worker starvation (17884)",
    "701": "Out of memory (701)",
    "802": "Buffer pool memory (802)",
    "9002": "Transaction log full (9002)",
    "3041": "Backup failed (3041)",
    "18204": "Backup device error (18204)",
    "3201": "Backup device error (3201)",
    "4208": "BACKUP LOG on SIMPLE (4208)",
    "18264": "Backups completed",
    "18265": "Log backups completed",
    "startup": "Server start",
    "ready": "Ready for connections",
    "shutdown": "Shutdown",
    "cycled": "Error log cycled",
    "recovery": "Database recovery",
    "1222": "Deadlocks (1222)",
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
    i = 0
    while i < len(entries):
        entry = entries[i]
        if entry.text.strip() == "deadlock-list":
            # a 1222 graph is one logical block spread over many entries
            end = deadlock_graph.collect_block(entries, i)
            findings.append(summarise_deadlock(entry, deadlock_graph.parse_block(entries[i:end])))
            i = end
            continue
        ctx.observe(entry)
        for fn in RULES:
            finding = fn(entry, ctx)
            if finding is not None:
                findings.append(finding)
                break
        i += 1
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


# ---------------------------------------------------------------------------
# 701 / 802: memory; 9002: transaction log full
# ---------------------------------------------------------------------------

MEMORY_701_RE = re.compile(r"There is insufficient system memory in resource pool '(?P<pool>[^']*)' to run this query\.")
MEMORY_802_RE = re.compile(r"There is insufficient memory available in the buffer pool\.")
LOG_FULL_RE = re.compile(
    r"The transaction log for database '(?P<db>[^']+)' is full"
    r"(?: due to '(?P<wait>[A-Z_]+)'|\.? To find out why space in the log cannot be reused)"
)

LOG_REUSE_ADVICE = {
    "LOG_BACKUP": "The log is waiting for a log backup. Check the backup job; in SIMPLE recovery this should not happen.",
    "ACTIVE_TRANSACTION": "A long open transaction pins the log. Find it with DBCC OPENTRAN or sys.dm_tran_active_transactions.",
    "AVAILABILITY_REPLICA": "A secondary replica has not hardened the log yet. Check the log send and redo queues.",
    "REPLICATION": "Transactional replication has not read the log: check the Log Reader Agent.",
    "ACTIVE_BACKUP_OR_RESTORE": "A backup or restore is holding the log. Wait for it or check that it is not hung.",
    "DATABASE_MIRRORING": "The mirror is behind or disconnected.",
    "CHECKPOINT": "No checkpoint has happened since the last log truncation.",
    "LOG_SCAN": "A log scan (for example CDC or replication) is in progress.",
}
LOG_FULL_DEFAULT_ADVICE = "Look at log_reuse_wait_desc in sys.databases to see what blocks log reuse."


def _header_numbers(ctx, entry, number):
    header = ctx.header_for(entry, number)
    if header is None:
        return {}
    return {"error_severity": header[0], "error_state": header[1]}


@rule
def memory_701(entry, ctx):
    m = MEMORY_701_RE.search(entry.text)
    if not m:
        return None
    details = {"pool": m.group("pool")}
    details.update(_header_numbers(ctx, entry, 701))
    advice = ("A query could not get enough memory. Check max server memory, memory grants "
              "(sys.dm_exec_query_memory_grants) and what else runs on the host.")
    return Finding(entry, "memory", "701", "error",
                   "Insufficient system memory in resource pool '%s'" % details["pool"], details, advice)


@rule
def memory_802(entry, ctx):
    if not MEMORY_802_RE.search(entry.text):
        return None
    details = _header_numbers(ctx, entry, 802)
    advice = ("The buffer pool could not grow. Check max server memory against the host RAM, "
              "memory clerks (sys.dm_os_memory_clerks) and stolen memory.")
    return Finding(entry, "memory", "802", "error",
                   "Insufficient memory available in the buffer pool", details, advice)


@rule
def log_full(entry, ctx):
    m = LOG_FULL_RE.search(entry.text)
    if not m:
        return None
    wait = m.group("wait")
    details = {"database": m.group("db"), "log_reuse_wait": wait}
    details.update(_header_numbers(ctx, entry, 9002))
    advice = LOG_REUSE_ADVICE.get(wait, LOG_FULL_DEFAULT_ADVICE)
    title = "Transaction log of %s is full" % details["database"]
    if wait:
        title += " (%s)" % wait
    return Finding(entry, "log", "9002", "critical", title, details, advice)


# ---------------------------------------------------------------------------
# Backups: 3041 / 18204 / 3201 / 4208 and the success messages
# ---------------------------------------------------------------------------

BACKUP_FAILED_RE = re.compile(
    r"BACKUP failed to complete the command (?P<command>BACKUP (?P<kind>DATABASE|LOG)\s+"
    r"\[?(?P<db>[^\s\]]+)\]?.*?)\. Check the backup application log"
)
BACKUP_DEVICE_RE = re.compile(
    r"(?:BackupDiskFile::CreateMedia: Backup device '(?P<create>.+?)' failed to create"
    r"|Cannot open backup device '(?P<open>.+?)')\. Operating system error (?P<code>\d+)\((?P<text>.*?)\)\."
)
BACKUP_SIMPLE_RE = re.compile(r"The statement BACKUP LOG is not allowed while the recovery model is SIMPLE")
BACKUP_OK_RE = re.compile(
    r"(?P<what>Database|Log) (?:backed up|was backed up)\. Database: (?P<db>.+?), creation date\(time\): "
    r"(?P<created>[^,]+), (?:pages dumped: (?P<pages>\d+), )?first LSN: (?P<first>[\d:]+), last LSN: (?P<last>[\d:]+), "
    r"number of dump devices: (?P<devices>\d+), device information: \(FILE=(?P<file>\d+), TYPE=(?P<type>\w+): "
    r"\{'(?P<device>.+?)'\}\)"
)

OS_ERROR_ADVICE = {
    3: "The path does not exist: check the backup folder or share.",
    5: "Access denied: the SQL Server service account needs write permission on the target.",
    32: "The file is in use by another process (antivirus or another job).",
    53: "The network path was not found: check the file server name, DNS and the SMB path.",
    64: "The network name is no longer available: the share dropped mid-backup.",
    112: "The target volume is full: free space or move the backup folder.",
    1450: "Insufficient system resources: look at the file server and at memory pressure.",
}


@rule
def backup_failed(entry, ctx):
    m = BACKUP_FAILED_RE.search(entry.text)
    if not m:
        return None
    details = {
        "command": m.group("command"),
        "kind": m.group("kind").lower(),
        "database": m.group("db"),
    }
    advice = "Look at the entries just before this one for the underlying error (device, disk, permission)."
    title = "Backup of %s failed (%s)" % (details["database"], details["kind"])
    return Finding(entry, "backup", "3041", "error", title, details, advice)


@rule
def backup_device(entry, ctx):
    m = BACKUP_DEVICE_RE.search(entry.text)
    if not m:
        return None
    code = int(m.group("code"))
    device = m.group("create") or m.group("open")
    details = {
        "device": device,
        "os_error": code,
        "os_error_text": m.group("text"),
        "network": device.startswith("\\\\"),
    }
    advice = OS_ERROR_ADVICE.get(code, "Look up Windows error %d for the target device." % code)
    number = "18204" if m.group("create") else "3201"
    title = "Backup device %s: %s" % (device, m.group("text"))
    return Finding(entry, "backup", number, "error", title, details, advice)


@rule
def backup_on_simple(entry, ctx):
    if not BACKUP_SIMPLE_RE.search(entry.text):
        return None
    advice = "A log backup job targets a database in SIMPLE recovery. Remove it from the job or change the recovery model."
    return Finding(entry, "backup", "4208", "error", "BACKUP LOG attempted on a SIMPLE recovery database", {}, advice)


@rule
def backup_ok(entry, ctx):
    m = BACKUP_OK_RE.search(entry.text)
    if not m:
        return None
    is_db = m.group("what") == "Database"
    details = {
        "database": m.group("db"),
        "kind": "database" if is_db else "log",
        "first_lsn": m.group("first"),
        "last_lsn": m.group("last"),
        "device": m.group("device"),
        "pages": int(m.group("pages")) if m.group("pages") else None,
    }
    return Finding(entry, "backup", "18264" if is_db else "18265", "info",
                   "%s backup of %s completed" % (details["kind"].capitalize(), details["database"]), details)


# ---------------------------------------------------------------------------
# Startup and shutdown
# ---------------------------------------------------------------------------

BANNER_RE = re.compile(
    r"^Microsoft SQL Server (?P<year>\d{4}) \((?P<level>[^)]*)\)(?: \((?P<kb>KB\d+)\))? - "
    r"(?P<build>\d+\.\d+\.\d+\.\d+) \((?P<arch>[^)]*)\)"
)
EDITION_RE = re.compile(r"(?P<edition>[A-Za-z ]+ Edition(?: \(\d+-bit\))?) on (?P<os>[^\n]+)")
READY_RE = re.compile(r"^SQL Server is now ready for client connections")
SHUTDOWN_RES = (
    (re.compile(r"^SQL Server is terminating in response to a '(?P<how>\w+)' request from Service Control Manager"),
     "service control manager"),
    (re.compile(r"^SQL Server is terminating because of a system shutdown"), "system shutdown"),
    (re.compile(r"^SQL Server is terminating because of fatal exception"), "fatal exception"),
    (re.compile(r"^SQL Server is terminating this process"), "process terminated"),
)
CYCLED_RE = re.compile(r"^The error log has been reinitialized")
RECOVERY_RE = re.compile(
    r"^Recovery of database '(?P<db>[^']+)' \((?P<dbid>\d+)\) is (?P<pct>\d+)% complete"
    r"(?: \(approximately (?P<secs>\d+) seconds remain\))?"
)


@rule
def startup_banner(entry, ctx):
    m = BANNER_RE.match(entry.text)
    if not m:
        return None
    details = {
        "version_year": int(m.group("year")),
        "level": m.group("level"),
        "kb": m.group("kb"),
        "build": m.group("build"),
        "arch": m.group("arch"),
    }
    e = EDITION_RE.search(entry.text)
    if e:
        details["edition"] = e.group("edition")
        details["os"] = e.group("os").strip()
    title = "SQL Server %s %s (%s) started" % (details["version_year"], details["level"], details["build"])
    return Finding(entry, "lifecycle", "startup", "info", title, details)


@rule
def server_ready(entry, ctx):
    if not READY_RE.match(entry.text):
        return None
    return Finding(entry, "lifecycle", "ready", "info", "Ready for client connections", {})


@rule
def shutdown(entry, ctx):
    for regex, how in SHUTDOWN_RES:
        if regex.match(entry.text):
            severity = "critical" if how in ("fatal exception", "process terminated") else "info"
            return Finding(entry, "lifecycle", "shutdown", severity, "SQL Server shut down (%s)" % how,
                           {"how": how})
    return None


@rule
def error_log_cycled(entry, ctx):
    if not CYCLED_RE.match(entry.text):
        return None
    return Finding(entry, "lifecycle", "cycled", "info", "Error log cycled", {})


@rule
def database_recovery(entry, ctx):
    m = RECOVERY_RE.match(entry.text)
    if not m:
        return None
    details = {"database": m.group("db"), "percent": int(m.group("pct")),
               "seconds_remaining": int(m.group("secs")) if m.group("secs") else None}
    return Finding(entry, "lifecycle", "recovery", "info",
                   "Recovery of %s at %d%%" % (details["database"], details["percent"]), details)


# ---------------------------------------------------------------------------
# 1222: deadlock graph
# ---------------------------------------------------------------------------

def summarise_deadlock(entry, dl):
    victims = [dl.process(v) for v in dl.victims]
    victims = [v for v in victims if v is not None]
    objects = []
    for res in dl.resources:
        if res.object_name and res.object_name not in objects:
            objects.append(res.object_name)
    kinds = sorted({res.kind for res in dl.resources})
    details = {
        "victims": [
            {"spid": v.spid, "login": v.login, "app": v.app, "host": v.host,
             "procedure": v.procedure, "statement": v.statement}
            for v in victims
        ],
        "processes": [
            {"spid": p.spid, "login": p.login, "app": p.app, "host": p.host, "database": p.database,
             "procedure": p.procedure, "statement": p.statement, "wait_resource": p.wait_resource,
             "isolation": p.isolation}
            for p in dl.processes
        ],
        "objects": objects,
        "lock_kinds": kinds,
        "database": dl.processes[0].database if dl.processes else None,
    }
    advice = []
    if any(k in ("pagelock", "ridlock") for k in kinds):
        advice.append("Page or row-id locks point at heap or scan access: check for a missing index on %s."
                      % ", ".join(objects))
    if "keylock" in kinds and len(objects) > 1:
        advice.append("The sessions take %s in opposite orders; make every code path touch them in the same order."
                      % " and ".join(objects))
    if all((p.isolation or "").startswith("read committed") for p in dl.processes) and dl.processes:
        advice.append("Everything ran at READ COMMITTED; READ_COMMITTED_SNAPSHOT removes reader-writer deadlocks.")
    if victims:
        who = victims[0]
        title = "Deadlock on %s: victim spid %s%s" % (
            ", ".join(objects) or "unknown objects", who.spid,
            " (%s)" % (who.procedure or who.app) if (who.procedure or who.app) else "")
    else:
        title = "Deadlock on %s" % (", ".join(objects) or "unknown objects")
    return Finding(entry, "deadlock", "1222", "error", title, details, " ".join(advice))
