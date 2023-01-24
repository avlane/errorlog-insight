"""Startup, shutdown and recovery messages."""
import re

from ..model import Finding
from ..registry import LABELS, rule

LABELS.update({
    "startup": "Server start",
    "ready": "Ready for connections",
    "shutdown": "Shutdown",
    "cycled": "Error log cycled",
    "recovery": "Database recovery",
})

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
