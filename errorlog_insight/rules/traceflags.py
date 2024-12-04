"""DBCC TRACEON / TRACEOFF messages."""
import re

from ..model import Finding
from ..registry import LABELS, rule

LABELS["traceflag"] = "Trace flag changes"

TRACE_RE = re.compile(r"DBCC TRACE(?P<action>ON|OFF) (?P<flags>[\d, ]+?), server process ID \(SPID\) (?P<spid>\d+)\.")

# A few flags a DBA will meet in an error log, with what they do.
KNOWN_FLAGS = {
    1117: "grow all files in a filegroup together",
    1118: "uniform extents only (tempdb, before SQL Server 2016)",
    1204: "write deadlock participants to the error log",
    1222: "write the deadlock graph to the error log",
    2371: "lower auto-update statistics threshold for large tables",
    3226: "do not log successful backups in the error log",
    3604: "send DBCC output to the client",
    3605: "send DBCC output to the error log",
    4199: "enable query optimizer fixes released after RTM",
    9481: "use the legacy cardinality estimator",
}
# Flags worth a warning when they stay on, because they flood the log or change plans.
NOISY_FLAGS = {3605: "output goes to the error log until it is turned off"}


@rule
def trace_flag(entry, ctx):
    m = TRACE_RE.search(entry.text)
    if not m:
        return None
    flags = [int(f) for f in re.findall(r"\d+", m.group("flags"))]
    action = m.group("action").lower()
    details = {
        "flags": flags,
        "action": action,
        "spid": int(m.group("spid")),
        "meaning": {str(f): KNOWN_FLAGS.get(f, "not in the built-in list") for f in flags},
    }
    title = "Trace flag %s turned %s (spid %d)" % (", ".join(str(f) for f in flags), action, details["spid"])
    advice = ""
    if action == "on":
        for f in flags:
            if f in NOISY_FLAGS:
                advice = "Flag %d: %s." % (f, NOISY_FLAGS[f])
    return Finding(entry, "config", "traceflag", "info", title, details, advice)
