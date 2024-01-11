"""Memory errors 701 and 802, and a full transaction log (9002)."""
import re

from ..model import Finding
from ..registry import LABELS, rule, header_numbers

LABELS.update({
    "701": "Out of memory (701)",
    "802": "Buffer pool memory (802)",
    "9002": "Transaction log full (9002)",
    "17890": "Memory paged out (17890)",
    "8645": "Memory grant timeout (8645)",
})

MEMORY_701_RE = re.compile(r"There is insufficient system memory in resource pool '(?P<pool>[^']*)' to run this query\.")
MEMORY_802_RE = re.compile(r"There is insufficient memory available in the buffer pool\.")
LOG_FULL_RE = re.compile(
    r"The transaction log for database '(?P<db>[^']+)' is full"
    r"(?: due to '(?P<wait>[A-Z_]+)'|\.? To find out why space in the log cannot be reused)"
)

PAGED_OUT_RE = re.compile(
    r"A significant part of sql server process memory has been paged out\. This may result in a performance "
    r"degradation\. Duration: (?P<seconds>\d+) seconds\. Working set \(KB\): (?P<ws>\d+), "
    r"committed \(KB\): (?P<committed>\d+), memory utilization: (?P<util>\d+)%\."
)
GRANT_TIMEOUT_RE = re.compile(
    r"A timeout occurred while waiting for memory resources to execute the query"
    r"(?: in resource pool '(?P<pool>[^']+)' \((?P<poolid>\d+)\))?\."
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


@rule
def memory_701(entry, ctx):
    m = MEMORY_701_RE.search(entry.text)
    if not m:
        return None
    details = {"pool": m.group("pool")}
    details.update(header_numbers(ctx, entry, 701))
    advice = ("A query could not get enough memory. Check max server memory, memory grants "
              "(sys.dm_exec_query_memory_grants) and what else runs on the host.")
    return Finding(entry, "memory", "701", "error",
                   "Insufficient system memory in resource pool '%s'" % details["pool"], details, advice)


@rule
def memory_802(entry, ctx):
    if not MEMORY_802_RE.search(entry.text):
        return None
    details = header_numbers(ctx, entry, 802)
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
    details.update(header_numbers(ctx, entry, 9002))
    advice = LOG_REUSE_ADVICE.get(wait, LOG_FULL_DEFAULT_ADVICE)
    title = "Transaction log of %s is full" % details["database"]
    if wait:
        title += " (%s)" % wait
    return Finding(entry, "log", "9002", "critical", title, details, advice)


@rule
def memory_paged_out(entry, ctx):
    m = PAGED_OUT_RE.search(entry.text)
    if not m:
        return None
    seconds = int(m.group("seconds"))
    util = int(m.group("util"))
    details = {
        "duration_seconds": seconds,
        "working_set_kb": int(m.group("ws")),
        "committed_kb": int(m.group("committed")),
        "memory_utilization": util,
    }
    severity = "error" if util < 50 or seconds >= 300 else "warning"
    advice = ("The operating system took memory away from SQL Server. On a VM look for a balloon driver or a "
              "host under pressure; on any host consider 'Lock pages in memory' and a lower max server memory.")
    title = "%d%% of SQL Server memory is in the working set (paged out for %d s)" % (util, seconds)
    return Finding(entry, "memory", "17890", severity, title, details, advice)


@rule
def memory_grant_timeout(entry, ctx):
    m = GRANT_TIMEOUT_RE.search(entry.text)
    if not m:
        return None
    details = {"pool": m.group("pool"), "pool_id": int(m.group("poolid")) if m.group("poolid") else None}
    details.update(header_numbers(ctx, entry, 8645))
    advice = ("The query waited too long for its memory grant. Check sys.dm_exec_query_memory_grants for "
              "queries holding large grants, and look for bad cardinality estimates behind them.")
    return Finding(entry, "memory", "8645", "error", "Memory grant timeout", details, advice)
