"""Memory errors 701 and 802, and a full transaction log (9002)."""
import re

from ..model import Finding
from ..registry import LABELS, rule, header_numbers

LABELS.update({
    "701": "Out of memory (701)",
    "802": "Buffer pool memory (802)",
    "9002": "Transaction log full (9002)",
})

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
