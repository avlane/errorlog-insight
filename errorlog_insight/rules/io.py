"""Slow I/O: message 833."""
import re

from ..model import Finding
from ..registry import LABELS, rule

LABELS.update({
    "833": "Slow I/O (833)",
})

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
