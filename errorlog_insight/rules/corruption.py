"""I/O errors that threaten database integrity: 823, 824 and 825."""
import re

from ..model import Finding
from ..registry import LABELS, header_numbers, rule

LABELS.update({
    "823": "OS I/O error (823)",
    "824": "Logical I/O error (824)",
    "825": "Read retry (825)",
})

LOGICAL_RE = re.compile(
    r"SQL Server detected a logical consistency-based I/O error: (?P<kind>[^(.]+?)(?: \((?P<detail>[^)]*)\))?\. "
    r"It occurred during a (?P<op>read|write) of page \((?P<file>\d+):(?P<page>\d+)\) in database ID (?P<dbid>\d+) "
    r"at offset (?P<offset>0x[0-9A-Fa-f]+) in file '(?P<path>.+?)'\."
)
OS_ERROR_RE = re.compile(
    r"The operating system returned error (?P<code>\d+)\((?P<text>.*?)\) to SQL Server during a "
    r"(?P<op>read|write) at offset (?P<offset>0x[0-9A-Fa-f]+) in file '(?P<path>.+?)'\."
)
RETRY_RE = re.compile(
    r"A read of the file '(?P<path>.+?)' at offset (?P<offset>0x[0-9A-Fa-f]+) succeeded after failing "
    r"(?P<times>\d+) time\(s\) with error: (?P<kind>[^(.]+?)(?: \((?P<detail>[^)]*)\))?\."
)

CHECKDB_ADVICE = ("Run DBCC CHECKDB on the database now, find the last good backups, and have the storage "
                  "layer checked (controller, firmware, multipath, anything that touched the LUN).")


@rule
def logical_io_error(entry, ctx):
    m = LOGICAL_RE.search(entry.text)
    if not m:
        return None
    details = {
        "kind": m.group("kind").strip(),
        "detail": m.group("detail"),
        "operation": m.group("op"),
        "file_id": int(m.group("file")),
        "page": int(m.group("page")),
        "database_id": int(m.group("dbid")),
        "offset": m.group("offset"),
        "path": m.group("path"),
    }
    details.update(header_numbers(ctx, entry, 824))
    title = "Page (%d:%d) of database %d failed a %s: %s" % (
        details["file_id"], details["page"], details["database_id"], details["operation"], details["kind"])
    return Finding(entry, "corruption", "824", "critical", title, details, CHECKDB_ADVICE)


@rule
def os_io_error(entry, ctx):
    m = OS_ERROR_RE.search(entry.text)
    if not m:
        return None
    details = {
        "os_error": int(m.group("code")),
        "os_error_text": m.group("text"),
        "operation": m.group("op"),
        "offset": m.group("offset"),
        "path": m.group("path"),
    }
    details.update(header_numbers(ctx, entry, 823))
    title = "Windows error %d during a %s of %s" % (details["os_error"], details["operation"], details["path"])
    return Finding(entry, "corruption", "823", "critical", title, details, CHECKDB_ADVICE)


@rule
def read_retry(entry, ctx):
    m = RETRY_RE.search(entry.text)
    if not m:
        return None
    details = {
        "path": m.group("path"),
        "offset": m.group("offset"),
        "failures": int(m.group("times")),
        "kind": m.group("kind").strip(),
        "detail": m.group("detail"),
    }
    details.update(header_numbers(ctx, entry, 825))
    advice = ("The read worked on retry, so nothing was lost yet, but the storage returned bad data "
              "%d time(s). Treat it as a warning from failing hardware and run DBCC CHECKDB." % details["failures"])
    title = "Read of %s needed %d retry(s): %s" % (details["path"], details["failures"], details["kind"])
    return Finding(entry, "corruption", "825", "error", title, details, advice)
