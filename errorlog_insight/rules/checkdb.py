"""DBCC CHECKDB and friends: what they found and how long they ran."""
import re

from ..model import Finding
from ..registry import LABELS, rule

LABELS.update({
    "checkdb": "DBCC consistency checks",
    "17573": "CHECKDB finished clean (17573)",
})

DBCC_RE = re.compile(
    r"DBCC (?P<cmd>CHECKDB|CHECKTABLE|CHECKALLOC|CHECKCATALOG|CHECKFILEGROUP) \((?P<args>[^)]*)\)"
    r"(?: WITH (?P<options>[^.]+?))? executed by (?P<user>.+?) found (?P<found>\d+) errors? and repaired "
    r"(?P<repaired>\d+) errors?\. Elapsed time: (?P<h>\d+) hours (?P<m>\d+) minutes (?P<s>\d+) seconds\."
)
CLEAN_RE = re.compile(r"CHECKDB for database '(?P<db>[^']+)' finished without errors on")


@rule
def dbcc_result(entry, ctx):
    m = DBCC_RE.search(entry.text)
    if not m:
        return None
    found, repaired = int(m.group("found")), int(m.group("repaired"))
    elapsed = int(m.group("h")) * 3600 + int(m.group("m")) * 60 + int(m.group("s"))
    args = [a.strip() for a in m.group("args").split(",")]
    details = {
        "command": m.group("cmd"),
        "target": args[0],
        "arguments": args[1:],
        "options": m.group("options"),
        "user": m.group("user"),
        "errors_found": found,
        "errors_repaired": repaired,
        "elapsed_seconds": elapsed,
        "repair_mode": any(a.lower().startswith("repair") for a in args[1:]),
    }
    if found == 0:
        severity, advice = "info", ""
        title = "DBCC %s of %s found no errors (%d s)" % (details["command"], details["target"], elapsed)
    else:
        severity = "critical"
        title = "DBCC %s of %s found %d error(s), repaired %d" % (details["command"], details["target"], found, repaired)
        if details["repair_mode"]:
            advice = ("A repair option was used. REPAIR_ALLOW_DATA_LOSS deletes data to get consistent: "
                      "compare with the last good backup before accepting the result.")
        else:
            advice = ("Rerun with NO_INFOMSGS to list the errors. Prefer restoring from a clean backup to "
                      "repairing; check storage for the cause.")
    return Finding(entry, "corruption", "checkdb", severity, title, details, advice)


@rule
def checkdb_clean(entry, ctx):
    m = CLEAN_RE.search(entry.text)
    if not m:
        return None
    return Finding(entry, "corruption", "17573", "info", "CHECKDB of %s finished without errors" % m.group("db"),
                   {"database": m.group("db")})
