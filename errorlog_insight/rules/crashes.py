"""Stack dumps, assertions and fatal exceptions."""
import re

from .. import stackdump
from ..model import Finding
from ..registry import LABELS, rule, block_rule

LABELS.update({
    "stackdump": "Stack dumps",
    "17066": "Assertions (17065/17066)",
    "17310": "Session killed by exception",
})

ASSERTION_RE = re.compile(
    r"SQL Server Assertion: File: <(?P<file>[^>]+)>, line=(?P<line>\d+) Failed Assertion = '(?P<expr>.*?)'\."
)
FATAL_SESSION_RE = re.compile(
    r"A user request from the session with SPID (?P<spid>\d+) generated a fatal exception\."
)


@block_rule(stackdump.starts_dump)
def stack_dump_rule(entries, i):
    end = stackdump.collect(entries, i)
    dump = stackdump.parse(entries[i:end])
    details = {
        "kind": dump.kind,
        "file": dump.path,
        "spid": dump.spid or None,
        "exception_code": dump.exception_code or None,
        "exception_name": dump.exception_name or None,
        "location": dump.location or None,
        "expression": dump.expression or None,
        "input_buffer": dump.input_buffer or None,
        "signature": dump.signature or None,
        "modules": dump.modules[:5],
    }
    if dump.kind == "exception":
        severity = "critical"
        what = dump.exception_name or "exception"
        advice = ("A fatal exception means a bug or corruption. Keep %s and the input buffer, compare the build "
                  "with the latest cumulative update, and open a support case with the dump." % (dump.file_name or "the dump"))
    elif dump.kind == "non-yielding":
        severity = "error"
        what = "non-yielding scheduler"
        advice = "Matches a 17883 entry just before: see its CPU pattern, then the dump for what the worker was doing."
    elif dump.kind == "assertion":
        severity = "error"
        what = "assertion %s" % (dump.location or "")
        advice = "Run DBCC CHECKDB on the affected database and check the build for a fix."
    else:
        severity = "error"
        what = "dump"
        advice = "Check the dump file with support; the log does not say why it was taken."
    title = "Stack dump (%s) %s" % (what.strip(), dump.file_name)
    finding = Finding(entries[i], "dump", "stackdump", severity, title.strip(), details, advice)
    return finding, end


@rule
def assertion(entry, ctx):
    m = ASSERTION_RE.search(entry.text)
    if not m:
        return None
    details = {"file": m.group("file"), "line": int(m.group("line")), "expression": m.group("expr")}
    advice = "Assertions are bugs or corruption. Run DBCC CHECKDB and look for a fix in a newer build."
    return Finding(entry, "dump", "17066", "error",
                   "Assertion failed in %s line %s" % (details["file"], details["line"]), details, advice)


@rule
def fatal_session(entry, ctx):
    m = FATAL_SESSION_RE.search(entry.text)
    if not m:
        return None
    details = {"spid": int(m.group("spid"))}
    return Finding(entry, "dump", "17310", "critical",
                   "Session %s terminated by a fatal exception" % m.group("spid"), details,
                   "See the stack dump written just before this message.")
