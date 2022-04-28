r"""Summarise the stack dump banners SQL Server writes into the ERRORLOG.

A dump shows up as a run of entries from one process:

    Using 'dbghelp.dll' version '4.0.5'
    ***Stack Dump being sent to ...\LOG\SQLDump0007.txt
    SqlDumpExceptionHandler: Process 61 generated fatal exception c0000005 ...
    * BEGIN STACK DUMP:
    * Exception Code = c0000005 EXCEPTION_ACCESS_VIOLATION
    * Input Buffer 255 bytes -
    ...
    Stack Signature for the dump is 0x000000000000A2D1
    External dump process return code 0x20000001.

The dump file itself is not read; only what the log says about it.
"""
import re
from dataclasses import dataclass, field

DUMP_GAP_SECONDS = 15

STARTERS = ("Using 'dbghelp.dll'", "**Dump thread", "***Stack Dump being sent to")
END_MARKER = "External dump process"

DUMP_FILE_RE = re.compile(r"\*\*\*Stack Dump being sent to (?P<path>.+)")
HANDLER_RE = re.compile(
    r"SqlDumpExceptionHandler: Process (?P<spid>\d+) generated fatal exception (?P<code>[0-9a-fA-F]+) "
    r"(?P<name>\w+)\."
)
EXCEPTION_RE = re.compile(r"\* Exception Code = (?P<code>[0-9a-fA-F]+) (?P<name>\w+)")
LOCATION_RE = re.compile(r"\* Location:\s+(?P<location>\S+)")
EXPRESSION_RE = re.compile(r"\* Expression:\s+(?P<expression>.+)")
SIGNATURE_RE = re.compile(r"Stack Signature for the dump is (?P<sig>0x[0-9A-Fa-f]+)")
MODULE_RE = re.compile(r"^[0-9A-Fa-f]{12,16} Module\((?P<module>[\w.]+)\+")
SPID_RE = re.compile(r"\*\s+\d\d/\d\d/\d\d \d\d:\d\d:\d\d spid (?P<spid>\d+)")


def starts_dump(entry):
    return entry.text.startswith(STARTERS)


@dataclass
class StackDump:
    path: str = ""
    kind: str = "unknown"  # exception, assertion, non-yielding or unknown
    spid: int = 0
    exception_code: str = ""
    exception_name: str = ""
    location: str = ""
    expression: str = ""
    input_buffer: str = ""
    signature: str = ""
    modules: list = field(default_factory=list)

    @property
    def file_name(self):
        return self.path.replace("\\", "/").rsplit("/", 1)[-1] if self.path else ""


def collect(entries, start):
    """Index just past the dump that starts at entries[start]."""
    first = entries[start]
    end = start + 1
    last = first.timestamp
    finished = False
    while end < len(entries) and not finished:
        e = entries[end]
        if e.process != first.process:
            break
        if (e.timestamp - last).total_seconds() > DUMP_GAP_SECONDS:
            break
        if e is not entries[start] and starts_dump(e) and e.text.startswith("Using 'dbghelp.dll'"):
            break
        last = e.timestamp
        finished = e.text.startswith(END_MARKER)
        end += 1
    return end


def parse(entries):
    dump = StackDump()
    in_buffer = False
    buffer_lines = []
    for entry in entries:
        text = entry.text
        line = text.split("\n", 1)[0]
        m = DUMP_FILE_RE.match(line)
        if m:
            dump.path = m.group("path").strip()
            continue
        m = HANDLER_RE.match(line)
        if m:
            dump.kind = "exception"
            dump.spid = int(m.group("spid"))
            dump.exception_code = m.group("code").lower()
            dump.exception_name = m.group("name")
            continue
        m = EXCEPTION_RE.match(line)
        if m and not dump.exception_code:
            dump.kind = "exception"
            dump.exception_code = m.group("code").lower()
            dump.exception_name = m.group("name")
        m = SPID_RE.match(line)
        if m and not dump.spid:
            dump.spid = int(m.group("spid"))
        if "Non-yielding Scheduler" in line:
            dump.kind = "non-yielding"
        m = LOCATION_RE.match(line)
        if m:
            dump.kind = "assertion" if dump.kind == "unknown" else dump.kind
            dump.location = m.group("location")
        m = EXPRESSION_RE.match(line)
        if m:
            dump.expression = m.group("expression").strip()
        m = SIGNATURE_RE.search(line)
        if m:
            dump.signature = m.group("sig")
        m = MODULE_RE.match(line)
        if m and m.group("module") not in dump.modules:
            dump.modules.append(m.group("module"))
        if line.startswith("* Input Buffer"):
            in_buffer = True
            continue
        if in_buffer:
            body = line[1:] if line.startswith("*") else line
            if line.strip() == "*" or not body.startswith("   "):
                in_buffer = False
            else:
                buffer_lines.append(body.strip())
    dump.input_buffer = " ".join(buffer_lines)
    return dump
