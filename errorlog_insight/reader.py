"""Read SQL Server ERRORLOG files into entries.

The error log is UTF-16 LE with a BOM. Every entry starts with a line like

    2021-03-02 08:14:22.35 Logon       Error: 18456, Severity: 14, State: 8.

(date, time with centiseconds, process, message). Lines that do not start with
a timestamp belong to the previous entry.
"""
import codecs
import csv
import io
import re
from datetime import datetime

from .model import Entry

TAB = chr(9)
LINE_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{2,3}) (\S+)(?:\s+(.*))?$"
)


def _looks_like_utf16_le(data):
    """UTF-16 LE text without a BOM: ASCII characters alternate with NUL bytes."""
    sample = data[:200]
    if len(sample) < 4:
        return False
    odd = sample[1::2]
    return odd.count(0) >= 0.8 * len(odd)


def decode(data):
    """Decode raw ERRORLOG bytes to text.

    SQL Server writes UTF-16 LE with a BOM, but files that were copied while the
    instance was still writing can end in half a character, tools sometimes drop
    the BOM, and old or Linux logs may be UTF-8 or a legacy code page.
    """
    if data.startswith(codecs.BOM_UTF16_LE):
        body = data[2:]
        return body[: len(body) // 2 * 2].decode("utf-16-le", errors="replace")
    if data.startswith(codecs.BOM_UTF16_BE):
        body = data[2:]
        return body[: len(body) // 2 * 2].decode("utf-16-be", errors="replace")
    if _looks_like_utf16_le(data):
        return data[: len(data) // 2 * 2].decode("utf-16-le", errors="replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def _timestamp(m):
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    micro = int(m.group(7).ljust(6, "0"))
    return datetime(year, month, day, hour, minute, second, micro)


def parse_entries(text, source="", replica=""):
    """Split decoded log text into Entry objects."""
    entries = []
    current = None
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.replace("\x00", "")
        m = LINE_RE.match(line)
        if m:
            current = Entry(_timestamp(m), m.group(8), m.group(9) or "", source, lineno, replica)
            entries.append(current)
        elif current is not None:
            current.text += "\n" + line
    for entry in entries:
        entry.text = entry.text.rstrip()
    return entries


def looks_like_readerrorlog(text):
    """True for output saved from sp_readerrorlog (LogDate, ProcessInfo, Text)."""
    return text.lstrip().startswith("LogDate")


def parse_readerrorlog(text, source="", replica=""):
    """Parse tab-separated sp_readerrorlog output saved from SSMS.

    Fields that contain line breaks are quoted by SSMS, so the csv module does
    the heavy lifting. The Text column keeps its embedded newlines.
    """
    entries = []
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=TAB)
    header = next(reader, None)
    if not header or header[0].strip() != "LogDate":
        raise ValueError("not sp_readerrorlog output: missing LogDate header")
    for row in reader:
        if len(row) < 3 or not row[0].strip():
            continue
        stamp = row[0].strip()
        when = datetime.strptime(stamp[:19], "%Y-%m-%d %H:%M:%S")
        if len(stamp) > 20:
            when = when.replace(microsecond=int(stamp[20:].ljust(6, "0")[:6]))
        entries.append(Entry(when, row[1].strip(), row[2].rstrip(), source, reader.line_num, replica))
    return entries


def read_entries(path, replica=""):
    """Read an ERRORLOG file (or saved sp_readerrorlog output) from disk.

    `replica` is a free label (server name) stored on every entry, so entries
    from several servers can be told apart after they are merged.
    """
    with open(path, "rb") as f:
        data = f.read()
    text = decode(data)
    if looks_like_readerrorlog(text):
        return parse_readerrorlog(text, source=str(path), replica=replica)
    return parse_entries(text, source=str(path), replica=replica)
