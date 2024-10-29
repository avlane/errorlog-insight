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


def iter_line_entries(lines, source="", replica=""):
    """Yield Entry objects from an iterable of physical lines, one entry at a time.

    The text of an entry is assembled when the next entry starts, so a file is
    never needed in memory all at once.
    """
    current = None
    parts = None
    for lineno, line in enumerate(lines, 1):
        line = line.rstrip("\r\n").replace("\x00", "")
        m = LINE_RE.match(line)
        if m:
            if current is not None:
                current.text = "\n".join(parts).rstrip()
                yield current
            parts = [m.group(9) or ""]
            current = Entry(_timestamp(m), m.group(8), "", source, lineno, replica)
        elif current is not None:
            parts.append(line)
    if current is not None:
        current.text = "\n".join(parts).rstrip()
        yield current


def parse_entries(text, source="", replica=""):
    """Split decoded log text into Entry objects."""
    return list(iter_line_entries(text.splitlines(), source, replica))


# Column names of the two saved-grid layouts: sp_readerrorlog and the SSMS Log File Viewer.
GRID_HEADERS = (("LogDate", "ProcessInfo", "Text"), ("Date", "Source", "Message"))

# Dates in saved grids follow the client's locale. Only layouts that cannot be
# confused with each other are tried (month first, as on US English clients).
GRID_DATE_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
)


def _grid_delimiter(first_line):
    return TAB if TAB in first_line else ","


def looks_like_readerrorlog(text):
    """True for a grid saved from sp_readerrorlog or from the Log File Viewer."""
    first = text.lstrip().split("\n", 1)[0].strip()
    names = tuple(n.strip().strip('"') for n in first.split(_grid_delimiter(first)))
    return names[:3] in GRID_HEADERS


def parse_grid_date(stamp):
    """Parse the date column of a saved grid, with or without fractional seconds."""
    stamp = stamp.strip()
    head, _, fraction = stamp.partition(".")
    if fraction and not fraction.isdigit():
        head, fraction = stamp, ""
    for fmt in GRID_DATE_FORMATS:
        try:
            when = datetime.strptime(head, fmt)
        except ValueError:
            continue
        if fraction:
            when = when.replace(microsecond=int(fraction.ljust(6, "0")[:6]))
        return when
    raise ValueError("unrecognised date in saved grid: %r" % stamp)


def parse_readerrorlog(text, source="", replica=""):
    """Parse a saved grid: tab separated (sp_readerrorlog) or comma separated (Log File Viewer).

    Fields that contain line breaks are quoted by SSMS, so the csv module does
    the heavy lifting. The Text column keeps its embedded newlines. The Log File
    Viewer lists the newest entry first, so such a grid is reversed into time order.
    """
    entries = []
    text = text.lstrip()
    delimiter = _grid_delimiter(text.split("\n", 1)[0])
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
    header = next(reader, None)
    if not header or tuple(h.strip() for h in header[:3]) not in GRID_HEADERS:
        raise ValueError("not a saved error log grid: missing LogDate/Date header")
    for row in reader:
        if len(row) < 3 or not row[0].strip():
            continue
        entries.append(Entry(parse_grid_date(row[0]), row[1].strip(), row[2].rstrip(), source, reader.line_num, replica))
    if len(entries) > 1 and entries[0].timestamp > entries[-1].timestamp:
        entries.reverse()  # newest first: reversing (not sorting) keeps same-second entries in log order
    return entries


SNIFF_BYTES = 64 * 1024


def _choose_encoding(head):
    """Encoding and number of bytes to skip (the BOM) for a file that starts with `head`."""
    if head.startswith(codecs.BOM_UTF16_LE):
        return "utf-16-le", 2
    if head.startswith(codecs.BOM_UTF16_BE):
        return "utf-16-be", 2
    if head.startswith(codecs.BOM_UTF8):
        return "utf-8", 3
    if _looks_like_utf16_le(head):
        return "utf-16-le", 0
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start < len(head) - 4:  # a character cut off at the end of the sample does not count
            return "cp1252", 0
    return "utf-8", 0


def iter_entries(path, replica=""):
    """Read an ERRORLOG file entry by entry, without loading the whole file.

    Saved grids (sp_readerrorlog, Log File Viewer) are small and need the csv
    module, so those are read in one go.
    """
    with open(path, "rb") as raw:
        head = raw.read(SNIFF_BYTES)
        encoding, skip = _choose_encoding(head)
        sample = head[skip:].decode(encoding, errors="replace")
        if looks_like_readerrorlog(sample):
            raw.seek(skip)
            text = raw.read().decode(encoding, errors="replace")
            for entry in parse_readerrorlog(text, source=str(path), replica=replica):
                yield entry
            return
        raw.seek(skip)
        with io.TextIOWrapper(raw, encoding=encoding, errors="replace", newline=None) as lines:
            for entry in iter_line_entries(lines, source=str(path), replica=replica):
                yield entry


def read_entries(path, replica=""):
    """Read an ERRORLOG file (or saved sp_readerrorlog output) from disk.

    `replica` is a free label (server name) stored on every entry, so entries
    from several servers can be told apart after they are merged.
    """
    return list(iter_entries(path, replica))
