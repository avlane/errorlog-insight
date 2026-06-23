"""Merge entries and findings from several files into one timeline."""
import os
import re
from datetime import timedelta

from .model import Entry, Finding

SOURCE_RE = re.compile(r"^(?P<label>[A-Za-z0-9_.-]+)=(?P<path>.+)$")


def split_source(arg):
    """Split 'SQLDR02=logs/dr02/ERRORLOG' into ('SQLDR02', path). The label is None when there is none.

    Paths with a drive letter (C:\\logs) have a colon, not an equals sign, so they are never mistaken
    for a label, and a file that really exists is always taken as a path.
    """
    m = SOURCE_RE.match(arg)
    if m and not os.path.exists(arg):
        return m.group("label"), m.group("path")
    return None, arg


def parse_source(arg):
    """(label, path) for one file argument; a plain path gets its file name as label."""
    label, path = split_source(arg)
    return label or default_label(path), path


def default_label(path):
    """File name without directory or extension: ERRORLOG.1 -> ERRORLOG, SQLDR02.log -> SQLDR02."""
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1]  # also splits Windows paths on other systems
    return os.path.splitext(name)[0]


def merge_entries(*lists: list[Entry]) -> list[Entry]:
    """All entries of all lists in time order. Ties keep file order, then line order."""
    tagged = []
    for file_no, entries in enumerate(lists):
        for entry in entries:
            tagged.append((entry.timestamp, file_no, entry.lineno, entry))
    tagged.sort(key=lambda t: t[:3])
    return [t[3] for t in tagged]


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Findings from any number of files in time order."""
    order = {}
    for f in findings:
        order.setdefault(f.entry.replica or f.entry.source, len(order))
    return sorted(findings, key=lambda f: (f.entry.timestamp, order[f.entry.replica or f.entry.source],
                                           f.entry.lineno))


def timeline_lines(findings, min_rank=0):
    """One line per finding: time, replica, severity, title."""
    from .model import severity_rank

    out = []
    for f in merge_findings(findings):
        if severity_rank(f.severity) < min_rank:
            continue
        label = f.entry.replica or default_label(f.entry.source)
        out.append("%s  %-12s %-8s %s" % (f.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-4],
                                           label, f.severity, f.title))
    return out


OFFSET_RE = re.compile(r"^(?P<label>[A-Za-z0-9_.-]+)=(?P<sign>[+-])(?P<value>\d+(?:\.\d+)?)(?P<unit>ms|s|m|h)?$")
UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, None: 1.0}


def parse_offset(text):
    """Parse 'SQLDR02=+2.5s' into ('SQLDR02', timedelta). Units: ms, s (default), m, h."""
    m = OFFSET_RE.match(text)
    if not m:
        raise ValueError("offset must look like LABEL=+2s or LABEL=-1.5m, got %r" % text)
    seconds = float(m.group("value")) * UNITS[m.group("unit")]
    if m.group("sign") == "-":
        seconds = -seconds
    return m.group("label"), timedelta(seconds=seconds)


def apply_offset(entries, delta):
    """Shift every entry by `delta` (positive moves the entries later). Used to correct clock skew."""
    for entry in entries:
        entry.timestamp += delta
    return entries
