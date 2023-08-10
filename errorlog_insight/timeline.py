"""Merge entries and findings from several files into one timeline."""
import os
import re

SOURCE_RE = re.compile(r"^(?P<label>[A-Za-z0-9_.-]+)=(?P<path>.+)$")


def parse_source(arg):
    """Split 'SQLDR02=logs/dr02/ERRORLOG' into (label, path); a plain path gets its file name as label.

    Paths with a drive letter (C:\\logs) have a colon, not an equals sign, so they are never mistaken
    for a label. A path that really contains '=' can be written as ./name=x.
    """
    m = SOURCE_RE.match(arg)
    if m and not os.path.exists(arg):
        return m.group("label"), m.group("path")
    return default_label(arg), arg


def default_label(path):
    """File name without directory or extension: ERRORLOG.1 -> ERRORLOG, SQLDR02.log -> SQLDR02."""
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1]  # also splits Windows paths on other systems
    return os.path.splitext(name)[0]


def merge_entries(*lists):
    """All entries of all lists in time order. Ties keep file order, then line order."""
    tagged = []
    for file_no, entries in enumerate(lists):
        for entry in entries:
            tagged.append((entry.timestamp, file_no, entry.lineno, entry))
    tagged.sort(key=lambda t: t[:3])
    return [t[3] for t in tagged]


def merge_findings(findings):
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
