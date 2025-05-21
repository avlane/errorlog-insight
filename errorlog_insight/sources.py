"""Turn command line file arguments into (label, path) pairs and remove duplicates.

* Wildcards are expanded here because Windows shells do not: ``ERRORLOG*`` finds
  ERRORLOG, ERRORLOG.1, ERRORLOG.2, ... in natural order.
* ``LABEL=pattern`` gives every matching file the same label, which is how the
  archives of one server are told apart from another server's logs.
* The same entry can reach us twice (a copy of the log next to the original, or
  two rotated files that overlap); duplicates are dropped.
"""
import glob
import re

from .timeline import default_label, split_source

WILDCARD_RE = re.compile(r"[*?\[]")


def natural_key(path):
    """Sort ERRORLOG.2 before ERRORLOG.10."""
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", path)]


def expand_sources(args):
    """Return [(label, path)]. A pattern that matches nothing is kept as is so the open() error names it."""
    out = []
    for arg in args:
        label, path = split_source(arg)
        matches = sorted(glob.glob(path), key=natural_key) if WILDCARD_RE.search(path) else []
        for match in matches or [path]:
            out.append((label or default_label(match), match))
    return out


def drop_duplicate_entries(entries):
    """Entries with the same server, time, process and text appear once, first occurrence kept."""
    seen = set()
    out = []
    for e in entries:
        key = (e.replica, e.timestamp, e.process, e.text)
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out


def drop_duplicate_findings(findings):
    seen = set()
    out = []
    for f in findings:
        e = f.entry
        key = (e.replica, e.timestamp, e.process, f.code, f.title)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
