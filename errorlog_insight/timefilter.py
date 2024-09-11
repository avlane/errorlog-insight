"""--since / --until: keep only the entries in a time window."""
from datetime import datetime

FORMATS = (
    "%Y-%m-%d",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%dT%H:%M:%S",
)


def parse_when(text):
    """Parse 2024-05-14, 2024-05-14 01:30 or 2024-05-14T01:30:15. A bare date means midnight."""
    for fmt in FORMATS:
        try:
            return datetime.strptime(text.strip(), fmt)
        except ValueError:
            continue
    raise ValueError("cannot read %r as a date and time (try 2024-05-14 or 2024-05-14T01:30)" % text)


def in_window(entries, since=None, until=None):
    """Entries with since <= timestamp < until. Either bound may be None."""
    if since is None and until is None:
        return list(entries)
    if since is not None and until is not None and until <= since:
        raise ValueError("--until (%s) is not after --since (%s)" % (until, since))
    return [e for e in entries
            if (since is None or e.timestamp >= since) and (until is None or e.timestamp < until)]
