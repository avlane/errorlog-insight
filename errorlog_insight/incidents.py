"""Group availability group events from one or more servers into failover incidents.

Role changes arrive as a burst of messages on every replica. Events that follow
each other within `gap` seconds belong to one incident. With the logs of both
sides the incident also says which replica gave up the primary role, which
took it, and how long no replica held it.
"""
from datetime import timedelta

from .timeline import merge_findings

INCIDENT_CODES = ("1480", "19406", "ag-transition", "41142")
INCIDENT_GAP = timedelta(seconds=90)

# Findings that often come shortly before a failover and hint at why it happened.
PRECURSOR_CODES = ("17883", "17884", "19407", "19421", "41005", "35206", "35201", "1479", "701", "17890")
LOOKBACK = timedelta(minutes=5)


def _label(finding):
    return finding.entry.replica or finding.entry.source or "unknown"


def find_incidents(findings, gap=INCIDENT_GAP, lookback=LOOKBACK):
    """Return a list of incident dicts, oldest first.

    `precursors` lists the suspicious findings (from any server) in the
    `lookback` period before the first event, and `likely_cause` is a one-line
    reading of them.
    """
    events = [f for f in merge_findings(findings) if f.code in INCIDENT_CODES]
    groups = []
    for f in events:
        if groups and f.entry.timestamp - groups[-1][-1].entry.timestamp <= gap:
            groups[-1].append(f)
        else:
            groups.append([f])
    precursors = [f for f in merge_findings(findings) if f.code in PRECURSOR_CODES]
    return [_describe(group, precursors, lookback) for group in groups]


def _describe(group, precursors, lookback):
    ags = sorted({f.details["ag"] for f in group if "ag" in f.details})
    databases = sorted({f.details["database"] for f in group if f.code == "1480"})
    replicas = sorted({_label(f) for f in group})
    old_primary = new_primary = None
    left_at = became_at = None
    for f in group:
        if f.code != "1480":
            continue
        if f.details["old_role"] == "PRIMARY" and left_at is None:
            old_primary, left_at = _label(f), f.entry.timestamp
        if f.details["new_role"] == "PRIMARY" and became_at is None:
            new_primary, became_at = _label(f), f.entry.timestamp
    failed = any(f.code == "41142" for f in group)
    failover = old_primary is not None or new_primary is not None
    unplanned = any(
        (f.code == "1480" and not f.details["planned"]) or (f.code == "19406" and not f.details["user_initiated"])
        for f in group)
    if failed:
        kind = "failed failover"
    elif failover:
        kind = "unplanned failover" if unplanned else "planned failover"
    elif any(f.code == "1480" and f.details["new_role"] == "SECONDARY" for f in group):
        kind = "replica rejoined"
    else:
        kind = "role activity"
    gap_seconds = None
    if left_at is not None and became_at is not None:
        gap_seconds = round((became_at - left_at).total_seconds(), 3)
    start = group[0].entry.timestamp
    before = [f for f in precursors if start - lookback <= f.entry.timestamp <= group[-1].entry.timestamp]
    return {
        "kind": kind,
        "start": group[0].entry.timestamp,
        "end": group[-1].entry.timestamp,
        "ags": ags,
        "databases": databases,
        "replicas": replicas,
        "old_primary": old_primary,
        "new_primary": new_primary,
        "no_primary_seconds": gap_seconds,
        "clock_skew_suspected": gap_seconds is not None and gap_seconds < 0,
        "events": len(group),
        "precursors": [{"code": f.code, "replica": _label(f), "time": f.entry.timestamp, "title": f.title}
                       for f in before],
        "likely_cause": _likely_cause(kind, {f.code for f in before}),
    }


def _likely_cause(kind, codes):
    """A one-line reading of the precursor codes. None when there is nothing to say."""
    if kind == "planned failover":
        return "requested by a person or a script"
    if "41005" in codes:
        return "the cluster lost quorum"
    if codes & {"19407", "19421"}:
        if "17883" in codes:
            return "a non-yielding scheduler kept SQL Server from renewing its lease with the cluster"
        return "the lease with the cluster expired (look for a stalled host or network loss to the cluster)"
    if codes & {"35206", "35201", "1479"}:
        return "the replicas lost contact with each other"
    if codes & {"701", "17890", "17884"}:
        return "memory or worker pressure on the instance"
    return None
