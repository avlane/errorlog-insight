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


def _label(finding):
    return finding.entry.replica or finding.entry.source or "unknown"


def find_incidents(findings, gap=INCIDENT_GAP):
    """Return a list of incident dicts, oldest first."""
    events = [f for f in merge_findings(findings) if f.code in INCIDENT_CODES]
    groups = []
    for f in events:
        if groups and f.entry.timestamp - groups[-1][-1].entry.timestamp <= gap:
            groups[-1].append(f)
        else:
            groups.append([f])
    return [_describe(group) for group in groups]


def _describe(group):
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
    }
