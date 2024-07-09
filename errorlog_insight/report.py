"""Plain-text and JSON reports."""
import collections
import json

from . import __version__

from .classify import LABELS
from .cluster import cluster_entries
from .model import severity_rank
from .summaries import io_summary, login_summary
from .timeline import timeline_lines

ADVICE_LIMIT = 10
SCHEMA_VERSION = 1  # bumped when a field is removed or changes meaning; new fields do not bump it


def _span(entries):
    if not entries:
        return "no entries"
    first = min(e.timestamp for e in entries)
    last = max(e.timestamp for e in entries)
    return "%s .. %s" % (first.strftime("%Y-%m-%d %H:%M:%S"), last.strftime("%Y-%m-%d %H:%M:%S"))


def group_findings(findings):
    """Group findings by message code, worst groups first."""
    groups = collections.OrderedDict()
    for f in findings:
        groups.setdefault(f.code, []).append(f)

    def worst(items):
        return max(severity_rank(f.severity) for f in items)

    return sorted(groups.items(), key=lambda kv: (-worst(kv[1]), -len(kv[1]), kv[0]))


def render_text(entries, findings, files=(), unknown=(), top=10, bursts=(), timeline=False, incidents=()):
    lines = ["errorlog-insight report", ""]
    for name in files:
        lines.append("File:     %s" % name)
    lines.append("Period:   %s" % _span(entries))
    lines.append("Entries:  %d" % len(entries))
    lines.append("Findings: %d" % len(findings))
    lines.append("")
    if not findings:
        lines.append("Nothing recognised.")
        lines.extend(_incident_lines(incidents))
        lines.extend(_unrecognised_lines(unknown, top))
        return "\n".join(lines) + "\n"

    lines.append("Findings by type")
    for code, items in group_findings(findings):
        worst = max(items, key=lambda f: severity_rank(f.severity)).severity
        lines.append("  %-7s %-24s x%-4d worst: %s" % (code, LABELS.get(code, code), len(items), worst))
    lines.append("")

    lines.append("Most severe")
    ranked = sorted(findings, key=lambda f: (-severity_rank(f.severity), f.entry.timestamp))
    several = len({f.entry.replica for f in findings}) > 1
    for f in ranked[:ADVICE_LIMIT]:
        where = "[%s] " % f.entry.replica if several and f.entry.replica else ""
        lines.append("  [%s] %s  %s%s" % (f.severity.upper(), f.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"), where, f.title))
        if f.advice:
            lines.append("      -> %s" % f.advice)
    if len(ranked) > ADVICE_LIMIT:
        lines.append("  ... and %d more" % (len(ranked) - ADVICE_LIMIT))
    lines.extend(_incident_lines(incidents))
    lines.extend(_io_lines(findings))
    lines.extend(_login_lines(findings))
    lines.extend(_burst_lines(bursts))
    if timeline:
        lines.extend(["", "Timeline"] + ["  " + t for t in timeline_lines(findings)])
    lines.extend(_unrecognised_lines(unknown, top))
    return "\n".join(lines) + "\n"


def _incident_lines(incidents):
    if not incidents:
        return []
    lines = ["", "Availability group incidents"]
    for inc in incidents:
        when = "%s .. %s" % (inc["start"].strftime("%Y-%m-%d %H:%M:%S"), inc["end"].strftime("%H:%M:%S"))
        move = ""
        if inc["old_primary"] or inc["new_primary"]:
            move = "  %s -> %s" % (inc["old_primary"] or "?", inc["new_primary"] or "?")
        gap = ""
        if inc["no_primary_seconds"] is not None:
            gap = "  no primary for %.1f s" % inc["no_primary_seconds"]
            if inc["clock_skew_suspected"]:
                gap += " (negative: clocks differ, try --offset)"
        lines.append("  %s  %-18s %s%s%s" % (when, inc["kind"], ", ".join(inc["ags"]) or "-", move, gap))
        if inc["databases"]:
            lines.append("      databases: %s" % ", ".join(inc["databases"]))
        if inc["likely_cause"]:
            lines.append("      likely cause: %s" % inc["likely_cause"])
        for p in inc["precursors"][:5]:
            lines.append("      before: %s [%s] %s" % (p["time"].strftime("%H:%M:%S"), p["replica"], p["title"]))
    return lines


def _io_lines(findings):
    rows = io_summary(findings)
    if not rows:
        return []
    lines = ["", "Slow I/O by file"]
    for r in rows:
        lines.append("  %s (%s, %s)  worst %d s, %d requests in %d message(s), %d episode(s), %s .. %s" % (
            r["file"], r["database"], r["file_kind"], r["max_seconds"], r["requests"], r["messages"],
            r["episodes"], r["first"].strftime("%H:%M:%S"), r["last"].strftime("%H:%M:%S")))
    return lines


def _login_lines(findings):
    rows = login_summary(findings)
    if not rows:
        return []
    lines = ["", "Login failures by client"]
    for r in rows:
        who = ", ".join(r["users"][:3]) + (" +%d more" % (len(r["users"]) - 3) if len(r["users"]) > 3 else "")
        lines.append("  %-16s x%-3d %-18s %s" % (r["client"], r["failures"], r["pattern"], who))
    return lines


def _burst_lines(bursts):
    if not bursts:
        return []
    lines = ["", "Bursts (well above the recent rate)"]
    for b in bursts:
        lines.append("  %-7s %-24s x%-4d %s .. %s  (baseline %.2f per bucket)" % (
            b.key, LABELS.get(b.key, b.key), b.count, b.start.strftime("%Y-%m-%d %H:%M"),
            b.end.strftime("%H:%M"), b.baseline))
    return lines


def _unrecognised_lines(unknown, top):
    clusters = cluster_entries(unknown)
    if not clusters:
        return []
    lines = ["", "Unrecognised messages (%d entries, %d templates)" % (len(unknown), len(clusters))]
    for c in clusters[:top]:
        lines.append("  x%-4d %s" % (c.count, c.template))
    if len(clusters) > top:
        lines.append("  ... and %d more templates" % (len(clusters) - top))
    return lines


def _iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % (ts.microsecond // 1000)


def finding_to_dict(f):
    return {
        "timestamp": _iso(f.entry.timestamp),
        "process": f.entry.process,
        "source": f.entry.source,
        "replica": f.entry.replica,
        "line": f.entry.lineno,
        "severity": f.severity,
        "category": f.category,
        "code": f.code,
        "title": f.title,
        "details": f.details,
        "advice": f.advice,
    }


def cluster_to_dict(c):
    return {
        "template": c.template,
        "count": c.count,
        "first_seen": _iso(c.first_seen),
        "last_seen": _iso(c.last_seen),
        "processes": sorted(c.processes),
        "sample": c.sample.first_line,
    }


def burst_to_dict(b):
    return {"key": b.key, "start": _iso(b.start), "end": _iso(b.end), "count": b.count,
            "peak": b.peak, "baseline": b.baseline}


def incident_to_dict(inc):
    return dict(inc, start=_iso(inc["start"]), end=_iso(inc["end"]),
                precursors=[dict(p, time=_iso(p["time"])) for p in inc["precursors"]])


def render_json(entries, findings, files=(), unknown=(), top=10, bursts=(), timeline=False, incidents=()):
    # the findings list is already in time order, so the JSON needs no separate timeline
    first = min((e.timestamp for e in entries), default=None)
    last = max((e.timestamp for e in entries), default=None)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "errorlog-insight", "version": __version__},
        "files": list(files),
        "entries": len(entries),
        "period": {"first": _iso(first) if first else None, "last": _iso(last) if last else None},
        "findings": [finding_to_dict(f) for f in findings],
        "bursts": [burst_to_dict(b) for b in bursts],
        "incidents": [incident_to_dict(i) for i in incidents],
        "summaries": {
            "io": [dict(r, first=_iso(r["first"]), last=_iso(r["last"])) for r in io_summary(findings)],
            "logins": [dict(r, first=_iso(r["first"]), last=_iso(r["last"])) for r in login_summary(findings)],
        },
        "unrecognised": [cluster_to_dict(c) for c in cluster_entries(unknown)[:top]],
    }
    return json.dumps(doc, indent=2) + "\n"
