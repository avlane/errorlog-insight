"""The JSON report. The format is described in docs/json-format.md."""
import json

from .. import __version__
from ..summaries import io_summary, login_summary
from .common import iso, ranked_clusters

SCHEMA_VERSION = 1  # bumped when a field is removed or changes meaning; new fields do not bump it


def finding_to_dict(f):
    return {
        "timestamp": iso(f.entry.timestamp),
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
        "id": c.id,
        "severity_guess": c.severity_guess,
        "template": c.template,
        "count": c.count,
        "first_seen": iso(c.first_seen),
        "last_seen": iso(c.last_seen),
        "processes": sorted(c.processes),
        "variants": c.variants,
        "sample": c.sample.first_line,
    }


def burst_to_dict(b):
    return {"key": b.key, "label": b.label, "start": iso(b.start), "end": iso(b.end), "count": b.count,
            "peak": b.peak, "baseline": b.baseline}


def insight_to_dict(i):
    return {
        "code": i.code,
        "title": i.title,
        "severity": i.severity,
        "confidence": i.confidence,
        "start": iso(i.start),
        "end": iso(i.end),
        "advice": i.advice,
        "evidence": [{"timestamp": iso(f.entry.timestamp), "replica": f.entry.replica, "line": f.entry.lineno,
                      "code": f.code, "title": f.title} for f in i.evidence],
    }


def incident_to_dict(inc):
    out = {k: v for k, v in inc.items() if k != "findings"}  # the findings are already in the findings list
    out.update(start=iso(inc["start"]), end=iso(inc["end"]),
               precursors=[dict(p, time=iso(p["time"])) for p in inc["precursors"]])
    return out


def render_json(entries, findings, files=(), unknown=(), top=10, bursts=(), timeline=False, incidents=(),
                insights=(), servers=(), comparison=None):
    # the findings list is already in time order, so the JSON needs no separate timeline
    first = min((e.timestamp for e in entries), default=None)
    last = max((e.timestamp for e in entries), default=None)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "errorlog-insight", "version": __version__},
        "files": list(files),
        "entries": len(entries),
        "period": {"first": iso(first) if first else None, "last": iso(last) if last else None},
        "findings": [finding_to_dict(f) for f in findings],
        "bursts": [burst_to_dict(b) for b in bursts],
        "incidents": [incident_to_dict(i) for i in incidents],
        "insights": [insight_to_dict(i) for i in insights],
        "comparison": None if comparison is None else {
            "baseline": comparison["baseline"],
            "templates_compared": comparison["templates_compared"],
            "new_codes": comparison["new_codes"],
            "increased": comparison["increased"],
            "new_templates": [cluster_to_dict(c) for c in comparison["new_templates"]],
            "known_templates": comparison["known_templates"],
        },
        "servers": [dict(info, started=iso(info["started"])) for info in servers],
        "summaries": {
            "io": [dict(r, first=iso(r["first"]), last=iso(r["last"])) for r in io_summary(findings)],
            "logins": [dict({k: v for k, v in r.items() if k != "findings"}, first=iso(r["first"]), last=iso(r["last"]))
                       for r in login_summary(findings)],
        },
        "unrecognised": [cluster_to_dict(c) for c in ranked_clusters(unknown)[:top]],
    }
    return json.dumps(doc, indent=2) + "\n"
