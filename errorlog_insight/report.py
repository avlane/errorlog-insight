"""Plain-text and JSON reports."""
import collections
import json

from .classify import LABELS
from .model import severity_rank

ADVICE_LIMIT = 10


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


def render_text(entries, findings, files=()):
    lines = ["errorlog-insight report", ""]
    for name in files:
        lines.append("File:     %s" % name)
    lines.append("Period:   %s" % _span(entries))
    lines.append("Entries:  %d" % len(entries))
    lines.append("Findings: %d" % len(findings))
    lines.append("")
    if not findings:
        lines.append("Nothing recognised.")
        return "\n".join(lines) + "\n"

    lines.append("Findings by type")
    for code, items in group_findings(findings):
        worst = max(items, key=lambda f: severity_rank(f.severity)).severity
        lines.append("  %-7s %-24s x%-4d worst: %s" % (code, LABELS.get(code, code), len(items), worst))
    lines.append("")

    lines.append("Most severe")
    ranked = sorted(findings, key=lambda f: (-severity_rank(f.severity), f.entry.timestamp))
    for f in ranked[:ADVICE_LIMIT]:
        lines.append("  [%s] %s  %s" % (f.severity.upper(), f.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"), f.title))
        if f.advice:
            lines.append("      -> %s" % f.advice)
    if len(ranked) > ADVICE_LIMIT:
        lines.append("  ... and %d more" % (len(ranked) - ADVICE_LIMIT))
    return "\n".join(lines) + "\n"


def _iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % (ts.microsecond // 1000)


def finding_to_dict(f):
    return {
        "timestamp": _iso(f.entry.timestamp),
        "process": f.entry.process,
        "source": f.entry.source,
        "line": f.entry.lineno,
        "severity": f.severity,
        "category": f.category,
        "code": f.code,
        "title": f.title,
        "details": f.details,
        "advice": f.advice,
    }


def render_json(entries, findings, files=()):
    first = min((e.timestamp for e in entries), default=None)
    last = max((e.timestamp for e in entries), default=None)
    doc = {
        "files": list(files),
        "entries": len(entries),
        "period": {"first": _iso(first) if first else None, "last": _iso(last) if last else None},
        "findings": [finding_to_dict(f) for f in findings],
    }
    return json.dumps(doc, indent=2) + "\n"
