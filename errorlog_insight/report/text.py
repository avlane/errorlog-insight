"""The plain-text report."""
from ..classify import LABELS
from ..model import severity_rank
from ..serverinfo import describe
from ..summaries import io_summary, login_summary
from ..timeline import timeline_lines
from .common import group_findings, ranked_clusters

ADVICE_LIMIT = 10


def _span(entries):
    if not entries:
        return "no entries"
    first = min(e.timestamp for e in entries)
    last = max(e.timestamp for e in entries)
    return "%s .. %s" % (first.strftime("%Y-%m-%d %H:%M:%S"), last.strftime("%Y-%m-%d %H:%M:%S"))


def render_text(entries, findings, files=(), unknown=(), top=10, bursts=(), timeline=False, incidents=(),
                insights=(), servers=(), comparison=None, clusters=None):
    lines = ["errorlog-insight report", ""]
    for name in files:
        lines.append("File:     %s" % name)
    lines.append("Period:   %s" % _span(entries))
    lines.append("Entries:  %d" % len(entries))
    lines.append("Findings: %d" % len(findings))
    lines.append("")
    if servers:
        lines.append("Servers (one line per start in the logs)")
        for info in servers:
            lines.append("  %s  %s  %s" % (info["started"].strftime("%Y-%m-%d %H:%M:%S"), info["server"], describe(info)))
        lines.append("")
    if not findings:
        lines.append("Nothing recognised.")
        lines.extend(_comparison_lines(comparison))
        lines.extend(_incident_lines(incidents))
        lines.extend(_burst_lines(bursts))
        lines.extend(_unrecognised_lines(unknown, top, clusters))
        return "\n".join(lines) + "\n"

    lines.extend(_insight_lines(insights))
    lines.extend(_comparison_lines(comparison))
    lines.append("Findings by type")
    groups = group_findings(findings)
    code_width = max(len(code) for code, _ in groups)
    label_width = max(len(LABELS.get(code, code)) for code, _ in groups)
    for code, items in groups:
        worst = max(items, key=lambda f: severity_rank(f.severity)).severity
        lines.append("  %-*s  %-*s  x%-4d worst: %s" % (code_width, code, label_width, LABELS.get(code, code),
                                                      len(items), worst))
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
    lines.extend(_unrecognised_lines(unknown, top, clusters))
    return "\n".join(lines) + "\n"


def _comparison_lines(comparison):
    if comparison is None:
        return []
    src = comparison["baseline"]
    since = " (%s to %s)" % (src["first"][:10], src["last"][:10]) if src.get("first") else ""
    lines = ["New since the baseline%s" % since]
    if not comparison["templates_compared"]:
        lines.append("  The baseline was made with different message grouping rules, so unrecognised messages "
                     "are not compared; save a new baseline.")
    elif not (comparison["new_codes"] or comparison["increased"] or comparison["new_templates"]):
        lines.append("  Nothing new: %d known message group(s)." % comparison["known_templates"])
    for c in comparison["new_codes"]:
        lines.append("  new finding type: %s (%s) x%d" % (c["code"], c["label"], c["count"]))
    for c in comparison["increased"]:
        lines.append("  more than before: %s (%s) %d -> %d" % (c["code"], c["label"], c["before"], c["now"]))
    for t in comparison["new_templates"]:
        guess = " [%s?]" % t.severity_guess if t.severity_guess != "info" else ""
        lines.append("  new message x%d%s %s" % (t.count, guess, t.template))
    lines.append("")
    return lines


def _insight_lines(insights):
    if not insights:
        return []
    lines = ["Insights (most important first)"]
    for i in insights:
        span = i.start.strftime("%Y-%m-%d %H:%M:%S")
        if i.end != i.start:
            span += " .. " + (i.end.strftime("%H:%M:%S") if i.end.date() == i.start.date()
                              else i.end.strftime("%Y-%m-%d %H:%M:%S"))
        lines.append("  [%s, %s confidence] %s" % (i.severity.upper(), i.confidence, i.title))
        lines.append("      %d finding(s), %s" % (len(i.evidence), span))
        if i.advice:
            lines.append("      -> %s" % i.advice)
    lines.append("")
    return lines


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
        name = b.label or LABELS.get(b.key, b.key)
        lines.append("  %-7s %-24s x%-4d %s .. %s  (baseline %.2f per bucket)" % (
            b.key.replace("template:", ""), name, b.count, b.start.strftime("%Y-%m-%d %H:%M"),
            b.end.strftime("%H:%M"), b.baseline))
    return lines


def _unrecognised_lines(unknown, top, clusters=None):
    clusters = ranked_clusters(unknown, clusters)
    if not clusters:
        return []
    lines = ["", "Unrecognised messages (%d entries, %d templates)" % (len(unknown), len(clusters))]
    for c in clusters[:top]:
        guess = " [%s?]" % c.severity_guess if c.severity_guess != "info" else ""
        lines.append("  x%-4d%s %s" % (c.count, guess, c.template))
        seen = c.first_seen.strftime("%Y-%m-%d %H:%M:%S")
        if c.last_seen != c.first_seen:
            seen += " .. " + (c.last_seen.strftime("%H:%M:%S") if c.last_seen.date() == c.first_seen.date()
                              else c.last_seen.strftime("%Y-%m-%d %H:%M:%S"))
        more = ", %d variants" % c.variants if c.variants > 1 else ""
        lines.append("        %s  %s%s  [%s]" % (seen, ", ".join(sorted(c.processes)), more, c.id))
    if len(clusters) > top:
        lines.append("  ... and %d more templates" % (len(clusters) - top))
    return lines
