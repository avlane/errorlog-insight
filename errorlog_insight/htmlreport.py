"""Self-contained HTML report: one file, inline CSS, no scripts, no network."""
import html
import json

from .classify import LABELS
from .cluster import cluster_entries
from .model import severity_rank
from .report import group_findings
from .summaries import io_summary, login_summary
from .timeline import default_label

CSS = """
:root { --bg: #ffffff; --fg: #1d2330; --muted: #5d6677; --line: #d9dde5; --card: #f6f7f9;
        --info: #3b6ea5; --warning: #a86a00; --error: #b3261e; --critical: #7d0f2b; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #14171d; --fg: #e4e7ee; --muted: #9aa3b5; --line: #2c3340; --card: #1b2029;
          --info: #7fb0e6; --warning: #e0a53a; --error: #f08a82; --critical: #ff6b8b; }
}
body { background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 62rem; padding: 1.5rem 1rem 3rem; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
h2 { font-size: 1.15rem; margin: 2rem 0 .5rem; border-bottom: 1px solid var(--line); padding-bottom: .25rem; }
.muted { color: var(--muted); }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: .3rem .6rem; border-bottom: 1px solid var(--line); vertical-align: top; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
details { background: var(--card); border: 1px solid var(--line); border-left-width: 4px; border-radius: 4px; margin: .35rem 0; padding: .3rem .7rem; }
details.sev-info { border-left-color: var(--info); }
details.sev-warning { border-left-color: var(--warning); }
details.sev-error { border-left-color: var(--error); }
details.sev-critical { border-left-color: var(--critical); }
summary { cursor: pointer; }
.badge { font-size: .75rem; font-weight: 600; text-transform: uppercase; letter-spacing: .03em; }
.badge.sev-info { color: var(--info); } .badge.sev-warning { color: var(--warning); }
.badge.sev-error { color: var(--error); } .badge.sev-critical { color: var(--critical); }
dl.kv { display: grid; grid-template-columns: max-content 1fr; gap: .15rem 1rem; margin: .5rem 0; }
dl.kv dt { color: var(--muted); } dl.kv dd { margin: 0; overflow-wrap: anywhere; }
code { font: 13px ui-monospace, monospace; }
@media (max-width: 40rem) { dl.kv { grid-template-columns: 1fr; } }
"""


def esc(value):
    return html.escape("" if value is None else str(value))


def _time(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def _value(v):
    if isinstance(v, (dict, list)):
        return "<code>%s</code>" % esc(json.dumps(v, ensure_ascii=False))
    return esc(v)


def _finding_html(f):
    parts = ['<details class="sev-%s">' % esc(f.severity)]
    label = f.entry.replica or default_label(f.entry.source) if f.entry.source else f.entry.replica
    parts.append('<summary><span class="badge sev-%s">%s</span> <span class="muted">%s %s</span> %s</summary>' % (
        esc(f.severity), esc(f.severity), esc(_time(f.entry.timestamp)), esc(label), esc(f.title)))
    if f.advice:
        parts.append("<p>%s</p>" % esc(f.advice))
    rows = [("code", f.code), ("process", f.entry.process)] + [(k, v) for k, v in f.details.items() if v not in (None, "", [])]
    parts.append('<dl class="kv">%s</dl>' % "".join("<dt>%s</dt><dd>%s</dd>" % (esc(k), _value(v)) for k, v in rows))
    parts.append("</details>")
    return "".join(parts)


def render_html(entries, findings, files=(), unknown=(), top=10, bursts=(), timeline=False, incidents=()):
    out = ['<!doctype html>', '<html lang="en">', '<head>', '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           "<title>errorlog-insight report</title>", "<style>%s</style>" % CSS, "</head>", "<body>",
           "<h1>errorlog-insight report</h1>"]
    if entries:
        first = min(e.timestamp for e in entries)
        last = max(e.timestamp for e in entries)
        period = "%s to %s" % (_time(first), _time(last))
    else:
        period = "no entries"
    out.append('<p class="muted">%s &middot; %d entries &middot; %d findings</p>' % (esc(period), len(entries), len(findings)))
    if files:
        out.append('<p class="muted">%s</p>' % ", ".join(esc(f) for f in files))

    if findings:
        out.append("<h2>Findings by type</h2><table><tr><th>Code</th><th>Type</th><th>Count</th><th>Worst</th></tr>")
        for code, items in group_findings(findings):
            worst = max(items, key=lambda f: severity_rank(f.severity)).severity
            out.append('<tr><td>%s</td><td>%s</td><td class="num">%d</td><td><span class="badge sev-%s">%s</span></td></tr>' % (
                esc(code), esc(LABELS.get(code, code)), len(items), esc(worst), esc(worst)))
        out.append("</table>")
        out.append("<h2>Findings</h2>")
        ranked = sorted(findings, key=lambda f: (-severity_rank(f.severity), f.entry.timestamp))
        out.extend(_finding_html(f) for f in ranked)
    else:
        out.append("<p>Nothing recognised.</p>")

    if incidents:
        out.append("<h2>Availability group incidents</h2><table><tr><th>When</th><th>Kind</th><th>AG</th><th>Old primary</th><th>New primary</th><th>No primary</th><th>Databases</th><th>Likely cause</th></tr>")
        for inc in incidents:
            gap = "" if inc["no_primary_seconds"] is None else "%.1f s" % inc["no_primary_seconds"]
            out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                esc(_time(inc["start"])), esc(inc["kind"]), esc(", ".join(inc["ags"])), esc(inc["old_primary"]),
                esc(inc["new_primary"]), esc(gap), esc(", ".join(inc["databases"])), esc(inc["likely_cause"])))
        out.append("</table>")

    io_rows = io_summary(findings)
    if io_rows:
        out.append("<h2>Slow I/O by file</h2><table><tr><th>File</th><th>Database</th><th>Worst</th><th>Requests</th><th>Episodes</th><th>First</th><th>Last</th></tr>")
        for r in io_rows:
            out.append('<tr><td><code>%s</code></td><td>%s</td><td class="num">%d s</td><td class="num">%d</td><td class="num">%d</td><td>%s</td><td>%s</td></tr>' % (
                esc(r["file"]), esc(r["database"]), r["max_seconds"], r["requests"], r["episodes"],
                esc(_time(r["first"])), esc(_time(r["last"]))))
        out.append("</table>")

    login_rows = login_summary(findings)
    if login_rows:
        out.append("<h2>Login failures by client</h2><table><tr><th>Client</th><th>Failures</th><th>Pattern</th><th>Logins</th><th>First</th><th>Last</th></tr>")
        for r in login_rows:
            out.append('<tr><td>%s</td><td class="num">%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                esc(r["client"]), r["failures"], esc(r["pattern"]), esc(", ".join(r["users"])),
                esc(_time(r["first"])), esc(_time(r["last"]))))
        out.append("</table>")

    if bursts:
        out.append("<h2>Bursts</h2><table><tr><th>Code</th><th>Type</th><th>Start</th><th>End</th><th>Count</th><th>Baseline</th></tr>")
        for b in bursts:
            out.append('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="num">%d</td><td class="num">%.2f</td></tr>' % (
                esc(b.key), esc(LABELS.get(b.key, b.key)), esc(_time(b.start)), esc(_time(b.end)), b.count, b.baseline))
        out.append("</table>")

    clusters = cluster_entries(unknown)
    if clusters:
        out.append("<h2>Unrecognised messages</h2><table><tr><th>Count</th><th>Template</th><th>First seen</th></tr>")
        for c in clusters[:top]:
            out.append('<tr><td class="num">%d</td><td><code>%s</code></td><td>%s</td></tr>' % (c.count, esc(c.template), esc(_time(c.first_seen))))
        out.append("</table>")
        if len(clusters) > top:
            out.append('<p class="muted">%d more templates not shown.</p>' % (len(clusters) - top))
    out.append("</body></html>")
    return "\n".join(out) + "\n"
