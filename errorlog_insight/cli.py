"""Command line entry point."""
import argparse
import os
import sys

from . import __version__
from .bursts import find_bursts
from .classify import classify, unclassified
from .config import ConfigError, load_settings
from .htmlreport import render_html
from .incidents import find_incidents
from .reader import read_entries
from .timefilter import in_window, parse_when
from .timeline import apply_offset, merge_entries, merge_findings, parse_offset, parse_source
from .model import SEVERITIES, severity_rank
from .report import render_json, render_text


FORMATS = ("text", "json", "html")
EXTENSION_FORMATS = {".json": "json", ".html": "html", ".htm": "html"}
RENDERERS = {"text": render_text, "json": render_json, "html": render_html}


def choose_format(args):
    """--format wins; otherwise the extension of -o decides; otherwise text."""
    if args.format:
        return args.format
    if args.output:
        return EXTENSION_FORMATS.get(os.path.splitext(args.output)[1].lower(), "text")
    return "text"


def build_parser():
    p = argparse.ArgumentParser(
        prog="errorlog-insight",
        description="Summarise SQL Server ERRORLOG files.",
    )
    p.add_argument("files", nargs="+", metavar="[LABEL=]FILE",
                   help="ERRORLOG files (UTF-16 LE) or saved sp_readerrorlog output; "
                        "a LABEL (for example SQLDR02=ERRORLOG.1) names the server in merged output")
    p.add_argument("--format", choices=FORMATS, default=None,
                   help="report format (default: text, or guessed from the -o file extension)")
    p.add_argument("--json", dest="format", action="store_const", const="json", help="same as --format json")
    p.add_argument("--html", dest="format", action="store_const", const="html", help="same as --format html")
    p.add_argument("--min-severity", choices=SEVERITIES, default=None,
                   help="hide findings below this severity (default: info)")
    p.add_argument("--top", type=int, default=None, metavar="N",
                   help="show the N biggest groups of unrecognised messages (default: 10)")
    p.add_argument("--burst-min", type=int, default=None, metavar="N",
                   help="fewest events in one bucket that can count as a burst (default: 5)")
    p.add_argument("--burst-factor", type=float, default=None, metavar="X",
                   help="how many times the recent average a bucket must reach (default: 3)")
    p.add_argument("--since", metavar="WHEN",
                   help="ignore entries before this time, for example 2024-05-14 or 2024-05-14T01:30")
    p.add_argument("--until", metavar="WHEN", help="ignore entries from this time on (exclusive)")
    p.add_argument("--offset", action="append", default=[], metavar="LABEL=+2s",
                   help="shift one server's timestamps to correct clock skew, for example SQLDR02=-1.5s "
                        "(units: ms, s, m, h; repeatable)")
    p.add_argument("--timeline", action="store_true",
                   help="list the findings of all files in one time-ordered timeline")
    p.add_argument("--config", metavar="FILE",
                   help="read defaults for --top, --min-severity and the burst options from a TOML or INI file")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write the report to FILE (UTF-8) instead of standard output")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


def _utf8_stdout():
    """Windows consoles default to a legacy code page; log text (logins, paths) is not always ASCII."""
    stream = sys.stdout
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")
    return stream


def main(argv=None, out=None):
    args = build_parser().parse_args(argv)
    if out is None and not args.output:
        out = _utf8_stdout()
    try:
        settings = load_settings(args.config, args.top, args.min_severity, args.burst_min, args.burst_factor)
    except ConfigError as exc:
        sys.stderr.write("errorlog-insight: %s\n" % exc)
        return 2
    try:
        offsets = dict(parse_offset(o) for o in args.offset)
    except ValueError as exc:
        sys.stderr.write("errorlog-insight: %s\n" % exc)
        return 2
    try:
        since = parse_when(args.since) if args.since else None
        until = parse_when(args.until) if args.until else None
        in_window([], since, until)  # validates the pair
    except ValueError as exc:
        sys.stderr.write("errorlog-insight: %s\n" % exc)
        return 2
    per_file = []
    all_findings, unknown = [], []
    paths = []
    for arg in args.files:
        label, path = parse_source(arg)
        paths.append(path)
        entries = read_entries(path, replica=label)
        if label in offsets:
            apply_offset(entries, offsets.pop(label))
        entries = in_window(entries, since, until)
        found = classify(entries)
        per_file.append(entries)
        all_findings.extend(found)
        unknown.extend(unclassified(entries, found))
    if offsets:
        sys.stderr.write("errorlog-insight: --offset names no input file: %s\n" % ", ".join(sorted(offsets)))
        return 2
    entries = merge_entries(*per_file)
    floor = severity_rank(settings.min_severity)
    findings = merge_findings([f for f in all_findings if severity_rank(f.severity) >= floor])
    bursts = find_bursts(findings, settings.bursts)
    incidents = find_incidents(all_findings)  # planned failovers are info, so use the unfiltered findings
    render = RENDERERS[choose_format(args)]
    report = render(entries, findings, paths, unknown=unknown, top=settings.top, bursts=bursts,
                    timeline=args.timeline, incidents=incidents)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(report)
    else:
        out.write(report)
    return 0


def console_main():
    """Entry point for the installed errorlog-insight script."""
    sys.exit(main())
