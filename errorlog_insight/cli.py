"""Command line entry point."""
import argparse
import sys

from . import __version__
from .bursts import find_bursts
from .classify import classify, unclassified
from .config import ConfigError, load_settings
from .htmlreport import render_html
from .reader import read_entries
from .timeline import apply_offset, merge_entries, merge_findings, parse_offset, parse_source
from .model import SEVERITIES, severity_rank
from .report import render_json, render_text


def build_parser():
    p = argparse.ArgumentParser(
        prog="errorlog-insight",
        description="Summarise SQL Server ERRORLOG files.",
    )
    p.add_argument("files", nargs="+", metavar="[LABEL=]FILE",
                   help="ERRORLOG files (UTF-16 LE) or saved sp_readerrorlog output; "
                        "a LABEL (for example SQLDR02=ERRORLOG.1) names the server in merged output")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="write JSON instead of text")
    fmt.add_argument("--html", action="store_true", help="write a self-contained HTML report instead of text")
    p.add_argument("--min-severity", choices=SEVERITIES, default=None,
                   help="hide findings below this severity (default: info)")
    p.add_argument("--top", type=int, default=None, metavar="N",
                   help="show the N biggest groups of unrecognised messages (default: 10)")
    p.add_argument("--burst-min", type=int, default=None, metavar="N",
                   help="fewest events in one bucket that can count as a burst (default: 5)")
    p.add_argument("--burst-factor", type=float, default=None, metavar="X",
                   help="how many times the recent average a bucket must reach (default: 3)")
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
    per_file = []
    all_findings, unknown = [], []
    paths = []
    for arg in args.files:
        label, path = parse_source(arg)
        paths.append(path)
        entries = read_entries(path, replica=label)
        if label in offsets:
            apply_offset(entries, offsets.pop(label))
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
    render = render_json if args.json else render_html if args.html else render_text
    report = render(entries, findings, paths, unknown=unknown, top=settings.top, bursts=bursts,
                    timeline=args.timeline)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(report)
    else:
        out.write(report)
    return 0


def console_main():
    """Entry point for the installed errorlog-insight script."""
    sys.exit(main())
