"""Command line entry point."""
import argparse
import sys

from . import __version__
from .bursts import BurstConfig, find_bursts
from .classify import classify, unclassified
from .reader import read_entries
from .model import SEVERITIES, severity_rank
from .report import render_json, render_text


def build_parser():
    p = argparse.ArgumentParser(
        prog="errorlog-insight",
        description="Summarise SQL Server ERRORLOG files.",
    )
    p.add_argument("files", nargs="+", help="ERRORLOG files (UTF-16 LE) or saved sp_readerrorlog output")
    p.add_argument("--json", action="store_true", help="write JSON instead of text")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info",
                   help="hide findings below this severity (default: info)")
    p.add_argument("--top", type=int, default=10, metavar="N",
                   help="show the N biggest groups of unrecognised messages (default: 10)")
    p.add_argument("--burst-min", type=int, default=5, metavar="N",
                   help="fewest events in one bucket that can count as a burst (default: 5)")
    p.add_argument("--burst-factor", type=float, default=3.0, metavar="X",
                   help="how many times the recent average a bucket must reach (default: 3)")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


def main(argv=None, out=None):
    out = out or sys.stdout
    args = build_parser().parse_args(argv)
    entries = []
    for path in args.files:
        entries.extend(read_entries(path))
    floor = severity_rank(args.min_severity)
    all_findings = classify(entries)
    findings = [f for f in all_findings if severity_rank(f.severity) >= floor]
    unknown = unclassified(entries, all_findings)
    config = BurstConfig(min_count=args.burst_min, factor=args.burst_factor)
    bursts = find_bursts(findings, config)
    render = render_json if args.json else render_text
    out.write(render(entries, findings, args.files, unknown=unknown, top=args.top, bursts=bursts))
    return 0


def console_main():
    """Entry point for the installed errorlog-insight script."""
    sys.exit(main())
