"""Command line entry point."""
import argparse
import sys

from . import __version__
from .classify import classify
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
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


def main(argv=None, out=None):
    out = out or sys.stdout
    args = build_parser().parse_args(argv)
    entries = []
    for path in args.files:
        entries.extend(read_entries(path))
    floor = severity_rank(args.min_severity)
    findings = [f for f in classify(entries) if severity_rank(f.severity) >= floor]
    render = render_json if args.json else render_text
    out.write(render(entries, findings, args.files))
    return 0
