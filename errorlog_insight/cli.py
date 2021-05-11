"""Command line entry point."""
import argparse
import sys

from . import __version__
from .classify import classify
from .reader import read_entries
from .report import render_text


def build_parser():
    p = argparse.ArgumentParser(
        prog="errorlog-insight",
        description="Summarise SQL Server ERRORLOG files.",
    )
    p.add_argument("files", nargs="+", help="ERRORLOG files (UTF-16 LE) or saved sp_readerrorlog output")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


def main(argv=None, out=None):
    out = out or sys.stdout
    args = build_parser().parse_args(argv)
    entries = []
    for path in args.files:
        entries.extend(read_entries(path))
    findings = classify(entries)
    out.write(render_text(entries, findings, args.files))
    return 0
