"""Command line entry point."""
import argparse
import json
import os
import shutil
import sys
from datetime import timedelta

from . import __version__
from .baseline import BaselineError, compare, make_baseline, read_baseline, write_baseline
from .bursts import find_bursts, find_template_bursts
from .cluster import cluster_entries
from .classify import LABELS, classify, unclassified
from .config import ConfigError, load_settings
from .customrules import forget_labels
from .incidents import find_incidents
from .insights import find_insights
from .reader import read_entries
from .redact import Redactor
from .serverinfo import collect_server_info
from .sources import drop_duplicate_entries, drop_duplicate_findings, expand_sources
from .timefilter import in_window, parse_when
from .timeline import apply_offset, merge_entries, merge_findings, parse_offset
from .model import SEVERITIES, severity_rank
from .report import render_html, render_json, render_text, wrap_report
from .report.htmlout import DEFAULT_HTML_LIMIT


FORMATS = ("text", "json", "html")
EXTENSION_FORMATS = {".json": "json", ".html": "html", ".htm": "html"}
RENDERERS = {"text": render_text, "json": render_json, "html": render_html}


def choose_format(args):
    """--format wins; otherwise the extension of -o decides; otherwise text."""
    match (args.format, args.output):
        case (str() as chosen, _):
            return chosen
        case (None, str() as path):
            return EXTENSION_FORMATS.get(os.path.splitext(path)[1].lower(), "text")
        case _:
            return "text"


def write_private_json(path, data):
    """Write JSON that only the owner may read (the redaction map undoes the redaction)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    os.chmod(path, 0o600)  # also when the file already existed with wider permissions


def shift_to_utc(loaded):
    """Move every server's entries to UTC using the "UTC adjustment" line of its startup.

    Returns the labels for which no such line was found (their entries are not touched). The line is
    written once per start, so a daylight saving change in the middle of a long-running instance is not
    followed.
    """
    offsets = {}
    for label, _, entries in loaded:
        for info in collect_server_info(entries):
            if "utc_offset_minutes" in info and label not in offsets:
                offsets[label] = info["utc_offset_minutes"]
    unknown = set()
    for label, _, entries in loaded:
        if label in offsets:
            apply_offset(entries, timedelta(minutes=-offsets[label]))
        else:
            unknown.add(label)
    return unknown


def build_parser():
    p = argparse.ArgumentParser(
        prog="errorlog-insight",
        description="Summarise SQL Server ERRORLOG files.",
    )
    p.add_argument("files", nargs="*", metavar="[LABEL=]FILE",
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
    p.add_argument("--utc", action="store_true",
                   help="convert times to UTC using the 'UTC adjustment' line of each server's startup "
                        "(applied after --offset and before --since/--until)")
    p.add_argument("--baseline", metavar="FILE",
                   help="compare with a baseline saved earlier and list what is new")
    p.add_argument("--save-baseline", metavar="FILE",
                   help="write a summary of this log (finding counts and unrecognised templates) to FILE, "
                        "to compare later logs with")
    p.add_argument("--redact", action="store_true",
                   help="replace IP addresses, account and login names, server names and file paths with "
                        "stable pseudonyms before analysing, so the report can be shared")
    p.add_argument("--redact-map", metavar="FILE",
                   help="with --redact: write a JSON file that maps each pseudonym back to the original value "
                        "(keep it private: it undoes the redaction)")
    p.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERITY",
                   help="exit with status 1 when there is a finding of at least this severity "
                        "(info, warning, error or critical), for scripts and monitoring")
    p.add_argument("--html-limit", type=int, default=None, metavar="N",
                   help="show at most N findings in the HTML report, worst first (default: 500; 0 shows all)")
    p.add_argument("--width", type=int, default=None, metavar="N",
                   help="wrap the text report at N columns (default: the terminal width when writing to a "
                        "terminal, otherwise no wrapping; 0 turns wrapping off)")
    p.add_argument("--no-insights", action="store_true",
                   help="leave out the insights section (readings that combine several findings)")
    p.add_argument("--since", metavar="WHEN",
                   help="ignore entries before this time, for example 2024-05-14 or 2024-05-14T01:30")
    p.add_argument("--until", metavar="WHEN", help="ignore entries from this time on (exclusive)")
    p.add_argument("--offset", action="append", default=[], metavar="LABEL=+2s",
                   help="shift one server's timestamps to correct clock skew, for example SQLDR02=-1.5s "
                        "(units: ms, s, m, h; repeatable)")
    p.add_argument("--burst-window", type=int, default=None, metavar="N",
                   help="how many buckets of history make the baseline of a burst (default: 30)")
    p.add_argument("--bucket-seconds", type=int, default=None, metavar="N",
                   help="width of a burst bucket in seconds (default: 60)")
    p.add_argument("--timeline", action="store_true",
                   help="list the findings of all files in one time-ordered timeline")
    p.add_argument("--config", metavar="FILE",
                   help="read defaults for --top, --min-severity and the burst options from a TOML or INI file")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write the report to FILE (UTF-8) instead of standard output")
    p.add_argument("--list-codes", action="store_true",
                   help="list the finding codes the rules can produce, with their names, and exit")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


def _utf8_stdout():
    """Windows consoles default to a legacy code page; log text (logins, paths) is not always ASCII."""
    stream = sys.stdout
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")
    return stream


def text_width(args, out):
    """--width if given; else the terminal width when the report goes to a terminal; else 0 (no wrapping)."""
    if args.width is not None:
        return args.width
    if args.output or not getattr(out, "isatty", lambda: False)():
        return 0
    return shutil.get_terminal_size((100, 24)).columns


def code_sort_key(code):
    """Message numbers first, in numeric order, then the named codes."""
    return (0, int(code), "") if code.isdigit() else (1, 0, code)


def list_codes():
    width = max(len(code) for code in LABELS)
    return "".join("%-*s  %s\n" % (width, code, LABELS[code]) for code in sorted(LABELS, key=code_sort_key))


def main(argv=None, out=None):
    """Run the tool. Exit status: 0 done, 1 a finding at or above --fail-on, 2 bad arguments or input."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if out is None and not args.output:
        out = _utf8_stdout()
    if args.list_codes:
        out.write(list_codes())
        return 0
    if not args.files:
        parser.error("no input files (give an ERRORLOG, or --list-codes)")
    try:
        settings = load_settings(args.config, args.top, args.min_severity, args.burst_min, args.burst_factor,
                                 args.burst_window, args.bucket_seconds)
    except ConfigError as exc:
        sys.stderr.write("errorlog-insight: %s\n" % exc)
        return 2
    try:
        return run(args, settings, out)
    finally:
        forget_labels(settings.custom_rules)   # the names belong to this run, not to the process


def run(args, settings, out):
    """Everything after the arguments and the config file have been read."""
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
    try:
        baseline = read_baseline(args.baseline) if args.baseline else None
    except BaselineError as exc:
        sys.stderr.write("errorlog-insight: %s\n" % exc)
        return 2
    loaded = []
    for label, path in expand_sources(args.files):
        try:
            loaded.append((label, path, read_entries(path, replica=label)))
        except OSError as exc:
            sys.stderr.write("errorlog-insight: cannot read %s: %s\n" % (path, exc.strerror or exc))
            return 2
        except ValueError as exc:  # a saved grid with an unreadable header or date
            sys.stderr.write("errorlog-insight: %s: %s\n" % (path, exc))
            return 2
    paths = [path for _, path, _ in loaded]
    for label, _, entries in loaded:
        if label in offsets:
            apply_offset(entries, offsets[label])
    if set(offsets) - {label for label, _, _ in loaded}:
        missing = sorted(set(offsets) - {label for label, _, _ in loaded})
        sys.stderr.write("errorlog-insight: --offset names no input file: %s\n" % ", ".join(missing))
        return 2
    if args.utc:
        for label in sorted(shift_to_utc(loaded)):
            sys.stderr.write("errorlog-insight: no UTC adjustment line for %s; its times are left as they are\n" % label)
    if args.redact:
        redactor = Redactor()
        redactor.learn([e for _, _, entries in loaded for e in entries], [label for label, _, _ in loaded])
        for _, _, entries in loaded:
            redactor.entries(entries)
        paths = [redactor.file(path) for path in paths]
        if args.redact_map:
            write_private_json(args.redact_map, redactor.mapping())
    elif args.redact_map:
        sys.stderr.write("errorlog-insight: --redact-map needs --redact\n")
        return 2
    per_file = []
    all_findings, unknown = [], []
    for _, _, entries in loaded:
        entries = in_window(entries, since, until)
        found = classify(entries, settings.custom_rules)
        per_file.append(entries)
        all_findings.extend(found)
        unknown.extend(unclassified(entries, found))
    entries = drop_duplicate_entries(merge_entries(*per_file))
    all_findings = drop_duplicate_findings(merge_findings(all_findings))
    unknown = drop_duplicate_entries(unknown)
    floor = severity_rank(settings.min_severity)
    findings = merge_findings([f for f in all_findings if severity_rank(f.severity) >= floor])
    clusters = cluster_entries(unknown)  # the slowest step on a big log: do it once
    bursts = sorted(find_bursts(findings, settings.bursts) + find_template_bursts(clusters, settings.bursts),
                    key=lambda b: (b.start, b.key))
    incidents = find_incidents(all_findings)  # planned failovers are info, so use the unfiltered findings
    insights = [] if args.no_insights else [
        i for i in find_insights(all_findings) if severity_rank(i.severity) >= floor]
    try:
        comparison = compare(baseline, all_findings, unknown, clusters) if baseline is not None else None
    except BaselineError as exc:
        sys.stderr.write("errorlog-insight: %s: %s\n" % (args.baseline, exc))
        return 2
    if args.save_baseline:
        write_baseline(args.save_baseline, make_baseline(entries, all_findings, unknown, paths, clusters))
    render = RENDERERS[choose_format(args)]
    report = render(entries, findings, paths, unknown=unknown, top=settings.top, bursts=bursts,
                    timeline=args.timeline, incidents=incidents, insights=insights,
                    servers=collect_server_info(entries), comparison=comparison, clusters=clusters,
                    html_limit=args.html_limit if args.html_limit is not None else DEFAULT_HTML_LIMIT)
    if choose_format(args) == "text":
        report = wrap_report(report, text_width(args, out))
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(report)
    else:
        out.write(report)
    if args.fail_on and any(severity_rank(f.severity) >= severity_rank(args.fail_on) for f in all_findings):
        return 1
    return 0


def console_main():
    """Entry point for the installed errorlog-insight script."""
    sys.exit(main())
