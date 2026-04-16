"""Slow or cancelled file autogrowth: messages 5144 and 5145."""
import re

from ..model import Finding
from ..registry import LABELS, header_numbers, rule

LABELS.update({
    "5144": "Autogrow cancelled (5144)",
    "5145": "Slow autogrow (5145)",
})

TOOK_RE = re.compile(
    r"Autogrow of file '(?P<file>[^']+)' in database '(?P<db>[^']+)' took (?P<ms>\d+) milliseconds"
)
CANCELLED_RE = re.compile(
    r"Autogrow of file '(?P<file>[^']+)' in database '(?P<db>[^']+)' was cancelled by user or timed out after "
    r"(?P<ms>\d+) milliseconds"
)
SLOW_MS = 15000

GROWTH_ADVICE = ("Growing by a percentage gets slower as the file gets bigger. Set a fixed growth in MB "
                 "(256 MB to 1 GB for busy files) and pre-size the file for the expected load. Data files "
                 "grow without zeroing when instant file initialization is on; log files are always zeroed "
                 "(before SQL Server 2022, which skips it for growths of 64 MB or less).")


@rule
def slow_autogrow(entry, ctx):
    m = TOOK_RE.search(entry.text)
    if not m:
        return None
    ms = int(m.group("ms"))
    details = {"file": m.group("file"), "database": m.group("db"), "milliseconds": ms}
    details.update(header_numbers(ctx, entry, 5145))
    severity = "warning" if ms >= SLOW_MS else "info"
    title = "Autogrow of %s (%s) took %.1f s" % (details["file"], details["database"], ms / 1000.0)
    return Finding(entry, "storage", "5145", severity, title, details, GROWTH_ADVICE if severity == "warning" else "")


@rule
def cancelled_autogrow(entry, ctx):
    m = CANCELLED_RE.search(entry.text)
    if not m:
        return None
    ms = int(m.group("ms"))
    details = {"file": m.group("file"), "database": m.group("db"), "milliseconds": ms}
    details.update(header_numbers(ctx, entry, 5144))
    title = "Autogrow of %s (%s) gave up after %.1f s" % (details["file"], details["database"], ms / 1000.0)
    advice = ("Sessions waiting for this growth failed or stalled, and the file did not grow. " + GROWTH_ADVICE)
    return Finding(entry, "storage", "5144", "error", title, details, advice)
