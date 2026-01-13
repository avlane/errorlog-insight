"""Save what a quiet period looked like, and compare a later log with it.

A baseline is a small JSON file: how many findings of each code there were, and which message
templates (by their stable id) the rules did not recognise, with counts. Comparing a new log with
it answers "what is here that I have not seen before?", which is often more useful than a list
of everything.
"""
import json

from . import __version__
from .cluster import cluster_entries
from .report.common import iso

SCHEMA_VERSION = 1


class BaselineError(ValueError):
    pass


def make_baseline(entries, findings, unknown, files=()):
    """Build the baseline document from one analysis (use the unfiltered findings)."""
    codes = {}
    for f in findings:
        codes[f.code] = codes.get(f.code, 0) + 1
    templates = {}
    for c in cluster_entries(unknown):
        templates[c.id] = {"template": c.template, "count": c.count}
    stamps = [e.timestamp for e in entries]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "errorlog-insight", "version": __version__},
        "source": {
            "files": list(files),
            "entries": len(entries),
            "first": iso(min(stamps)) if stamps else None,
            "last": iso(max(stamps)) if stamps else None,
        },
        "codes": dict(sorted(codes.items())),
        "templates": dict(sorted(templates.items())),
    }


def write_baseline(path, baseline):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(baseline, f, indent=2)
        f.write("\n")


def read_baseline(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as exc:
        raise BaselineError("cannot read baseline %s: %s" % (path, exc.strerror or exc))
    except json.JSONDecodeError as exc:
        raise BaselineError("%s is not a baseline file: %s" % (path, exc))
    return data
