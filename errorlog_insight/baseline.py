"""Save what a quiet period looked like, and compare a later log with it.

A baseline is a small JSON file: how many findings of each code there were, and which message
templates (by their stable id) the rules did not recognise, with counts. Comparing a new log with
it answers "what is here that I have not seen before?", which is often more useful than a list
of everything.
"""
import json

from . import __version__
from .classify import LABELS
from .cluster import TEMPLATE_SCHEME, cluster_entries
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
        "template_scheme": TEMPLATE_SCHEME,
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


INCREASE_FACTOR = 3
INCREASE_MIN = 5


def check_baseline(data):
    """Raise BaselineError unless `data` looks like something write_baseline produced."""
    if not isinstance(data, dict) or not isinstance(data.get("codes"), dict) or not isinstance(data.get("templates"), dict):
        raise BaselineError("not a baseline file (no codes and templates)")
    version = data.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise BaselineError("not a baseline file (no schema_version)")
    if version > SCHEMA_VERSION:
        raise BaselineError("written by a newer errorlog-insight (baseline format %d, this one reads up to %d)"
                            % (version, SCHEMA_VERSION))
    return data


def compare(baseline, findings, unknown):
    """What is in this log that the baseline does not have.

    * new_codes: finding codes the baseline never saw;
    * increased: codes now at least INCREASE_FACTOR times as frequent (and at least INCREASE_MIN);
    * new_templates: unrecognised message groups whose id is not in the baseline, biggest first;
    * known_templates: how many unrecognised groups are old news.

    A baseline made with a different template scheme (the masking rules changed) cannot be compared by
    template id: only the finding codes are compared and templates_compared is False.
    """
    check_baseline(baseline)
    now = {}
    for f in findings:
        now[f.code] = now.get(f.code, 0) + 1
    new_codes, increased = [], []
    for code in sorted(now):
        before = baseline["codes"].get(code, 0)
        label = LABELS.get(code, code)
        if before == 0:
            new_codes.append({"code": code, "label": label, "count": now[code]})
        elif now[code] >= INCREASE_MIN and now[code] >= INCREASE_FACTOR * before:
            increased.append({"code": code, "label": label, "before": before, "now": now[code]})
    clusters = cluster_entries(unknown)
    comparable = baseline.get("template_scheme") == TEMPLATE_SCHEME
    new_templates = [c for c in clusters if c.id not in baseline["templates"]] if comparable else []
    return {
        "baseline": baseline.get("source", {}),
        "templates_compared": comparable,
        "new_codes": new_codes,
        "increased": increased,
        "new_templates": new_templates,
        "known_templates": len(clusters) - len(new_templates) if comparable else 0,
    }
