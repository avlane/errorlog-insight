"""Rules written in the config file.

    [[rule]]                       # TOML
    name = "Licence server"
    pattern = "licensing service at (?P<host>\\S+)"
    severity = "error"
    title = "Licence server {host} unreachable"
    advice = "Check the licence server and the firewall."

In an INI file the same thing is a section called [rule:Licence server]. The pattern is a Python
regular expression searched in the whole entry text. Named groups become details and can be used
in the title as {name}. Custom rules are tried before the built-in ones.
"""
import re

from .model import SEVERITIES, Finding
from .registry import LABELS

KEYS = {"name", "pattern", "severity", "title", "advice", "code", "ignore_case"}


class RuleError(ValueError):
    pass


class _Defaults(dict):
    """format_map helper: an unknown or unmatched {name} stays visible instead of raising."""

    def __missing__(self, key):
        return "{%s}" % key


def _truthy(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def make_rule(spec):
    """Build a rule function from one config table. Raises RuleError for anything unusable."""
    unknown = set(spec) - KEYS
    if unknown:
        raise RuleError("unknown key(s) in rule: %s" % ", ".join(sorted(unknown)))
    name = str(spec.get("name", "")).strip()
    if not name:
        raise RuleError("a rule needs a name")
    if not spec.get("pattern"):
        raise RuleError("rule %r needs a pattern" % name)
    severity = spec.get("severity", "warning")
    if severity not in SEVERITIES:
        raise RuleError("rule %r: severity must be one of %s" % (name, ", ".join(SEVERITIES)))
    flags = re.IGNORECASE if _truthy(spec.get("ignore_case", False)) else 0
    try:
        regex = re.compile(spec["pattern"], flags)
    except re.error as exc:
        raise RuleError("rule %r: bad pattern: %s" % (name, exc))
    code = str(spec.get("code") or "custom:" + re.sub(r"\W+", "-", name.lower()).strip("-"))
    title_template = str(spec.get("title") or name)
    advice = str(spec.get("advice", ""))
    LABELS[code] = name

    def custom_rule(entry, ctx):
        m = regex.search(entry.text)
        if not m:
            return None
        details = {k: v for k, v in m.groupdict().items() if v is not None}
        title = title_template.format_map(_Defaults(details))
        return Finding(entry, "custom", code, severity, title, details, advice)

    custom_rule.__name__ = "custom_" + code
    return custom_rule


def rules_from_config(data):
    """Collect rule tables from parsed config: [[rule]] (TOML) and [rule:NAME] sections (INI)."""
    specs = []
    table = data.get("rule", [])
    if isinstance(table, dict):
        table = [table]
    specs.extend(table)
    for section, values in data.items():
        if section.startswith("rule:"):
            spec = dict(values)
            spec.setdefault("name", section[len("rule:"):])
            specs.append(spec)
    return [make_rule(spec) for spec in specs]
