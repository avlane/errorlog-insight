"""Rule-based classification of ERRORLOG entries.

Rules (see the rules package) are plain functions registered with @rule. Each
receives the entry and a Context (which remembers the "Error: N, Severity: S,
State: X." header that SQL Server writes as a separate entry just before the
message text) and returns a Finding or None. The first rule that returns a
Finding wins. Block rules consume a run of entries instead of a single one.
"""
from . import rules  # noqa: F401  (registers every rule)
from .registry import BLOCK_RULES, ERROR_HEADER_RE, LABELS, RULES, Context  # noqa: F401


def _try_block_rules(entries, i):
    entry = entries[i]
    for starts, fn in BLOCK_RULES:
        if starts(entry):
            return fn(entries, i)
    return None


def classify(entries, extra_rules=()):
    """Run every rule over the entries and return the findings in log order.

    `extra_rules` (for example rules from the config file) are tried before the built-in ones.
    """
    rules = list(extra_rules) + RULES
    ctx = Context()
    findings = []
    i = 0
    while i < len(entries):
        entry = entries[i]
        block = _try_block_rules(entries, i)
        if block is not None:
            finding, end = block
            finding.covered = list(entries[i:end])
            findings.append(finding)
            i = end
            continue
        ctx.observe(entry)
        for fn in rules:
            finding = fn(entry, ctx)
            if finding is not None:
                findings.append(finding)
                break
        i += 1
    return findings


def unclassified(entries, findings):
    """Entries no rule accounted for.

    The separate 'Error: N, Severity: S, State: X.' header is not interesting
    on its own when the entry after it was classified.
    """
    covered = set()
    for f in findings:
        covered.update(id(e) for e in f.entries)
    out = []
    for i, entry in enumerate(entries):
        if id(entry) in covered:
            continue
        nxt = entries[i + 1] if i + 1 < len(entries) else None
        if ERROR_HEADER_RE.match(entry.first_line) and nxt is not None and id(nxt) in covered:
            continue
        out.append(entry)
    return out
