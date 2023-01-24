"""Rule registry and the per-log Context shared by all rules."""
import re

RULES = []
BLOCK_RULES = []  # (starts, fn): fn(entries, i) -> (Finding, end) for findings that span entries

# Human-readable name per message number / pseudo code, used by the reports.
# Each rules module adds its own entries.
LABELS = {}

ERROR_HEADER_RE = re.compile(r"^Error: (\d+), Severity: (\d+), State: (\d+)\.")
HEADER_WINDOW_SECONDS = 5


def rule(fn):
    RULES.append(fn)
    return fn


def block_rule(starts):
    """Register a rule over a run of entries; starts(entry) says where a block may begin."""
    def register(fn):
        BLOCK_RULES.append((starts, fn))
        return fn
    return register


class Context:
    """State carried from one entry to the next while classifying a log."""

    def __init__(self):
        self.header = None  # (entry, number, severity, state)

    def observe(self, entry):
        m = ERROR_HEADER_RE.match(entry.first_line)
        if m:
            self.header = (entry, int(m.group(1)), int(m.group(2)), int(m.group(3)))

    def header_for(self, entry, number):
        """Return (severity, state) of the matching Error: header, if there is one."""
        if self.header is None:
            return None
        head, num, severity, state = self.header
        if num != number:
            return None
        if head.process != entry.process:
            return None
        if abs((entry.timestamp - head.timestamp).total_seconds()) > HEADER_WINDOW_SECONDS:
            return None
        return severity, state


def header_numbers(ctx, entry, number):
    """Severity and state of the Error: header for `number`, as detail keys (or nothing)."""
    header = ctx.header_for(entry, number)
    if header is None:
        return {}
    return {"error_severity": header[0], "error_state": header[1]}
