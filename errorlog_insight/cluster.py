"""Group messages the classifiers do not know into templates.

Each message is reduced to a template by masking the parts that vary from one
occurrence to the next (numbers, addresses, paths, quoted names). Messages that
reduce to the same template are one cluster. There is no learning involved:
the masks below are the whole algorithm.
"""
import re
from dataclasses import dataclass, field

MAX_TEMPLATE_CHARS = 300

# Order matters: the specific shapes go first so the generic number mask does
# not eat parts of a GUID or an address.
MASKS = [
    (re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"), "<GUID>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b(?::\d+)?"), "<IP>"),
    (re.compile(r"\b0x[0-9A-Fa-f]+\b"), "<HEX>"),
    (re.compile(r"\\\\[\w.$-]+\\[^\s'\"\])]*"), "<PATH>"),
    (re.compile(r"\b[A-Za-z]:\\[^\s'\"\])]*"), "<PATH>"),
    (re.compile(r"'[^']*'"), "'<STR>'"),
    (re.compile(r'"[^"]*"'), '"<STR>"'),
    (re.compile(r"\[[^\]]*\]"), "[<ID>]"),
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "<NUM>"),
]


def mask(text):
    """Return the template of one message (first line only)."""
    line = text.split("\n", 1)[0].strip()
    for regex, token in MASKS:
        line = regex.sub(token, line)
    if len(line) > MAX_TEMPLATE_CHARS:
        line = line[:MAX_TEMPLATE_CHARS] + "..."
    return line


@dataclass
class Cluster:
    template: str
    count: int = 0
    first_seen: object = None
    last_seen: object = None
    sample: object = None
    processes: set = field(default_factory=set)

    def add(self, entry):
        self.count += 1
        if self.first_seen is None or entry.timestamp < self.first_seen:
            self.first_seen = entry.timestamp
        if self.last_seen is None or entry.timestamp > self.last_seen:
            self.last_seen = entry.timestamp
        if self.sample is None:
            self.sample = entry
        self.processes.add(entry.process)


def cluster_entries(entries):
    """Cluster entries by template; the biggest clusters come first."""
    clusters = {}
    for entry in entries:
        template = mask(entry.text)
        if not template:
            continue
        cluster = clusters.get(template)
        if cluster is None:
            cluster = clusters[template] = Cluster(template)
        cluster.add(entry)
    return sorted(clusters.values(), key=lambda c: (-c.count, c.first_seen, c.template))
