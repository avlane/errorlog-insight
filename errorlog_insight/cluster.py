"""Group messages the classifiers do not know into templates.

Each message is reduced to a template by masking the parts that vary from one
occurrence to the next (numbers, addresses, paths, quoted names). Messages that
reduce to the same template are one cluster. Templates that are almost the
same (same length, same first word, most words equal) are then merged, and the
words that differ become <*>. There is no learning involved: the masks and the
similarity rule below are the whole algorithm.
"""
import hashlib
import re
from dataclasses import dataclass, field

# Template ids depend on the masks below. Change them and ids change, so a saved baseline would
# call every old message new: bump this number with any change to MASKS, SIMILARITY or MIN_WORDS.
TEMPLATE_SCHEME = 1

MAX_TEMPLATE_CHARS = 300
WILDCARD = "<*>"
SIMILARITY = 0.7   # share of word positions that must match for two templates to merge
MIN_WORDS = 4      # shorter messages are only merged when identical

# Order matters: the specific shapes go first so the generic number mask does
# not eat parts of a GUID or an address.
MASKS = [
    (re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"), "<GUID>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b(?::\d+)?"), "<IP>"),
    (re.compile(r"\b0x[0-9A-Fa-f]+\b"), "<HEX>"),
    (re.compile(r"\bS-1-\d+(?:-\d+)+\b"), "<SID>"),
    (re.compile(r"\b\d{4}[-/]\d{2}[-/]\d{2}\b"), "<DATE>"),
    (re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b"), "<TIME>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{8}:[0-9A-Fa-f]{8}:[0-9A-Fa-f]{4}|\d+:\d+:\d+)\b"), "<LSN>"),
    (re.compile(r"\bv?\d+(?:\.\d+){2,}\b"), "<VER>"),
    (re.compile(r"\\\\[\w.$-]+\\[^\s'\"\])]*"), "<PATH>"),
    (re.compile(r"\b[A-Za-z]:\\[^\s'\"\])]*"), "<PATH>"),
    (re.compile(r"\b[A-Za-z][\w-]*\\[A-Za-z_][\w.$-]*"), "<ACCOUNT>"),
    (re.compile(r"\bspid\d+s?\b", re.I), "<SPID>"),
    (re.compile(r"'[^']*'"), "'<STR>'"),
    (re.compile(r'"[^"]*"'), '"<STR>"'),
    (re.compile(r"\[[^\]]*\]"), "[<ID>]"),
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "<NUM>"),
]


# Words that make an unrecognised message worth a look. Checked in this order; the first level that
# matches wins. This is a guess from vocabulary, nothing more, and the reports mark it with a "?".
SEVERITY_WORDS = (
    ("critical", re.compile(r"\b(corrupt\w*|fatal|terminating|assertion|stack dump|access violation)\b", re.I)),
    ("error", re.compile(r"\b(fail(ed|ure|s)?|error|cannot|can not|unable|denied|time[ds]? ?out|exception|"
                         r"could not|unexpected|invalid|aborted|refused|rejected)\b", re.I)),
    ("warning", re.compile(r"\b(warning|deprecated|retry|retries|not enough|low|exceed\w*|stall\w*|slow)\b", re.I)),
)
# "found <NUM> errors and repaired <NUM> errors", "no errors", "without errors" are not errors.
BENIGN_ERROR_PHRASES = re.compile(r"(\bno errors?\b|\bwithout errors?\b|<NUM> errors? and repaired|\b0 errors?\b)", re.I)
INFORMATIONAL = re.compile(r"(informational message|no user action is required)", re.I)


def guess_severity(template):
    """Guess how serious an unrecognised message is from its words: info, warning, error or critical."""
    text = BENIGN_ERROR_PHRASES.sub(" ", template)
    for level, regex in SEVERITY_WORDS:
        if regex.search(text):
            # "This is an informational message only" outweighs a stray word, except for the worst words
            if level != "critical" and INFORMATIONAL.search(template):
                return "info"
            return level
    return "info"


def template_id(template):
    """Short stable id of a template: the same template gets the same id in every run and on every machine."""
    return hashlib.blake2s(template.encode("utf-8"), digest_size=4).hexdigest()


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
    variants: int = 0  # how many distinct masked templates were merged into this one
    timestamps: list = field(default_factory=list)

    @property
    def id(self):
        return template_id(self.template)

    @property
    def severity_guess(self):
        return guess_severity(self.template)

    def add(self, entry):
        self.count += 1
        self.timestamps.append(entry.timestamp)
        if self.first_seen is None or entry.timestamp < self.first_seen:
            self.first_seen = entry.timestamp
        if self.last_seen is None or entry.timestamp > self.last_seen:
            self.last_seen = entry.timestamp
        if self.sample is None:
            self.sample = entry
        self.processes.add(entry.process)


def similarity(a, b):
    """Share of positions where two equally long word lists agree (wildcards agree with anything)."""
    if len(a) != len(b) or not a:
        return 0.0
    same = sum(1 for x, y in zip(a, b, strict=True) if x == y or x == WILDCARD or y == WILDCARD)
    return same / float(len(a))


def merge_words(a, b):
    return [x if x == y else WILDCARD for x, y in zip(a, b, strict=True)]


def cluster_entries(entries, threshold=SIMILARITY):
    """Cluster entries by template; the biggest clusters come first."""
    exact = {}
    for entry in entries:
        template = mask(entry.text)
        if not template:
            continue
        cluster = exact.get(template)
        if cluster is None:
            cluster = exact[template] = Cluster(template, variants=1)
        cluster.add(entry)

    merged = []  # clusters after similarity merging, in order of first appearance of their biggest template
    for cluster in sorted(exact.values(), key=lambda c: (-c.count, c.first_seen, c.template)):
        words = cluster.template.split()
        target = None
        if len(words) >= MIN_WORDS:
            for other in merged:
                other_words = other.template.split()
                if (len(other_words) == len(words) and other_words[0] == words[0]
                        and similarity(other_words, words) >= threshold):
                    target = other
                    break
        if target is None:
            merged.append(cluster)
        else:
            target.template = " ".join(merge_words(target.template.split(), words))
            target.count += cluster.count
            target.timestamps.extend(cluster.timestamps)
            target.variants += cluster.variants
            target.first_seen = min(target.first_seen, cluster.first_seen)
            target.last_seen = max(target.last_seen, cluster.last_seen)
            target.processes |= cluster.processes
    return sorted(merged, key=lambda c: (-c.count, c.first_seen, c.template))
