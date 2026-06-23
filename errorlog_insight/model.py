"""Data model shared by the reader and the analysers."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Entry:
    """One logical ERRORLOG entry (a timestamped line plus its continuation lines)."""

    timestamp: datetime
    process: str
    text: str
    source: str = ""
    lineno: int = 0
    replica: str = ""

    @property
    def first_line(self) -> str:
        return self.text.split("\n", 1)[0]


SEVERITIES = ("info", "warning", "error", "critical")


def severity_rank(name: str) -> int:
    """Position of a severity name: info 0, warning 1, error 2, critical 3. Raises ValueError for others."""
    return SEVERITIES.index(name)


@dataclass(slots=True)
class Finding:
    """A classified entry: what it is, how bad it is, and what to try next."""

    entry: Entry
    category: str
    code: str
    severity: str
    title: str
    details: dict[str, Any] = field(default_factory=dict)
    advice: str = ""
    covered: list[Entry] = field(default_factory=list)  # every entry this finding accounts for

    @property
    def entries(self) -> list[Entry]:
        return self.covered or [self.entry]
