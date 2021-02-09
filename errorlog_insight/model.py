"""Data model shared by the reader and the analysers."""
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Entry:
    """One logical ERRORLOG entry (a timestamped line plus its continuation lines)."""

    timestamp: datetime
    process: str
    text: str
    source: str = ""
    lineno: int = 0

    @property
    def first_line(self):
        return self.text.split("\n", 1)[0]
