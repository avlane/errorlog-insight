"""The rules. Importing a module registers its rules, and the import order is the
order in which rules are tried (the first rule that matches an entry wins)."""
from . import login, io, scheduler, memory, corruption, backup, lifecycle, deadlocks, crashes, ag  # noqa: F401
