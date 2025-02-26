"""Insights: readings that combine several findings.

A finding says what one message means. An insight says what a group of findings
probably means together, for example "the slow I/O happened while a snapshot
backup had the database frozen". Every insight rule is a plain function that
looks at the full list of findings (any number of servers, unfiltered) and
returns Insight objects with the findings that back them as evidence.

The rules only use timestamps, server labels and the details the classifiers
already extracted. They say how sure they are: "high" when the evidence is
direct, "medium" when it is circumstantial.
"""
from dataclasses import dataclass, field
from datetime import timedelta

from .model import severity_rank
from .timeline import merge_findings

CONFIDENCE = ("low", "medium", "high")
INSIGHT_RULES = []


@dataclass
class Insight:
    code: str
    title: str
    severity: str
    confidence: str
    evidence: list = field(default_factory=list)
    advice: str = ""

    @property
    def start(self):
        return min(f.entry.timestamp for f in self.evidence)

    @property
    def end(self):
        return max(f.entry.timestamp for f in self.evidence)


def insight_rule(fn):
    INSIGHT_RULES.append(fn)
    return fn


def server_of(finding):
    return finding.entry.replica or finding.entry.source or ""


def of_code(findings, *codes):
    return [f for f in findings if f.code in codes]


def find_insights(findings):
    """Run every insight rule. Most severe and most certain first, then by time."""
    ordered = merge_findings(findings)
    found = []
    for rule_fn in INSIGHT_RULES:
        found.extend(rule_fn(ordered))
    return sorted(found, key=lambda i: (-severity_rank(i.severity), -CONFIDENCE.index(i.confidence), i.start, i.code))


# ---------------------------------------------------------------------------
# Slow I/O that coincides with maintenance
# ---------------------------------------------------------------------------

EPISODE_GAP = timedelta(minutes=10)
FREEZE_TIMEOUT = timedelta(minutes=5)   # a freeze with no "resumed" message is assumed to last this long
AFTERMATH = timedelta(minutes=2)        # stalls that end just after the window still count, with less confidence


def _stall_episodes(findings):
    """Group 833 findings per server and file; a ten minute gap starts a new episode."""
    last = {}
    episodes = []
    for f in of_code(findings, "833"):
        key = (server_of(f), f.details["file"])
        current = last.get(key)
        if current is None or f.entry.timestamp - current[-1].entry.timestamp > EPISODE_GAP:
            current = last[key] = []
            episodes.append(current)
        current.append(f)
    return episodes


def _freeze_windows(findings):
    """(server, database, start, end, finding) for each I/O freeze."""
    windows = []
    resumes = of_code(findings, "io-resumed")
    for frozen in of_code(findings, "io-frozen"):
        end = None
        for r in resumes:
            if (server_of(r) == server_of(frozen) and r.details["database"] == frozen.details["database"]
                    and r.entry.timestamp >= frozen.entry.timestamp):
                end = r.entry.timestamp
                break
        windows.append((server_of(frozen), frozen.details["database"], frozen.entry.timestamp,
                        end or frozen.entry.timestamp + FREEZE_TIMEOUT, frozen))
    return windows


def _checkdb_windows(findings):
    windows = []
    for f in of_code(findings, "checkdb"):
        end = f.entry.timestamp
        windows.append((server_of(f), f.details["target"], end - timedelta(seconds=f.details["elapsed_seconds"]), end, f))
    return windows


def _overlap(episode, start, end):
    """How an episode relates to a window: "during", "after" (within AFTERMATH) or None."""
    first = min(f.entry.timestamp - timedelta(seconds=f.details["seconds"]) for f in episode)
    last = max(f.entry.timestamp for f in episode)
    if first <= end and last >= start:
        return "during"
    if end < first <= end + AFTERMATH:
        return "after"
    return None


@insight_rule
def io_stalls_during_maintenance(findings):
    out = []
    episodes = _stall_episodes(findings)
    for episode in episodes:
        server = server_of(episode[0])
        path = episode[0].details["file"]
        worst = max(f.details["seconds"] for f in episode)
        for kind, windows, label, advice in (
            ("snapshot", _freeze_windows(findings), "a snapshot backup froze I/O on",
             "A VSS or other snapshot backup froze the database. Long freezes are normal for slow snapshot "
             "providers, but check the provider and the SAN snapshot time."),
            ("checkdb", _checkdb_windows(findings), "DBCC consistency checking was running on",
             "CHECKDB reads every page and competes with normal I/O. Move it to a quiet period or run it on a "
             "restored copy or a secondary."),
        ):
            for w_server, database, start, end, cause in windows:
                if w_server != server:
                    continue
                relation = _overlap(episode, start, end)
                if relation is None:
                    continue
                title = "Slow I/O on %s overlaps maintenance: %s %s" % (path, label, database)
                out.append(Insight(
                    "io-during-" + kind, title, "warning" if worst < 30 else "error",
                    "high" if relation == "during" else "medium", list(episode) + [cause], advice))
    return out


# ---------------------------------------------------------------------------
# A full log that is waiting for log backups
# ---------------------------------------------------------------------------

BACKUP_LOOKBACK = timedelta(hours=6)
DEVICE_ERROR_WINDOW = timedelta(seconds=5)


def _failed_log_backups(findings, server, database, before):
    """3041 failures of BACKUP LOG for `database` shortly before `before`, with the device error that caused them."""
    out = []
    devices = of_code(findings, "18204", "3201")
    for f in of_code(findings, "3041"):
        if (server_of(f) == server and f.details["kind"] == "log" and f.details["database"] == database
                and before - BACKUP_LOOKBACK <= f.entry.timestamp <= before):
            out.append(f)
            out.extend(d for d in devices if server_of(d) == server
                       and timedelta(0) <= f.entry.timestamp - d.entry.timestamp <= DEVICE_ERROR_WINDOW)
    return out


@insight_rule
def log_full_waiting_for_backup(findings):
    out = []
    for full in of_code(findings, "9002"):
        if full.details.get("log_reuse_wait") != "LOG_BACKUP":
            continue
        database = full.details["database"]
        failures = _failed_log_backups(findings, server_of(full), database, full.entry.timestamp)
        if failures:
            reasons = sorted({f.details["os_error_text"] for f in failures if "os_error_text" in f.details})
            because = " (%s)" % "; ".join(reasons) if reasons else ""
            out.append(Insight(
                "logfull-backups-failing",
                "The log of %s is full because log backups have been failing%s" % (database, because),
                "critical", "high", failures + [full],
                "Fix the cause of the failed log backups first, then take a log backup so the log can be reused. "
                "Growing the log file only delays the next 9002."))
        else:
            out.append(Insight(
                "logfull-no-backups",
                "The log of %s is full and no log backup failure is logged" % database,
                "critical", "medium", [full],
                "SQL Server is waiting for a log backup and none was attempted, or the attempts are not in this "
                "log: check that the log backup job exists, is enabled and is not blocked or hung."))
    return out


# ---------------------------------------------------------------------------
# A non-yielding scheduler with an outside cause
# ---------------------------------------------------------------------------

CAUSE_WINDOW = timedelta(minutes=10)


def _nearby(findings, anchor, codes, before=CAUSE_WINDOW, after=timedelta(minutes=1)):
    """Findings of `codes` on the same server from `before` ahead of the anchor to `after` behind it."""
    start = anchor.entry.timestamp - before
    end = anchor.entry.timestamp + after
    return [f for f in of_code(findings, *codes)
            if server_of(f) == server_of(anchor) and start <= f.entry.timestamp <= end]


@insight_rule
def non_yielding_with_outside_cause(findings):
    out = []
    for ny in of_code(findings, "17883"):
        paged = _nearby(findings, ny, ("17890",))
        slow_io = _nearby(findings, ny, ("833",), before=timedelta(minutes=2))
        if paged:
            confidence = "high" if ny.details["pattern"] == "stalled" else "medium"
            out.append(Insight(
                "stall-from-paged-out-memory",
                "Scheduler %d stalled while SQL Server memory was being paged out" % ny.details["scheduler"],
                "error", confidence, paged + [ny],
                "A worker that uses no CPU but holds a scheduler is often waiting for pages to come back from disk. "
                "Fix the memory trimming (lock pages in memory, max server memory, VM ballooning) before chasing "
                "the query."))
        if slow_io and ny.details["pattern"] != "cpu-bound":
            out.append(Insight(
                "stall-with-slow-io",
                "Scheduler %d stalled while storage was reporting slow I/O" % ny.details["scheduler"],
                "error", "medium", slow_io + [ny],
                "The worker was not burning CPU, and I/O requests were taking over 15 seconds in the same minutes. "
                "Look at the storage first: %s." % ", ".join(sorted({f.details["volume"] for f in slow_io}))))
    return out
