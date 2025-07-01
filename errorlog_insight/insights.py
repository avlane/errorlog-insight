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
from datetime import date, timedelta

from .incidents import find_incidents
from .model import severity_rank
from .rules.login import decode_login_state
from .summaries import login_summary
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


# ---------------------------------------------------------------------------
# AG data movement suspended
# ---------------------------------------------------------------------------

SYSTEM_SUSPENDS = ("SUSPEND_FROM_REDO", "SUSPEND_FROM_APPLY", "SUSPEND_FROM_CAPTURE", "SUSPEND_FROM_UNDO")
LOCAL_ERROR_CODES = ("9002", "823", "824", "825", "833", "1105")
SUSPEND_LOOKBACK = timedelta(minutes=10)


@insight_rule
def suspend_after_local_error(findings):
    out = []
    for susp in of_code(findings, "35264"):
        if susp.details["reason"] not in SYSTEM_SUSPENDS:
            continue
        causes = _nearby(findings, susp, LOCAL_ERROR_CODES, before=SUSPEND_LOOKBACK, after=timedelta(seconds=0))
        if not causes:
            continue
        database = susp.details["database"]
        same_db = [c for c in causes if c.code == "9002" and c.details["database"] == database]
        best = same_db or causes
        names = sorted({c.code for c in best})
        out.append(Insight(
            "suspend-after-local-error",
            "Data movement for %s was suspended right after error %s on %s" % (database, "/".join(names), server_of(susp)),
            "error", "high" if same_db else "medium", best + [susp],
            "The replica suspended itself because applying log failed. Fix the error shown (free log space, "
            "repair storage), then resume with ALTER DATABASE %s SET HADR RESUME." % database))
    return out


@insight_rule
def suspend_never_resumed(findings):
    out = []
    resumes = of_code(findings, "35265")
    for susp in of_code(findings, "35264"):
        later = [r for r in resumes if server_of(r) == server_of(susp)
                 and r.details["database"] == susp.details["database"]
                 and r.entry.timestamp > susp.entry.timestamp]
        if later:
            continue
        by_user = susp.details["by_user"]
        out.append(Insight(
            "suspend-not-resumed",
            "Data movement for %s on %s was suspended and not resumed in these logs" % (
                susp.details["database"], server_of(susp)),
            "warning" if by_user else "error", "high", [susp],
            "A person suspended it; make sure the maintenance is finished and resume it." if by_user else
            "Until it is resumed the secondary falls behind and the log cannot be truncated on the primary."))
    return out


# ---------------------------------------------------------------------------
# An availability group that keeps failing over
# ---------------------------------------------------------------------------

FLAP_WINDOW = timedelta(hours=1)
FLAP_COUNT = 3
FAILOVER_KINDS = ("planned failover", "unplanned failover", "failed failover")


@insight_rule
def availability_group_flapping(findings):
    out = []
    incidents = [i for i in find_incidents(findings) if i["kind"] in FAILOVER_KINDS]
    by_group = {}
    for inc in incidents:
        by_group.setdefault(tuple(inc["ags"]), []).append(inc)
    for ags, items in by_group.items():
        start = 0
        reported_until = None
        for end in range(len(items)):
            while items[end]["start"] - items[start]["start"] > FLAP_WINDOW:
                start += 1
            run = items[start:end + 1]
            if len(run) < FLAP_COUNT or (reported_until is not None and run[0]["start"] <= reported_until):
                continue
            # extend the run while further incidents keep arriving within the window
            tail = end + 1
            while tail < len(items) and items[tail]["start"] - items[tail - 1]["start"] <= FLAP_WINDOW:
                tail += 1
            run = items[start:tail]
            reported_until = run[-1]["end"]
            unplanned = sum(1 for i in run if i["kind"] != "planned failover")
            evidence = [f for inc in run for f in inc["findings"] if f.code == "1480"]
            name = ", ".join(ags) or "an availability group"
            out.append(Insight(
                "ag-flapping",
                "%s failed over %d times between %s and %s (%d unplanned)" % (
                    name, len(run), run[0]["start"].strftime("%H:%M"), run[-1]["end"].strftime("%H:%M"), unplanned),
                "critical" if unplanned >= FLAP_COUNT else "error", "high", evidence,
                "Repeated failovers usually mean a health check keeps failing on a marginal condition: look at "
                "the cause of the first one, then at the lease and health check timeouts, the cluster's "
                "failover threshold, and the network between the nodes. Consider manual failover mode until fixed."))
    return out


# ---------------------------------------------------------------------------
# Who is behind the failed logins
# ---------------------------------------------------------------------------

@insight_rule
def login_failure_sources(findings):
    out = []
    for row in login_summary(findings):
        n = row["failures"]
        users = row["users"]
        client = row["client"]
        if row["pattern"] == "password guessing":
            sa = " (including sa)" if any(u.lower() == "sa" for u in users) else ""
            out.append(Insight(
                "login-guessing",
                "%s tried wrong passwords %d times for %s%s" % (client, n, ", ".join(users[:3]), sa),
                "error", "high", row["findings"],
                "If the address is not a known application, block it at the firewall and rename or disable sa. "
                "If it is, someone is running a job with an old password."))
        elif row["pattern"] == "many users tried":
            out.append(Insight(
                "login-spray",
                "%s tried %d different logins in a few minutes (%s ...)" % (client, len(users), ", ".join(users[:4])),
                "error", "high", row["findings"],
                "Walking through common names such as sa and admin is a scan. SQL Server should not be reachable "
                "from that address; restrict it, and make sure sa is disabled and has a long password."))
        elif row["pattern"] == "repeating client":
            state = max(row["states"], key=lambda k: row["states"][k])
            _, cause, fix = decode_login_state(state)
            out.append(Insight(
                "login-stale-client",
                "%s has failed to log in %d times over %.1f hours (state %s)" % (
                    client, n, (row["last"] - row["first"]).total_seconds() / 3600.0, state),
                "warning", "medium", row["findings"],
                "A service keeps retrying. %s %s" % (cause, fix)))
    return out


# ---------------------------------------------------------------------------
# Versions that are out of support (or about to be)
# ---------------------------------------------------------------------------

# End of extended support per release, as published by Microsoft. Versions
# that are not listed are not judged.
EXTENDED_SUPPORT_END = {
    2012: date(2022, 7, 12),
    2014: date(2024, 7, 9),
    2016: date(2026, 7, 14),
    2017: date(2027, 10, 12),
    2019: date(2030, 1, 8),
    2022: date(2033, 1, 11),
}
SUPPORT_WARNING = timedelta(days=365)


@insight_rule
def version_support(findings):
    """Judge each start against the date it happened, not against today, so old logs stay reproducible."""
    out = []
    for startup in of_code(findings, "startup"):
        year = startup.details["version_year"]
        ends = EXTENDED_SUPPORT_END.get(year)
        if ends is None:
            continue
        when = startup.entry.timestamp.date()
        build = startup.details["build"]
        if when > ends:
            out.append(Insight(
                "version-unsupported",
                "SQL Server %d (%s) was out of support when it started: extended support ended %s" % (year, build, ends.isoformat()),
                "error", "high", [startup],
                "No security fixes are issued for this version any more. Plan the upgrade; until then restrict "
                "network access to it."))
        elif ends - when <= SUPPORT_WARNING:
            out.append(Insight(
                "version-ending",
                "SQL Server %d (%s) reaches the end of extended support on %s" % (year, build, ends.isoformat()),
                "warning", "high", [startup],
                "Schedule the upgrade before that date."))
        if startup.details["level"] == "RTM":
            out.append(Insight(
                "version-rtm",
                "SQL Server %d is running the original RTM build (%s) with no cumulative update" % (year, build),
                "warning", "medium", [startup],
                "Cumulative updates carry most of the fixes for a release, including several for the "
                "problems in this log. Apply the latest one after testing."))
    return out


# ---------------------------------------------------------------------------
# Unusual startup options
# ---------------------------------------------------------------------------

@insight_rule
def startup_options(findings):
    out = []
    for params in of_code(findings, "startup-params"):
        d = params.details
        if d["single_user"]:
            out.append(Insight(
                "startup-single-user",
                "%s was started in single-user mode (-m)" % (server_of(params) or "the instance"),
                "warning", "high", [params],
                "Only one connection is accepted, and an application or monitoring tool can take it before "
                "you do. Restart normally once the maintenance is done."))
        if d["minimal_configuration"]:
            out.append(Insight(
                "startup-minimal-config",
                "%s was started with minimal configuration (-f)" % (server_of(params) or "the instance"),
                "warning", "high", [params],
                "Minimal configuration starts in single-user mode with reduced memory and is meant for repairing "
                "a bad configuration setting. Restart normally afterwards."))
    return out
