"""Non-yielding schedulers (17883) and worker starvation (17884)."""
import re

from ..model import Finding
from ..registry import LABELS, rule

LABELS.update({
    "17883": "Non-yielding (17883)",
    "17884": "Worker starvation (17884)",
})

NON_YIELDING_RE = re.compile(
    r"Process (?P<spid>\d+:\d+:\d+) \((?P<thread>0x[0-9A-Fa-f]+)\) Worker (?P<worker>0x[0-9A-Fa-f]+) "
    r"appears to be non-yielding on Scheduler (?P<scheduler>\d+)\. "
    r"Thread creation time: (?P<created>\d+)\. "
    r"Approx Thread CPU Used: kernel (?P<kernel>\d+) ms, user (?P<user>\d+) ms\. "
    r"Process Utilization (?P<util>\d+)%\. System Idle (?P<idle>\d+)%\. Interval: (?P<interval>\d+) ms\."
)

STARVATION_RE = re.compile(
    r"New queries assigned to process on Node (?P<node>\d+) have not been picked up by a worker thread "
    r"in the last (?P<seconds>\d+) seconds\..*?"
    r"SQL Process Utilization: (?P<util>\d+)%\. System Idle: (?P<idle>\d+)%\.",
    re.S,
)


@rule
def non_yielding(entry, ctx):
    m = NON_YIELDING_RE.search(entry.text)
    if not m:
        return None
    kernel, user = int(m.group("kernel")), int(m.group("user"))
    interval = int(m.group("interval"))
    cpu_ms = kernel + user
    cpu_share = cpu_ms / interval if interval else 0.0
    if cpu_share >= 0.7:
        pattern = "cpu-bound"
        advice = ("The worker burned CPU the whole time without yielding: look for a runaway scan or "
                  "loop, a CLR or regex-heavy function, or a bug fixed in a later cumulative update.")
    elif cpu_share <= 0.1:
        pattern = "stalled"
        advice = ("The worker used almost no CPU while it held the scheduler, so it was waiting outside "
                  "SQL Server: preemptive calls (linked server, extended procedure), paging, a driver "
                  "or antivirus. Check what else happened at this time.")
    else:
        pattern = "mixed"
        advice = "Partly running and partly waiting; correlate with stack dumps and memory messages."
    details = {
        "scheduler": int(m.group("scheduler")),
        "worker": m.group("worker"),
        "kernel_ms": kernel,
        "user_ms": user,
        "interval_ms": interval,
        "cpu_share": round(cpu_share, 2),
        "process_utilization": int(m.group("util")),
        "system_idle": int(m.group("idle")),
        "pattern": pattern,
    }
    severity = "critical" if interval >= 120000 else "error"
    title = "Scheduler %d non-yielding for %.0f s (%s)" % (details["scheduler"], interval / 1000.0, pattern)
    return Finding(entry, "scheduler", "17883", severity, title, details, advice)


@rule
def worker_starvation(entry, ctx):
    m = STARVATION_RE.search(entry.text)
    if not m:
        return None
    seconds = int(m.group("seconds"))
    details = {
        "node": int(m.group("node")),
        "seconds": seconds,
        "process_utilization": int(m.group("util")),
        "system_idle": int(m.group("idle")),
    }
    advice = ("No worker thread was free. Check for a blocking chain holding many workers, THREADPOOL "
              "waits, and whether max worker threads is sensible for the core count.")
    severity = "critical" if seconds >= 180 else "error"
    title = "New queries waited %d s for a worker thread" % seconds
    return Finding(entry, "scheduler", "17884", severity, title, details, advice)
