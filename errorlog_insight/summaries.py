"""Roll individual findings up into per-subject summaries."""
from collections import Counter, OrderedDict
from datetime import timedelta

EPISODE_GAP = timedelta(minutes=10)

# 18456 states that mean "this name or password is wrong" (as opposed to a database or server problem)
GUESSING_STATES = (2, 5, 8, 9)
BRUTE_FORCE_ATTEMPTS = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=5)
SPRAY_USERS = 3
SPRAY_WINDOW = timedelta(minutes=10)
REPEATING_ATTEMPTS = 10
REPEATING_SPAN = timedelta(hours=2)


def io_summary(findings):
    """Slow I/O per file: how often, how bad, and in how many separate episodes.

    A new episode starts when the file was quiet for ten minutes. The rows are
    sorted worst first (longest wait, then most requests).
    """
    files = OrderedDict()
    for f in findings:
        if f.code != "833":
            continue
        d = f.details
        row = files.get(d["file"])
        if row is None:
            row = files[d["file"]] = {
                "file": d["file"], "volume": d["volume"], "database": d["database"],
                "file_kind": d["file_kind"], "messages": 0, "requests": 0, "max_seconds": 0,
                "first": f.entry.timestamp, "last": f.entry.timestamp, "episodes": 0, "_prev": None,
            }
        row["messages"] += 1
        row["requests"] += d["count"]
        row["max_seconds"] = max(row["max_seconds"], d["seconds"])
        row["first"] = min(row["first"], f.entry.timestamp)
        row["last"] = max(row["last"], f.entry.timestamp)
        if row["_prev"] is None or f.entry.timestamp - row["_prev"] > EPISODE_GAP:
            row["episodes"] += 1
        row["_prev"] = f.entry.timestamp
    rows = list(files.values())
    for row in rows:
        del row["_prev"]
    rows.sort(key=lambda r: (-r["max_seconds"], -r["requests"], r["file"]))
    return rows


def _busiest_window(events, window, value=lambda e: e):
    """Most distinct value(e) seen in any span of `window` (events are (time, ...) tuples in time order)."""
    best, start = 0, 0
    for end in range(len(events)):
        while events[end][0] - events[start][0] > window:
            start += 1
        best = max(best, len({value(e) for e in events[start:end + 1]}))
    return best


def _login_pattern(events):
    """Name the likely cause of a client's failures. events: sorted (time, user, state) tuples."""
    guesses = [e for e in events if e[2] in GUESSING_STATES]
    if guesses:
        by_user = {}
        for e in guesses:
            by_user.setdefault(e[1], []).append(e)
        for user_events in by_user.values():
            # every attempt counts, so use the position as the distinct value
            numbered = [(e[0], i) for i, e in enumerate(user_events)]
            if _busiest_window(numbered, BRUTE_FORCE_WINDOW, lambda e: e[1]) >= BRUTE_FORCE_ATTEMPTS:
                return "password guessing"
        if _busiest_window(guesses, SPRAY_WINDOW, lambda e: e[1]) >= SPRAY_USERS:
            return "many users tried"
    if len(events) >= REPEATING_ATTEMPTS and events[-1][0] - events[0][0] >= REPEATING_SPAN:
        return "repeating client"
    return "occasional"


def login_summary(findings):
    """18456 failures per client address with a guess at what is going on there.

    Patterns: "password guessing" (five or more wrong passwords for one login
    within five minutes), "many users tried" (three or more different logins
    within ten minutes), "repeating client" (ten or more failures spread over
    two hours or more, typically a service with a stale credential or database)
    and "occasional". Worst patterns first, then most failures.
    """
    clients = OrderedDict()
    for f in findings:
        if f.code != "18456":
            continue
        d = f.details
        client = d.get("client") or "unknown"
        clients.setdefault(client, []).append((f.entry.timestamp, d["user"], d["state"]))
    rows = []
    for client, events in clients.items():
        events.sort(key=lambda e: e[0])
        rows.append({
            "client": client,
            "failures": len(events),
            "users": sorted({e[1] for e in events}),
            "states": dict(sorted(Counter(e[2] for e in events).items(), key=lambda kv: (kv[0] is None, kv[0]))),
            "first": events[0][0],
            "last": events[-1][0],
            "pattern": _login_pattern(events),
        })
    order = {"password guessing": 0, "many users tried": 1, "repeating client": 2, "occasional": 3}
    rows.sort(key=lambda r: (order[r["pattern"]], -r["failures"], r["client"]))
    return rows
