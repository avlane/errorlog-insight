"""Roll individual findings up into per-subject summaries."""
from collections import OrderedDict
from datetime import timedelta

EPISODE_GAP = timedelta(minutes=10)


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
