"""Burst detection against a rolling baseline.

Events are counted in fixed-width buckets. A bucket is a burst when it holds
at least `min_count` events and at least `factor` times the average of the
`window` buckets before it. Neighbouring burst buckets are merged.

Two details keep the baseline honest:

* buckets that were themselves bursts are left out of the history, so one
  burst does not hide the next one;
* near the start of the log the average is taken over the buckets that exist,
  not over a full window of mostly empty ones, which would make every early
  event look like a spike.

This is deliberately plain arithmetic: no seasonality, no model, nothing that
cannot be checked with a calculator.
"""
from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

EPOCH = datetime(2000, 1, 1)


@dataclass
class BurstConfig:
    bucket_seconds: int = 60
    window: int = 30       # buckets of history that make the baseline
    factor: float = 3.0
    min_count: int = 5


@dataclass
class Burst:
    key: str
    start: datetime
    end: datetime
    count: int
    peak: int
    baseline: float
    label: str = ""   # human readable name when the key is not a finding code


def _bucket_index(ts, width):
    return int((ts - EPOCH).total_seconds() // width)


def detect_bursts(timestamps: list[datetime], config: BurstConfig | None = None, key: str = "") -> list[Burst]:
    """Return the Burst objects found in a list of datetimes."""
    config = config or BurstConfig()
    counts = defaultdict(int)
    for ts in timestamps:
        counts[_bucket_index(ts, config.bucket_seconds)] += 1
    occupied = sorted(counts)
    bursts = []
    current = None
    burst_buckets = set()
    first_idx = occupied[0] if occupied else 0
    for pos, idx in enumerate(occupied):
        window_start = bisect_left(occupied, idx - config.window, 0, pos)
        history = sum(counts[j] for j in occupied[window_start:pos] if j not in burst_buckets)
        covered = min(config.window, idx - first_idx)  # buckets of log behind this one, up to a window
        baseline = history / float(covered) if covered else 0.0
        count = counts[idx]
        is_burst = count >= config.min_count and count >= config.factor * baseline
        if is_burst:
            burst_buckets.add(idx)
            if current is not None and idx - current["last"] <= 1:
                current["last"] = idx
                current["count"] += count
                current["peak"] = max(current["peak"], count)
                current["baseline"] = max(current["baseline"], baseline)
            else:
                if current is not None:
                    bursts.append(_finish(current, config, key))
                current = {"first": idx, "last": idx, "count": count, "peak": count, "baseline": baseline}
        elif current is not None:
            bursts.append(_finish(current, config, key))
            current = None
    if current is not None:
        bursts.append(_finish(current, config, key))
    return bursts


def _finish(c, config, key):
    start = EPOCH + timedelta(seconds=c["first"] * config.bucket_seconds)
    end = EPOCH + timedelta(seconds=(c["last"] + 1) * config.bucket_seconds)
    return Burst(key, start, end, c["count"], c["peak"], round(c["baseline"], 3))


def find_bursts(findings, config=None, min_severity_rank=1):
    """Bursts per finding code, ignoring findings below the given severity rank."""
    from .model import severity_rank

    by_code = defaultdict(list)
    for f in findings:
        if severity_rank(f.severity) >= min_severity_rank:
            by_code[f.code].append(f.entry.timestamp)
    bursts = []
    for code, stamps in by_code.items():
        bursts.extend(detect_bursts(stamps, config, key=code))
    return sorted(bursts, key=lambda b: (b.start, b.key))


def find_template_bursts(clusters, config=None, min_severity_rank=1):
    """Bursts of unrecognised messages, per template group.

    Only templates whose words sound at least as serious as `min_severity_rank` (1 is warning) are
    considered: a burst of "Starting up database" at startup is expected.
    """
    from .model import severity_rank

    bursts = []
    for cluster in clusters:
        if severity_rank(cluster.severity_guess) < min_severity_rank:
            continue
        for b in detect_bursts(cluster.timestamps, config, key="template:" + cluster.id):
            b.label = cluster.template
            bursts.append(b)
    return sorted(bursts, key=lambda b: (b.start, b.key))
