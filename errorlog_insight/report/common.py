"""Helpers shared by the text, JSON and HTML reports."""
import collections

from ..cluster import cluster_entries
from ..model import severity_rank


def group_findings(findings):
    """Group findings by message code, worst groups first."""
    groups = collections.OrderedDict()
    for f in findings:
        groups.setdefault(f.code, []).append(f)

    def worst(items):
        return max(severity_rank(f.severity) for f in items)

    return sorted(groups.items(), key=lambda kv: (-worst(kv[1]), -len(kv[1]), kv[0]))


def ranked_clusters(unknown, clusters=None):
    """Template groups, the ones that sound serious first, then by count.

    Pass `clusters` (from cluster_entries) when they were computed already; clustering a big log is
    the slowest part of the report.
    """
    if clusters is None:
        clusters = cluster_entries(unknown)
    return sorted(clusters, key=lambda c: -severity_rank(c.severity_guess))  # stable: count order is kept inside a level


def iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % (ts.microsecond // 1000)
