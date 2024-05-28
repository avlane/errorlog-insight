"""Availability groups and the Windows cluster: lease expiry (19407, 19421) and quorum loss (41005)."""
import re

from ..model import Finding
from ..registry import LABELS, header_numbers, rule

LABELS.update({
    "19407": "AG lease expired (19407)",
    "19421": "AG lease renewal failed (19421)",
    "41005": "Replica manager offline (41005)",
})

LEASE_EXPIRED_RE = re.compile(
    r"The lease between availability group '(?P<ag>[^']+)' and the Windows Server Failover Cluster has expired"
)
LEASE_RENEWAL_RE = re.compile(
    r"The renewal of the lease between availability group '(?P<ag>[^']+)' and the Windows Server Failover "
    r"Cluster failed because (?P<why>.+?)\."
)
QUORUM_RE = re.compile(
    r"Always ?On: The availability replica manager is going offline because the local Windows Server Failover "
    r"Clustering \(WSFC\) node has lost quorum"
)

LEASE_ADVICE = ("SQL Server and the cluster stopped hearing each other for longer than the lease timeout "
                "(20 s by default). Look just before this for a non-yielding scheduler (17883), a stalled VM "
                "(snapshot, vMotion), CPU starvation or network loss to the cluster, and check the cluster log.")


@rule
def lease_expired(entry, ctx):
    m = LEASE_EXPIRED_RE.search(entry.text)
    if not m:
        return None
    details = {"ag": m.group("ag")}
    details.update(header_numbers(ctx, entry, 19407))
    return Finding(entry, "ag", "19407", "critical",
                   "%s: lease with the cluster expired" % details["ag"], details, LEASE_ADVICE)


@rule
def lease_renewal_failed(entry, ctx):
    m = LEASE_RENEWAL_RE.search(entry.text)
    if not m:
        return None
    details = {"ag": m.group("ag"), "because": m.group("why")}
    details.update(header_numbers(ctx, entry, 19421))
    return Finding(entry, "ag", "19421", "error",
                   "%s: lease renewal failed (%s)" % (details["ag"], details["because"]), details, LEASE_ADVICE)


@rule
def quorum_lost(entry, ctx):
    if not QUORUM_RE.search(entry.text):
        return None
    advice = ("The node lost cluster quorum, so every availability group on it went offline. Check the other "
              "nodes, the witness (file share or cloud) and the cluster network.")
    return Finding(entry, "ag", "41005", "critical", "Availability replica manager offline: cluster quorum lost",
                   {}, advice)
