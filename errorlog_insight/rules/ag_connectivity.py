"""Availability group connectivity between replicas: 1479, 35201, 35202, 35206."""
import re

from ..model import Finding
from ..registry import LABELS, header_numbers, rule

LABELS.update({
    "1479": "Mirroring connection timeout (1479)",
    "35201": "AG connect timeout (35201)",
    "35202": "AG connection established (35202)",
    "35206": "AG connection lost (35206)",
})

MIRROR_TIMEOUT_RE = re.compile(
    r'The mirroring connection to "(?P<endpoint>[^"]+)" has timed out for database "(?P<db>[^"]+)" after '
    r"(?P<seconds>\d+) seconds without a response"
)
CONNECT_TIMEOUT_RE = re.compile(
    r"A connection timeout has occurred while attempting to establish a connection to availability replica "
    r"'(?P<replica>[^']+)' with id \[(?P<id>[0-9A-Fa-f-]+)\]"
)
PREVIOUS_TIMEOUT_RE = re.compile(
    r"A connection timeout has occurred on a previously established connection to availability replica "
    r"'(?P<replica>[^']+)' with id \[(?P<id>[0-9A-Fa-f-]+)\]"
)
ESTABLISHED_RE = re.compile(
    r"A connection for availability group '(?P<ag>[^']+)' from availability replica '(?P<src>[^']+)' with id\s+"
    r"\[(?P<src_id>[0-9A-Fa-f-]+)\] to '(?P<dst>[^']+)' with id \[(?P<dst_id>[0-9A-Fa-f-]+)\] has been successfully established"
)

NETWORK_ADVICE = ("Check the network path to the replica on the endpoint port (default 5022): firewall rules, "
                  "NIC and switch errors, and whether the other instance is up or has moved to RESOLVING.")


@rule
def mirroring_timeout(entry, ctx):
    m = MIRROR_TIMEOUT_RE.search(entry.text)
    if not m:
        return None
    details = {"endpoint": m.group("endpoint"), "database": m.group("db"), "seconds": int(m.group("seconds"))}
    details.update(header_numbers(ctx, entry, 1479))
    return Finding(entry, "ag", "1479", "warning",
                   "Timeout talking to %s for %s" % (details["endpoint"], details["database"]), details, NETWORK_ADVICE)


@rule
def replica_connect_timeout(entry, ctx):
    m = CONNECT_TIMEOUT_RE.search(entry.text)
    if not m:
        return None
    details = {"replica": m.group("replica"), "replica_id": m.group("id").upper()}
    details.update(header_numbers(ctx, entry, 35201))
    advice = NETWORK_ADVICE + " Also check that the endpoint address configured for the replica really is its mirroring endpoint."
    return Finding(entry, "ag", "35201", "warning",
                   "Cannot connect to replica %s" % details["replica"], details, advice)


@rule
def replica_connection_lost(entry, ctx):
    m = PREVIOUS_TIMEOUT_RE.search(entry.text)
    if not m:
        return None
    details = {"replica": m.group("replica"), "replica_id": m.group("id").upper()}
    details.update(header_numbers(ctx, entry, 35206))
    return Finding(entry, "ag", "35206", "warning",
                   "Lost the connection to replica %s" % details["replica"], details, NETWORK_ADVICE)


@rule
def replica_connected(entry, ctx):
    m = ESTABLISHED_RE.search(entry.text)
    if not m:
        return None
    details = {"ag": m.group("ag"), "from": m.group("src"), "to": m.group("dst"),
               "to_id": m.group("dst_id").upper()}
    return Finding(entry, "ag", "35202", "info",
                   "%s: connection %s -> %s established" % (details["ag"], details["from"], details["to"]), details)
