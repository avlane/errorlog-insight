"""Availability group messages: roles, replica state, data movement, failover blockers."""
import re

from ..model import Finding
from ..registry import LABELS, rule, header_numbers

LABELS.update({
    "1480": "AG database role change (1480)",
    "19406": "AG replica state change (19406)",
    "ag-transition": "AG role transition",
    "35264": "AG data movement suspended (35264)",
    "35265": "AG data movement resumed (35265)",
    "41142": "AG cannot become primary (41142)",
})

ROLE_CHANGE_RE = re.compile(
    r'The (?P<kind>availability group|mirroring) database "(?P<db>[^"]+)" is changing roles from '
    r'"(?P<old>\w+)" to "(?P<new>\w+)" because the mirroring session or availability group failed over '
    r'due to (?P<reason>[^.]+?)\.'
)
REPLICA_STATE_RE = re.compile(
    r"The state of the local availability replica in availability group '(?P<ag>[^']+)' has changed from "
    r"'(?P<old>\w+)' to '(?P<new>\w+)'\.\s+The state changed because (?P<reason>.+?)\.\s+For more information"
)
TRANSITION_RE = re.compile(
    r"Always ?On: The local replica of availability group '(?P<ag>[^']+)' is preparing to transition to the "
    r"(?P<role>\w+) role"
)

CANNOT_BE_PRIMARY_RE = re.compile(
    r"The availability replica for availability group '(?P<ag>[^']+)' on this instance of SQL Server cannot "
    r"become the primary replica\."
)

# A replica that is not in one of these states is not serving its role.
HEALTHY_REPLICA_STATES = ("PRIMARY_NORMAL", "SECONDARY_NORMAL")


@rule
def role_change(entry, ctx):
    m = ROLE_CHANGE_RE.search(entry.text)
    if not m:
        return None
    reason = m.group("reason")
    old, new = m.group("old"), m.group("new")
    planned = "manual" in reason or "role synchronization" in reason
    details = {"database": m.group("db"), "old_role": old, "new_role": new, "reason": reason, "planned": planned}
    severity = "info" if planned else "warning"
    if new == "RESOLVING" and not planned:
        advice = "An unplanned loss of the role: check the WSFC cluster log, quorum and the network between replicas."
    else:
        advice = ""
    title = "%s: %s -> %s (%s)" % (details["database"], old, new, reason)
    return Finding(entry, "ag", "1480", severity, title, details, advice)


@rule
def replica_state(entry, ctx):
    m = REPLICA_STATE_RE.search(entry.text)
    if not m:
        return None
    reason = m.group("reason")
    new = m.group("new")
    user = "user initiated" in reason
    details = {"ag": m.group("ag"), "old_state": m.group("old"), "new_state": new,
               "reason": reason, "user_initiated": user}
    if new in HEALTHY_REPLICA_STATES or user:
        severity = "info"
    else:
        severity = "warning"
    title = "%s: replica %s -> %s" % (details["ag"], m.group("old"), new)
    return Finding(entry, "ag", "19406", severity, title, details)


@rule
def ag_transition(entry, ctx):
    m = TRANSITION_RE.search(entry.text)
    if not m:
        return None
    details = {"ag": m.group("ag"), "role": m.group("role")}
    return Finding(entry, "ag", "ag-transition", "info",
                   "%s: preparing to become %s" % (details["ag"], details["role"]), details)



SUSPENDED_RE = re.compile(
    r"Always ?On Availability Groups data movement for database '(?P<db>[^']+)' has been suspended for the "
    r'following reason: "(?P<who>\w+)" \(Source ID (?P<sid>\d+); Source string: \'(?P<src>\w+)\'\)'
)
RESUMED_RE = re.compile(r"Always ?On Availability Groups data movement for database '(?P<db>[^']+)' has been resumed")

SUSPEND_ADVICE = {
    "SUSPEND_FROM_USER": "Someone ran ALTER DATABASE ... SET HADR SUSPEND. Resume it when the maintenance is done.",
    "SUSPEND_FROM_PARTNER": "The other replica suspended its side; look in its error log for the cause.",
    "SUSPEND_FROM_REDO": ("The redo thread on this secondary failed. Look just before this entry for a disk, "
                          "corruption (823/824) or log-full (9002) error on this replica."),
    "SUSPEND_FROM_APPLY": "Applying log on this replica failed. Look just before this entry for the error.",
    "SUSPEND_FROM_CAPTURE": "Log capture on the primary failed. Check the primary's log and disk.",
    "SUSPEND_FROM_RESTART": "The database came up suspended after a restart. Check why recovery of the AG state failed.",
    "SUSPEND_FROM_UNDO": "Undo after a failover failed on this replica; check the entries before this one.",
    "SUSPEND_FROM_REVALIDATION": ("Revalidation after a role change found this replica ahead of the new primary: "
                                  "the log diverged, and the database must be reseeded or restored."),
    "SUSPEND_FROM_XRF_UPDATE": "Updating the cross-replica fork information failed; check the entries before this one.",
}


@rule
def data_movement_suspended(entry, ctx):
    m = SUSPENDED_RE.search(entry.text)
    if not m:
        return None
    who = m.group("who")
    source = m.group("src")
    details = {"database": m.group("db"), "source": who, "source_id": int(m.group("sid")),
               "reason": source, "by_user": who == "user"}
    severity = "warning" if who == "user" else "error"
    advice = SUSPEND_ADVICE.get(source, "Find the error that preceded the suspend, fix it, then resume the database.")
    return Finding(entry, "ag", "35264", severity,
                   "Data movement suspended for %s (%s)" % (details["database"], source), details, advice)


@rule
def data_movement_resumed(entry, ctx):
    m = RESUMED_RE.search(entry.text)
    if not m:
        return None
    return Finding(entry, "ag", "35265", "info", "Data movement resumed for %s" % m.group("db"),
                   {"database": m.group("db")})


@rule
def cannot_become_primary(entry, ctx):
    m = CANNOT_BE_PRIMARY_RE.search(entry.text)
    if not m:
        return None
    details = {"ag": m.group("ag"), "force_quorum_hint": "Force Quorum" in entry.text}
    details.update(header_numbers(ctx, entry, 41142))
    advice = ("Check sys.dm_hadr_database_replica_states for databases that are not SYNCHRONIZED. If the old "
              "primary is gone, FAILOVER with ALLOW_DATA_LOSS brings this replica online; know how much "
              "data the asynchronous replica was behind before you do it.")
    return Finding(entry, "ag", "41142", "error",
                   "%s: this replica cannot become primary" % details["ag"], details, advice)
