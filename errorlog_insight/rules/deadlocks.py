"""Trace flag 1222 deadlock graphs."""
from .. import deadlock as deadlock_graph
from ..model import Finding
from ..registry import LABELS, block_rule

LABELS.update({
    "1222": "Deadlocks (1222)",
})

@block_rule(lambda entry: entry.text.strip() == "deadlock-list")
def deadlock_rule(entries, i):
    end = deadlock_graph.collect_block(entries, i)
    return summarise_deadlock(entries[i], deadlock_graph.parse_block(entries[i:end])), end


def summarise_deadlock(entry, dl):
    victims = [dl.process(v) for v in dl.victims]
    victims = [v for v in victims if v is not None]
    objects = []
    for res in dl.resources:
        if res.object_name and res.object_name not in objects:
            objects.append(res.object_name)
    kinds = sorted({res.kind for res in dl.resources})
    details = {
        "victims": [
            {"spid": v.spid, "login": v.login, "app": v.app, "host": v.host,
             "procedure": v.procedure, "statement": v.statement}
            for v in victims
        ],
        "processes": [
            {"spid": p.spid, "login": p.login, "app": p.app, "host": p.host, "database": p.database,
             "procedure": p.procedure, "statement": p.statement, "wait_resource": p.wait_resource,
             "isolation": p.isolation}
            for p in dl.processes
        ],
        "objects": objects,
        "lock_kinds": kinds,
        "database": dl.processes[0].database if dl.processes else None,
    }
    advice = []
    if any(k in ("pagelock", "ridlock") for k in kinds):
        advice.append("Page or row-id locks point at heap or scan access: check for a missing index on %s."
                      % ", ".join(objects))
    if "keylock" in kinds and len(objects) > 1:
        advice.append("The sessions take %s in opposite orders; make every code path touch them in the same order."
                      % " and ".join(objects))
    if all((p.isolation or "").startswith("read committed") for p in dl.processes) and dl.processes:
        advice.append("Everything ran at READ COMMITTED; READ_COMMITTED_SNAPSHOT removes reader-writer deadlocks.")
    if victims:
        who = victims[0]
        title = "Deadlock on %s: victim spid %s%s" % (
            ", ".join(objects) or "unknown objects", who.spid,
            " (%s)" % (who.procedure or who.app) if (who.procedure or who.app) else "")
    else:
        title = "Deadlock on %s" % (", ".join(objects) or "unknown objects")
    return Finding(entry, "deadlock", "1222", "error", title, details, " ".join(advice))
