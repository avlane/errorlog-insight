"""Parse trace flag 1222 deadlock output from the ERRORLOG.

With trace flag 1222 on, SQL Server writes the deadlock graph into the error
log one line per XML node, each line with its own timestamp and the system
spid that wrote it (for example spid17s). Attribute values are not quoted, so
the line

    process id=process1e8f3c8c8 taskpriority=0 waitresource=KEY: 5:7205 (a1b2) waittime=4120 ...

is split on " name=" boundaries instead of on whitespace.
"""
import re
from dataclasses import dataclass, field

BLOCK_GAP_SECONDS = 3

ATTR_RE = re.compile(r"(\w+)=(.*?)(?=\s+\w+=|$)")
RESOURCE_KINDS = (
    "keylock", "pagelock", "ridlock", "objectlock", "hobtlock", "extentlock",
    "allocationlock", "databaselock", "filelock", "metadatalock", "applicationlock",
    "exchangeEvent",
)


def parse_attrs(text):
    return {k: v.strip() for k, v in ATTR_RE.findall(text)}


@dataclass
class DeadlockProcess:
    id: str
    attrs: dict
    frames: list = field(default_factory=list)  # [{"procname": ..., "line": ..., "text": ...}]
    inputbuf: str = ""

    @property
    def spid(self):
        return int(self.attrs["spid"]) if self.attrs.get("spid", "").isdigit() else None

    @property
    def ecid(self):
        """Execution context: 0 is the coordinating thread, above 0 is a parallel worker."""
        value = self.attrs.get("ecid", "")
        return int(value) if value.isdigit() else 0

    @property
    def database(self):
        return self.attrs.get("currentdbname")

    @property
    def login(self):
        return self.attrs.get("loginname")

    @property
    def app(self):
        return self.attrs.get("clientapp")

    @property
    def host(self):
        return self.attrs.get("hostname")

    @property
    def wait_resource(self):
        return self.attrs.get("waitresource")

    @property
    def isolation(self):
        return self.attrs.get("isolationlevel")

    @property
    def procedure(self):
        """Name of the first stored procedure on the stack, if any."""
        for frame in self.frames:
            name = frame.get("procname", "")
            if name and name != "adhoc":
                return name
        return None

    @property
    def statement(self):
        for frame in self.frames:
            if frame.get("text"):
                return frame["text"]
        return self.inputbuf or None


@dataclass
class DeadlockResource:
    kind: str
    attrs: dict
    owners: list = field(default_factory=list)   # [(process id, mode)]
    waiters: list = field(default_factory=list)  # [(process id, mode)]

    @property
    def object_name(self):
        return self.attrs.get("objectname")

    @property
    def index_name(self):
        return self.attrs.get("indexname")

    @property
    def mode(self):
        return self.attrs.get("mode")


@dataclass
class Deadlock:
    victims: list = field(default_factory=list)
    processes: list = field(default_factory=list)
    resources: list = field(default_factory=list)

    def process(self, process_id):
        for p in self.processes:
            if p.id == process_id:
                return p
        return None

    def edges(self):
        """(waiter process, owner process, resource) triples: who waits for whom."""
        out = []
        for res in self.resources:
            for waiter, _ in res.waiters:
                for owner, _ in res.owners:
                    out.append((waiter, owner, res))
        return out


def collect_block(entries, start):
    """Return the index just past the deadlock block that starts at entries[start].

    The graph is written by one system spid in a burst, so the block runs until
    another process writes, the gap grows, or the next graph starts.
    """
    first = entries[start]
    end = start + 1
    last_time = first.timestamp
    while end < len(entries):
        e = entries[end]
        if e.process != first.process or e.text.strip() == "deadlock-list":
            break
        if (e.timestamp - last_time).total_seconds() > BLOCK_GAP_SECONDS:
            break
        last_time = e.timestamp
        end += 1
    return end


def parse_block(entries):
    dl = Deadlock()
    state = None
    process = None
    frame = None
    resource = None
    side = None
    for entry in entries:
        for raw in entry.text.split("\n"):
            line = raw.strip()
            if not line:
                continue
            word = line.split(" ", 1)[0]
            if line == "deadlock-list" or line == "process-list" or line == "victim-list":
                state = None
            elif line.startswith("deadlock victim="):
                dl.victims.append(line.split("=", 1)[1].strip())
            elif word == "victimProcess":
                dl.victims.append(parse_attrs(line[len(word):])["id"])
            elif word == "process" and line.startswith("process id="):
                attrs = parse_attrs(line[len("process "):])
                process = DeadlockProcess(attrs["id"], attrs)
                dl.processes.append(process)
                state = "process"
            elif line == "executionStack":
                state = "stack"
            elif word == "frame" and process is not None:
                frame = parse_attrs(line[len("frame "):])
                frame["text"] = ""
                process.frames.append(frame)
                state = "frame"
            elif line == "inputbuf":
                state = "inputbuf"
            elif line == "resource-list":
                state = "resources"
            elif word in RESOURCE_KINDS:
                resource = DeadlockResource(word, parse_attrs(line[len(word):]))
                dl.resources.append(resource)
                state = "resource"
            elif line == "owner-list":
                side = "owners"
            elif line == "waiter-list":
                side = "waiters"
            elif word in ("owner", "waiter") and resource is not None and "id=" in line:
                attrs = parse_attrs(line[len(word):])
                # lock resources say mode=, exchange events say event= instead
                getattr(resource, side or word + "s").append((attrs["id"], attrs.get("mode") or attrs.get("event")))
            elif state == "frame" and frame is not None:
                frame["text"] = (frame["text"] + " " + line).strip()
            elif state == "inputbuf" and process is not None:
                process.inputbuf = (process.inputbuf + " " + line).strip()
    return dl
