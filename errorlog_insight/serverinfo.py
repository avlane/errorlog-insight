"""What the startup messages say about the server itself.

Every start writes the version banner followed by a few dozen lines about the
machine: processors, memory, authentication mode, service account, virtual
machine hints. This collects them per start, per server.
"""
import re
from datetime import timedelta

from .rules.lifecycle import BANNER_RE, EDITION_RE

STARTUP_WINDOW = timedelta(seconds=60)

PATTERNS = (
    ("cpu", re.compile(
        r"SQL Server detected (?P<sockets>\d+) sockets? with (?P<cores>\d+) cores? per socket and "
        r"(?P<per_socket>\d+) logical processors? per socket, (?P<total>\d+) total logical processors; "
        r"using (?P<used>\d+) logical processors")),
    ("ram", re.compile(r"Detected (?P<mb>\d+) MB of RAM")),
    ("auth", re.compile(r"Authentication mode is (?P<mode>\w+)\.")),
    ("account", re.compile(r"The service account is '(?P<account>[^']+)'")),
    ("machine", re.compile(r"System Manufacturer: '(?P<manufacturer>[^']*)', System Model: '(?P<model>[^']*)'")),
    ("utc", re.compile(r"UTC adjustment: (?P<sign>[+-]?)(?P<hours>\d+):(?P<minutes>\d+)")),
    ("collation", re.compile(r"Default collation: (?P<collation>.+?) \(")),
    ("pid", re.compile(r"Server process ID is (?P<pid>\d+)")),
)

# (manufacturer, model) fragments that mean "this is a virtual machine"
VIRTUAL_HINTS = ("vmware", "virtual machine", "xen", "innotek", "qemu", "kvm", "amazon ec2", "google compute",
                 "virtualbox", "hvm")


def _is_virtual(manufacturer, model):
    text = ("%s %s" % (manufacturer, model)).lower()
    return any(h in text for h in VIRTUAL_HINTS)


def collect_server_info(entries):
    """One dict per start found in the entries, in time order.

    A start is the version banner plus the entries from the same server in the
    following minute. Fields the log does not mention are left out.
    """
    ordered = sorted(entries, key=lambda e: (e.replica, e.timestamp, e.lineno))
    starts = []
    for i, entry in enumerate(ordered):
        banner = BANNER_RE.match(entry.text)
        if not banner:
            continue
        info = {
            "server": entry.replica or entry.source,
            "started": entry.timestamp,
            "version_year": int(banner.group("year")),
            "level": banner.group("level"),
            "kb": banner.group("kb"),
            "build": banner.group("build"),
            "architecture": banner.group("arch"),
        }
        edition = EDITION_RE.search(entry.text)
        if edition:
            info["edition"] = edition.group("edition")
            info["os"] = edition.group("os").strip()
            info["platform"] = "linux" if info["os"].lower().startswith("linux") else "windows"
        for later in ordered[i + 1:]:
            if later.replica != entry.replica or later.timestamp - entry.timestamp > STARTUP_WINDOW:
                break
            if BANNER_RE.match(later.text):
                break
            for name, regex in PATTERNS:
                m = regex.search(later.text)
                if m and name not in info:
                    info[name] = m.groupdict()
        starts.append(info)
    return [_tidy(s) for s in sorted(starts, key=lambda s: (s["started"], s["server"]))]


def _tidy(info):
    """Turn the raw regex groups into plain fields."""
    out = {k: v for k, v in info.items() if k not in ("cpu", "ram", "auth", "account", "machine", "utc", "collation", "pid")}
    if "cpu" in info:
        cpu = info["cpu"]
        out["logical_processors"] = int(cpu["total"])
        out["logical_processors_used"] = int(cpu["used"])
        out["sockets"] = int(cpu["sockets"])
    if "ram" in info:
        out["memory_mb"] = int(info["ram"]["mb"])
    if "auth" in info:
        out["authentication"] = info["auth"]["mode"].lower()
    if "account" in info:
        out["service_account"] = info["account"]["account"]
    if "machine" in info:
        m = info["machine"]
        out["manufacturer"], out["model"] = m["manufacturer"], m["model"]
        out["virtual"] = _is_virtual(m["manufacturer"], m["model"])
    if "utc" in info:
        u = info["utc"]
        minutes = int(u["hours"]) * 60 + int(u["minutes"])
        out["utc_offset_minutes"] = -minutes if u["sign"] == "-" else minutes
    if "collation" in info:
        out["collation"] = info["collation"]["collation"]
    if "pid" in info:
        out["process_id"] = int(info["pid"]["pid"])
    return out


def _short_os(text):
    """'Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)' -> 'Windows Server 2019 Standard 10.0'."""
    text = re.sub(r"\s*<[^>]*>", "", text)
    return re.sub(r"\s*\((?:Build [^)]*|Hypervisor)\)", "", text).strip()


def describe(info):
    """One line for a report."""
    parts = ["SQL Server %s %s (%s)" % (info["version_year"], info["level"], info["build"])]
    if info.get("edition"):
        parts.append(info["edition"].replace(" (64-bit)", ""))
    if info.get("os"):
        parts.append(_short_os(info["os"]))
    if "logical_processors" in info:
        parts.append("%d logical CPUs" % info["logical_processors"])
    if "memory_mb" in info:
        parts.append("%.0f GB RAM" % (info["memory_mb"] / 1024.0))
    if "authentication" in info:
        parts.append("%s authentication" % info["authentication"])
    if info.get("virtual"):
        parts.append("virtual machine")
    return ", ".join(parts)
