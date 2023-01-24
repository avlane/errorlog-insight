"""Backup failures and completions."""
import re

from ..model import Finding
from ..registry import LABELS, rule

LABELS.update({
    "3041": "Backup failed (3041)",
    "18204": "Backup device error (18204)",
    "3201": "Backup device error (3201)",
    "4208": "BACKUP LOG on SIMPLE (4208)",
    "18264": "Backups completed",
    "18265": "Log backups completed",
})

BACKUP_FAILED_RE = re.compile(
    r"BACKUP failed to complete the command (?P<command>BACKUP (?P<kind>DATABASE|LOG)\s+"
    r"\[?(?P<db>[^\s\]]+)\]?.*?)\. Check the backup application log"
)
BACKUP_DEVICE_RE = re.compile(
    r"(?:BackupDiskFile::CreateMedia: Backup device '(?P<create>.+?)' failed to create"
    r"|Cannot open backup device '(?P<open>.+?)')\. Operating system error (?P<code>\d+)\((?P<text>.*?)\)\."
)
BACKUP_SIMPLE_RE = re.compile(r"The statement BACKUP LOG is not allowed while the recovery model is SIMPLE")
BACKUP_OK_RE = re.compile(
    r"(?P<what>Database|Log) (?:backed up|was backed up)\. Database: (?P<db>.+?), creation date\(time\): "
    r"(?P<created>[^,]+), (?:pages dumped: (?P<pages>\d+), )?first LSN: (?P<first>[\d:]+), last LSN: (?P<last>[\d:]+), "
    r"number of dump devices: (?P<devices>\d+), device information: \(FILE=(?P<file>\d+), TYPE=(?P<type>\w+): "
    r"\{'(?P<device>.+?)'\}\)"
)

OS_ERROR_ADVICE = {
    3: "The path does not exist: check the backup folder or share.",
    5: "Access denied: the SQL Server service account needs write permission on the target.",
    32: "The file is in use by another process (antivirus or another job).",
    53: "The network path was not found: check the file server name, DNS and the SMB path.",
    64: "The network name is no longer available: the share dropped mid-backup.",
    112: "The target volume is full: free space or move the backup folder.",
    1450: "Insufficient system resources: look at the file server and at memory pressure.",
}


@rule
def backup_failed(entry, ctx):
    m = BACKUP_FAILED_RE.search(entry.text)
    if not m:
        return None
    details = {
        "command": m.group("command"),
        "kind": m.group("kind").lower(),
        "database": m.group("db"),
    }
    advice = "Look at the entries just before this one for the underlying error (device, disk, permission)."
    title = "Backup of %s failed (%s)" % (details["database"], details["kind"])
    return Finding(entry, "backup", "3041", "error", title, details, advice)


@rule
def backup_device(entry, ctx):
    m = BACKUP_DEVICE_RE.search(entry.text)
    if not m:
        return None
    code = int(m.group("code"))
    device = m.group("create") or m.group("open")
    details = {
        "device": device,
        "os_error": code,
        "os_error_text": m.group("text"),
        "network": device.startswith("\\\\"),
    }
    advice = OS_ERROR_ADVICE.get(code, "Look up Windows error %d for the target device." % code)
    number = "18204" if m.group("create") else "3201"
    title = "Backup device %s: %s" % (device, m.group("text"))
    return Finding(entry, "backup", number, "error", title, details, advice)


@rule
def backup_on_simple(entry, ctx):
    if not BACKUP_SIMPLE_RE.search(entry.text):
        return None
    advice = "A log backup job targets a database in SIMPLE recovery. Remove it from the job or change the recovery model."
    return Finding(entry, "backup", "4208", "error", "BACKUP LOG attempted on a SIMPLE recovery database", {}, advice)


@rule
def backup_ok(entry, ctx):
    m = BACKUP_OK_RE.search(entry.text)
    if not m:
        return None
    is_db = m.group("what") == "Database"
    details = {
        "database": m.group("db"),
        "kind": "database" if is_db else "log",
        "first_lsn": m.group("first"),
        "last_lsn": m.group("last"),
        "device": m.group("device"),
        "pages": int(m.group("pages")) if m.group("pages") else None,
    }
    return Finding(entry, "backup", "18264" if is_db else "18265", "info",
                   "%s backup of %s completed" % (details["kind"].capitalize(), details["database"]), details)
