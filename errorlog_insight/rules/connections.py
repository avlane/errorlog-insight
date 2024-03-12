"""Connection problems: SSPI handshake failures (17806), untrusted domains (18452), not ready (17187)."""
import re

from ..model import Finding
from ..registry import LABELS, header_numbers, rule

LABELS.update({
    "17806": "SSPI handshake failed (17806)",
    "18452": "Untrusted domain login (18452)",
    "17187": "Not ready for connections (17187)",
})

SSPI_RE = re.compile(
    r"SSPI handshake failed with error code (?P<code>0x[0-9A-Fa-f]+), state (?P<state>\d+) while establishing a "
    r"connection with integrated security; the connection has been closed\. Reason: (?P<reason>[^.]+)\."
    r"(?: The Windows error code indicates the cause of failure\. (?P<cause>.*?))?\s*"
    r"(?:\[CLIENT: (?P<client>[^\]]*)\])?\s*$",
    re.S,
)
UNTRUSTED_RE = re.compile(
    r"Login failed\. The login is from an untrusted domain and cannot be used with Windows authentication\."
    r"(?: \[CLIENT: (?P<client>[^\]]*)\])?"
)
NOT_READY_RE = re.compile(
    r"SQL Server is not ready to accept new client connections\..*?(?:\[CLIENT: (?P<client>[^\]]*)\])?\s*$", re.S)

# SSPI status code -> (short meaning, what to check)
SSPI_CODES = {
    "0x80090311": ("no domain controller could be contacted",
                   "Check that the SQL Server host and the client can reach a domain controller, and DNS."),
    "0x8009030c": ("the logon attempt failed",
                   "Check the account (locked, expired, disabled) and the clock difference between client and server."),
    "0x80090304": ("the local security authority cannot be contacted",
                   "Check the Netlogon service and LSASS health on the SQL Server machine."),
    "0x8009030b": ("no credentials are available in the security package",
                   "The client sent no usable credentials: double hop, or a service running as a local account."),
    "0x80090308": ("the token supplied to the function is invalid",
                   "Often a Kerberos ticket that is too large or malformed; check group membership size and SPNs."),
    "0x8009030d": ("the credentials supplied were not recognized",
                   "Check the account and the domain trust between the client and the server."),
    "0x80090322": ("the target principal name is incorrect",
                   "A Kerberos SPN problem: look for duplicate or missing MSSQLSvc SPNs (setspn -L)."),
}


@rule
def sspi_failed(entry, ctx):
    m = SSPI_RE.search(entry.text)
    if not m:
        return None
    code = m.group("code").lower()
    meaning, advice = SSPI_CODES.get(code, ("unrecognised SSPI status", "Look the status code up in the Windows SSPI error list."))
    details = {
        "status": code,
        "state": int(m.group("state")),
        "meaning": meaning,
        "client": m.group("client"),
        "windows_text": (m.group("cause") or "").strip() or None,
    }
    details.update(header_numbers(ctx, entry, 17806))
    return Finding(entry, "connection", "17806", "warning",
                   "Windows authentication failed for %s: %s" % (details["client"] or "a client", meaning), details, advice)


@rule
def untrusted_domain(entry, ctx):
    m = UNTRUSTED_RE.search(entry.text)
    if not m:
        return None
    details = {"client": m.group("client")}
    advice = "The client's domain is not trusted by the server's domain. Use a SQL login, or fix the trust."
    return Finding(entry, "connection", "18452", "warning", "Login from an untrusted domain", details, advice)


@rule
def not_ready(entry, ctx):
    m = NOT_READY_RE.search(entry.text)
    if not m:
        return None
    details = {"client": m.group("client")}
    advice = "Clients connected while the server was starting or recovering. Check for a restart or a long recovery just before."
    return Finding(entry, "connection", "17187", "warning", "Connection refused: server not ready", details, advice)
