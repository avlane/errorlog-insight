"""Replace identifying values with stable pseudonyms before a report is shared.

--redact swaps, consistently across all files given:

* IPv4 addresses for addresses from the documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x),
  so they still look like addresses and still group the same way;
* Windows accounts DOMAIN\\name for DOMAIN1\\user-1 and so on, and SQL logins for login-1
  (sa and the built-in NT AUTHORITY and NT SERVICE accounts are kept);
* server names: the labels given on the command line, the "Server name is" line, UNC servers
  (\\\\server\\share), TCP endpoints and the hostname= of a deadlock graph, for server-1 ...;
* file paths of the input files, for file-1 ...

Database names, file names inside the server, queries and message numbers are left alone, because the
reader of the report needs them. The replacement happens on the entries before they are classified,
so every output (text, HTML, JSON, baselines) is redacted the same way. It is a convenience, not a
guarantee: read the report before you send it.
"""
import re

KEEP_LOGINS = {"sa"}
DOC_RANGES = ("192.0.2.", "198.51.100.", "203.0.113.")

TOKEN_RE = re.compile(
    r"(?P<path>[A-Za-z]:\\[^\s'\"\])]*)"                          # C:\...: kept as is, and protects what is inside
    r"|(?P<builtin>NT (?:AUTHORITY|SERVICE)\\[\w$.-]+)"          # kept
    r"|\\\\(?P<unc>[\w.-]+)(?P<uncrest>\\[^\s'\"\])]*)?"                 # \\server\share\dir: only the server changes
    r"|(?P<ip>(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d))"
    r"|\b(?P<domain>[A-Za-z][\w-]+)\\(?P<account>[A-Za-z_][\w.$-]*)"
    r"|(?<=TCP://)(?P<endpoint>[\w.-]+)"
    r"|(?<=hostname=)(?P<hostname>\S+)"
    r"|(?<=loginname=)(?P<loginname>\S+)"
    r"|(?<=Login failed for user ')(?P<login>(?:[^']|'')*)(?=')"
)
SERVER_NAME_RE = re.compile(r"Server name is '([^']+)'")


class Redactor:
    def __init__(self):
        self.ips = {}
        self.domains = {}
        self.accounts = {}
        self.logins = {}
        self.servers = {}
        self.files = {}
        self.originals = {}      # (kind, lower-cased key) -> first spelling seen
        self._host_re = None

    # --- pseudonyms ------------------------------------------------------
    def _number(self, table, key):
        return table.setdefault(key, len(table) + 1)

    def ip(self, value):
        octets = value.split(".")
        if any(int(o) > 255 for o in octets):
            return value                       # not an address (a version number, for example)
        n = self._number(self.ips, value) - 1
        if n < 3 * 250:
            return "%s%d" % (DOC_RANGES[n // 250], n % 250 + 1)
        return "198.18.%d.%d" % ((n // 250) % 256, n % 250 + 1)

    def server(self, name):
        self.originals.setdefault(("server", name.lower()), name)
        return "server-%d" % self._number(self.servers, name.lower())

    def account(self, domain, name):
        self.originals.setdefault(("account", name.lower()), name)
        return "DOMAIN%d\\user-%d" % (self._number(self.domains, domain.upper()), self._number(self.accounts, name.lower()))

    def login(self, name):
        if name in KEEP_LOGINS or name == "":
            return name
        if "\\" in name:
            domain, _, user = name.partition("\\")
            return self.account(domain, user)
        self.originals.setdefault(("login", name.lower()), name)
        return "login-%d" % self._number(self.logins, name.lower())

    def file(self, path):
        return "file-%d" % self._number(self.files, str(path))

    def mapping(self):
        """Pseudonym -> original value, by kind, so the owner can read the redacted report.

        Servers, logins and accounts are stored lower-cased because they were matched without regard to
        case; the first spelling seen is kept in `originals`.
        """
        out = {"ip": {}, "domain": {}, "account": {}, "login": {}, "server": {}, "file": {}}
        for ip in self.ips:
            out["ip"][self.ip(ip)] = ip
        for name, n in self.domains.items():
            out["domain"]["DOMAIN%d" % n] = name
        for name, n in self.accounts.items():
            out["account"]["user-%d" % n] = self.originals.get(("account", name), name)
        for name, n in self.logins.items():
            out["login"]["login-%d" % n] = self.originals.get(("login", name), name)
        for name, n in self.servers.items():
            out["server"]["server-%d" % n] = self.originals.get(("server", name), name)
        for name, n in self.files.items():
            out["file"]["file-%d" % n] = name
        return out

    # --- applying them ---------------------------------------------------
    def learn(self, entries, labels=()):
        """Collect the server names that appear as plain words (labels and 'Server name is' lines)."""
        names = set(l for l in labels if l)
        for e in entries:
            m = SERVER_NAME_RE.search(e.text)
            if m:
                names.add(m.group(1))
        for name in sorted(names):
            self.server(name)
        if self.servers:
            words = sorted(self.servers, key=len, reverse=True)
            self._host_re = re.compile(r"(?<![\w.-])(%s)(?:\.[A-Za-z][\w-]*)*(?![\w-])" % "|".join(re.escape(w) for w in words), re.I)

    def text(self, value):
        def repl(m):
            if m.group("path") or m.group("builtin"):
                return m.group(0)
            if m.group("unc"):
                return "\\\\" + self.server(m.group("unc")) + (m.group("uncrest") or "")
            if m.group("ip"):
                return self.ip(m.group("ip"))
            if m.group("domain"):
                return self.account(m.group("domain"), m.group("account"))
            if m.group("endpoint"):
                return self.server(m.group("endpoint").split(".")[0])
            if m.group("hostname"):
                return self.server(m.group("hostname"))
            if m.group("loginname"):
                return self.login(m.group("loginname"))
            if m.group("login") is not None:
                return self.login(m.group("login").replace("''", "'"))
            return m.group(0)
        out = TOKEN_RE.sub(repl, value)
        if self._host_re is not None:
            out = self._host_re.sub(lambda m: self.server(m.group(1)), out)
        return out

    def entries(self, entries):
        """Redact entries in place (text, process is kept, source and replica are pseudonymised)."""
        for e in entries:
            e.text = self.text(e.text)
            if e.replica:
                e.replica = self.server(e.replica)
            if e.source:
                e.source = self.file(e.source)
        return entries
