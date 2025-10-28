# errorlog-insight

Rule-based insight for SQL Server ERRORLOG files. No ML, no network calls,
no third-party packages: a pile of regular expressions and a little arithmetic.

SQL Server writes its ERRORLOG as UTF-16 LE with a byte order mark, and a single
logical entry can span several physical lines (the startup banner, stack dumps,
`FlushCache` messages). This tool reads those files, splits them into entries
and (as it grows) classifies the well-known messages, groups the unknown ones
and points at the interesting parts.

## Install

```
pip install .
errorlog-insight ERRORLOG
```

There are no dependencies. Running from a checkout works too.

## Usage

```
python3 -m errorlog_insight ERRORLOG ERRORLOG.1
```

prints the findings grouped by message number, worst first, with a hint on what
to look at next. Files can be the real UTF-16 ERRORLOG, a grid saved from
`sp_readerrorlog` (tab separated), or an export from the SSMS Log File Viewer
(comma separated, newest first, dates like `3/2/2021 8:14:22 AM`).

Options:

* `--format text|json|html` picks the report (default text; with `-o` the file extension decides).
  `--json` and `--html` are shorthands.
* `--json` writes the same findings as JSON (one object per finding with its details); the
  format is described in [docs/json-format.md](docs/json-format.md).
* `--html` writes one self-contained HTML page (inline CSS, no scripts, light and dark),
  with every finding expandable to show what was extracted from it.
* `-o FILE` writes the report to FILE as UTF-8. (Standard output is switched to UTF-8
  too, because logins and paths in the log are not always ASCII and Windows consoles
  default to a legacy code page.)
* `--top N` sets how many groups of unrecognised messages are listed (default 10).
* `--burst-min N` and `--burst-factor X` tune burst detection: a minute with at least N
  events of one kind, and X times the average of the previous 30 minutes, is reported as a burst.
* Wildcards are expanded by the tool (Windows shells do not): `ERRORLOG*` takes ERRORLOG,
  ERRORLOG.1, ERRORLOG.2 ... in natural order. Identical entries from the same server are
  counted once, so a copy of a log next to the original changes nothing.
* Give a file a name with `LABEL=FILE`, for example `SQLPROD01=ERRORLOG SQLDR02=dr02/ERRORLOG.1`;
  the label is used as the replica in merged output (the default is the file name), and a
  label in front of a wildcard applies to every file it matches.
* `--utc` converts the times to UTC with the `UTC adjustment` line each start writes, so logs
  from servers in different time zones line up. (The line is written once per start: a daylight
  saving change while the instance keeps running is not followed.) A server whose log has no such
  line is left as it is, with a warning.
* `--since WHEN` and `--until WHEN` keep only the entries in a window (`2024-05-14`,
  `2024-05-14 01:30`, `2024-05-14T01:30:15`; `--until` is exclusive). The window is applied
  before anything is classified, to the times as shown (after `--offset` and `--utc`).
* `--offset LABEL=+2s` shifts one server's timestamps (units `ms`, `s`, `m`, `h`) when its clock
  is off, so the merged order of a failover is right.
* `--timeline` lists the findings of all given files (for example the logs of both AG
  replicas) as one time-ordered list with the file name as the replica column.
* `--no-insights` leaves out the insights section (see below).
* `--min-severity {info,warning,error,critical}` hides the less interesting findings.

Messages no rule recognises are grouped by template: numbers, addresses, GUIDs,
paths and quoted names are masked, so "Starting up database 'A'." and
"Starting up database 'B'." are one group with a count.

Recognised so far:

| Area | Messages |
|---|---|
| Logins | 18456 with the state decoded into a cause |
| I/O | 833 slow I/O (file, database, duration) |
| Schedulers | 17883 non-yielding, 17884 worker starvation |
| Memory and log | 701, 802, 9002 (with the log reuse wait) |
| Connections | 17806 SSPI handshake, 18452, 17187 |
| Corruption | 823, 824, 825 |
| Backups | 3041, 18204, 3201, 4208 and the success messages |
| Deadlocks | trace flag 1222 graphs: victim, objects, who waits for whom |
| Crashes | stack dumps, assertions (17065/17066), 17310 |
| Availability groups | 1480 role changes, 19406 replica state, 35264/35265 data movement, 41142 |
| Lifecycle | startup banner, ready, shutdown, recovery progress |

## Insights

On top of the per-message findings, the report has a section of *insights*: readings that
combine several findings, each with its evidence, a severity and a confidence (high when the
evidence is direct, medium when it is circumstantial). Current ones: slow I/O that overlaps a
snapshot freeze or a CHECKDB run, a full log that is waiting for failing log backups, a
non-yielding scheduler with memory trimming or slow I/O next to it, AG data movement that
suspended itself after a local error or was never resumed, an AG that keeps failing over, and
the sources of failed logins (guessing, scanning, a service with a stale credential). They use
timestamps, server labels and the details already extracted, nothing else.

## Using it as a library

```python
from errorlog_insight.reader import iter_entries, read_entries
from errorlog_insight.classify import classify

for entry in iter_entries("ERRORLOG.1"):      # lazy: one entry at a time
    print(entry.timestamp, entry.process, entry.first_line)

findings = classify(read_entries("ERRORLOG.1"))  # classification needs the entries as a list
```

## Config file

`--config FILE` reads defaults for `--top`, `--min-severity` and the burst options from
a TOML file (Python 3.11+) or an INI file; flags on the command line win.

```toml
[report]
top = 20
min_severity = "warning"

[bursts]
min = 8
factor = 4.0
```

See [docs/classifiers.md](docs/classifiers.md) for what each rule extracts and how
it picks a severity.

## Tests

```
python3 -m unittest discover
```

Fixtures live in `tests/fixtures/`. The `.log` files are UTF-16 LE with BOM and
CRLF line endings like the real thing; the readable sources are in
`tests/fixtures/src/` and `tools/encode_log.py` converts between them.
GitHub Actions runs the same command on Python 3.10 to 3.14 (with warnings turned into errors, so deprecations show up early).
All server names, logins and addresses in the fixtures are made up.
