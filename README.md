# errorlog-insight

Rule-based insight for SQL Server ERRORLOG files. No ML, no network calls, no third-party
packages: regular expressions, counting and comparisons of timestamps.

SQL Server writes its ERRORLOG as UTF-16 LE with a byte order mark, and one logical entry can span
several physical lines (the startup banner, stack dumps, deadlock graphs). This tool reads those
files, recognises the well-known messages, groups the unknown ones, notices bursts, lines up the logs of
several servers (the two sides of an availability group, say) and points at what is worth looking at.

## What it looks like

[docs/sample-output.txt](docs/sample-output.txt) is a real run on one of the test fixtures: a
non-yielding scheduler, the lease with the cluster expiring, and the failover that followed, with
the likely cause worked out from the events before it. A test regenerates it, so it never goes stale.

## Install and run

```
pip install .
errorlog-insight ERRORLOG
```

There are no dependencies. Running from a checkout works too: `python3 -m errorlog_insight ERRORLOG`.
Python 3.10 or newer.

Input can be the real ERRORLOG from Windows or Linux (UTF-16, UTF-8 and Windows-1252 are all read), a
grid saved from `sp_readerrorlog` (tab separated), or an export from the SSMS Log File Viewer
(comma separated, newest first, dates like `3/2/2021 8:14:22 AM`).

```
errorlog-insight ERRORLOG ERRORLOG.1                       # one server, two files
errorlog-insight 'ERRORLOG*'                               # wildcards are expanded by the tool
errorlog-insight SQLPROD01=prod/ERRORLOG SQLDR02=dr/ERRORLOG --timeline
errorlog-insight ERRORLOG --since 2026-03-02 --until 2026-03-03 --format html -o day.html
```

## Options

Reading the logs

| Option | Effect |
|---|---|
| `LABEL=FILE` | Name a server. The label is the replica in merged output (default: the file name); in front of a wildcard it applies to every match. Identical entries from the same server are counted once. |
| `--since WHEN`, `--until WHEN` | Keep only a time window (`2026-03-02`, `2026-03-02 01:30`, `2026-03-02T01:30:15`; `--until` is exclusive). Applied before anything is classified, to the times as shown. |
| `--offset LABEL=+2s` | Shift one server's times (units `ms`, `s`, `m`, `h`) to correct clock skew, so the merged order of a failover is right. |
| `--utc` | Convert to UTC with the `UTC adjustment` line each start writes. (A daylight saving change while the instance keeps running is not followed.) |
| `--config FILE` | Defaults and extra rules from a TOML or INI file; see below. |

What is reported

| Option | Effect |
|---|---|
| `--min-severity {info,warning,error,critical}` | Hide the less interesting findings. |
| `--top N` | How many groups of unrecognised messages to list (10). |
| `--no-insights` | Leave out the insights section. |
| `--burst-min N`, `--burst-factor X`, `--burst-window N`, `--bucket-seconds N` | Burst detection: a bucket (60 s) with at least N events (5) and X times (3) the average of the previous 30 buckets. |
| `--timeline` | The findings of all files as one time-ordered list with a replica column. |
| `--baseline FILE` | Add a "New since the baseline" section: finding types it never had, types three times as frequent, and unrecognised messages whose template it has not seen. |
| `--save-baseline FILE` | Write a small JSON summary of this log to compare later logs with. |
| `--list-codes` | Print every finding code the rules can produce, with its name, and exit. |

Output

| Option | Effect |
|---|---|
| `--format text\|json\|html` | The report format (default text; with `-o` the file extension decides). `--json` and `--html` are shorthands. |
| `-o FILE`, `--output FILE` | Write the report to FILE as UTF-8. (Standard output is switched to UTF-8 too, because logins and paths are not always ASCII.) |
| `--width N` | Wrap the text report at N columns. Default: the terminal width on a terminal, no wrapping for files and pipes; 0 turns it off. |
| `--html-limit N` | Expand at most N findings in the HTML report, worst first (500; 0 shows all). The tables, the chart and the JSON always count every finding. |
| `--fail-on SEVERITY` | Exit with status 1 when any finding (not only the ones shown) reaches that severity. |

Sharing a report

| Option | Effect |
|---|---|
| `--redact` | Replace IP addresses, account and login names, server names and input file paths with stable pseudonyms (documentation-range addresses, `DOMAIN1\user-1`, `login-1`, `server-1`, `file-1`) before anything is analysed. Database names, queries and message numbers stay, because the reader needs them. Read the result before you send it. |
| `--redact-map FILE` | With `--redact`: write a private (mode 600) JSON file that maps the pseudonyms back. |

Exit status: 0 the report was written, 1 a finding reached `--fail-on`, 2 bad arguments or unreadable
input (the message says which file and why).

## What it recognises

| Area | Messages |
|---|---|
| Logins | 18456 with the state decoded into a cause; connection problems 17806 (SSPI), 18452, 17187 |
| I/O and storage | 833 slow I/O (file, database, duration), checkpoint flushes, snapshot freezes, autogrowth 5144 and 5145, corruption 823, 824, 825, DBCC CHECKDB results |
| Schedulers and memory | 17883 non-yielding, 17884 worker starvation, 701, 802, 8645, 17890 |
| Log space and backups | 9002 (with the log reuse wait), 3041, 18204, 3201, 4208, backup completions |
| Deadlocks | trace flag 1222 graphs: victim, objects, who waits for whom; parallel query deadlocks |
| Crashes | stack dumps, assertions (17065/17066), 17310 |
| Availability groups | 1480 role changes, 19406 replica state, 35264/35265 data movement, 41142, replica connectivity (1479, 35201, 35202, 35206), lease and quorum (19407, 19421, 41005) |
| Server | startup banner and parameters, ready, shutdown, recovery, trace flags |

`errorlog-insight --list-codes` lists every code; [docs/classifiers.md](docs/classifiers.md) says what
each rule extracts and how it picks a severity. Messages no rule recognises are grouped by template
(numbers, addresses, GUIDs, paths and quoted names are masked, so "Starting up database 'A'." and
"Starting up database 'B'." are one group with a count), the ones that sound serious come first, and
bursts of them are noticed too.

## Insights

On top of the per-message findings, the report has a section of *insights*: readings that
combine several findings, each with its evidence, a severity and a confidence (high when the
evidence is direct, medium when it is circumstantial). Current ones: slow I/O that overlaps a
snapshot freeze or a CHECKDB run, a full log that is waiting for failing log backups, a
non-yielding scheduler with memory trimming or slow I/O next to it, AG data movement that
suspended itself after a local error or was never resumed, an AG that keeps failing over, repeated
slow autogrowth and a log that could not grow and then ran full, versions that were out of support
(judged at the date of the log, not today), unusual startup options, and the sources of failed logins
(guessing, scanning, a service with a stale credential). They use timestamps, server labels and the
details already extracted, nothing else; [docs/heuristics.md](docs/heuristics.md) says how, and where
they can be wrong.

Availability group events from all given servers are also grouped into *failover incidents*: who gave
up the primary role, who took it, how long nobody held it, and what happened in the five minutes before.

## Config file

`--config FILE` reads defaults for `--top`, `--min-severity` and the burst options from a TOML file
(Python 3.11+) or an INI file; flags on the command line win.

```toml
[report]
top = 20
min_severity = "warning"

[bursts]
min = 8
factor = 4.0
```

### Your own rules

A message you care about that no built-in rule knows can be given a rule in the config file (TOML
`[[rule]]` tables, or INI sections called `[rule:NAME]`). Custom rules are tried before the built-in
ones; named groups in the pattern become details and can be used in the title.

```toml
[[rule]]
name = "Licence server"
pattern = 'Unable to contact the licensing service at (?P<host>\d+\.\d+\.\d+\.\d+)'
severity = "error"
title = "Licence server {host} unreachable"
advice = "Check the licence server and the firewall."
```

## Using it as a library

```python
from errorlog_insight.reader import iter_entries, read_entries
from errorlog_insight.classify import classify

for entry in iter_entries("ERRORLOG.1"):      # lazy: one entry at a time
    print(entry.timestamp, entry.process, entry.first_line)

findings = classify(read_entries("ERRORLOG.1"))  # classification needs the entries as a list
```

The JSON output is described in [docs/json-format.md](docs/json-format.md); it carries a
`schema_version`, and new fields do not bump it.

## Development

```
python3 -m unittest discover
```

Fixtures live in `tests/fixtures/` (described in its README). The `.log` files are UTF-16 LE with BOM
and CRLF line endings like the real thing; the readable sources are in `tests/fixtures/src/` and
`tools/encode_log.py` converts. All server names, logins and addresses in them are made up. Tests also
check that every rule has a name and a fixture, that reports are identical whatever the hash seed, that
damaged input never gives a traceback, and that the documents and the sample output are current.

GitHub Actions runs the suite on Python 3.10 to 3.14 with warnings turned into errors, so deprecations
show up early. See [CHANGELOG.md](CHANGELOG.md) for what changed when.
