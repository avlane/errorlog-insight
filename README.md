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
to look at next. Files can be the real UTF-16 ERRORLOG or text saved from
`sp_readerrorlog`.

Options:

* `--json` writes the same findings as JSON (one object per finding with its details).
* `--top N` sets how many groups of unrecognised messages are listed (default 10).
* `--burst-min N` and `--burst-factor X` tune burst detection: a minute with at least N
  events of one kind, and X times the average of the previous 30 minutes, is reported as a burst.
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
| Backups | 3041, 18204, 3201, 4208 and the success messages |
| Deadlocks | trace flag 1222 graphs: victim, objects, who waits for whom |
| Crashes | stack dumps, assertions (17065/17066), 17310 |
| Availability groups | 1480 role changes, 19406 replica state, 35264/35265 data movement, 41142 |
| Lifecycle | startup banner, ready, shutdown, recovery progress |

## Tests

```
python3 -m unittest discover
```

Fixtures live in `tests/fixtures/`. The `.log` files are UTF-16 LE with BOM and
CRLF line endings like the real thing; the readable sources are in
`tests/fixtures/src/` and `tools/encode_log.py` converts between them.
GitHub Actions runs the same command on Python 3.8 to 3.10.
All server names, logins and addresses in the fixtures are made up.
