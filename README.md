# errorlog-insight

Rule-based insight for SQL Server ERRORLOG files. No ML, no network calls,
no third-party packages: a pile of regular expressions and a little arithmetic.

SQL Server writes its ERRORLOG as UTF-16 LE with a byte order mark, and a single
logical entry can span several physical lines (the startup banner, stack dumps,
`FlushCache` messages). This tool reads those files, splits them into entries
and (as it grows) classifies the well-known messages, groups the unknown ones
and points at the interesting parts.

## Usage

```
python3 -m errorlog_insight ERRORLOG ERRORLOG.1
```

prints the findings grouped by message number, worst first, with a hint on what
to look at next. Files can be the real UTF-16 ERRORLOG or text saved from
`sp_readerrorlog`.

Options:

* `--json` writes the same findings as JSON (one object per finding with its details).
* `--min-severity {info,warning,error,critical}` hides the less interesting findings.

Recognised so far: failed logins (18456, with the state decoded into a cause)
and slow I/O warnings (833, with file, database and duration).

## Tests

```
python3 -m unittest discover
```

Fixtures live in `tests/fixtures/`. The `.log` files are UTF-16 LE with BOM and
CRLF line endings like the real thing; the readable sources are in
`tests/fixtures/src/` and `tools/encode_log.py` converts between them.
GitHub Actions runs the same command on Python 3.8 to 3.10.
All server names, logins and addresses in the fixtures are made up.
