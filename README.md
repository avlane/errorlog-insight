# errorlog-insight

Rule-based insight for SQL Server ERRORLOG files. No ML, no network calls,
no third-party packages: a pile of regular expressions and a little arithmetic.

SQL Server writes its ERRORLOG as UTF-16 LE with a byte order mark, and a single
logical entry can span several physical lines (the startup banner, stack dumps,
`FlushCache` messages). This tool reads those files, splits them into entries
and (as it grows) classifies the well-known messages, groups the unknown ones
and points at the interesting parts.

## Status

Early days. Right now it only reads files:

```python
from errorlog_insight.reader import read_entries

for entry in read_entries("ERRORLOG.1"):
    print(entry.timestamp, entry.process, entry.first_line)
```

## Tests

```
python3 -m unittest discover
```

Fixtures live in `tests/fixtures/`. The `.log` files are UTF-16 LE with BOM and
CRLF line endings like the real thing; the readable sources are in
`tests/fixtures/src/` and `tools/encode_log.py` converts between them.
All server names, logins and addresses in the fixtures are made up.
