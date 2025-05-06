# JSON output

`errorlog-insight --json` writes one JSON document. `schema_version` is 1; it
only changes when a field is removed or changes meaning, never when a field is
added, so readers should ignore keys they do not know.

| key | content |
|---|---|
| `schema_version` | integer, currently 1 |
| `tool` | `name` and `version` of errorlog-insight |
| `files` | the input paths |
| `entries` | number of log entries read |
| `period` | `first` and `last` timestamp (`YYYY-MM-DDTHH:MM:SS.mmm`, local time of the log) |
| `findings` | list of findings, in time order |
| `incidents` | availability group failover incidents |
| `insights` | readings that combine several findings (see below) |
| `bursts` | bursts of findings against the rolling baseline |
| `summaries` | `io` (slow I/O per file) and `logins` (failures per client) |
| `unrecognised` | the biggest groups of messages no rule recognised |

## A finding

```json
{
  "timestamp": "2021-04-06T02:24:12.010",
  "process": "spid22s",
  "source": "tests/fixtures/io_stalls.log",
  "replica": "io_stalls",
  "line": 14,
  "severity": "error",
  "category": "io",
  "code": "833",
  "title": "I/O stall: 7 request(s) over 30 s on E:\\SQLData\\Sales_Data1.mdf (Sales)",
  "details": {"count": 7, "seconds": 30, "file": "E:\\SQLData\\Sales_Data1.mdf", "volume": "E:", "database": "Sales"},
  "advice": "Check storage latency on E: ..."
}
```

`severity` is one of `info`, `warning`, `error`, `critical`. `code` is the SQL
Server message number where there is one, otherwise a short name such as
`startup`, `stackdump` or `checkdb`. `details` differs per code; see
[classifiers.md](classifiers.md). Times are the times in the log: ERRORLOG
timestamps have no time zone.

## Incidents

`kind`, `start`, `end`, `ags`, `databases`, `replicas`, `old_primary`,
`new_primary`, `no_primary_seconds`, `clock_skew_suspected`, `events`,
`precursors` (list of `code`, `replica`, `time`, `title`) and `likely_cause`.

## Insights

`code`, `title`, `severity`, `confidence` (`low`, `medium` or `high`), `start`, `end`,
`advice` and `evidence`: a list of references to findings (`timestamp`, `replica`, `line`,
`code`, `title`), not copies, so the details stay in `findings`.

## Bursts

`key` (the finding code), `start`, `end`, `count`, `peak` (largest bucket) and
`baseline` (events per bucket before the burst).

## Unrecognised messages

`template`, `count`, `first_seen`, `last_seen`, `processes` and a `sample` first
line.
