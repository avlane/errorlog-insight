# Changelog

## 1.0.0 (2026-06)

First release that calls the output stable.

* Baselines: `--save-baseline` and `--baseline` show what is new since a quiet period, including
  unrecognised messages by stable template id. Baselines record the template scheme and are refused
  or only partly compared when it differs.
* `--redact` and `--redact-map` for sharing reports; `--fail-on` for scripts; `--list-codes`;
  `--width`; `--html-limit`; `--burst-window` and `--bucket-seconds`.
* Autogrowth rules (5144, 5145) and insights for repeated slow growth and for a log that could not
  grow and then ran full.
* Input errors exit with status 2 and a message; a damaged timestamp no longer stops the run.
* About a third faster on big logs; the report is byte-for-byte the same whatever the hash seed.
* Typed data model, `py.typed`.

## 0.9 (2025)

* Insights: slow I/O during snapshots and CHECKDB, a full log waiting for failing log backups,
  non-yielding schedulers with an outside cause, AG suspensions, flapping AGs, failed-login sources,
  unsupported versions, unusual startup options.
* Server information from the startup messages, `--utc`, wildcards and de-duplication, startup
  parameters, SQL Server on Linux.
* Guessed severity and bursts for unrecognised messages, stable template ids.
* Custom rules in the config file. Python 3.10 is the minimum.

## 0.8 (2024)

* Corruption (823, 824, 825), DBCC results, SSPI and connection errors, trace flags, memory pressure.
* Parallel query deadlocks, AG connectivity, lease and quorum messages, causes for failover incidents.
* `--since`, `--until`, `--format`, versioned JSON, an activity chart and severity filter in the HTML
  report, streaming reads.

## 0.7 and earlier (2021 to 2023)

* ERRORLOG reader for UTF-16 files, `sp_readerrorlog` and Log File Viewer exports.
* Classifiers for failed logins, slow I/O, schedulers, memory, log full, backups, deadlocks (trace
  flag 1222), stack dumps, availability groups, startup and shutdown.
* Template grouping of unrecognised messages, burst detection, merged timelines across servers,
  failover incidents, text, JSON and HTML output, config files.
