# What each classifier looks for

Every finding has a severity (`info`, `warning`, `error`, `critical`), a short
title, a `details` dictionary with the values pulled out of the message, and a
line of advice where there is something useful to say. This page lists the
rules, what they extract and how they pick the severity.

Rules match on the message text, not on the message number, because most of
these messages are written without an `Error: N` line. Where SQL Server does
write the separate `Error: N, Severity: S, State: X.` entry first, the rule
reads the state from it (the entry must come from the same process within five
seconds).

## Logins: 18456

`Login failed for user 'x'. Reason: ... [CLIENT: ip]`

* details: `user`, `reason`, `client`, `state`, `kind`, `cause`
* The state decodes to a cause: 5 unknown login, 7 disabled, 8 wrong password,
  11/12 server access check failed, 38 database cannot be opened, 58 SQL
  authentication on a Windows-only server, and so on. `kind` is one of
  credentials, authorization, database, config, server or unknown.
* Without the header entry (a filtered `sp_readerrorlog`), the state is guessed
  from the reason text.
* severity: warning

### Login failures by client

The report groups 18456 findings by client address and names the pattern:
*password guessing* (five or more wrong passwords for one login within five
minutes), *many users tried* (three or more different logins within ten
minutes), *repeating client* (ten or more failures spread over two hours or
more, usually a service with a stale password or database name) and
*occasional*. Only the credential states 2, 5, 8 and 9 count towards the first
two patterns.

## Slow I/O: 833

`SQL Server has encountered N occurrence(s) of I/O requests taking longer than
15 seconds ... on file [path] in database [db] (id)`

* details: `count`, `seconds`, `file`, `volume`, `file_kind` (data or log),
  `database`, `database_id`, `handle`, `offset`, `network`
* severity: warning below 30 s, error from 30 s, critical from 60 s

## Schedulers: 17883 and 17884

* 17883 non-yielding: details `scheduler`, `kernel_ms`, `user_ms`,
  `interval_ms`, `cpu_share`, `pattern`. The pattern is `cpu-bound` when the
  worker used 70% or more of the interval as CPU, `stalled` at 10% or less
  (it was waiting outside SQL Server), otherwise `mixed`. Error, critical when
  the interval is two minutes or more.
* 17884 no free worker: details `seconds`, `process_utilization`,
  `system_idle`. Error, critical from 180 s.

## Memory and log space: 701, 802, 9002

* 701 and 802: error. 701 reports the resource pool.
* 17890 working set trimmed ("a significant part of sql server process memory has been
  paged out"): details `duration_seconds`, `working_set_kb`, `committed_kb`,
  `memory_utilization`. Warning, error when under 50% remains or it lasted five minutes.
* 8645 memory grant timeout: error, with the resource pool when the message names one.
* 9002 log full: critical. Details carry `database` and `log_reuse_wait`; the
  advice depends on the wait (LOG_BACKUP, ACTIVE_TRANSACTION,
  AVAILABILITY_REPLICA, REPLICATION, ...). Messages from before SQL Server 2012
  have no reason and get the generic advice.

## Backups

* 3041 backup failed (error): `command`, `kind` (database or log), `database`.
* 18204 and 3201 device errors (error): `device`, `os_error`, `os_error_text`,
  `network`; the advice depends on the Windows error (3, 5, 32, 53, 64, 112,
  1450).
* 4208 BACKUP LOG on a SIMPLE database (error).
* 18264 and 18265, the success messages (info): `database`, `kind`, LSNs,
  `device`, `pages`.

## Deadlocks: trace flag 1222

The graph is written one XML node per entry. The parser (`deadlock.py`) rebuilds
the processes, their execution stacks and input buffers, the resources and the
owner and waiter lists. The finding names the victim and the objects, and the
advice follows the shape of the graph: opposite lock order on key locks,
page or row-id locks that suggest a missing index, and READ COMMITTED
sessions that would not deadlock with READ_COMMITTED_SNAPSHOT. Error.

## Crashes

* Stack dump blocks (`stackdump.py`): the dump file path, the kind (exception,
  assertion or non-yielding), exception code and name, spid, the input buffer,
  the signature and the first modules on the stack. Critical for exceptions.
* 17065/17066 assertion messages (error) and 17310 session terminated by a fatal
  exception (critical).

## Availability groups

* 1480 database role change: details `database`, `old_role`, `new_role`,
  `reason`, `planned`. Planned (manual failover, role synchronization) is
  info; anything else is a warning.
* 19406 replica state change: details `ag`, `old_state`, `new_state`, `reason`,
  `user_initiated`. Warning when the replica ends up in a state other than
  PRIMARY_NORMAL or SECONDARY_NORMAL and nobody asked for it.
* 35264 data movement suspended: details `database`, `source`, `source_id`,
  `reason` (the SUSPEND_FROM_* string), `by_user`. Warning when a person did
  it, error otherwise. 35265 is the resume (info).
* 41142 replica cannot become primary (error).

### Failover incidents

`incidents.py` groups the role and state messages of all given servers into
incidents (events less than 90 seconds apart). With the logs of both sides an
incident names the old and the new primary and how long no replica was
primary. The kind is *planned failover*, *unplanned failover*, *failed
failover* (41142 present), *replica rejoined* or *role activity*. A negative
"no primary" time means the clocks of the two servers differ; use `--offset`.
Incidents are built from all findings, so `--min-severity` does not hide them.

## Startup and shutdown

Startup banner (version, level, KB, build, edition, OS), ready for connections,
shutdown (service stop, system shutdown, fatal exception), error log
reinitialised and database recovery progress. Info, except shutdowns caused by
a fatal exception, which are critical.

## What is left

Entries no rule accounts for are grouped by template (see `cluster.py`): GUIDs,
addresses, hex, paths, quoted names and numbers are masked, and identical
templates are counted.
