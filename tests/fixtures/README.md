# Fixtures

Everything here is made up. Servers are SQLPROD01, SQLDR02 and FILESRV01, the
domain is CONTOSO, the addresses are in 10.20.x.x (or 203.0.113.x, a documentation range)
and the databases are Sales, Reporting, Staging and Archive. The message texts
follow what SQL Server writes; the surrounding scenarios are invented.

`src/*.txt` is the readable source, `*.log` the same text as SQL Server writes
it (UTF-16 LE, byte order mark, CRLF). `tools/encode_log.py` converts, and
`tests/test_fixtures.py` fails if a `.log` no longer matches its source.

| fixture | what it shows |
|---|---|
| startup_2019, startup_single_user, shutdown | banner, startup parameters (trace flags, -m, -f), recovery, ready, stop request, system shutdown |
| login_failures, login_patterns | 18456 with many states; guessing, spraying and a stale service |
| io_stalls | 833 on data, log, tempdb and a UNC path, plus FlushCache and a VSS freeze |
| nonyielding | 17883 (cpu-bound and stalled) and 17884 |
| memory_logfull, memory_pressure | 701, 802, 9002 in both wordings; 17890 and 8645 |
| backup_failures | 3041, 18204, 3201, 4208 and the success messages |
| deadlock_1222, deadlock_parallel | key, page and row id lock graphs; a parallel query deadlock |
| stackdump | access violation, assertion and non-yielding dumps |
| corruption, checkdb | 823, 824, 825 and DBCC results |
| connections | 17806 with several status codes, 18452, 17187 |
| ag_primary, ag_secondary | one planned failover seen from both sides |
| ag_unplanned_old_primary, ag_unplanned_new_primary | an unplanned failover and the old primary rejoining |
| ag_datamovement, ag_failed_failover | 35264/35265 and 41142 |
| ag_connectivity, ag_lease, ag_lease_failover | lost replica connections; lease expiry after a stall |
| insight_io | slow I/O during a snapshot freeze and during CHECKDB, and one stall nothing explains |
| insight_logfull | log backups failing for hours, then 9002 LOG_BACKUP; one log with no failures logged |
| insight_nonyield | non-yielding schedulers after paged-out memory and during slow I/O; one with no outside cause |
| insight_ag_suspend | a secondary suspending itself after log full and corruption; one resume, one user suspend |
| insight_ag_flap | four automatic failovers in forty minutes |
| template_burst | an unrecognised error message repeating 12 times in a minute, plus quiet noise |
| linux_server | SQL Server 2022 on Ubuntu: banner, POSIX paths, errno values, a dump in /var/opt/mssql/log |
| traceflags | DBCC TRACEON and TRACEOFF |
| noise | messages no rule recognises, for the template clustering |
| sp_readerrorlog.tsv, log_viewer_export.csv | saved grids (tab separated; CSV, newest first) |
