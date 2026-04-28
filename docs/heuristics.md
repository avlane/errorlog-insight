# How the heuristics work

Everything here is plain code you can read in a few minutes: regular expressions, counting,
and comparisons of timestamps. There is no model and no training data. This page says what
each part does and, as important, where it can be wrong.

## Reading the log

An entry starts at a line with a timestamp (`2021-03-02 08:14:22.35 Logon ...`); lines without
one belong to the entry before. The file is read as UTF-16 (LE or BE, with or without a byte
order mark), UTF-8 or Windows-1252, sampling the first 64 KB. Times have no time zone in the
log, so none is invented; `--utc` uses the `UTC adjustment` line of each start, which is written
once per start and so cannot follow a daylight saving change while the instance keeps running.

## Rules

A rule is a function that gets one entry (or, for deadlock graphs and stack dumps, a run of
entries) and returns a finding or nothing. Rules match the message text, because most of these
messages are written without their number. The first rule that matches wins, so the order in
`rules/__init__.py` matters where two patterns could overlap. The separate `Error: N, Severity:
S, State: X.` entry is attached to the message that follows it from the same process within five
seconds. See [classifiers.md](classifiers.md) for each rule.

Severity is a fixed table per rule plus, where the message has a number in it, a threshold
(for example a 833 stall of 30 seconds is an error and 60 seconds is critical). The thresholds
are judgement calls and are written next to the code.

## Unrecognised messages

1. The first line of the message is reduced to a template by masking, in this order: GUIDs, IP
   addresses, hex numbers, version numbers, SIDs, dates, times, LSNs, UNC and drive paths,
   `DOMAIN\account` names, spids, quoted strings, bracketed names and finally plain numbers.
2. Equal templates are one group.
3. Groups with the same number of words and the same first word are merged when at least 70% of
   the word positions agree; the differing words become `<*>`. Messages of fewer than four words
   are only merged when identical.
4. A word list gives each group a guessed severity (`[error?]`). The list is short and
   English-only; "no errors" and messages that call themselves informational are exempt.

Limits: a message whose variable part is a plain word that looks like the rest of the text
("Moved file alpha to disk one") is only caught by step 3, and two unrelated messages that
happen to share a skeleton can be merged. The threshold is a constant at the top of
`cluster.py`.

## Bursts

Findings (except info) are counted per code in one-minute buckets. A bucket is a burst when it has
at least `--burst-min` events (5) and at least `--burst-factor` (3) times the average of the
previous 30 buckets, counting only buckets that were not bursts themselves and, near the start of
a log, only the buckets that exist. Neighbouring burst buckets are merged. The same is done for
unrecognised templates that sound like a warning or worse.

Limits: the first bucket of a log has no history and is judged on its count alone, and a rate that
rises slowly never exceeds three times its own recent average.

## Incidents and insights

An incident is a run of availability group role and state messages, from any number of servers,
with less than 90 seconds between them. With both sides' logs it names the old and the new
primary and the time nobody held the role; a negative time means the clocks differ (see
`--offset`). The five minutes before an incident are searched for stalls, lease and quorum
messages, lost replica connections and memory errors on any server, and the first match in a fixed
order becomes the `likely_cause`.

Insights combine findings of the same server (found by its label) using time windows: slow I/O
inside a freeze or CHECKDB window (confidence high) or within two minutes after it (medium); a full
log with failing log backups in the previous six hours; a stalled scheduler with a trimmed working
set in the previous ten minutes or slow I/O in the previous two; a system suspend of AG data
movement within ten minutes of a local error; three or more failovers of one AG within an hour;
failed-login patterns per client address; three or more slow growths of one file within six hours
(and 30 s in all), and a growth that timed out followed within ten minutes by a full log; versions judged against Microsoft's published end of
support at the date of the log.

Limits: correlation in time is not causation. The confidence says which insights rest on a window
that contains the evidence and which only sit next to it. Clock skew between servers breaks every
rule that compares two servers.

## What it does not do

It does not connect to a server, read dump files, query DMVs, or predict anything. It does not
know your normal: a message that is routine on your system but serious on most others will be
reported as serious.
