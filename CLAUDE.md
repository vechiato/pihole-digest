# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`pihole-digest.py` is a single-file, stdlib-only Python script that reads Pi-hole's FTL long-term
database (`pihole-FTL.db`, SQLite) directly and renders a self-contained SARG-style HTML report
(one file, inline CSS, no JS, no external assets). There is no package or build step — the entire
project is the script plus `README.md`, a `tests/` suite, and `docs/sample-report.html` (an example
output, plus its screenshot `docs/sample-report.png` used in the README).

## Running it

```bash
./pihole-digest.py                          # last 7 days, writes pihole-digest.html
./pihole-digest.py --days 30
./pihole-digest.py --from 2026-07-01 --to 2026-07-14
./pihole-digest.py --db /path/to/pihole-FTL.db --output /tmp/report.html
```

Requires Python 3.8+ and read access to a real (or copied) `pihole-FTL.db`. There's no mock/fixture
database in the repo — to test changes, run against a live Pi-hole's DB (opened `mode=ro`, safe to
run against a live instance) or a copy of one. Regenerate `docs/sample-report.html` by pointing
`--output` at it after making rendering changes, so the example stays in sync (and reshoot
`docs/sample-report.png` if the layout changed visibly).

Run tests with `python3 -m unittest discover -s tests` (stdlib `unittest`, no third-party test
deps). Tests build an in-memory SQLite DB shaped like the FTL `queries`/`network_addresses` schema
rather than depending on a real Pi-hole database. GitHub Actions (`.github/workflows/tests.yml`)
runs the same suite on push/PR across Python 3.8-3.13. There is no linter; for anything the unit
tests don't cover (e.g. visual CSS layout), verify by running against a real database and opening
the resulting HTML.

## Architecture

Everything lives in `pihole-digest.py`, structured as a straight-line pipeline with four stages:

1. **`time_window(args)`** — resolves `--days` or `--from`/`--to` into `(t0, t1)` Unix timestamp
   bounds plus `datetime` objects for display.
2. **`gather(con, t0, t1, args)`** — issues one SQL query per report section (totals, per-day,
   top clients, top permitted/blocked domains, status breakdown, per-client detail) against the
   `queries` table, returning a single `dict` keyed by section name. All aggregation (COUNT, SUM,
   GROUP BY, LIMIT) happens in SQL, not Python, so it scales to multi-month/million-row databases —
   **new report sections should follow this pattern**, not fetch raw rows and aggregate in Python.
3. **`client_names(con, clients, do_resolve)`** — maps client IP → display name from FTL's own
   `network_addresses` table, with an optional reverse-DNS fallback (`--resolve`) for anything
   unnamed. Falls back silently (via bare `except sqlite3.Error`) if `network_addresses` doesn't
   exist (older FTL schema).
4. **`build_html(d, names, start, end, args)`** — pure string-building into HTML, using small
   helpers (`esc`, `fmt`, `pct`, `bar`, `stack`, `domain_table`) that each render one small piece
   (a percentage bar, a stacked permitted/blocked bar, a domain ranking table). No templating
   engine — just f-strings. All user-controlled/DB-sourced values (domains, client names) must go
   through `esc()` (an `html.escape` wrapper) before being interpolated into the output.

Two module-level constants encode Pi-hole's FTL status/type schema and should be the only things
touched when adapting to a different FTL version:
- `STATUS_NAMES` / `BLOCKED_STATUSES` — FTL v6 query status codes; a status is "blocked" iff its
  code is in `BLOCKED_STATUSES`. `BLOCKED_SQL` is a pre-built `status IN (...)` SQL fragment derived
  from this tuple and reused across every query in `gather()`. If adapting for FTL v5's status
  codes, update both constants together.
- `QUERY_TYPES` — FTL query type codes (A, AAAA, PTR, HTTPS, etc.) shown in per-client tag chips.

`main()` wires the four stages together: parse args → resolve time window → open DB read-only →
gather → resolve names → render → write file.

## Conventions

- Stdlib only — no third-party dependencies (`argparse`, `html`, `socket`, `sqlite3`, `datetime`).
  Keep it that way; it's a stated design goal (see README "Requirements").
- SQL does the aggregation; Python only formats. Don't pull raw query rows into Python to compute
  counts/sums that SQL can already do.
- The DB connection is always opened read-only (`file:...?mode=ro`) — never change this to a
  writable connection.
- Report is a single HTML string built by concatenating fragments in `build_html`; keep new
  sections consistent with the existing dark-terminal CSS theme defined in the `CSS` constant.
