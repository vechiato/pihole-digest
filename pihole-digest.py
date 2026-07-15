#!/usr/bin/env python3
r"""
pihole-digest.py

SARG-style HTML report generator for Pi-hole, reading directly from the
FTL long-term database (/etc/pihole/pihole-FTL.db).

Produces a single self-contained HTML file with:
  - Summary totals (queries, blocked, block rate, clients, domains)
  - Queries per day
  - Top clients with per-client block rate
  - Top permitted and top blocked domains
  - Blocked-status breakdown (gravity / regex / denylist / upstream)
  - Per-client detail: top permitted + blocked domains, query types

Stdlib only (sqlite3). Opens the database read-only, so it is safe to run
against a live FTL database. Aggregation is done in SQL, so it copes with
large (multi-month) databases without loading rows into memory.

Usage:
  ./pihole-digest.py                          # last 7 days
  ./pihole-digest.py --days 30
  ./pihole-digest.py --from 2026-07-01 --to 2026-07-14
  ./pihole-digest.py --db /etc/pihole/pihole-FTL.db \
      --output /var/www/html/pihole-digest.html --top 25 --max-clients 20

Cron example (daily report for the previous 7 days):
  15 6 * * * root /usr/local/bin/pihole-digest.py --days 7 \
      --output /var/www/html/reports/digest-$(date +\%F).html

Notes:
  - Pi-hole is DNS-level only: reports are per client (IP/hostname), by
    domain. There is no bandwidth, URL path, or per-user data as with
    SARG/Squid. Clients using DoH or hardcoded upstream DNS will not appear.
  - Hostnames are taken from FTL's network_addresses table when available;
    --resolve adds a reverse-DNS fallback for anything still unnamed.
"""

import argparse
import html
import socket
import sqlite3
import sys
from datetime import datetime, timedelta

# FTL query status codes (src/database/query-table.c / FTL docs).
STATUS_NAMES = {
    0: "unknown",
    1: "blocked (gravity)",
    2: "forwarded",
    3: "cache",
    4: "blocked (regex)",
    5: "blocked (exact denylist)",
    6: "blocked (upstream, known IP)",
    7: "blocked (upstream, NULL)",
    8: "blocked (upstream, NXRA)",
    9: "blocked (gravity, CNAME)",
    10: "blocked (regex, CNAME)",
    11: "blocked (exact denylist, CNAME)",
    12: "retried",
    13: "retried (ignored)",
    14: "in progress",
    15: "blocked (database busy)",
    16: "blocked (special domain)",
    17: "cache (stale)",
    18: "blocked (upstream, EDE15)",
}
BLOCKED_STATUSES = (1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18)

QUERY_TYPES = {
    1: "A", 2: "AAAA", 3: "ANY", 4: "SRV", 5: "SOA", 6: "PTR", 7: "TXT",
    8: "NAPTR", 9: "MX", 10: "DS", 11: "RRSIG", 12: "DNSKEY", 13: "NS",
    14: "OTHER", 15: "SVCB", 16: "HTTPS",
}


def parse_args():
    p = argparse.ArgumentParser(description="SARG-style HTML report from the Pi-hole FTL database.")
    p.add_argument("--db", default="/etc/pihole/pihole-FTL.db", help="Path to pihole-FTL.db")
    p.add_argument("--days", type=int, default=7, help="Report on the last N days (default 7)")
    p.add_argument("--from", dest="date_from", help="Start date YYYY-MM-DD (overrides --days)")
    p.add_argument("--to", dest="date_to", help="End date YYYY-MM-DD inclusive (default: today)")
    p.add_argument("--top", type=int, default=25, help="Rows per top-N table (default 25)")
    p.add_argument("--max-clients", type=int, default=20, help="Per-client detail sections to include (default 20)")
    p.add_argument("--per-client-top", type=int, default=15, help="Domains per client detail table (default 15)")
    p.add_argument("--output", default="pihole-digest.html", help="Output HTML file")
    p.add_argument("--resolve", action="store_true", help="Reverse-DNS fallback for clients FTL has no name for")
    return p.parse_args()


def time_window(args):
    if args.date_from:
        start = datetime.strptime(args.date_from, "%Y-%m-%d")
        end = (datetime.strptime(args.date_to, "%Y-%m-%d") if args.date_to
               else datetime.now()) + timedelta(days=1)
        if args.date_to:
            end = datetime.strptime(args.date_to, "%Y-%m-%d") + timedelta(days=1)
    else:
        end = datetime.now() + timedelta(seconds=1)
        start = (end - timedelta(days=args.days)).replace(
            hour=0, minute=0, second=0, microsecond=0)
    return int(start.timestamp()), int(end.timestamp()), start, end


def connect_ro(path):
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        con.execute("SELECT 1 FROM queries LIMIT 1")
        return con
    except sqlite3.Error as e:
        sys.exit(f"error: cannot open {path} read-only ({e}). "
                 "Check the path and that this user can read the file.")


def client_names(con, clients, do_resolve):
    """Map client IP -> display name, from FTL's network table, then rDNS."""
    names = {}
    try:
        for ip, name in con.execute(
                "SELECT ip, name FROM network_addresses "
                "WHERE name IS NOT NULL AND name != ''"):
            names[ip] = name
    except sqlite3.Error:
        pass  # older schema without network_addresses
    if do_resolve:
        for ip in clients:
            if ip not in names:
                try:
                    names[ip] = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror, OSError):
                    pass
    return names


BLOCKED_SQL = "status IN (%s)" % ",".join(str(s) for s in BLOCKED_STATUSES)


def gather(con, t0, t1, args):
    q = lambda sql, *p: con.execute(sql, (t0, t1) + p).fetchall()
    where = "timestamp >= ? AND timestamp < ?"
    d = {}

    d["total"], d["blocked"], d["clients_n"], d["domains_n"] = q(
        f"SELECT COUNT(*), SUM({BLOCKED_SQL}), "
        f"COUNT(DISTINCT client), COUNT(DISTINCT domain) FROM queries WHERE {where}")[0]
    d["blocked"] = d["blocked"] or 0

    d["per_day"] = q(
        f"SELECT date(timestamp,'unixepoch','localtime') AS day, "
        f"COUNT(*), SUM({BLOCKED_SQL}) FROM queries WHERE {where} "
        f"GROUP BY day ORDER BY day")

    d["top_clients"] = q(
        f"SELECT client, COUNT(*) AS n, SUM({BLOCKED_SQL}) AS b, "
        f"COUNT(DISTINCT domain) FROM queries WHERE {where} "
        f"GROUP BY client ORDER BY n DESC LIMIT ?", args.top)

    d["top_permitted"] = q(
        f"SELECT domain, COUNT(*) AS n, COUNT(DISTINCT client) FROM queries "
        f"WHERE {where} AND NOT {BLOCKED_SQL} "
        f"GROUP BY domain ORDER BY n DESC LIMIT ?", args.top)

    d["top_blocked"] = q(
        f"SELECT domain, COUNT(*) AS n, COUNT(DISTINCT client) FROM queries "
        f"WHERE {where} AND {BLOCKED_SQL} "
        f"GROUP BY domain ORDER BY n DESC LIMIT ?", args.top)

    d["status_breakdown"] = q(
        f"SELECT status, COUNT(*) AS n FROM queries WHERE {where} "
        f"GROUP BY status ORDER BY n DESC")

    # Per-client detail for the busiest clients
    detail_clients = [r[0] for r in d["top_clients"][: args.max_clients]]
    d["detail"] = {}
    for c in detail_clients:
        d["detail"][c] = {
            "permitted": q(
                f"SELECT domain, COUNT(*) AS n FROM queries "
                f"WHERE {where} AND client = ? AND NOT {BLOCKED_SQL} "
                f"GROUP BY domain ORDER BY n DESC LIMIT ?", c, args.per_client_top),
            "blocked": q(
                f"SELECT domain, COUNT(*) AS n FROM queries "
                f"WHERE {where} AND client = ? AND {BLOCKED_SQL} "
                f"GROUP BY domain ORDER BY n DESC LIMIT ?", c, args.per_client_top),
            "types": q(
                f"SELECT type, COUNT(*) AS n FROM queries "
                f"WHERE {where} AND client = ? GROUP BY type ORDER BY n DESC", c),
        }
    return d


# ---------------------------------------------------------------- HTML ----

CSS = """
:root {
  --bg: #0f1418; --panel: #161d23; --panel2: #1b242c;
  --ink: #d8e1e8; --dim: #7d8b96; --line: #263038;
  --ok: #4aa3df; --blocked: #e05252; --accent: #d8e1e8;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--ink);
  font: 14px/1.5 "SF Mono", "Cascadia Code", "JetBrains Mono", Menlo, Consolas, monospace;
  padding: 32px 24px 64px; max-width: 1100px; margin: 0 auto; }
h1 { font-size: 20px; font-weight: 600; letter-spacing: .04em; }
h1 span { color: var(--dim); font-weight: 400; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .14em;
  color: var(--dim); margin: 40px 0 12px; border-bottom: 1px solid var(--line);
  padding-bottom: 6px; }
.meta { color: var(--dim); font-size: 12px; margin-top: 4px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px; margin-top: 20px; }
.card { background: var(--panel); border: 1px solid var(--line);
  border-radius: 4px; padding: 12px 14px; }
.card .v { font-size: 22px; font-weight: 600; }
.card .l { font-size: 11px; color: var(--dim); text-transform: uppercase;
  letter-spacing: .1em; margin-top: 2px; }
.card.blk .v { color: var(--blocked); }
table { width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--line); border-radius: 4px; overflow: hidden; }
th { text-align: left; font-size: 11px; color: var(--dim);
  text-transform: uppercase; letter-spacing: .08em; font-weight: 500;
  padding: 8px 12px; background: var(--panel2); border-bottom: 1px solid var(--line); }
td { padding: 6px 12px; border-bottom: 1px solid var(--line); font-size: 13px;
  vertical-align: middle; }
tr:last-child td { border-bottom: none; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
td.dom { word-break: break-all; }
.bar { position: relative; background: var(--panel2); height: 10px;
  border-radius: 2px; min-width: 120px; overflow: hidden; }
.bar i { position: absolute; inset: 0 auto 0 0; display: block; }
.bar i.ok { background: var(--ok); }
.bar i.blk { background: var(--blocked); }
.stack { display: flex; height: 10px; border-radius: 2px; overflow: hidden;
  min-width: 160px; background: var(--panel2); }
.stack i.ok { background: var(--ok); }
.stack i.blk { background: var(--blocked); }
.pct { color: var(--dim); font-size: 12px; }
.pct.hot { color: var(--blocked); }
.client-block { margin-top: 24px; }
.client-block h3 { font-size: 14px; font-weight: 600; margin-bottom: 2px; }
.client-block .sub { color: var(--dim); font-size: 12px; margin-bottom: 10px; }
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
@media (max-width: 760px) { .cols { grid-template-columns: 1fr; } }
.tag { display: inline-block; font-size: 11px; color: var(--dim);
  border: 1px solid var(--line); border-radius: 3px; padding: 1px 6px;
  margin: 0 4px 4px 0; }
.empty { color: var(--dim); font-size: 12px; padding: 10px 12px;
  background: var(--panel); border: 1px solid var(--line); border-radius: 4px; }
footer { margin-top: 48px; color: var(--dim); font-size: 11px;
  border-top: 1px solid var(--line); padding-top: 12px; }
a { color: var(--ok); text-decoration: none; }
"""


def esc(s):
    return html.escape(str(s))


def fmt(n):
    return f"{n:,}"


def pct(part, whole):
    return f"{(100.0 * part / whole):.1f}%" if whole else "0.0%"


def bar(part, whole, cls="ok"):
    w = (100.0 * part / whole) if whole else 0
    return f'<div class="bar"><i class="{cls}" style="width:{w:.1f}%"></i></div>'


def stack(ok_n, blk_n, scale):
    ow = (100.0 * ok_n / scale) if scale else 0
    bw = (100.0 * blk_n / scale) if scale else 0
    return (f'<div class="stack"><i class="blk" style="width:{bw:.1f}%"></i>'
            f'<i class="ok" style="width:{ow:.1f}%"></i></div>')


def domain_table(rows, total, label, with_clients=True):
    if not rows:
        return f'<div class="empty">No {esc(label)} queries in this period.</div>'
    top = rows[0][1]
    head = "<tr><th>#</th><th>Domain</th><th class=num>Queries</th><th class=num>%</th>"
    if with_clients:
        head += "<th class=num>Clients</th>"
    head += "<th></th></tr>"
    body = []
    for i, r in enumerate(rows, 1):
        dom, n = r[0], r[1]
        cells = (f"<td class=num>{i}</td><td class=dom>{esc(dom)}</td>"
                 f"<td class=num>{fmt(n)}</td><td class='num pct'>{pct(n, total)}</td>")
        if with_clients:
            cells += f"<td class=num>{fmt(r[2])}</td>"
        cells += f"<td>{bar(n, top, 'blk' if 'block' in label else 'ok')}</td>"
        body.append(f"<tr>{cells}</tr>")
    return f"<table>{head}{''.join(body)}</table>"


def build_html(d, names, start, end, args):
    total, blocked = d["total"], d["blocked"]
    permitted = total - blocked

    def cname(ip):
        n = names.get(ip)
        return f"{esc(n)} <span class=pct>({esc(ip)})</span>" if n else esc(ip)

    out = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
           f"<meta name=viewport content='width=device-width,initial-scale=1'>"
           f"<title>Pi-hole report {start:%Y-%m-%d} to {end - timedelta(seconds=1):%Y-%m-%d}</title>"
           f"<style>{CSS}</style></head><body>"]

    out.append(
        f"<h1>PI-HOLE DNS REPORT <span>// {start:%Y-%m-%d} &rarr; "
        f"{(end - timedelta(seconds=1)):%Y-%m-%d}</span></h1>"
        f"<div class=meta>database: {esc(args.db)} &middot; generated "
        f"{datetime.now():%Y-%m-%d %H:%M:%S} &middot; "
        f"DNS-level visibility only (no bandwidth/URLs; DoH and hardcoded "
        f"resolvers bypass Pi-hole)</div>")

    out.append(
        "<div class=cards>"
        f"<div class=card><div class=v>{fmt(total)}</div><div class=l>Total queries</div></div>"
        f"<div class=card><div class=v>{fmt(permitted)}</div><div class=l>Permitted</div></div>"
        f"<div class='card blk'><div class=v>{fmt(blocked)}</div><div class=l>Blocked</div></div>"
        f"<div class='card blk'><div class=v>{pct(blocked, total)}</div><div class=l>Block rate</div></div>"
        f"<div class=card><div class=v>{fmt(d['clients_n'])}</div><div class=l>Clients</div></div>"
        f"<div class=card><div class=v>{fmt(d['domains_n'])}</div><div class=l>Unique domains</div></div>"
        "</div>")

    # Per day
    out.append("<h2>Queries per day</h2>")
    if d["per_day"]:
        day_max = max(r[1] for r in d["per_day"])
        rows = "".join(
            f"<tr><td>{esc(day)}</td><td class=num>{fmt(n)}</td>"
            f"<td class=num>{fmt(b or 0)}</td>"
            f"<td class='num pct{' hot' if n and (b or 0) / n > 0.25 else ''}'>{pct(b or 0, n)}</td>"
            f"<td>{stack(n - (b or 0), b or 0, day_max)}</td></tr>"
            for day, n, b in d["per_day"])
        out.append("<table><tr><th>Date</th><th class=num>Queries</th>"
                   "<th class=num>Blocked</th><th class=num>Rate</th><th></th></tr>"
                   f"{rows}</table>")
    else:
        out.append('<div class="empty">No queries in this period.</div>')

    # Top clients
    out.append("<h2>Top clients</h2>")
    if d["top_clients"]:
        cmax = d["top_clients"][0][1]
        rows = "".join(
            f"<tr><td class=num>{i}</td><td>{cname(c)}</td>"
            f"<td class=num>{fmt(n)}</td><td class=num>{fmt(b or 0)}</td>"
            f"<td class='num pct{' hot' if n and (b or 0) / n > 0.25 else ''}'>{pct(b or 0, n)}</td>"
            f"<td class=num>{fmt(doms)}</td><td>{stack(n - (b or 0), b or 0, cmax)}</td></tr>"
            for i, (c, n, b, doms) in enumerate(d["top_clients"], 1))
        out.append("<table><tr><th>#</th><th>Client</th><th class=num>Queries</th>"
                   "<th class=num>Blocked</th><th class=num>Rate</th>"
                   "<th class=num>Domains</th><th></th></tr>"
                   f"{rows}</table>")
    else:
        out.append('<div class="empty">No clients in this period.</div>')

    out.append("<h2>Top permitted domains</h2>")
    out.append(domain_table(d["top_permitted"], permitted, "permitted"))
    out.append("<h2>Top blocked domains</h2>")
    out.append(domain_table(d["top_blocked"], blocked, "blocked"))

    # Status breakdown
    out.append("<h2>Blocked-status breakdown</h2>")
    blk_rows = [(s, n) for s, n in d["status_breakdown"] if s in BLOCKED_STATUSES]
    if blk_rows:
        smax = max(n for _, n in blk_rows)
        rows = "".join(
            f"<tr><td>{esc(STATUS_NAMES.get(s, f'status {s}'))}</td>"
            f"<td class=num>{fmt(n)}</td>"
            f"<td class='num pct'>{pct(n, blocked)}</td>"
            f"<td>{bar(n, smax, 'blk')}</td></tr>"
            for s, n in blk_rows)
        out.append("<table><tr><th>Status</th><th class=num>Queries</th>"
                   f"<th class=num>% of blocked</th><th></th></tr>{rows}</table>")
    else:
        out.append('<div class="empty">Nothing was blocked in this period.</div>')

    # Per-client detail
    out.append(f"<h2>Per-client detail (top {len(d['detail'])} clients)</h2>")
    for c, det in d["detail"].items():
        ctotal = sum(n for _, n in det["types"])
        tags = "".join(f'<span class=tag>{esc(QUERY_TYPES.get(t, f"type{t}"))} '
                       f'{fmt(n)}</span>' for t, n in det["types"])
        out.append(
            f"<div class=client-block><h3>{cname(c)}</h3>"
            f"<div class=sub>{fmt(ctotal)} queries &middot; query types: {tags or '&mdash;'}</div>"
            "<div class=cols>"
            f"<div>{domain_table(det['permitted'], ctotal, 'permitted', with_clients=False)}</div>"
            f"<div>{domain_table(det['blocked'], ctotal, 'blocked', with_clients=False)}</div>"
            "</div></div>")

    out.append("<footer>pihole-digest.py &middot; read-only against "
               "pihole-FTL.db &middot; blocked statuses: "
               f"{', '.join(str(s) for s in BLOCKED_STATUSES)}</footer>")
    out.append("</body></html>")
    return "".join(out)


def main():
    args = parse_args()
    t0, t1, start, end = time_window(args)
    con = connect_ro(args.db)
    try:
        data = gather(con, t0, t1, args)
        ips = [r[0] for r in data["top_clients"]]
        names = client_names(con, ips, args.resolve)
    finally:
        con.close()

    doc = build_html(data, names, start, end, args)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(doc)
    print(f"report written: {args.output} "
          f"({data['total']:,} queries, {data['blocked']:,} blocked, "
          f"{data['clients_n']:,} clients, "
          f"{start:%Y-%m-%d} to {(end - timedelta(seconds=1)):%Y-%m-%d})")


if __name__ == "__main__":
    main()
