#!/usr/bin/env python3
"""Unit tests for pihole-digest.py. Run: python3 -m unittest discover -s tests"""

import argparse
import importlib.util
import sqlite3
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "pihole-digest.py"
spec = importlib.util.spec_from_file_location("pihole_digest", SCRIPT)
pd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pd)


def make_db():
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE queries (timestamp INTEGER, type INTEGER, "
                "status INTEGER, domain TEXT, client TEXT)")
    con.execute("CREATE TABLE network_addresses (ip TEXT, name TEXT)")
    return con


def args_ns(**over):
    base = dict(top=25, max_clients=20, per_client_top=15,
                date_from=None, date_to=None, days=7, db=":memory:")
    base.update(over)
    return argparse.Namespace(**base)


class TimeWindowTests(unittest.TestCase):
    def test_days_default(self):
        t0, t1, start, end = pd.time_window(args_ns(days=7))
        self.assertEqual((end - start).days, 7)
        self.assertEqual(start.hour, 0)

    def test_explicit_range_inclusive(self):
        args = args_ns(date_from="2026-07-01", date_to="2026-07-03")
        t0, t1, start, end = pd.time_window(args)
        self.assertEqual(start, datetime(2026, 7, 1))
        self.assertEqual(end, datetime(2026, 7, 4))  # +1 day, exclusive upper bound


class GatherAndRenderTests(unittest.TestCase):
    def setUp(self):
        self.con = make_db()
        now = int(datetime(2026, 7, 10, 12).timestamp())
        rows = [
            # timestamp, type, status, domain, client
            (now, 1, 2, "example.com", "192.168.1.10"),      # forwarded (permitted)
            (now, 1, 3, "example.com", "192.168.1.10"),      # cache (permitted)
            (now, 1, 1, "ads.example", "192.168.1.10"),       # blocked (gravity)
            (now, 6, 2, "example.com", "192.168.1.20"),      # PTR, permitted
            (now, 1, 4, "<script>bad.test", "192.168.1.20"),  # blocked (regex), unsafe domain
        ]
        self.con.executemany(
            "INSERT INTO queries (timestamp, type, status, domain, client) "
            "VALUES (?, ?, ?, ?, ?)", rows)
        self.con.execute(
            "INSERT INTO network_addresses (ip, name) VALUES (?, ?)",
            ("192.168.1.10", "desktop"))
        self.con.commit()
        self.t0 = now - 3600
        self.t1 = now + 3600
        self.args = args_ns()

    def test_totals_and_blocked_count(self):
        d = pd.gather(self.con, self.t0, self.t1, self.args)
        self.assertEqual(d["total"], 5)
        self.assertEqual(d["blocked"], 2)
        self.assertEqual(d["clients_n"], 2)

    def test_top_domains_split_permitted_vs_blocked(self):
        d = pd.gather(self.con, self.t0, self.t1, self.args)
        permitted_domains = {r[0] for r in d["top_permitted"]}
        blocked_domains = {r[0] for r in d["top_blocked"]}
        self.assertIn("example.com", permitted_domains)
        self.assertIn("ads.example", blocked_domains)
        self.assertIn("<script>bad.test", blocked_domains)

    def test_empty_window_does_not_crash(self):
        d = pd.gather(self.con, 0, 1, self.args)
        self.assertEqual(d["total"], 0)
        self.assertEqual(d["blocked"], 0)
        self.assertEqual(d["top_clients"], [])

    def test_html_escapes_unsafe_domain(self):
        d = pd.gather(self.con, self.t0, self.t1, self.args)
        names = pd.client_names(self.con, [r[0] for r in d["top_clients"]], False)
        start = datetime.fromtimestamp(self.t0)
        end = datetime.fromtimestamp(self.t1)
        html_out = pd.build_html(d, names, start, end, self.args)
        self.assertNotIn("<script>bad.test", html_out)
        self.assertIn("&lt;script&gt;bad.test", html_out)

    def test_html_uses_resolved_client_name(self):
        d = pd.gather(self.con, self.t0, self.t1, self.args)
        names = pd.client_names(self.con, [r[0] for r in d["top_clients"]], False)
        start = datetime.fromtimestamp(self.t0)
        end = datetime.fromtimestamp(self.t1)
        html_out = pd.build_html(d, names, start, end, self.args)
        self.assertIn("desktop", html_out)
        self.assertIn("192.168.1.20", html_out)  # unresolved client falls back to raw IP


class EmptyReportTests(unittest.TestCase):
    def test_build_html_on_empty_database(self):
        con = make_db()
        args = args_ns()
        start = datetime(2026, 7, 10)
        end = datetime(2026, 7, 11)
        d = pd.gather(con, int(start.timestamp()), int(end.timestamp()), args)
        names = pd.client_names(con, [], False)
        html_out = pd.build_html(d, names, start, end, args)
        con.close()
        self.assertEqual(html_out.count('<div class="empty">'), 5)
        self.assertIn("No queries in this period", html_out)
        self.assertIn("No clients in this period", html_out)
        self.assertIn("Nothing was blocked in this period", html_out)


class NoNetworkAddressesTableTests(unittest.TestCase):
    def test_client_names_falls_back_on_missing_table(self):
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE queries (timestamp INTEGER, type INTEGER, "
                     "status INTEGER, domain TEXT, client TEXT)")
        # no network_addresses table: older pre-v6 FTL schema
        names = pd.client_names(con, ["192.168.1.10"], False)
        con.close()
        self.assertEqual(names, {})


class FormattingHelperTests(unittest.TestCase):
    def test_pct_handles_zero_whole(self):
        self.assertEqual(pd.pct(0, 0), "0.0%")

    def test_fmt_adds_thousands_separator(self):
        self.assertEqual(pd.fmt(12345), "12,345")

    def test_esc_escapes_html(self):
        self.assertEqual(pd.esc("<b>&"), "&lt;b&gt;&amp;")


if __name__ == "__main__":
    unittest.main()
