"""
store.py — persistent history, asset correlation, diffing, and manual review.

The point of this layer is to turn one-shot scans into a tracked inventory over
time. The hard part is identity: DHCP hands out new IPs constantly, so keying an
asset on its IP would make the same machine look "new" every lease. Instead we
anchor identity on the most stable thing available, in this order:

    device name (NetBIOS / PTR / TLS CN)  ->  MAC  ->  IP

So a host that keeps its name but changes IP is recognised as the SAME asset with
a changed address (an 'ip_changed' event), not a new one. That directly answers
the "did this thing leave, or did it just get a new lease?" question: if the name
still shows up anywhere in the scan, the asset is still present.

No dependency on the scanner — record_scan() takes plain dicts, so this module is
testable on its own and the web app and CLI can both drive it.
"""

import json
import re
import shutil
import sqlite3
import time
from datetime import datetime, timezone

from categories import AGENT_CAPABLE, LEGACY_RENAMES, UNKNOWN_CATEGORIES

SCHEMA_VERSION = 2


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _norm_name(name):
    """Normalise a hostname for correlation: strip domain, lowercase."""
    if not name:
        return ""
    n = name.strip().lower()
    n = n.split(".")[0]           # drop DNS domain suffix
    n = re.sub(r"[^a-z0-9\-_]", "", n)
    return n


class Store:
    def __init__(self, path="ipid.db"):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def close(self):
        self.conn.close()

    def _init_schema(self):
        c = self.conn
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, total INTEGER, identified INTEGER, source TEXT);

        CREATE TABLE IF NOT EXISTS assets(
            asset_key TEXT PRIMARY KEY,
            name TEXT, current_ip TEXT,
            category TEXT, confidence TEXT,
            ports TEXT, evidence TEXT,
            ptr TEXT, netbios TEXT, tls_cn TEXT, snmp_descr TEXT,
            mac TEXT, oui_vendor TEXT, http_title TEXT, http_server TEXT,
            first_seen TEXT, last_seen TEXT, last_scan_id INTEGER,
            status TEXT DEFAULT 'present',
            override_category TEXT, override_vendor TEXT, override_notes TEXT,
            reviewed INTEGER DEFAULT 0);

        CREATE TABLE IF NOT EXISTS observations(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER, asset_key TEXT, ip TEXT,
            category TEXT, confidence TEXT, ports TEXT, ts TEXT);

        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER, asset_key TEXT, ts TEXT,
            type TEXT, detail TEXT);

        CREATE TABLE IF NOT EXISTS known_assets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT, ip TEXT, name TEXT, norm_name TEXT,
            os TEXT, last TEXT, meta TEXT, imported_at TEXT);
        CREATE INDEX IF NOT EXISTS idx_known_src ON known_assets(source);
        CREATE INDEX IF NOT EXISTS idx_known_name ON known_assets(norm_name);
        CREATE INDEX IF NOT EXISTS idx_known_ip ON known_assets(ip);

        CREATE TABLE IF NOT EXISTS schema_version(version INTEGER);

        -- The exact set of IPs each scan actually targeted, so "missing" can be
        -- scoped to this scan's scope instead of the whole inventory (1.3).
        CREATE TABLE IF NOT EXISTS scan_targets(scan_id INTEGER, ip TEXT);
        CREATE INDEX IF NOT EXISTS idx_targets_scan ON scan_targets(scan_id);

        -- IPs that were scanned but did not respond; kept for completeness but
        -- never promoted to assets (1.2).
        CREATE TABLE IF NOT EXISTS scan_unresponsive(scan_id INTEGER, ip TEXT);
        """)
        c.commit()
        self._migrate()

    def _migrate(self):
        c = self.conn
        row = c.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        current = row["version"] if row else 0
        if current == 0 and not row:
            c.execute("INSERT INTO schema_version(version) VALUES(0)")
            c.commit()
        if current >= SCHEMA_VERSION:
            return
        # Back the DB up before changing data, once, before the first migration.
        try:
            if self.path not in (":memory:", "") and current < SCHEMA_VERSION:
                shutil.copy2(self.path, f"{self.path}.v{current}.bak")
        except Exception:
            pass
        # v1 -> v2: rewrite legacy classifier category names to canonical (1.1).
        if current < 2:
            for old, new in LEGACY_RENAMES.items():
                c.execute("UPDATE assets SET category=? WHERE category=?", (new, old))
                c.execute("UPDATE assets SET override_category=? WHERE override_category=?",
                          (new, old))
                c.execute("UPDATE observations SET category=? WHERE category=?", (new, old))
        c.execute("DELETE FROM schema_version")
        c.execute("INSERT INTO schema_version(version) VALUES(?)", (SCHEMA_VERSION,))
        c.commit()

    # ---- identity ----------------------------------------------------------

    def _derive_name(self, r):
        return r.get("netbios") or r.get("ptr") or r.get("tls_cn") or ""

    def _resolve_key(self, r, seen_keys):
        """Find the asset this observation belongs to, or mint a new key."""
        name = _norm_name(self._derive_name(r))
        mac = (r.get("mac") or "").upper()
        ip = r.get("ip") or ""

        if name:
            return "name:" + name
        if mac:
            return "mac:" + mac
        # No stable identifier — try to attach to an existing asset currently
        # at this IP (covers a host that dropped its name this scan).
        row = self.conn.execute(
            "SELECT asset_key FROM assets WHERE current_ip=? AND asset_key NOT IN "
            "(SELECT value FROM json_each(?))",
            (ip, json.dumps(list(seen_keys))),
        ).fetchone()
        if row:
            return row["asset_key"]
        return "ip:" + ip

    # ---- recording ---------------------------------------------------------

    def record_scan(self, results, source="scan"):
        """results: list of dicts (see module docstring). Returns scan_id."""
        ts = _now()
        cur = self.conn.execute(
            "INSERT INTO scans(ts,total,identified,source) VALUES(?,?,?,?)",
            (ts, len(results),
             sum(1 for r in results if r.get("category") not in UNKNOWN_CATEGORIES),
             source),
        )
        scan_id = cur.lastrowid

        # Record the full scanned scope (every IP we probed, alive or not) so
        # "missing" can be scoped to it (1.3).
        target_ips = {r.get("ip") for r in results if r.get("ip")}
        self.conn.executemany(
            "INSERT INTO scan_targets(scan_id,ip) VALUES(?,?)",
            [(scan_id, ip) for ip in target_ips])

        seen_keys = set()
        for r in results:
            # Do not store dead IPs as assets (1.2). A host that did not answer
            # any probe is not an asset and must not count as "not in Qualys".
            if r.get("reachable") is False or r.get("category") in ("No response", "Error"):
                self.conn.execute(
                    "INSERT INTO scan_unresponsive(scan_id,ip) VALUES(?,?)",
                    (scan_id, r.get("ip", "")))
                continue
            key = self._resolve_key(r, seen_keys)
            seen_keys.add(key)
            self._upsert_asset(scan_id, ts, key, r)

        # Mark missing only assets whose current IP was IN this scan's scope but
        # was not seen present this time. An asset on a subnet this scan never
        # targeted is left untouched (1.3).
        rows = self.conn.execute(
            "SELECT asset_key,name,current_ip,status FROM assets WHERE last_scan_id!=?",
            (scan_id,),
        ).fetchall()
        for row in rows:
            if row["status"] == "present" and row["current_ip"] in target_ips:
                self.conn.execute(
                    "UPDATE assets SET status='missing' WHERE asset_key=?",
                    (row["asset_key"],))
                self._event(scan_id, ts, row["asset_key"], "missing",
                            f"{row['name'] or row['current_ip']} not seen this scan")
        self.conn.commit()
        return scan_id

    def _upsert_asset(self, scan_id, ts, key, r):
        name = self._derive_name(r)
        ip = r.get("ip") or ""
        cat = r.get("category") or "Unknown"
        conf = r.get("confidence") or "none"
        ports = r.get("ports") or ""
        prior = self.conn.execute(
            "SELECT * FROM assets WHERE asset_key=?", (key,)).fetchone()

        if prior is None:
            self.conn.execute("""
                INSERT INTO assets(asset_key,name,current_ip,category,confidence,
                    ports,evidence,ptr,netbios,tls_cn,snmp_descr,mac,oui_vendor,
                    http_title,http_server,first_seen,last_seen,last_scan_id,status)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'present')""",
                (key, name, ip, cat, conf, ports, r.get("evidence", ""),
                 r.get("ptr", ""), r.get("netbios", ""), r.get("tls_cn", ""),
                 r.get("snmp_descr", ""), r.get("mac", ""), r.get("oui_vendor", ""),
                 r.get("http_title", ""), r.get("http_server", ""),
                 ts, ts, scan_id))
            self._event(scan_id, ts, key, "new",
                        f"{name or ip} first seen as {cat}")
        else:
            # detect changes worth logging
            if prior["current_ip"] and prior["current_ip"] != ip:
                self._event(scan_id, ts, key, "ip_changed",
                            f"{prior['current_ip']} -> {ip}")
            if prior["category"] != cat and cat not in UNKNOWN_CATEGORIES:
                self._event(scan_id, ts, key, "category_changed",
                            f"{prior['category']} -> {cat}")
            if prior["ports"] != ports:
                self._event(scan_id, ts, key, "ports_changed",
                            f"{prior['ports']} -> {ports}")
            if prior["status"] == "missing":
                self._event(scan_id, ts, key, "returned",
                            f"{name or ip} seen again")
            self.conn.execute("""
                UPDATE assets SET name=?,current_ip=?,category=?,confidence=?,
                    ports=?,evidence=?,ptr=?,netbios=?,tls_cn=?,snmp_descr=?,
                    mac=?,oui_vendor=?,http_title=?,http_server=?,
                    last_seen=?,last_scan_id=?,status='present'
                WHERE asset_key=?""",
                (name or prior["name"], ip, cat, conf, ports,
                 r.get("evidence", ""), r.get("ptr", ""), r.get("netbios", ""),
                 r.get("tls_cn", ""), r.get("snmp_descr", ""), r.get("mac", ""),
                 r.get("oui_vendor", ""), r.get("http_title", ""),
                 r.get("http_server", ""), ts, scan_id, key))

        self.conn.execute("""
            INSERT INTO observations(scan_id,asset_key,ip,category,confidence,ports,ts)
            VALUES(?,?,?,?,?,?,?)""",
            (scan_id, key, ip, cat, conf, ports, ts))

    def _event(self, scan_id, ts, key, type_, detail):
        self.conn.execute(
            "INSERT INTO events(scan_id,asset_key,ts,type,detail) VALUES(?,?,?,?,?)",
            (scan_id, key, ts, type_, detail))

    # ---- queries -----------------------------------------------------------

    def _asset_view(self, row):
        d = dict(row)
        # effective category respects a manual override
        d["effective_category"] = d.get("override_category") or d["category"]
        d["overridden"] = bool(d.get("override_category"))
        return d

    def inventory(self, search="", category="", confidence="", status="",
                  sort="name"):
        q = "SELECT * FROM assets WHERE 1=1"
        args = []
        if status:
            q += " AND status=?"; args.append(status)
        if confidence:
            q += " AND confidence=?"; args.append(confidence)
        if category:
            q += " AND COALESCE(override_category,category)=?"; args.append(category)
        if search:
            like = f"%{search.lower()}%"
            q += (" AND (lower(name) LIKE ? OR current_ip LIKE ? OR "
                  "lower(evidence) LIKE ? OR lower(snmp_descr) LIKE ? OR "
                  "lower(http_title) LIKE ? OR lower(ports) LIKE ?)")
            args += [like, like, like, like, like, like]
        sort_col = {
            "name": "name", "ip": "current_ip", "category": "category",
            "confidence": "confidence", "last_seen": "last_seen DESC",
            "first_seen": "first_seen DESC",
        }.get(sort, "name")
        q += f" ORDER BY {sort_col}"
        rows = self.conn.execute(q, args).fetchall()
        return [self._asset_view(r) for r in rows]

    def review_queue(self):
        """Present assets that need a human: unknown category or low confidence,
        not yet reviewed/overridden."""
        rows = self.conn.execute("""
            SELECT * FROM assets
            WHERE status='present' AND reviewed=0 AND override_category IS NULL
              AND (category IN ('Unknown','Miscellaneous') OR confidence='low')
            ORDER BY current_ip""").fetchall()
        return [self._asset_view(r) for r in rows]

    def asset_detail(self, key):
        row = self.conn.execute(
            "SELECT * FROM assets WHERE asset_key=?", (key,)).fetchone()
        if not row:
            return None
        d = self._asset_view(row)
        d["events"] = [dict(e) for e in self.conn.execute(
            "SELECT * FROM events WHERE asset_key=? ORDER BY id DESC LIMIT 50",
            (key,)).fetchall()]
        d["observations"] = [dict(o) for o in self.conn.execute(
            "SELECT * FROM observations WHERE asset_key=? ORDER BY id DESC LIMIT 50",
            (key,)).fetchall()]
        d["known"] = self.known_for_asset(d)
        return d

    def set_override(self, key, category=None, vendor=None, notes=None):
        self.conn.execute("""
            UPDATE assets SET override_category=?,override_vendor=?,
                override_notes=?,reviewed=1 WHERE asset_key=?""",
            (category or None, vendor or None, notes or None, key))
        ts = _now()
        self._event(None, ts, key, "reviewed",
                    f"manually set to {category or 'reviewed'}"
                    + (f" ({vendor})" if vendor else ""))
        self.conn.commit()

    def summary(self):
        rows = self.conn.execute(
            "SELECT COALESCE(override_category,category) c, COUNT(*) n "
            "FROM assets WHERE status='present' GROUP BY c").fetchall()
        counts = {r["c"]: r["n"] for r in rows}
        total = sum(counts.values())
        missing = self.conn.execute(
            "SELECT COUNT(*) n FROM assets WHERE status='missing'").fetchone()["n"]
        review = len(self.review_queue())
        last = self.conn.execute(
            "SELECT id,ts FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return {"counts": counts, "total": total, "missing": missing,
                "review": review,
                "last_scan": dict(last) if last else None}

    def last_diff(self):
        """Change events from the most recent scan."""
        last = self.conn.execute(
            "SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if not last:
            return {"scan_id": None, "events": []}
        evs = self.conn.execute(
            "SELECT * FROM events WHERE scan_id=? ORDER BY id", (last["id"],)
        ).fetchall()
        return {"scan_id": last["id"], "events": [dict(e) for e in evs]}

    # ---- Qualys / Defender reconciliation ---------------------------------
    # AGENT_CAPABLE now lives in categories.py (the single source of truth).

    def import_known(self, source, records):
        """Replace all known assets for a source (qualys|defender) with records.
        records: list of {ip,name,os,last,meta} from importers.py."""
        ts = _now()
        self.conn.execute("DELETE FROM known_assets WHERE source=?", (source,))
        for r in records:
            self.conn.execute("""
                INSERT INTO known_assets(source,ip,name,norm_name,os,last,meta,imported_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (source, r.get("ip", ""), r.get("name", ""),
                 _norm_name(r.get("name", "")), r.get("os", ""), r.get("last", ""),
                 json.dumps(r.get("meta", {})), ts))
        self.conn.commit()
        return self.conn.execute(
            "SELECT COUNT(*) n FROM known_assets WHERE source=?",
            (source,)).fetchone()["n"]

    def _source_lookups(self, source):
        rows = self.conn.execute(
            "SELECT * FROM known_assets WHERE source=?", (source,)).fetchall()
        by_name, by_ip = {}, {}
        for r in rows:
            if r["norm_name"]:
                by_name[r["norm_name"]] = r
            if r["ip"]:
                by_ip[r["ip"]] = r
        return by_name, by_ip, rows

    def _match(self, asset, by_name, by_ip):
        nn = _norm_name(asset.get("name", ""))
        if nn and nn in by_name:
            return by_name[nn]
        ip = asset.get("current_ip") or ""
        if ip and ip in by_ip:
            return by_ip[ip]
        return None

    def coverage(self, source_filter=""):
        """Reconcile discovered (present) assets against Qualys + Defender.
        Returns per-asset coverage plus summary counts and 'known but not seen'."""
        q_name, q_ip, q_rows = self._source_lookups("qualys")
        d_name, d_ip, d_rows = self._source_lookups("defender")
        has_q = bool(q_rows)
        has_d = bool(d_rows)

        present = self.inventory(status="present")
        rows = []
        matched_q_ids, matched_d_ids = set(), set()
        s = {"present": len(present),
             "in_qualys": 0, "not_qualys": 0,
             "in_defender": 0, "missing_edr": 0,
             "has_qualys": has_q, "has_defender": has_d}

        for a in present:
            mq = self._match(a, q_name, q_ip) if has_q else None
            md = self._match(a, d_name, d_ip) if has_d else None
            if mq:
                matched_q_ids.add(mq["id"]); s["in_qualys"] += 1
            elif has_q:
                s["not_qualys"] += 1
            if md:
                matched_d_ids.add(md["id"]); s["in_defender"] += 1

            cat = a.get("effective_category", "")
            agent_capable = cat in AGENT_CAPABLE
            missing_edr = has_d and (md is None) and agent_capable
            if missing_edr:
                s["missing_edr"] += 1

            rows.append({
                "asset_key": a["asset_key"], "ip": a["current_ip"],
                "name": a["name"], "category": cat,
                "in_qualys": bool(mq), "in_defender": bool(md),
                "agent_capable": agent_capable, "missing_edr": missing_edr,
                "qualys": (dict(mq) if mq else None),
                "defender": (dict(md) if md else None),
            })

        # Known to Qualys/Defender but never seen on the network this run.
        not_seen = []
        for src, srows, matched in (("qualys", q_rows, matched_q_ids),
                                    ("defender", d_rows, matched_d_ids)):
            for r in srows:
                if r["id"] not in matched:
                    not_seen.append({"source": src, "ip": r["ip"],
                                     "name": r["name"], "os": r["os"],
                                     "last": r["last"]})
        s["known_not_seen"] = len(not_seen)

        if source_filter == "missing_edr":
            rows = [r for r in rows if r["missing_edr"]]
        elif source_filter == "not_qualys":
            rows = [r for r in rows if has_q and not r["in_qualys"]]

        return {"summary": s, "rows": rows, "not_seen": not_seen}

    def known_for_asset(self, asset):
        """Return {qualys:..., defender:...} known-record match for one asset."""
        out = {}
        for src in ("qualys", "defender"):
            by_name, by_ip, rows = self._source_lookups(src)
            m = self._match(asset, by_name, by_ip)
            out[src] = dict(m) if m else None
        return out
