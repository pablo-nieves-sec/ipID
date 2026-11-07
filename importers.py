"""
importers.py — read Qualys and Microsoft Defender asset exports and normalise
them into a common shape for reconciliation.

Both tools let you export the device/asset inventory as CSV (or XLSX). Column
names vary by report template and version, so instead of hard-coding headers we
detect them fuzzily: find the column whose header looks like an IP / hostname /
OS / last-seen field. Each row is normalised to:

    {"ip": str, "name": str, "os": str, "last": str, "meta": {...}}

The 'meta' dict keeps source-specific extras (tracking method, onboarding
status, health) so the UI can show "what Qualys/Defender know" about a host.
"""

import csv
import ipaddress
import json
import os
import re

try:
    from openpyxl import load_workbook
    _HAVE_OPENPYXL = True
except ImportError:
    _HAVE_OPENPYXL = False

IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def _read_rows(path):
    """Return a list of dict rows (header -> value) from CSV/TSV/XLSX."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".xlsx", ".xlsm"):
        if not _HAVE_OPENPYXL:
            raise RuntimeError("openpyxl required for .xlsx import")
        wb = load_workbook(path, read_only=True, data_only=True)
        ws = wb.active
        rows_iter = ws.iter_rows(values_only=True)
        headers = None
        out = []
        for row in rows_iter:
            if headers is None:
                # first non-empty row is the header
                if row and any(c is not None for c in row):
                    headers = [str(c).strip() if c is not None else "" for c in row]
                continue
            out.append({headers[i]: ("" if v is None else str(v))
                        for i, v in enumerate(row) if i < len(headers)})
        return out
    # CSV / TSV
    delim = "\t" if ext == ".tsv" else ","
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        return list(csv.DictReader(f, delimiter=delim))


def _find_col(headers, *needles, avoid=()):
    """Pick the first header containing any needle (and none of avoid)."""
    low = {h: h.lower() for h in headers}
    for h in headers:
        hl = low[h]
        if any(a in hl for a in avoid):
            continue
        if any(n in hl for n in needles):
            return h
    return None


def _first_ip(val):
    if not val:
        return ""
    for m in IP_RE.findall(val):
        try:
            ipaddress.ip_address(m)
            return m
        except ValueError:
            continue
    return ""


def normalize_qualys(path):
    rows = _read_rows(path)
    if not rows:
        return []
    headers = list(rows[0].keys())
    c_ip = _find_col(headers, "ip address", "ip", avoid=("description", "ipv6"))
    c_dns = _find_col(headers, "dns", "fqdn")
    c_nb = _find_col(headers, "netbios")
    c_host = _find_col(headers, "hostname", "host name") or c_dns or c_nb
    c_os = _find_col(headers, "operating system", "os platform", "os",
                     avoid=("netbios",))
    c_track = _find_col(headers, "tracking")
    c_last = _find_col(headers, "last scan", "last vuln", "last seen", "last")
    c_tags = _find_col(headers, "tags", "asset tags")

    out = []
    for r in rows:
        name = (r.get(c_nb) or r.get(c_dns) or r.get(c_host) or "").strip()
        ip = _first_ip(r.get(c_ip, "")) if c_ip else ""
        if not name and not ip:
            continue
        out.append({
            "ip": ip, "name": name,
            "os": (r.get(c_os, "") if c_os else "").strip(),
            "last": (r.get(c_last, "") if c_last else "").strip(),
            "meta": {
                "tracking": (r.get(c_track, "") if c_track else "").strip(),
                "tags": (r.get(c_tags, "") if c_tags else "").strip(),
            },
        })
    return out


def normalize_defender(path):
    rows = _read_rows(path)
    if not rows:
        return []
    headers = list(rows[0].keys())
    c_name = _find_col(headers, "device name", "computer name", "hostname",
                       "dns name", "name")
    c_ip = _find_col(headers, "ip address", "ip addresses", "ip",
                     avoid=("public",))
    c_os = _find_col(headers, "os platform", "operating system", "os",
                     avoid=("netbios",))
    c_onboard = _find_col(headers, "onboarding")
    c_health = _find_col(headers, "health")
    c_last = _find_col(headers, "last seen", "last device update", "last")
    c_domain = _find_col(headers, "domain")

    out = []
    for r in rows:
        name = (r.get(c_name, "") if c_name else "").strip()
        ip = _first_ip(r.get(c_ip, "")) if c_ip else ""
        if not name and not ip:
            continue
        out.append({
            "ip": ip, "name": name,
            "os": (r.get(c_os, "") if c_os else "").strip(),
            "last": (r.get(c_last, "") if c_last else "").strip(),
            "meta": {
                "onboarding": (r.get(c_onboard, "") if c_onboard else "").strip(),
                "health": (r.get(c_health, "") if c_health else "").strip(),
                "domain": (r.get(c_domain, "") if c_domain else "").strip(),
            },
        })
    return out
