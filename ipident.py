#!/usr/bin/env python3
"""
ipident.py — What is every IP for?

Give it a spreadsheet (.xlsx or .csv) of IP addresses (individual IPs or CIDR
ranges) and it probes each one across multiple signals, then classifies it into
a device category (printer, switch, firewall, endpoint, server, camera, etc.)
with an evidence trail and a confidence level.

Pure Python. No nmap, no system binaries. Only third-party dependency is
openpyxl (for reading/writing .xlsx). CSV works with zero dependencies.

Signals collected per IP:
  - Reverse DNS (PTR record)
  - TCP connect scan across a curated, high-signal port set
  - Banner grabbing on text-protocol ports (SSH, Telnet, FTP, SMTP, ...)
  - HTTP/HTTPS fingerprint (page <title>, Server header, redirect target)
  - TLS certificate inspection (CN / SANs / issuer)
  - SNMP sysDescr (UDP 161, minimal v2c GetRequest, community configurable)
  - NetBIOS name query (UDP 137) for Windows hostnames
  - Best-effort MAC + OUI vendor lookup (local subnet only, via OS ARP table)

Usage:
  python ipident.py input.xlsx -o results.xlsx
  python ipident.py ips.csv --profile quick --workers 100
  python ipident.py input.xlsx --no-snmp --timeout 1.5

This tool is for auditing networks you own or are authorized to assess.
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from categories import Cat

# openpyxl is only needed for .xlsx; imported lazily so CSV-only use needs nothing.
try:
    from openpyxl import load_workbook, Workbook
    _HAVE_OPENPYXL = True
except ImportError:
    _HAVE_OPENPYXL = False


# ---------------------------------------------------------------------------
# Port profiles — curated for CLASSIFICATION, not exhaustive scanning.
# Each port here is a meaningful tell for some device category.
# ---------------------------------------------------------------------------

PORT_PROFILES = {
    "quick": [22, 23, 80, 443, 445, 3389, 9100, 161, 5353],
    "standard": [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 515, 554,
        623, 631, 993, 995, 1433, 1723, 2000, 3306, 3389, 5060, 5432,
        5900, 8000, 8006, 8080, 8443, 9100, 10000,
        # UDP-probed separately: 161 (SNMP), 137 (NetBIOS), 5353 (mDNS)
        161, 137, 5353,
    ],
    "full": [
        21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
        465, 500, 502, 515, 548, 554, 587, 623, 631, 636, 993, 995, 1025,
        1433, 1521, 1723, 1900, 2000, 2049, 2082, 2222, 3128, 3268, 3306,
        3389, 4786, 5000, 5001, 5060, 5222, 5357, 5432, 5555, 5900, 5985,
        5986, 6379, 7547, 8000, 8006, 8008, 8080, 8083, 8291, 8443, 8888,
        9000, 9090, 9100, 9200, 9443, 10000, 27017, 47808, 49152,
        161, 137, 5353,
    ],
}

# Ports probed over UDP rather than TCP connect.
UDP_PORTS = {161, 137, 5353}

# Ports we attempt an HTTP/HTTPS fingerprint on.
HTTP_PORTS = {80, 8000, 8008, 8080, 8888, 9000, 9090, 10000, 5000, 2082}
HTTPS_PORTS = {443, 8006, 8083, 8443, 9443, 5986, 8291, 2083}

# Ports that emit a useful text banner on connect.
BANNER_PORTS = {21, 22, 23, 25, 110, 143, 587, 993, 995, 2222}


# ---------------------------------------------------------------------------
# Small OUI table (MAC prefix -> vendor). Best-effort, local subnet only.
# Not exhaustive; covers common enterprise gear. Prefix is upper-case, no seps.
# ---------------------------------------------------------------------------

OUI_VENDORS = {
    "001B17": "Cisco", "0025B4": "Cisco", "F866F2": "Cisco", "00000C": "Cisco",
    "E0553D": "Cisco Meraki", "88153B": "Cisco Meraki", "0018A9": "Cisco Meraki",
    "AC17C8": "Juniper", "2C6BF5": "Juniper", "F4CC55": "Aruba/HPE",
    "94F128": "Aruba/HPE", "18647E": "Ubiquiti", "24A43C": "Ubiquiti",
    "788A20": "Ubiquiti", "FCECDA": "Ubiquiti", "B4FBE4": "Ubiquiti",
    "001560": "HP", "3C52A1": "HP", "9C8ECD": "HP", "3863BB": "HP",
    "0017A4": "HP", "001321": "HP Printer", "00000F": "Xerox",
    "9CB654": "Canon", "00BBC1": "Canon", "0000AA": "Xerox",
    "AC162D": "Brother", "008077": "Brother", "0080A3": "Lantronix",
    "000CF1": "Intel", "3C0754": "Apple", "F0189E": "Apple", "A45E60": "Apple",
    "AC87A3": "Apple", "8C8590": "Apple", "F0DBF8": "Apple", "DC2B2A": "Apple",
    "001C42": "Parallels(VM)", "005056": "VMware", "000C29": "VMware",
    "0050F2": "Microsoft", "00155D": "Microsoft Hyper-V", "080027": "VirtualBox",
    "525400": "QEMU/KVM", "00E04C": "Realtek", "001B21": "Intel",
    "00408C": "Axis Camera", "ACCC8E": "Axis Camera", "00126A": "Polycom",
    "0004F2": "Polycom", "64167F": "Polycom", "001344": "Hikvision",
    "44A642": "Hikvision", "BCAD28": "Hikvision", "C0561D": "Dell iDRAC",
    "18DBF2": "Dell", "B083FE": "Dell", "F8BC12": "Dell",
    "F04DA2": "Dell", "001EC9": "Dell", "D067E5": "Dell",
    "F0921C": "HPE iLO", "9457A5": "HPE", "00A0D1": "Fortinet",
    "0009F5": "SonicWall", "C0EAE4": "SonicWall", "001B17b": "Palo Alto",
    "B4C799": "Palo Alto",
}


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class IPResult:
    ip: str
    reachable: bool = False
    ptr: str = ""
    open_ports: List[int] = field(default_factory=list)
    banners: Dict[int, str] = field(default_factory=dict)
    http_title: str = ""
    http_server: str = ""
    http_redirect: str = ""
    tls_cn: str = ""
    tls_san: str = ""
    tls_issuer: str = ""
    snmp_descr: str = ""
    netbios: str = ""
    mac: str = ""
    oui_vendor: str = ""
    category: str = "Unknown"
    confidence: str = "none"
    evidence: List[str] = field(default_factory=list)

    def ports_str(self) -> str:
        return ",".join(str(p) for p in sorted(self.open_ports))

    def evidence_str(self) -> str:
        return " | ".join(self.evidence)

    def to_dict(self) -> dict:
        """Flat dict shape consumed by store.py and the web API."""
        return {
            "ip": self.ip, "category": self.category, "confidence": self.confidence,
            "ptr": self.ptr, "netbios": self.netbios,
            "tls_cn": self.tls_cn, "snmp_descr": self.snmp_descr,
            "mac": self.mac, "oui_vendor": self.oui_vendor,
            "http_title": self.http_title, "http_server": self.http_server,
            "ports": self.ports_str(), "evidence": self.evidence_str(),
            "reachable": self.reachable,
        }


# ---------------------------------------------------------------------------
# Signal collectors
# ---------------------------------------------------------------------------

# Bound total concurrent sockets across all hosts so a big scan cannot exhaust
# Windows ephemeral ports / file handles (1S.3).
_SOCKET_SEM = threading.BoundedSemaphore(512)

# Reverse DNS is run on its own pool so a hard per-lookup timeout can be
# enforced. socket.gethostbyaddr() uses the OS resolver, which does NOT honor
# setdefaulttimeout(); on a corporate network a slow or filtered reverse zone
# would otherwise block every worker forever (the "stuck at 0/N" hang). We cap
# each lookup with future.result(timeout=...); a straggler keeps running in the
# pool but no longer blocks the scan.
_RDNS_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=16)


def reverse_dns(ip: str, timeout: float) -> str:
    try:
        fut = _RDNS_POOL.submit(socket.gethostbyaddr, ip)
        host, _, _ = fut.result(timeout=max(0.5, min(timeout, 3.0)))
        return host
    except Exception:
        return ""


def tcp_connect(ip: str, port: int, timeout: float) -> str:
    """Return 'open', 'refused', or 'closed'. A refusal still proves the host is
    alive (something answered), so it counts toward reachability (1.4)."""
    with _SOCKET_SEM:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return "open"
        except ConnectionRefusedError:
            return "refused"
        except Exception:
            return "closed"


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Read a text banner from a service that speaks first (or nudge it)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
            except socket.timeout:
                # Some services wait for input first.
                try:
                    s.sendall(b"\r\n")
                    data = s.recv(256)
                except Exception:
                    return ""
            text = data.decode("utf-8", "replace").strip()
            return re.sub(r"\s+", " ", text)[:200]
    except Exception:
        return ""


def http_fingerprint(ip: str, port: int, use_tls: bool, timeout: float) -> Tuple[str, str, str]:
    """Return (title, server_header, redirect_location) from an HTTP(S) probe."""
    scheme = "https" if use_tls else "http"
    host_hdr = ip if port in (80, 443) else f"{ip}:{port}"
    req = (
        f"GET / HTTP/1.1\r\nHost: {host_hdr}\r\n"
        "User-Agent: ipident/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    ).encode()
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # appliances use self-signed certs
            sock = ctx.wrap_socket(raw, server_hostname=ip)
        else:
            sock = raw
        sock.settimeout(timeout)
        sock.sendall(req)
        chunks = []
        deadline = time.time() + timeout
        while time.time() < deadline and len(b"".join(chunks)) < 16384:
            try:
                b = sock.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
        sock.close()
    except Exception:
        return "", "", ""

    resp = b"".join(chunks).decode("utf-8", "replace")
    headers_blob = resp.split("\r\n\r\n", 1)[0]

    server = ""
    location = ""
    for line in headers_blob.split("\r\n"):
        low = line.lower()
        if low.startswith("server:"):
            server = line.split(":", 1)[1].strip()
        elif low.startswith("location:"):
            location = line.split(":", 1)[1].strip()

    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", resp, re.IGNORECASE | re.DOTALL)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:150]

    return title, server, location


def tls_cert_info(ip: str, port: int, timeout: float) -> Tuple[str, str, str]:
    """Return (common_name, san_list, issuer) from the TLS certificate."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, port), timeout=timeout)
        sock = ctx.wrap_socket(raw, server_hostname=ip)
        # CERT_NONE hides parsed fields; pull the DER and parse minimally.
        der = sock.getpeercert(binary_form=True)
        sock.close()
    except Exception:
        return "", "", ""

    # Parse just the human-readable strings we care about out of the DER.
    # Full ASN.1 parsing is overkill; we extract CN and DNS SANs by pattern.
    cn = ""
    san = ""
    issuer = ""
    try:
        text = der.decode("latin-1")
        # Common Name appears after OID 55 04 03 (2.5.4.3) as a printable/UTF8 string.
        cn_matches = re.findall(r"\x55\x04\x03.{2}([ -~]{2,64})", text)
        if cn_matches:
            cn = cn_matches[0].strip()
            if len(cn_matches) > 1:
                issuer = cn_matches[-1].strip()
        # DNS SANs are stored as context tag 0x82 <len> <ascii>.
        san_hits = re.findall(r"\x82(.)([ -~]{3,})", text)
        names = []
        for length_byte, s in san_hits:
            n = s[: ord(length_byte)] if ord(length_byte) <= len(s) else s
            n = n.strip()
            if "." in n and re.match(r"^[A-Za-z0-9.\-\*]+$", n):
                names.append(n)
        san = ",".join(dict.fromkeys(names))[:200]
    except Exception:
        pass
    return cn, san, issuer


def snmp_sysdescr(ip: str, community: str, timeout: float) -> str:
    """Minimal SNMPv2c GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0)."""

    def ber_len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b

    def tlv(tag: int, val: bytes) -> bytes:
        return bytes([tag]) + ber_len(len(val)) + val

    def integer(n: int) -> bytes:
        b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=False)
        if b[0] & 0x80:
            b = b"\x00" + b
        return tlv(0x02, b)

    community_b = tlv(0x04, community.encode())
    version = integer(1)  # v2c
    # sysDescr.0 OID
    oid = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    varbind = tlv(0x30, tlv(0x06, oid) + tlv(0x05, b""))
    varbinds = tlv(0x30, varbind)
    req_id = integer(random.randint(1, 0x7FFFFFFF))
    pdu = tlv(0xA0, req_id + integer(0) + integer(0) + varbinds)  # GetRequest
    msg = tlv(0x30, version + community_b + pdu)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, (ip, 161))
        data, _ = s.recvfrom(2048)
        s.close()
    except Exception:
        return ""

    # Walk TLVs to find the last OCTET STRING (the sysDescr value).
    try:
        return _last_octet_string(data)
    except Exception:
        return ""


def _last_octet_string(data: bytes) -> str:
    """Very small TLV walker: return the last printable OCTET STRING value."""
    result = ""
    i = 0
    stack = [(0, len(data))]
    # Flat scan: iterate TLVs, descend into SEQUENCE/context-constructed.
    def parse(buf: bytes) -> None:
        nonlocal result
        idx = 0
        while idx < len(buf):
            tag = buf[idx]
            idx += 1
            if idx >= len(buf):
                break
            length = buf[idx]
            idx += 1
            if length & 0x80:
                num = length & 0x7F
                length = int.from_bytes(buf[idx:idx + num], "big")
                idx += num
            val = buf[idx:idx + length]
            idx += length
            if tag in (0x30, 0xA0, 0xA2):  # constructed: recurse
                parse(val)
            elif tag == 0x04:  # OCTET STRING
                s = val.decode("utf-8", "replace")
                if s.strip():
                    result = re.sub(r"\s+", " ", s).strip()[:200]
    parse(data)
    return result


def netbios_name(ip: str, timeout: float) -> str:
    """NetBIOS node status query (UDP 137) -> first non-group name (hostname)."""
    tid = random.randint(0, 0xFFFF)
    # NBSTAT query for "*" wildcard.
    packet = struct.pack(">H", tid) + bytes.fromhex(
        "0000000100000000000020434b41414141414141414141414141414141"
        "41414141414141414141414141410000210001"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (ip, 137))
        data, _ = s.recvfrom(2048)
        s.close()
    except Exception:
        return ""
    try:
        # Number of names is one byte at offset 56; names are 18 bytes each.
        count = data[56]
        off = 57
        for _ in range(count):
            name = data[off:off + 15].decode("ascii", "replace").strip()
            flags = data[off + 16]
            group = bool(flags & 0x80)
            if name and not group:
                return name
            off += 18
    except Exception:
        return ""
    return ""


def arp_lookup(ip: str) -> str:
    """Best-effort MAC from the local OS ARP table (only works same subnet)."""
    try:
        if sys.platform.startswith("linux"):
            out = subprocess.run(["ip", "neigh", "show", ip],
                                 capture_output=True, text=True, timeout=3).stdout
            m = re.search(r"([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})", out)
            return m.group(1).upper() if m else ""
        else:  # macOS / Windows / BSD 'arp -a'
            out = subprocess.run(["arp", "-a", ip],
                                 capture_output=True, text=True, timeout=3).stdout
            m = re.search(r"([0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5})", out)
            return m.group(1).upper().replace("-", ":") if m else ""
    except Exception:
        return ""


def oui_vendor(mac: str) -> str:
    if not mac:
        return ""
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return OUI_VENDORS.get(prefix, "")


# ---------------------------------------------------------------------------
# Per-IP orchestration
# ---------------------------------------------------------------------------

def probe_ip(ip: str, ports: List[int], timeout: float,
             do_snmp: bool, snmp_community: str,
             do_rdns: bool = False) -> IPResult:
    r = IPResult(ip=ip)

    tcp_ports = [p for p in ports if p not in UDP_PORTS]
    # Scan TCP ports concurrently within this IP (inner pool capped at 16; the
    # global _SOCKET_SEM bounds total sockets across all hosts).
    live_refused = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(tcp_ports) or 1)) as ex:
        futs = {ex.submit(tcp_connect, ip, p, timeout): p for p in tcp_ports}
        for f in concurrent.futures.as_completed(futs):
            st = f.result()
            if st == "open":
                r.open_ports.append(futs[f])
            elif st == "refused":
                live_refused = True

    # Reachable only if something actually answered: an open port, an active
    # refusal, SNMP/NetBIOS/ARP below. A PTR record alone is metadata, not
    # proof of life (1.4).
    r.reachable = bool(r.open_ports) or live_refused

    # Reverse DNS is off by default (it is the usual cause of corporate-network
    # hangs); when on, it is hard-timeout bounded. PTR never sets reachability.
    if do_rdns:
        r.ptr = reverse_dns(ip, timeout)

    # Banners on text ports.
    for p in r.open_ports:
        if p in BANNER_PORTS:
            b = grab_banner(ip, p, timeout)
            if b:
                r.banners[p] = b

    # HTTP fingerprint (first available web port wins for the summary fields).
    for p in r.open_ports:
        if p in HTTP_PORTS and not r.http_title and not r.http_server:
            title, server, loc = http_fingerprint(ip, p, False, timeout)
            r.http_title = r.http_title or title
            r.http_server = r.http_server or server
            r.http_redirect = r.http_redirect or loc
    for p in r.open_ports:
        if p in HTTPS_PORTS:
            if not r.tls_cn:
                cn, san, issuer = tls_cert_info(ip, p, timeout)
                r.tls_cn, r.tls_san, r.tls_issuer = cn, san, issuer
            if not r.http_title and not r.http_server:
                title, server, loc = http_fingerprint(ip, p, True, timeout)
                r.http_title = r.http_title or title
                r.http_server = r.http_server or server
                r.http_redirect = r.http_redirect or loc

    # SNMP (UDP 161) — independent of TCP scan.
    if do_snmp and (161 in ports):
        r.snmp_descr = snmp_sysdescr(ip, snmp_community, timeout)
        if r.snmp_descr and 161 not in r.open_ports:
            r.open_ports.append(161)
            r.reachable = True

    # NetBIOS (UDP 137).
    if 137 in ports:
        r.netbios = netbios_name(ip, timeout)
        if r.netbios and 137 not in r.open_ports:
            r.open_ports.append(137)
            r.reachable = True

    # MAC / OUI (local subnet only). An ARP entry means the host answered at
    # layer 2, so it also counts as reachable (1.4).
    r.mac = arp_lookup(ip)
    r.oui_vendor = oui_vendor(r.mac)
    if r.mac:
        r.reachable = True

    classify(r)
    return r


# ---------------------------------------------------------------------------
# Classification: rule-based scoring. Each rule votes weight into a category
# and records why. Highest total wins; margin + score set the confidence.
# ---------------------------------------------------------------------------

def classify(r: IPResult) -> None:
    scores: Dict[str, int] = {}
    ev: List[str] = []

    def vote(cat: str, weight: int, why: str) -> None:
        scores[cat] = scores.get(cat, 0) + weight
        ev.append(f"{why} -> {cat}(+{weight})")

    ports = set(r.open_ports)
    haystack = " ".join([
        r.ptr, r.http_title, r.http_server, r.tls_cn, r.tls_san,
        r.snmp_descr, r.oui_vendor, r.netbios,
        " ".join(r.banners.values()),
    ]).lower()

    def has(*words: str) -> bool:
        # Whole-token matching so "asa" no longer matches "casa", "ilo" "pilot",
        # "sip" "gossip", etc. (1.8). Boundaries are non-alphanumeric, so
        # hyphenated terms like "pan-os" still match.
        for w in words:
            if re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", haystack):
                return True
        return False

    # ---- Printers / MFPs ----
    if 9100 in ports:
        vote(Cat.PRINTER, 4, "port 9100 (raw print)")
    if 515 in ports:
        vote(Cat.PRINTER, 2, "port 515 (LPD)")
    if 631 in ports:
        vote(Cat.PRINTER, 2, "port 631 (IPP)")
    if has("jetdirect", "laserjet", "officejet", "printer", "imagerunner",
           "workcentre", "bizhub", "kyocera", "lexmark", "brother", "canon",
           "xerox", "ricoh"):
        vote(Cat.PRINTER, 3, "printer keyword in banner/SNMP/OUI")

    # ---- Switches / routers ----
    if has("switch", "catalyst", "procurve", "aruba", "junos", "cisco ios",
           "routeros", "mikrotik", "nexus", "powerconnect", "brocade"):
        vote(Cat.SWITCH, 4, "network-OS keyword")
    if 161 in ports and has("cisco", "juniper", "arista", "hpe", "dell") and 9100 not in ports:
        vote(Cat.SWITCH, 2, "SNMP + network vendor")
    if {23, 22, 161}.issubset(ports) and not (ports & {445, 3389, 9100}):
        vote(Cat.SWITCH, 1, "mgmt ports pattern (22/23/161)")

    # ---- Firewalls / security appliances ----
    if has("fortinet", "fortigate", "palo alto", "pan-os", "sonicwall",
           "sophos", "checkpoint", "check point", "pfsense", "opnsense",
           "watchguard", "meraki mx", "asa"):
        vote(Cat.FIREWALL, 5, "firewall vendor keyword")
    if 500 in ports or 4500 in ports:
        vote(Cat.FIREWALL, 1, "IPSec/IKE port")

    # ---- Wireless APs ----
    if has("unifi", "ubiquiti", "aironet", "meraki mr", "aruba ap",
           "access point", "wireless"):
        vote(Cat.AP, 4, "AP vendor keyword")

    # ---- Servers / hypervisors / management controllers ----
    if has("esxi", "vmware", "vcenter", "vsphere"):
        vote(Cat.SERVER_HV, 5, "VMware keyword")
    if has("proxmox") or 8006 in ports:
        vote(Cat.SERVER_HV, 4, "Proxmox")
    if has("ilo", "idrac", "ipmi", "bmc", "supermicro", "cimc"):
        vote(Cat.BMC, 5, "out-of-band mgmt controller")
    if 623 in ports:
        vote(Cat.BMC, 3, "port 623 (IPMI)")
    if has("windows server"):
        vote(Cat.SERVER_HV, 3, "Windows Server banner")
    server_svc = ports & {1433, 3306, 5432, 27017, 6379, 9200, 25, 389, 636}
    if server_svc:
        vote(Cat.SERVER, 2, f"server service ports {sorted(server_svc)}")

    # ---- Cameras / VoIP / IoT ----
    if 554 in ports:
        vote(Cat.CAMERA, 3, "port 554 (RTSP)")
    if has("axis", "hikvision", "dahua", "camera", "nvr", "dvr"):
        vote(Cat.CAMERA, 4, "camera vendor keyword")
    if 5060 in ports or has("polycom", "yealink", "grandstream", "sip", "voip", "asterisk"):
        vote(Cat.VOIP, 3, "SIP/VoIP signal")

    # ---- Endpoints ----
    if 3389 in ports:
        vote(Cat.WINDOWS, 3, "port 3389 (RDP)")
    if {445, 139} & ports:
        vote(Cat.WINDOWS, 2, "SMB/NetBIOS ports")
    if r.netbios:
        vote(Cat.WINDOWS, 2, f"NetBIOS name {r.netbios}")
    if has("apple", "darwin", "macos", "mac os", "airplay", "bonjour"):
        vote(Cat.MAC, 4, "Apple/mDNS signal")
    if 5353 in ports and has("apple"):
        vote(Cat.MAC, 2, "mDNS + Apple")
    if has("ubuntu", "debian", "centos", "red hat", "fedora", "openssh") and \
       not (ports & {9100, 161, 554}):
        # OpenSSH on a box with no printer/switch/camera tell -> likely a host.
        if 22 in ports:
            vote(Cat.LINUX, 2, "SSH + Linux banner")

    # ---- VM hint (adjusts nothing, just noted) ----
    if "vmware" in r.oui_vendor.lower() or "virtualbox" in r.oui_vendor.lower() \
       or "hyper-v" in r.oui_vendor.lower() or "qemu" in r.oui_vendor.lower():
        ev.append(f"OUI suggests virtual machine ({r.oui_vendor})")

    # ---- Decide ----
    if not r.reachable:
        r.category = Cat.NO_RESPONSE
        r.confidence = "none"
        r.evidence = ["host did not respond to any probe"]
        return

    if not scores:
        r.category = Cat.MISC
        r.confidence = "low"
        base = []
        if r.open_ports:
            base.append(f"open ports {r.ports_str()} but no category signature")
        if r.ptr:
            base.append(f"PTR {r.ptr}")
        r.evidence = base or ["responded but no identifying signals"]
        return

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_cat, top_score = ranked[0]
    runner = ranked[1][1] if len(ranked) > 1 else 0
    margin = top_score - runner

    r.category = top_cat
    if top_score >= 5 and margin >= 2:
        r.confidence = "high"
    elif top_score >= 3:
        r.confidence = "medium"
    else:
        r.confidence = "low"

    # Evidence: the winning category's lines first, then up to 3 for the
    # runner-up, then the close-call note (1.7).
    def _ev_for(cat: str) -> List[str]:
        return [e for e in ev if f"-> {cat}(" in e]
    r.evidence = _ev_for(top_cat)
    if len(ranked) > 1:
        r.evidence += _ev_for(ranked[1][0])[:3]
        if margin <= 1:
            r.evidence.append(f"close call vs {ranked[1][0]} ({ranked[1][1]} pts)")
    r.evidence = r.evidence[:10]


# ---------------------------------------------------------------------------
# Spreadsheet / CSV I/O
# ---------------------------------------------------------------------------

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")


def read_targets(path: str) -> List[str]:
    ext = os.path.splitext(path)[1].lower()
    cells: List[str] = []
    if ext in (".xlsx", ".xlsm"):
        if not _HAVE_OPENPYXL:
            sys.exit("openpyxl is required for .xlsx input. Run: pip install openpyxl")
        wb = load_workbook(path, read_only=True, data_only=True)
        ws = wb.active
        for row in ws.iter_rows(values_only=True):
            for c in row:
                if c is not None:
                    cells.append(str(c))
    elif ext in (".csv", ".tsv", ".txt"):
        delim = "\t" if ext == ".tsv" else ","
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.reader(f, delimiter=delim):
                cells.extend(row)
    else:
        sys.exit(f"Unsupported input type: {ext}. Use .xlsx, .csv, .tsv, or .txt")

    targets: List[str] = []
    seen = set()
    for cell in cells:
        for cidr in CIDR_RE.findall(cell):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                for host in net.hosts():
                    s = str(host)
                    if s not in seen:
                        seen.add(s)
                        targets.append(s)
            except ValueError:
                pass
        # Individual IPs not already captured by a CIDR match.
        stripped = CIDR_RE.sub("", cell)
        for ip in IP_RE.findall(stripped):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                targets.append(ip)
    return targets


OUTPUT_COLUMNS = [
    "IP", "Category", "Confidence", "PTR / Hostname", "Open Ports",
    "HTTP Title", "Server Header", "TLS CN", "TLS SAN", "SNMP sysDescr",
    "NetBIOS", "MAC", "OUI Vendor", "Banners", "Evidence",
]


def result_row(r: IPResult) -> List[str]:
    banners = "; ".join(f"{p}:{b}" for p, b in sorted(r.banners.items()))
    return [
        r.ip, r.category, r.confidence, r.ptr, r.ports_str(),
        r.http_title, r.http_server, r.tls_cn, r.tls_san, r.snmp_descr,
        r.netbios, r.mac, r.oui_vendor, banners, r.evidence_str(),
    ]


def _defang(value):
    """Neutralize spreadsheet formula injection: a cell a device controls (an
    HTTP title, SNMP string, banner) that starts with = + - @ TAB or CR is
    prefixed with an apostrophe so Excel/Sheets treat it as text, not a formula
    (1.11)."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def write_output(results: List[IPResult], path: str) -> None:
    ext = os.path.splitext(path)[1].lower()
    rows = [[_defang(c) for c in result_row(r)] for r in results]
    if ext == ".xlsx":
        if not _HAVE_OPENPYXL:
            sys.exit("openpyxl is required for .xlsx output. Run: pip install openpyxl")
        wb = Workbook()
        ws = wb.active
        ws.title = "IP Inventory"
        ws.append(OUTPUT_COLUMNS)
        for row in rows:
            ws.append(row)
            # Force every device-supplied cell to text so a defanged leading
            # apostrophe is honored and nothing is re-interpreted as a formula.
            for cell in ws[ws.max_row]:
                cell.data_type = "s"
        # Freeze header + rough column widths.
        ws.freeze_panes = "A2"
        widths = [16, 20, 11, 28, 22, 26, 20, 24, 26, 30, 16, 18, 16, 30, 50]
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[chr(64 + i) if i <= 26 else "A"].width = w
        wb.save(path)
    else:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(OUTPUT_COLUMNS)
            w.writerows(rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Classify what every IP in a spreadsheet is for (pure Python, no nmap).")
    ap.add_argument("input", help="Input .xlsx / .csv / .tsv / .txt of IPs or CIDRs")
    ap.add_argument("-o", "--output", default=None,
                    help="Output file (.xlsx or .csv). Default: <input>_identified.xlsx")
    ap.add_argument("--profile", choices=list(PORT_PROFILES), default="standard",
                    help="Port set to scan (default: standard)")
    ap.add_argument("--workers", type=int, default=64,
                    help="Concurrent hosts scanned at once (default: 64)")
    ap.add_argument("--timeout", type=float, default=2.0,
                    help="Per-probe timeout in seconds (default: 2.0)")
    ap.add_argument("--snmp-community", default="public",
                    help="SNMP community string (default: public)")
    ap.add_argument("--no-snmp", action="store_true", help="Skip SNMP probing")
    ap.add_argument("--rdns", action="store_true",
                    help="Enable reverse DNS lookups (off by default; the usual "
                         "cause of slow/hung scans on corporate networks)")
    ap.add_argument("--db", default=None,
                    help="Also record results into a history DB (SQLite) for diffing")
    ap.add_argument("--qualys", default=None,
                    help="Qualys asset export (CSV/XLSX) to reconcile against (needs --db)")
    ap.add_argument("--defender", default=None,
                    help="Defender device export (CSV/XLSX) to reconcile against (needs --db)")
    ap.add_argument("--report", default=None,
                    help="After scanning, write a static HTML report to this path (needs --db)")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        sys.exit(f"Input not found: {args.input}")

    output = args.output or (os.path.splitext(args.input)[0] + "_identified.xlsx")

    print(f"[*] Reading targets from {args.input} ...")
    targets = read_targets(args.input)
    if not targets:
        sys.exit("No valid IP addresses found in the input.")
    ports = PORT_PROFILES[args.profile]
    print(f"[*] {len(targets)} unique IPs | profile '{args.profile}' "
          f"({len(ports)} ports) | {args.workers} workers | timeout {args.timeout}s")

    results: List[IPResult] = []
    done = 0
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {
            ex.submit(probe_ip, ip, ports, args.timeout,
                      not args.no_snmp, args.snmp_community, args.rdns): ip
            for ip in targets
        }
        for f in concurrent.futures.as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:
                r = IPResult(ip=futs[f])
                r.category = "Error"
                r.evidence = [f"probe error: {e}"]
                results.append(r)
            done += 1
            if done % 10 == 0 or done == len(targets):
                pct = 100 * done / len(targets)
                print(f"\r[*] Scanned {done}/{len(targets)} ({pct:.0f}%)", end="", flush=True)
    print()

    # Keep original input order where possible.
    order = {ip: i for i, ip in enumerate(targets)}
    results.sort(key=lambda r: order.get(r.ip, 1 << 30))

    write_output(results, output)
    elapsed = time.time() - t0

    if args.db:
        try:
            from store import Store
            st = Store(args.db)
            scan_id = st.record_scan([r.to_dict() for r in results], source=args.input)
            diff = st.last_diff()
            print(f"[+] Recorded scan #{scan_id} to {args.db} "
                  f"({len(diff['events'])} change events since last scan)")
            if args.qualys or args.defender:
                import importers
                if args.qualys:
                    n = st.import_known("qualys", importers.normalize_qualys(args.qualys))
                    print(f"[+] Imported {n} Qualys assets")
                if args.defender:
                    n = st.import_known("defender", importers.normalize_defender(args.defender))
                    print(f"[+] Imported {n} Defender assets")
                cov = st.coverage()["summary"]
                print("\n    Coverage reconciliation:")
                if cov["has_qualys"]:
                    print(f"      {cov['not_qualys']:>5}  on network but NOT in Qualys (unmanaged)")
                if cov["has_defender"]:
                    print(f"      {cov['missing_edr']:>5}  agent-capable hosts MISSING Defender (EDR gap)")
                print(f"      {cov['known_not_seen']:>5}  known to Qualys/Defender but not seen on network")
            st.close()
            if args.report:
                import report
                path = report.build_report(args.db, args.report)
                print(f"[+] Wrote static HTML report: {path}")
        except Exception as e:
            print(f"[!] Could not record history: {e}")

    # Console summary by category.
    summary: Dict[str, int] = {}
    for r in results:
        summary[r.category] = summary.get(r.category, 0) + 1
    print(f"\n[+] Done in {elapsed:.1f}s. Wrote {len(results)} rows to {output}\n")
    print("    Category breakdown:")
    for cat, n in sorted(summary.items(), key=lambda kv: kv[1], reverse=True):
        print(f"      {n:>5}  {cat}")


if __name__ == "__main__":
    main()
