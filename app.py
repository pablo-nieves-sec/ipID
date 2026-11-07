"""
app.py — the local ipID web app. Launch it, open the browser, scan, review.

Ties together:
  - ipident.py  : the scanning engine (pure Python)
  - store.py    : SQLite history / correlation / diffing / manual review
  - dashboard   : the data-driven UI (templates/dashboard.html)

Runs entirely on localhost. Scans execute in a background thread so the UI stays
responsive and can poll progress.

    python app.py            # then open http://127.0.0.1:5000
    python app.py --seed     # load two demo scans so the UI has data to show
"""

import argparse
import os
import sys
import tempfile
import threading
import time
import webbrowser

from flask import Flask, jsonify, request, send_from_directory

import ipident
from categories import CATEGORY_CHOICES
from store import Store

# Works both when run as a .py and when frozen into a PyInstaller .exe.
# Bundled data (templates/) lives under sys._MEIPASS when frozen; the writable
# DB should sit next to the executable, not inside the read-only bundle.
if getattr(sys, "frozen", False):
    BUNDLE_DIR = sys._MEIPASS
    APP_DIR = os.path.dirname(sys.executable)
else:
    BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__))
    APP_DIR = BUNDLE_DIR
TEMPLATES_DIR = os.path.join(BUNDLE_DIR, "templates")

app = Flask(__name__, static_folder=TEMPLATES_DIR, static_url_path="")
DB_PATH = os.environ.get("IPID_DB", os.path.join(APP_DIR, "ipid.db"))

# ---- background scan state ------------------------------------------------
_scan = {"running": False, "done": 0, "total": 0, "recent": [], "scan_id": None}
_scan_lock = threading.Lock()


def _new_store():
    return Store(DB_PATH)


_cancel = threading.Event()


def _run_scan(targets, profile, timeout, workers, do_snmp, do_rdns=False):
    import concurrent.futures
    ports = ipident.PORT_PROFILES[profile]
    results = []
    _cancel.clear()
    with _scan_lock:
        _scan.update(running=True, done=0, total=len(targets), recent=[],
                     scan_id=None, stopped=False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(ipident.probe_ip, ip, ports, timeout, do_snmp,
                          "public", do_rdns): ip for ip in targets}
        for f in concurrent.futures.as_completed(futs):
            if _cancel.is_set():
                # Stop requested: drop remaining work and record what we have.
                for other in futs:
                    other.cancel()
                break
            try:
                # Hard ceiling per host so one wedged probe cannot stall the
                # whole scan; abandon it and move on.
                r = f.result(timeout=max(20, timeout * 12))
            except Exception:
                with _scan_lock:
                    _scan["done"] += 1
                continue
            results.append(r)
            with _scan_lock:
                _scan["done"] += 1
                if r.category not in ("No response", "Unknown"):
                    name = r.netbios or r.ptr or r.tls_cn or ""
                    _scan["recent"].insert(0, {"ip": r.ip, "category": r.category,
                                               "name": name})
                    _scan["recent"] = _scan["recent"][:15]
    st = _new_store()
    scan_id = st.record_scan([r.to_dict() for r in results], source="web")
    st.close()
    with _scan_lock:
        _scan.update(running=False, scan_id=scan_id,
                     stopped=_cancel.is_set())


# ---- routes ---------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(TEMPLATES_DIR, "dashboard.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    with _scan_lock:
        if _scan["running"]:
            return jsonify({"error": "a scan is already running"}), 409

    profile = request.form.get("profile", "standard")
    timeout = float(request.form.get("timeout", 2.0))
    workers = int(request.form.get("workers", 64))
    do_snmp = request.form.get("snmp", "1") != "0"
    # Reverse DNS is off by default; it is the usual cause of corporate hangs.
    do_rdns = request.form.get("rdns", "0") == "1"

    # targets come from an uploaded file or a pasted list
    tmp_path = None
    if "file" in request.files and request.files["file"].filename:
        f = request.files["file"]
        suffix = os.path.splitext(f.filename)[1] or ".txt"
        fd, tmp_path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        f.save(tmp_path)
    else:
        text = request.form.get("targets", "")
        fd, tmp_path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write(text)

    try:
        targets = ipident.read_targets(tmp_path)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

    if not targets:
        return jsonify({"error": "no valid IPs found"}), 400

    threading.Thread(target=_run_scan,
                     args=(targets, profile, timeout, workers, do_snmp, do_rdns),
                     daemon=True).start()
    return jsonify({"started": True, "total": len(targets)})


@app.route("/api/scan/stop", methods=["POST"])
def api_stop():
    _cancel.set()
    return jsonify({"stopping": True})


@app.route("/api/scan/status")
def api_status():
    with _scan_lock:
        s = dict(_scan)
    s["pct"] = round(100 * s["done"] / s["total"]) if s["total"] else 0
    return jsonify(s)


@app.route("/api/summary")
def api_summary():
    st = _new_store()
    out = st.summary()
    st.close()
    return jsonify(out)


@app.route("/api/inventory")
def api_inventory():
    st = _new_store()
    out = st.inventory(
        search=request.args.get("search", ""),
        category=request.args.get("category", ""),
        confidence=request.args.get("confidence", ""),
        status=request.args.get("status", ""),
        sort=request.args.get("sort", "name"))
    st.close()
    return jsonify(out)


@app.route("/api/review")
def api_review():
    st = _new_store()
    out = st.review_queue()
    st.close()
    return jsonify(out)


@app.route("/api/asset/<path:key>")
def api_asset(key):
    st = _new_store()
    out = st.asset_detail(key)
    st.close()
    if not out:
        return jsonify({"error": "not found"}), 404
    return jsonify(out)


@app.route("/api/asset/<path:key>/override", methods=["POST"])
def api_override(key):
    data = request.get_json(force=True)
    st = _new_store()
    st.set_override(key, category=data.get("category"),
                    vendor=data.get("vendor"), notes=data.get("notes"))
    out = st.asset_detail(key)
    st.close()
    return jsonify(out)


@app.route("/api/diff")
def api_diff():
    st = _new_store()
    out = st.last_diff()
    st.close()
    return jsonify(out)


@app.route("/api/import/<source>", methods=["POST"])
def api_import(source):
    if source not in ("qualys", "defender"):
        return jsonify({"error": "source must be qualys or defender"}), 400
    if "file" not in request.files or not request.files["file"].filename:
        return jsonify({"error": "no file uploaded"}), 400
    import importers
    f = request.files["file"]
    suffix = os.path.splitext(f.filename)[1] or ".csv"
    fd, tmp = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    f.save(tmp)
    try:
        records = (importers.normalize_qualys(tmp) if source == "qualys"
                   else importers.normalize_defender(tmp))
    except Exception as e:
        os.remove(tmp)
        return jsonify({"error": f"could not parse: {e}"}), 400
    os.remove(tmp)
    st = _new_store()
    n = st.import_known(source, records)
    st.close()
    return jsonify({"source": source, "imported": n})


@app.route("/api/coverage")
def api_coverage():
    st = _new_store()
    out = st.coverage(source_filter=request.args.get("filter", ""))
    st.close()
    return jsonify(out)


@app.route("/api/report")
def api_report():
    import report
    from flask import Response
    fd, tmp = tempfile.mkstemp(suffix=".html")
    os.close(fd)
    try:
        report.build_report(DB_PATH, tmp)
        with open(tmp, "r", encoding="utf-8") as f:
            html = f.read()
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return Response(html, mimetype="text/html",
                    headers={"Content-Disposition": "attachment; filename=ipID_report.html"})


@app.route("/api/categories")
def api_categories():
    return jsonify(CATEGORY_CHOICES)


def seed_demo():
    """Two synthetic scans so the UI has something to show without live gear."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    st = _new_store()
    scan1 = [
        {"ip":"10.0.4.12","category":"Windows Endpoints","confidence":"high","netbios":"DESKTOP-A1B2","ports":"139,445,3389","evidence":"SMB hostname; RDP 3389"},
        {"ip":"10.0.4.15","category":"Windows Endpoints","confidence":"high","netbios":"WKS-FINANCE04","ports":"139,445","evidence":"NetBIOS name; SMB"},
        {"ip":"10.0.1.10","category":"Servers / Hypervisors","confidence":"high","ptr":"esxi01.corp","tls_cn":"esxi01","http_title":"VMware ESXi","ports":"443,902","evidence":"TLS CN esxi01; VMware"},
        {"ip":"10.0.1.20","category":"Servers / Hypervisors","confidence":"high","netbios":"DC01","ports":"88,389,445","evidence":"LDAP; Kerberos; SMB"},
        {"ip":"10.0.7.5","category":"Printers / MFPs","confidence":"high","ptr":"hp-lj-3fl.corp","snmp_descr":"HP LaserJet MFP M528","ports":"80,161,515,9100","evidence":"SNMP HP LaserJet; 9100"},
        {"ip":"10.0.0.1","category":"Switches / Routers","confidence":"high","snmp_descr":"Cisco IOS Catalyst 9300","ports":"22,23,161","evidence":"SNMP Cisco"},
        {"ip":"10.0.0.254","category":"Firewalls","confidence":"high","tls_cn":"FGT-fw01","http_title":"FortiGate","ports":"443,22","evidence":"FortiGate title; TLS FGT"},
        {"ip":"10.0.9.31","category":"Cameras / IoT","confidence":"high","ptr":"cam-lobby","ports":"80,554","evidence":"RTSP; Axis OUI"},
        {"ip":"10.0.11.7","category":"Miscellaneous","confidence":"low","ports":"8081","evidence":"open 8081 only; no signature"},
        {"ip":"10.0.11.19","category":"Miscellaneous","confidence":"low","ports":"2323","evidence":"responds, banner unreadable"},
        {"ip":"10.0.11.28","category":"Miscellaneous","confidence":"low","ptr":"ups-3fl","snmp_descr":"","ports":"161","evidence":"PTR ups-3fl; SNMP timeout"},
    ]
    st.record_scan(scan1, source="seed-scan-1")
    scan2 = [
        {"ip":"10.0.4.55","category":"Windows Endpoints","confidence":"high","netbios":"DESKTOP-A1B2","ports":"139,445,3389","evidence":"SMB hostname; RDP 3389"},  # DHCP moved
        {"ip":"10.0.4.15","category":"Windows Endpoints","confidence":"high","netbios":"WKS-FINANCE04","ports":"139,445","evidence":"NetBIOS name; SMB"},
        {"ip":"10.0.1.10","category":"Servers / Hypervisors","confidence":"high","ptr":"esxi01.corp","tls_cn":"esxi01","http_title":"VMware ESXi","ports":"443,902","evidence":"TLS CN esxi01; VMware"},
        {"ip":"10.0.1.20","category":"Servers / Hypervisors","confidence":"high","netbios":"DC01","ports":"88,389,445","evidence":"LDAP; Kerberos; SMB"},
        {"ip":"10.0.0.1","category":"Switches / Routers","confidence":"high","snmp_descr":"Cisco IOS Catalyst 9300","ports":"22,23,161,443","evidence":"SNMP Cisco"},  # new port
        {"ip":"10.0.0.254","category":"Firewalls","confidence":"high","tls_cn":"FGT-fw01","http_title":"FortiGate","ports":"443,22","evidence":"FortiGate title"},
        {"ip":"10.0.9.31","category":"Cameras / IoT","confidence":"high","ptr":"cam-lobby","ports":"80,554","evidence":"RTSP; Axis OUI"},
        {"ip":"10.0.11.7","category":"Miscellaneous","confidence":"low","ports":"8081","evidence":"open 8081 only; no signature"},
        {"ip":"10.0.11.28","category":"Miscellaneous","confidence":"low","ptr":"ups-3fl","ports":"161","evidence":"PTR ups-3fl; SNMP timeout"},
        {"ip":"10.0.6.44","category":"Windows Endpoints","confidence":"medium","netbios":"LAPTOP-NEW07","ports":"445,3389","evidence":"RDP; SMB"},  # brand new
        # 10.0.7.5 printer + 10.0.11.19 dropped -> missing
    ]
    st.record_scan(scan2, source="seed-scan-2")
    # demo Qualys + Defender inventories so the Coverage tab has data
    st.import_known("qualys", [
        {"ip":"10.0.4.12","name":"DESKTOP-A1B2","os":"Windows 10","last":"2026-07-20","meta":{"tracking":"AGENT","tags":"Workstations"}},
        {"ip":"10.0.4.15","name":"WKS-FINANCE04","os":"Windows 11","last":"2026-07-19","meta":{"tracking":"IP","tags":"Finance"}},
        {"ip":"10.0.1.10","name":"esxi01","os":"VMware ESXi 8","last":"2026-07-18","meta":{"tracking":"IP","tags":"Servers"}},
        {"ip":"10.0.1.20","name":"DC01","os":"Windows Server 2022","last":"2026-07-20","meta":{"tracking":"AGENT","tags":"DomainControllers"}},
        {"ip":"10.0.0.1","name":"","os":"Cisco IOS","last":"2026-07-15","meta":{"tracking":"IP","tags":"Network"}},
        {"ip":"10.0.99.99","name":"OLDSERVER","os":"Windows Server 2012","last":"2026-05-01","meta":{"tracking":"IP","tags":"Decommission"}},
    ])
    st.import_known("defender", [
        {"ip":"10.0.4.55","name":"DESKTOP-A1B2","os":"Windows10","last":"2026-07-26","meta":{"onboarding":"Onboarded","health":"Active","domain":"corp.local"}},
        {"ip":"10.0.1.20","name":"DC01","os":"WindowsServer2022","last":"2026-07-26","meta":{"onboarding":"Onboarded","health":"Active","domain":"corp.local"}},
        {"ip":"10.0.6.44","name":"LAPTOP-NEW07","os":"Windows11","last":"2026-07-25","meta":{"onboarding":"Onboarded","health":"Active","domain":"corp.local"}},
    ])
    st.close()
    print(f"[+] Seeded demo data into {DB_PATH}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", action="store_true", help="Load demo data and exit")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-browser", action="store_true",
                    help="Don't auto-open the browser")
    args = ap.parse_args()
    if args.seed:
        seed_demo()
    else:
        url = f"http://{args.host}:{args.port}"
        print(f"[*] ipID running at {url}")
        # frozen .exe is double-clicked, so pop the browser open automatically
        if getattr(sys, "frozen", False) and not args.no_browser:
            threading.Timer(1.2, lambda: webbrowser.open(url)).start()
        app.run(host=args.host, port=args.port, debug=False)
