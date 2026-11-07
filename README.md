# ipID — asset identification & coverage reconciliation

Built for a **Qualys + Microsoft Defender** shop. Point it at a spreadsheet of
IPs; it classifies every host on the wire (printer, switch, firewall, endpoint,
server, camera, VoIP, …) with an evidence trail and confidence — then reconciles
what it *found* against what Qualys and Defender *think they know*. The gaps are
the findings:

- **On the network but not in Qualys** → unmanaged / unscanned assets.
- **Agent-capable host with no Defender agent** → EDR coverage gap.
- **Known to Qualys/Defender but not seen** → likely offline or decommissioned.

Pure-Python scanning engine (no nmap, no root). History across scans, with a
review queue for the unknowns.

## Run
```
pip install -r requirements.txt
python app.py --seed     # optional: demo data incl. Qualys/Defender coverage
python app.py            # open http://127.0.0.1:5000
```

### Windows (or any OS) — no Python needed to run it
The dashboard is HTML, but a browser can't scan networks on its own, so the
scanning runs in a tiny local process. To ship that as one double-clickable file:
```
build_windows.bat        # on Windows  -> dist\ipID.exe
./build_unix.sh          # on macOS/Linux -> dist/ipID
```
You only need Python + internet on the machine that BUILDS it; the resulting
binary bundles everything and, when launched, starts the local server and opens
the dashboard in the browser automatically. (Build on the OS you want to run on —
you can't cross-build a Windows .exe from macOS/Linux.)

### Static HTML report (no server, no install, just a page)
Export a single self-contained `.html` snapshot — inventory, category breakdown,
Qualys/Defender coverage, and per-asset detail with history, all baked in. Opens
on any machine by double-clicking; read-only (no live scanning). Great for
sharing with a teammate or attaching to a ticket.
```
python report.py --db ipid.db -o ipID_report.html
```
Or click **Export report** in the dashboard, or add `--report out.html` to a CLI scan.

CLI (headless), with reconciliation:
```
python ipident.py targets.xlsx --db ipid.db \
       --qualys qualys_export.csv --defender defender_export.csv
```

## Reconciling with Qualys & Defender
Export the asset/device inventory from each and import it (buttons in the UI, or
the CLI flags above). Column names are detected fuzzily, so most Qualys VMDR
asset exports and Defender device-inventory exports work as-is:
- **Qualys**: IP, DNS/NetBIOS name, OS, tracking method, last scan, tags.
- **Defender**: device name, OS platform, onboarding status, health, last seen, IPs.

The **Coverage gaps** tab shows the unmanaged and missing-EDR hosts; each asset's
drawer shows exactly what Qualys and Defender hold for it. Only agent-capable
device types (endpoints/servers) are ever flagged "missing Defender" — a printer
without an EDR agent is not a finding.

## Identity across scans (DHCP)
Assets correlate on the most stable identifier available —
**device name (NetBIOS / PTR / TLS CN) → MAC → IP** — so a host that keeps its
name but gets a new DHCP lease stays the SAME asset (IP change logged), and it
still matches its Qualys/Defender record even when the IP has drifted.

## Files
- `ipident.py` — scanning + classification engine (also a CLI)
- `store.py` — SQLite history, correlation, diffing, overrides, reconciliation
- `importers.py` — Qualys / Defender export parsers (fuzzy column detection)
- `app.py` — Flask local web app
- `report.py` — static self-contained HTML report exporter
- `build_windows.bat` / `build_unix.sh` — package into one double-clickable binary
- `templates/dashboard.html` — the UI
- `PROJECT_NOTES.md` — design notes, decisions, roadmap

## Notes
- Only scan networks you own or are authorized to assess.
- Scanning is unauthenticated (outside-in); pair it with the authenticated
  ground truth from Qualys/Defender — that pairing is the whole point.
- Classifier rules, agent-capable categories, and the OUI table are easy to tune.
