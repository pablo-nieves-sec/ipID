# ipID - fixes applied (this round)

Scope: unstick the hung scan and land the critical Phase 0/1 correctness bugs
from the work plan, with no new dependencies (still just flask + openpyxl) so it
stays drop-in. Verified offline; test on a real subnet when ready.

## The hang (what you hit on screen)
- Reverse DNS was the cause: `gethostbyaddr()` ignores the socket timeout, so on
  a corporate network every worker blocked on the first lookup (stuck at 0/N).
  - Reverse DNS is now **off by default**. A "reverse DNS" checkbox in the UI
    (and `--rdns` on the CLI) turns it on; even then each lookup is hard-timeout
    bounded and runs on its own pool, so it can never wedge the scan.
- **Stop button** added (red, appears while scanning) - cancels in flight and
  records whatever finished.
- Per-host hard ceiling in the scan loop so one slow host can't stall the run.
- Global socket semaphore (512) + per-host port concurrency capped at 16, to
  avoid Windows ephemeral-port/handle exhaustion.

## Correctness bugs fixed
- **1.1 Category mismatch (the big one):** the classifier emitted `Printer`,
  `Endpoint (Windows)`, etc. while coverage/UI expected `Printers / MFPs`,
  `Windows Endpoints`. Result: missing-EDR never fired for real Windows/Mac/
  hypervisor hosts. All names now come from one module, `categories.py`.
  A DB migration rewrites old category values to the new names.
- **1.0 Schema versioning:** `schema_version` table + migrations, DB backed up
  (`ipid.db.vN.bak`) before the first migration.
- **1.2 Dead IPs are no longer stored as assets** (so they stop counting as "not
  in Qualys"); recorded in `scan_unresponsive` for completeness.
- **1.3 "Missing" is scoped to the scan's targets:** scanning subnet B no longer
  marks subnet A's hosts missing (`scan_targets` table).
- **1.4 Reachability:** a host is reachable only if a port answered (open or
  refused), SNMP/NetBIOS answered, or ARP returned a MAC. A PTR record alone no
  longer counts as alive.
- **1.7 Evidence:** the drawer now shows the winning category's evidence first,
  then a few runner-up lines, instead of every line.
- **1.8 Keyword matching:** whole-word now, so `asa` no longer matches "casa",
  `ilo` "pilot", `sip` "gossip".
- **1.11 Spreadsheet formula injection:** device-supplied cells starting with
  `= + - @` tab/CR are defanged and written as text in xlsx/CSV.

## Not done yet (bigger phases, need deps / real exports / fixtures)
1.5 cert parsing (needs `cryptography`), 1.6 full identity model, 1.9 exact
importer column maps, 1.10 coverage staleness, 1S.1/1S.2 web-app auth + input
caps, Phase 2 (map-scan agent subtraction), Phase 3/3B (mDNS/SSDP/SNMP-expand/
IPP/SIP probes, DHCP/switch/Intune importers), Phase 4 (Recog + evidence-vote
rewrite, vendor/model/firmware), Phase 5 (hardening), Phase 6/7.

## How to run after updating
```
python app.py --seed     # demo data
python app.py            # http://127.0.0.1:5000  (reverse DNS off by default)
```
First real try: pick the **quick** profile, leave reverse DNS unchecked.
