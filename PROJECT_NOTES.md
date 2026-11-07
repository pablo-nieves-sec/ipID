# ipID — Project Notes & Handoff

Capture of the full thought process, decisions, current state, and roadmap so
this can be picked back up later without re-deriving everything.
(Tool was renamed from "ipident" to **ipID**.)

---

## The problem
Replace the old Qualys-era workflow: a spreadsheet of IPs + a script that
ssh/telnet/pinged them + manual browser lookups for the rest. Goal: give it a
spreadsheet, get back **what every IP is for** — a device *category* with
evidence and confidence — and now, tracked over time.

Key reframe: the user wants a *category label per IP*, not raw scan data.

---

## Architecture (as built)
- `ipident.py` — pure-Python scanning + classification engine. Also a standalone
  CLI (spreadsheet in / xlsx or csv out). `--db` records into history.
- `store.py` — SQLite: history, asset correlation, diffing, manual overrides.
  No dependency on the scanner (takes plain dicts) so it's independently testable.
- `app.py` — Flask local web app. Background-threaded scans, REST API, serves UI.
- `templates/dashboard.html` — data-driven dashboard (inventory, review queue,
  search/filter/sort, asset drawer with inline classification).

## Decisions (and why)
1. **Pure Python, no nmap.** Category ID rides on SNMP/TLS/HTTP/ports, not OS
   stack fingerprinting. Buys clean packaging, no root, `pip install` only.
   Costs ~5-10% only on the silent-endpoint tail. Optional nmap path could be
   added later (used only if present).
2. **CLI engine first, web app second.** Matches the Vendor Risk Console pattern.
3. **Identity anchored on NAME, then MAC, then IP** — see below.
4. **Minimal deps:** flask + openpyxl. Everything else stdlib. SNMP is a
   hand-rolled minimal v2c GET; TLS parsed from DER; HTTP via raw sockets.
5. **Threads** for network I/O concurrency (readable; fine for I/O-bound).


## Qualys + Defender reconciliation (primary use case)
Target environment uses Qualys (VMDR) + Microsoft Defender for Endpoint. The
tool's strongest value there is RECONCILIATION, not just classification:
- `importers.py` parses Qualys asset exports and Defender device exports (fuzzy
  column detection, CSV/XLSX).
- `store.import_known(source, records)` stores them; `store.coverage()` matches
  discovered (present) assets against them by NAME then IP.
- Findings surfaced: on-network-but-not-in-Qualys (unmanaged), agent-capable
  host missing Defender (EDR gap), and known-but-not-seen (offline/decommissioned).
- Domain-correct nuance: only AGENT_CAPABLE categories (endpoints/servers) are
  flagged "missing Defender" — a printer without EDR is not a finding.
- UI: "Coverage gaps" tab + import buttons; each asset drawer shows what Qualys
  and Defender hold for it. CLI: `--qualys` / `--defender` flags with `--db`.
- Name-anchored matching means a DHCP'd host still matches its Qualys/Defender
  record even when its IP drifted. All verified offline with synthetic exports.

## Identity / correlation (the DHCP problem)
Keying on IP would make every DHCP lease look like a new host. Instead correlate
on the most stable id available: **device name (NetBIOS/PTR/TLS CN) → MAC → IP**.
A host that keeps its name but changes IP = same asset, `ip_changed` event, still
present. Verified: DESKTOP-A1B2 moved .12 → .55 across scans and stayed ONE
present asset with both IPs in its history.

## History / diffing
Every scan recorded (scans, observations, events tables). Events computed on
record: new, missing, returned, ip_changed, category_changed, ports_changed.
Dashboard shows "since last scan" counts and per-asset history.

## Review workflow
Review queue = present assets that are Unknown/Miscellaneous OR low-confidence
AND not yet reviewed/overridden. Click an IP → drawer shows all signals + history
+ a form to set device type / vendor / notes. Saving marks it reviewed, applies
an effective category override, and drops it from the queue.

---

## Current state
### Built & tested offline
- store.py: correlation, DHCP IP-change, missing/new/returned, review queue,
  override, search, filter — all asserted with synthetic scans.
- app.py: every API route exercised via Flask test client (summary, diff,
  inventory + search/category/confidence/status/sort, review, asset detail,
  override). Dashboard HTML serves.
- Real pipeline (probe_ip → to_dict → record_scan) run against loopback, no errors.
- `app.py --seed` loads two demo scans so the UI is populated (incl. a DHCP move,
  a new host, two missing hosts, a category change, unknowns for the review queue).

### NOT yet tested (needs real gear / job data)
- SNMP v2c parser, NetBIOS(137), mDNS(5353) vs live devices.
- Classifier accuracy vs ground truth (no validation set yet — build a confusion
  matrix against ~20 known devices first).
- MAC/OUI only resolves same-subnet (rarely fires from a central scanner).
- Scale/threading behavior at thousands of hosts; no checkpoint/resume yet.

---

## Roadmap / backlog (ranked)
1. **Validate against real devices** — everything else is speculative until then.
2. **Benchmark against runZero's free tier** (direct commercial analog: HD Moore,
   unauthenticated asset inventory + device-type ID, free <100 assets). Decide the
   niche deliberately — likely: zero-install, tuned to our vendor mix, and
   **reconcile against Tenable** (our defensible wedge).
3. History/diffing — DONE (SQLite).
4. Tenable reconciliation — cross-check discovered assets vs Tenable, flag gaps.
5. Wire real AI to the **review queue only** — LLM reads the messy combined
   signals for ambiguous leftovers and proposes an ID. (Ties back to where this
   whole thing started: AI in vuln management. Deterministic scanning stays
   non-LLM.)
6. Harden untested collectors (SNMP/TLS); add OT-safety (rate limiting, no
   aggressive probes) before touching production networks.
7. Discovery (ping/ARP sweep) so it finds hosts, not just classifies given ones.
8. IPv6; more UDP coverage; favicon hashing (strong tell, not yet implemented).

## Honest positioning
This is a strong **portfolio + personal-workflow** tool, not a market-beater —
runZero already does unauthenticated asset inventory extremely well. The
defensible angles are the two things it won't do for us specifically: our exact
vendor mix, and Tenable reconciliation.

## Guardrails
- Only scan authorized networks. Keep scanning deterministic (no LLM guessing
  ports/CVEs). Verify AI-enriched output before it drives action.
