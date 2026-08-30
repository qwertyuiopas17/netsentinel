# NetSentinel — Real Backend Status & What's Left To Do

> Honest reconciliation of `BACKEND_FIXES_FINAL.md` against the actual code in
> `github.com/qwertyuiopas17/netsentinel`. Written after reading the source,
> the model feature manifests, and the live-test numbers.
>
> **Read this as: what is genuinely done, what only *looks* done, and the
> exact work only you can finish (because it needs Python, the ONNX models,
> the 8 GB pcap, and a `git push` — none of which exist in the Figma
> workspace where these fixes were drafted).**

---

## 1. True status (not the headline)

| # | Problem | Claimed | **Actual** |
|---|---------|---------|------------|
| 1 | Covariate shift | "validated" | ⚠️ **CSV column-name match only.** PCAP extraction failed (no CICFlowMeter). Distribution never compared. |
| 2 | Wire bots 5 & 6 | "fixed, 6/6" | ❌ **Loaded, never routed.** `analyzer.py` calls only ddos/dga/c2/ett. Live test = 0 port-scan, 0 exfil. |
| 3 | C2 FFT mean-removal | "fixed" | ✅ **Genuinely fixed** (`c2_beacon.py:62`, raw FFT). |
| 4 | CV-gate false positives | "fixed" | ✅ **Genuinely fixed** (benign-periodic filters, `c2_beacon.py:171-200`). |
| 5 | 5-tuple flow id | "fixed" | ⚠️ **Field exists but is `null`** on every path except DNS — `flow_meta` isn't passed. |
| 6 | Test coverage | "complete" | ⚠️ Tests exist; **unit tests pass but don't catch the routing gap** (they call detectors directly). |

**The one fact that settles it:** your own live run on `Friday-WorkingHours.pcap`
detected `DDoS 342 · DGA 166 · C2 32 · VPN 158` and **zero Port Scan, zero
Exfiltration**. Six models load; four detect. That's the real state.

---

## 2. The core blocker — feature-schema mismatch (this is why routing alone won't work)

The three feature sets in your repo do **not overlap**:

| Producer / consumer | Feature set |
|---|---|
| `flow_extractor.py` **produces** | 59 CIC-IDS features + 29 ETT features (`Flow Packets/s`, …) |
| `port_scan_features.json` **needs** | 39 **UNSW-NB15** features (`rate, sttl, dttl, sload, sinpkt, swin, stcpb, ct_srv_src, ct_state_ttl, is_ftp_login`, …) |
| `exfil_meta.json` **needs** | 24 **DNS-lexical** features (`dns_entropy, dns_bigram_entropy, subdomain_length, fqdn_count`, …) |

So if you just add `registry.port_scan.predict(features)` in the analyzer, every
UNSW feature resolves to `features.get(name, 0.0) == 0.0` → XGBoost scores noise
→ **a flood of false port-scan alerts.** Wiring without feature builders is worse
than not wiring. **The real work is building two new feature extractors**, not
adding a function call.

**Design note on exfil:** `exfil_vae` is a **DNS-tunneling** detector (reconstruction
error over domain-name features). It never looks at byte volume — so the frontend
"outbound/inbound byte-ratio" panel is the *wrong visualization for this model*.
Either re-label that panel to "DNS-tunnel anomaly" (entropy / subdomain length /
recon-error), or train a separate byte-volume exfil model. Pick one; don't ship
a panel that claims to show something the model doesn't compute.

---

## 3. Fixes to apply (code) — drafted, UNTESTED, you must run them

> None of this was executed — there's no Python/onnxruntime here. Treat every
> snippet as a starting point to run against your tests, not a finished patch.

### 3a. Populate the 5-tuple on every path (`pipeline/analyzer.py`) — low risk, do first

Right now `flow_meta` is only passed on the DNS path. Pass it everywhere so
`alert.flow` stops being `null`. Every event that carries a flow should forward
its 5-tuple:

```python
def _analyze_flow(self, event: dict) -> dict | None:
    features = event.get("features", {})
    flow_meta = event.get("flow_meta") or {           # <-- add this
        "src_ip":   event.get("source_ip"),
        "src_port": features.get("src_port", 0),
        "dst_ip":   event.get("dest_ip"),
        "dst_port": features.get("dst_port", 0),
        "protocol": features.get("protocol", "TCP"),
    }
    # ...ddos / ett as today, but pass flow_meta into create_alert(...):
    alert = self.alert_manager.create_alert(result, source_ip=..., dest_ip=..., flow_meta=flow_meta)
```

Do the same in `_analyze_session` (C2). **You must confirm the extractor actually
puts `src_port`/`dst_port`/`protocol` on the event** — check `flow_extractor.py`
output; the 5-tuple key exists internally (`FlowState.key`), so expose it on the
emitted event dict if it isn't already.

### 3b. Align names with the frontend contract (`pipeline/alert_manager.py`) — low risk

The frontend `ThreatType` / `ModelName` enums won't match backend strings:

| Backend emits | Frontend expects |
|---|---|
| `threat_class: "Data Exfiltration"` | `"Exfiltration"` |
| `model_name: "exfil_vae"` | `"Exfil VAE"` |
| `model_name: "port_scan_xgboost"` | `"Port Scan XGBoost"` |
| `model_name: "ddos_binary_xgboost"` | `"DDoS XGBoost"` |

Fix in ONE place. Cleanest is a map in the frontend's `parseBackendAlert()`
(`src/data/useThreatFeed.ts`) so the backend stays raw:

```ts
const THREAT_MAP: Record<string,string> = { "Data Exfiltration": "Exfiltration" };
const MODEL_MAP: Record<string,string> = {
  exfil_vae: "Exfil VAE", port_scan_xgboost: "Port Scan XGBoost",
  ddos_binary_xgboost: "DDoS XGBoost", /* … */
};
// threatType: THREAT_MAP[raw.threat_class] ?? raw.threat_class
// model:      MODEL_MAP[raw.model_name]   ?? raw.model_name
```

### 3c. The feature builders (the real work) — `extractor/` — HIGH effort, needs your data

**Port scan (UNSW-NB15).** Add a builder that computes the 39 names in
`port_scan_features.json` from your accumulated `FlowState`. Some map directly
(`src_bytes`, `dst_bytes`, `src_pkts`, `dst_pkts`, `swin`, `stcpb`); several are
UNSW *connection-tracking* aggregates (`ct_srv_src`, `ct_dst_ltm`,
`ct_state_ttl`, `ct_src_dport_ltm`) that require a **sliding window over the last
100 connections** — you have to implement that window; it does not exist yet.
Until every one of the 39 is real, do **not** route the model.

**Exfil (DNS-lexical).** These 24 features are per-DNS-query, not per-flow.
Check `extractor/dns_extractor.py` first — it may already compute entropy /
subdomain length. Extend it to emit all 24 (`dns_bigram_entropy`,
`dns_vowel_ratio`, `fqdn_count`, `labels_max`, …) and route exfil on the **DNS
event path**, not the flow path.

**Only after the builders exist**, route the models (guarded by a real threshold):

```python
# analyzer._analyze_flow  — AFTER a real UNSW feature dict is built
if self.registry.port_scan and unsw_features:
    r = self.registry.port_scan.predict(unsw_features)
    if r["threat"] == "Port Scan" and r["confidence"] >= THRESHOLDS["port_scan"]:
        return self.alert_manager.create_alert(r, source_ip=..., dest_ip=..., flow_meta=flow_meta)

# analyzer._analyze_dns — AFTER all 24 DNS features are built
if self.registry.exfiltration and dns_features:
    r = self.registry.exfiltration.predict(dns_features)
    if r["threat"] == "Data Exfiltration" and r["confidence"] >= THRESHOLDS["exfiltration"]:
        return self.alert_manager.create_alert(r, source_ip=..., flow_meta={"domain": domain, ...})
```

### 3d. Emit the evidence the new frontend panels read (optional, only if you keep those panels)

- DDoS panel wants `evidence.src_ip_entropy` → compute Shannon entropy of source
  IPs seen against the target in the window, add to the ddos result's evidence.
- Port-scan panel wants `evidence.fan_out.ports[]` → collect the distinct dst
  ports the source hit; add to evidence.
- Exfil panel — see §2: change the panel, not the model.

---

## 4. What ONLY you can do (I can't, from here)

1. **Run it.** No Python, no onnxruntime, no models, no pcap in this workspace.
   Every snippet above is unverified. Run `tests/` after each change.
2. **Build & validate the two feature extractors** against real captures — this
   needs the models and labelled data on your machine.
3. **The covariate-shift experiment (Problem #1, still open).** This is the one
   that decides whether your accuracy numbers are real:
   - Run one labelled pcap through **CICFlowMeter** → `ref.csv`.
   - Run the *same* pcap through your `flow_extractor.py` → `ours.csv`.
   - Align on 5-tuple + start time; compute per-feature **KS statistic** and
     mean/std deltas; score both frames with the ONNX model and compare
     confusion matrices. The delta *is* the shift penalty. "62/62 column names
     present" is not this test.
4. **Produce `LIVE_RESULTS.md`** — per-class precision/recall from pcap replay
   through the real extractor→ONNX path (separate from training-split numbers),
   plus a false-positive rate on a purely-benign capture.
5. **Commit & push.** GitHub isn't authenticated in this workspace; only you can
   push to `netsentinel.git`.

---

## 5. Suggested order

1. §3a flow_meta + §3b name alignment — small, safe, makes existing 4 classes correct end-to-end.
2. §4.3 covariate KS experiment — until this runs, everything else is built on sand.
3. §3c exfil DNS builder (likely closest to done via `dns_extractor.py`) → route exfil.
4. §3c port-scan UNSW builder + sliding-window connection features → route port scan.
5. §4.4 LIVE_RESULTS.md with real per-class numbers.
6. Only then: claim 6-class detection, and only then publish bots 5/6 to Hugging Face.

**Do not** re-label the system "production ready" until §4.2–§4.4 pass on real
traffic. Right now the honest claim is: *"4-class live detection on real pcaps;
2 detectors trained and loaded, feature integration in progress; feature-
distribution validation pending."* That's a strong, defensible position — state
that, not "all 6 resolved."
