# NetSentinel â€” Session Handoff / Full Context

_Passive, unidirectional ML-based network intrusion **detection** sensor (detect + alert only â€” no block/quarantine/mitigate). Built for SIH 2026._

> **Purpose of this file:** complete context transfer so a fresh session can pick
> up without re-deriving anything. Read top-to-bottom. Nothing here consumed Kaggle
> credits â€” these are notes, not runs.

---

## 0. System summary

- **Stack:** Figma Make project (React 19 + Vite 8 + Tailwind v4) for the dashboard;
  Python FastAPI + ONNX + WebSocket backend for the sensor.
- **v1:** 6 flow-level ML models on a passive sensor, fused into a live dashboard.
- **v2 (SET ASIDE for now):** GNN (E-GraphSAGE) + masked-autoencoder correlation
  layer for multi-flow "Living off Trusted Sites" attack chains. Do NOT work on this
  until v1 foundation is proven.
- **Git note:** origin is api.figma.com, NOT GitHub â€” cannot push to GitHub from here.

### The 6 models
| Model | Type | Status |
|---|---|---|
| DDoS | XGBoost | âœ… healthiest, leave it |
| DGA | CNN-BiLSTM (char-level) | âœ… **just fixed â€” 0.9787 macro-F1** |
| C2 / beacon | BiLSTM + FFT | âš ï¸ sound, unproven on real beacons |
| ETT / encrypted | FT-Transformer | âœ… uses JSON scaler (immune to exfil bug) |
| Port Scan | XGBoost (UNSW-NB15) | âš ï¸ model fine, synthetic input was OOD |
| Exfil / DNS-tunnel | VAE (anomaly threshold) | âŒ **50% FP â€” scaler version bug, NOT retrain** |

---

## 1. The strategic conclusion (why build this at all)

- **Individual detectors are commodity.** DGA especially is a solved problem
  (Cisco Umbrella, Endgame CNN-BiLSTM, FANCI all hit 0.97â€“0.99). Your 0.9787 is
  legitimate and good, but it will NOT beat industry per-model. Do not pitch
  "my DGA beats Cisco" â€” you'd lose that.
- **Your real value is NOT any single model. It is:**
  1. **Correlation across signals** â€” fusing 6 detectors into one attack narrative
     (DGA â†’ C2 beacon â†’ exfil as a chain, not 6 disconnected alerts).
  2. **The v2 graph/sequence layer** â€” multi-flow behavioral correlation on encrypted
     traffic is genuinely open research (unlike commodity DGA). This is where you can
     be novel.
  3. **Deployability in a passive, offline, auditable enclave** â€” commercial cloud
     tools (Umbrella/XDR/SIEM) literally cannot run in a closed gov/defence network.
     That is your SIH constraint and your moat.
- **Honest pitch line:** _"The individual detectors match industry benchmarks; the
  contribution is fusing them into correlated attack chains in a passive, offline
  sensor that commercial cloud tools can't deploy into a closed network."_

### Fix vs. swap decision (asked & answered)
**Fix your gaps, don't swap in third-party models.** Every "problem" so far has been
plumbing (loader bug, scaler mismatch, synthetic input), not model quality. A better
third-party model dropped into the same plumbing fails the same way, and you'd
re-solve feature-format matching. Also judges value "did you build it."
- DDoS: leave it. DGA: done. ETT: leave it.
- Exfil: **fix the scaler** (don't replace). C2 + Port Scan: **test on real PCAP**.

---

## 2. DGA model â€” FIXED (full record)

### What was wrong (root causes, in order discovered)
1. **DGArchive silently loaded 0 domains.** The old loader's char-whitelist
   (`all(c in 'abc...-.')`) rejected every row because DGArchive CSV rows are
   **quoted** (`"domain.com"`) â€” the `"` char failed. â†’ DGA class was
   dictionary-only â†’ trivially separable â†’ **fake 100% F1**.
2. **Leaky split.** `train_test_split(..., stratify=labels)` put near-identical
   domains from the same family in both train and val â†’ memorization â†’ fake 1.0000.
3. **Deception dictionary-DGA** had bare labels with no TLD (`ytrbegofitr8b`) â†’ all
   failed the `'.' in d` filter. Appending a random TLD (NOT relaxing the filter,
   which would create a "no-dot=DGA" shortcut leak) fixed inclusion.
4. **OOM:** loading all 248M domains crashed Kaggle â†’ per-family cap of 5000 fixed it.

### The regression that kept happening
PC crash wiped fixed cells â†’ user re-ran OLD cells â†’ bugs reappeared:
- "0 families" back = old Cell 1 (bad loader).
- Val F1 = 1.0000 back = old Cell 2 (`stratify` random split).
**Lesson: both fixed cells must be in place together.**

### FINAL RESULT (accept â€” this is the canonical metric)
```
Epoch 20/20 | Train Acc: 0.9970 | Val Acc: 0.9370  F1: 0.9528
Best Macro F1: 0.9787   (family-wise split, ~27 DGA families held out)
ONNX inference: 1.853 ms/domain (540 domains/sec)
```
**Use "0.9787 macro-F1, family-wise split" in every doc. Delete all old "100% F1".**

### Edge-case test: 10/11 correct
- âœ… google.comâ†’Benign; xk4jf9a2m.bizâ†’DGA; tunnel domainâ†’Tunnel 0.988;
  crl.microsoft.com / stackoverflow.com / ocsp.digicert.com / api.github.com /
  cloudflare.comâ†’Benign; xk4jf9a2m3b7c.evil.comâ†’DGA.
- âŒ **`ec2-54-123-45-67.compute-1.amazonaws.com` â†’ DNS Tunnel (0.913)** â€” the one
  real miss. Long hyphen/number-heavy AWS hostnames collide with the synthetic
  tunnel shortcut. **Not a leak; explainable.** Optional cheap fix: add ~2â€“5k real
  cloud/CDN hostnames (AWS EC2, Azure, GCP, Akamai) to the benign class, retrain once.

### Model config (must match production preprocessing exactly)
- char-level CNN-BiLSTM; vocab 40 (0=PAD, 1=UNK, 2â€“39 = `a-z0-9-.`); `MAX_LEN=128`;
  classes `['benign','dga','dns_tunnel']`; ONNX input `domain_chars [batch,128] int64`.
- **Upload CHAR2IDX + MAX_LEN + CLASS_NAMES metadata to HF alongside the ONNX** â€” a
  vocab mismatch would silently break inference the way the scaler broke exfil.

### Data pipeline final numbers
Benign (Tranco) 1,000,000 â†’ 250k used Â· DGA 494,067 (474,067 DGArchive across 137
families @ 5000 cap + 20,000 TLD-appended Deception) â†’ 250k used Â· Tunnel 50,000.

### Working Cell 1 (data load) â€” key parts
```python
PER_FAMILY_CAP = 5000
# paths live in the config block (keep it as single source), e.g.:
#   DGARCHIVE_TGZ = '/kaggle/input/datasets/unded17/dgarchive/2024-11-28-dgarchive_full.tgz'
#   DECEPTION_CSV_1/2 = '.../deception_dga.csv', '.../deception2_dga.csv'
#   TRANCO_CSV = '/kaggle/input/datasets/unded17/tranco-top1m/tranco_XN67N.csv'
#   MAX_SAMPLES_PER_CLASS = 250000

import os, io, csv, tarfile, random
import pandas as pd
random.seed(42)

# [1/4] Tranco benign
benign_list = []
tdf = pd.read_csv(TRANCO_CSV, header=None)
col = 1 if tdf.shape[1] > 1 else 0
for d in tdf.iloc[:,col].dropna().astype(str):
    d = d.strip().lower()
    if "." in d and 3 < len(d) < 253:
        benign_list.append(d)

# [2/4] DGArchive â€” ROBUST quoted-CSV loader + per-family cap (THE fix)
dga_by_family = {}
with tarfile.open(DGARCHIVE_TGZ, "r:gz") as tar:
    for member in tar:
        if not member.isfile(): continue
        family = member.name.split("/")[-1].replace("_dga.csv","").replace(".csv","")
        f = tar.extractfile(member)
        if f is None: continue
        bucket = dga_by_family.setdefault(family, [])
        for row in csv.reader(io.TextIOWrapper(f, encoding="utf-8", errors="ignore")):
            if len(bucket) >= PER_FAMILY_CAP: break
            if not row: continue
            dom = row[0].strip().lower()
            if "." in dom and 3 < len(dom) < 253:
                bucket.append(dom)

# [3/4] Deception â€” append random TLD (avoid no-dot shortcut), cap 20k
TLDS = ['.com','.net','.org','.info','.biz','.ru','.co','.xyz','.online','.top']
ALLOWED = set("abcdefghijklmnopqrstuvwxyz0123456789-")
dec = []
for csv_path in [DECEPTION_CSV_1, DECEPTION_CSV_2]:
    df = pd.read_csv(csv_path, header=None)
    for d in df.iloc[:,0].dropna().astype(str):
        d = d.strip().lower()
        if 3 < len(d) < 60 and all(c in ALLOWED for c in d):
            dec.append(d + random.choice(TLDS))
if dec:
    random.shuffle(dec)
    dga_by_family["deception"] = dec[:20000]

# [4/4] paste your existing tunnel generator -> tunnel_list (target 50,000)
```
**Cell 1 acceptance:** `[2/4]` must print **~474,000 DGA from ~137 families**.
If it says 0 families, only the `DGARCHIVE_TGZ` path is wrong. Rerun just Cell 1
(CPU only, no credits) until 137 families appears.

### Working Cell 2 (family-wise split) â€” THE anti-leak fix
```python
import random
rng = random.Random(42)
fams = list(dga_by_family.keys()); rng.shuffle(fams)
n_val = max(1, len(fams)//5)
val_fams, train_fams = set(fams[:n_val]), set(fams[n_val:])
dga_train = [d for fam in train_fams for d in dga_by_family[fam]]
dga_val   = [d for fam in val_fams   for d in dga_by_family[fam]]

def split80(lst):
    lst = list(set(lst)); rng.shuffle(lst)
    k = int(len(lst)*0.8); return lst[:k], lst[k:]

dga_all = set(dga_train) | set(dga_val)
benign_clean = [d for d in set(benign_list) if d not in dga_all]
ben_train, ben_val = split80(benign_clean[:MAX_SAMPLES_PER_CLASS])
tun_train, tun_val = split80(tunnel_list[:50000])
dga_train = dga_train[:MAX_SAMPLES_PER_CLASS]; dga_val = dga_val[:MAX_SAMPLES_PER_CLASS]

X_train_d = ben_train + dga_train + tun_train
y_train   = [0]*len(ben_train) + [1]*len(dga_train) + [2]*len(tun_train)
X_test_d  = ben_val + dga_val + tun_val
y_test    = [0]*len(ben_val) + [1]*len(dga_val) + [2]*len(tun_val)
# keep existing DomainDataset/DataLoader using these; uses encode_domain (MAX_LEN=128)
```
**Cell 2 acceptance:** must print `Val DGA families held out: ~27`. There must be
**NO `train_test_split(..., stratify=...)` anywhere** â€” that line IS the leak.
**Pass = epoch-1 Val F1 â‰ˆ 0.90â€“0.96 climbing to ~0.97â€“0.98. Fail = 1.0000 (stop).**

### Harmless noise to ignore
The wall of `AssertionError: can only test a child process` /
`_MultiProcessingDataLoaderIter.__del__` is a cosmetic Kaggle DataLoader worker
shutdown bug (`num_workers>0`). Does NOT affect training/metrics. Silence with
`num_workers=0` if desired.

---

## 3. Other open issues (from status doc)

### ðŸ”´ Critical
1. **Exfil VAE ~50% FP** âŒ â€” root cause **scaler pickled with sklearn 1.6.1, run with
   1.3.2** â†’ 24 DNS features mis-scaled â†’ inflated reconstruction error. **Fix (cheap,
   ~30 min, no retrain):** pin `scikit-learn==<training version>`, re-pickle scaler,
   upload to HF `Unded-17/netsentinel-models`, re-run PCAP, confirm FP â†’ low single
   digits. Exfil is the ONLY model with both a pickle scaler AND an anomaly threshold,
   so it's the only one that can blow up this way. **This is the #1 next fix.**
2. Retrained exfil scaler not yet deployed to HF (no `hf_upload/`).

### ðŸŸ  High
3. **Covariate shift** â€” `ks_summary.txt` shows ~92% features shifted (stale; script
   skips if `ours.csv` exists). Affects DDoS/PortScan/ETT accuracy (degrades, doesn't
   flood FP). Fix: `rm ours.csv && python scripts/covariate_shift.py`; align feature
   units to CICFlowMeter (flag counts, packet rates, Fwd/Bwd Header Length).
4. **3 demo-tuning compromises in `analyzer.py`** â†’ revert to production defaults
   (video already recorded): (a) port-scan `num_ports>=30` bypass, (b) DGA entropy
   gate `>3.8` (restore 3.0), (c) exfil relaxed `>3.5/>15` (restore `>4.5/>30`).
5. **Doc inconsistencies** â€” accuracy tables (93.6/88 vs 99.2/98.7), entropy (2.59 vs
   12.4 bits), alert counts. Produce ONE reproducible train/val/test report; cite it
   everywhere.

### ðŸŸ¡ Medium
6. No upload validation on `/pcap/upload` (reject exe/pickle/oversized; delete after).
7. Port scan ~0 on simulator = synthetic OOD, not a bad model (real Nmap = 80â€“95%).
8. Simulator â‰  production path (mock feed bypasses models; use real PCAP to validate).
9. Runtime HF model download = reproducibility/offline concern (consider vendoring).
10. Vestigial `.onnx` files under `netsentinel/models/` â€” delete/repoint.

---

## 4. Datasets to validate each model (all FREE downloads)

| Model | Dataset | Notes |
|---|---|---|
| DDoS | **CIC-IDS-2017 `Friday-WorkingHours-Afternoon-DDos`** | 128k DDoS + 98k benign |
| Port Scan | **CIC-IDS-2017 `Friday-WorkingHours-Afternoon-PortScan`** | 159k scan flows â€” refutes "0 alerts" |
| C2 / beacon | **CTU-13 Scenario 1 (Neris) `CTU-Malware-Capture-Botnet-43`** | infected host 147.32.84.165 |
| Exfil / DNS-tunnel | **ggyggy666/DNS-Tunnel-Datasets** (or Daumel/dns-exfiltration-dataset) | real iodine+dnscat2+dns2tcp; re-test after scaler fix |
| ETT / encrypted | **CIRA-CIC-DoHBrw-2020** | encrypted DoH benign vs tunneled |
| DGA | â€” | already validated (DGArchive family-wise) |

**Rules:** (1) CIC-IDS-2017 has known label/duplicate errors â€” use cleaned version if
possible. (2) Use **raw PCAPs, not pre-made CSVs** â€” run PCAP â†’ *your* extractor â†’
model, so you actually test your pipeline and don't re-introduce covariate shift.
**Order:** Port Scan â†’ DDoS â†’ DNS-tunnel (after scaler fix) â†’ C2 â†’ ETT.

### Download sources
- CTU-13: https://www.stratosphereips.org/datasets-ctu13 Â·
  https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-43/
- CIC-IDS-2017: https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/tree/main Â·
  https://www.kaggle.com/datasets/sateeshkumar6289/cicids-2017-dataset (official: UNB CIC)
- DNS tunnel: https://github.com/ggyggy666/DNS-Tunnel-Datasets Â·
  https://github.com/Daumel/dns-exfiltration-dataset
- DoH: CIRA-CIC-DoHBrw-2020 (UNB CIC)

---

## 5. Next steps (priority order)

1. **Push DGA ONNX + vocab/MAX_LEN/CLASS_NAMES metadata** to HF `Unded-17/netsentinel-models`.
2. **Fix exfil scaler** (pin sklearn â†’ re-pickle â†’ upload â†’ re-run â†’ confirm FP drops).
3. **Prove models on real PCAPs** (Â§4 order) â€” converts "probably good" â†’ "proven".
4. Revert the 3 demo compromises; re-run covariate shift + align units.
5. Reconcile docs into one reproducible metrics report.
6. Add upload validation; delete vestigial `.onnx`.
7. **THEN** all remaining effort â†’ v2 correlation/graph layer (the only place work
   makes you *better than* industry, not just catching up).

### Related docs already in repo
- `src/imports/NETSENTINEL_STATUS_AND_ISSUES.md` â€” full âœ…/âš ï¸/âŒ status table.
- `src/imports/NETSENTINEL_V2_CRITIQUE_INTEGRATION_AND_FIXES.md` â€” v2 + jipper
  frontend integration + critique verification.
- `src/imports/analysis_and_action_plan.md` â€” per-model diagnosis (user-authored).

_End of handoff._

