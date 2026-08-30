# Graph Report - netsentinel  (2026-08-29)

## Corpus Check
- 65 files · ~94,515 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 416 nodes · 656 edges · 19 communities detected
- Extraction: 69% EXTRACTED · 31% INFERRED · 0% AMBIGUOUS · INFERRED: 201 edges (avg confidence: 0.61)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]

## God Nodes (most connected - your core abstractions)
1. `C2BeaconDetector` - 31 edges
2. `ModelRegistry` - 28 edges
3. `ExfiltrationDetector` - 24 edges
4. `FlowExtractor` - 20 edges
5. `PortScanDetector` - 19 edges
6. `DDoSDetector` - 18 edges
7. `AlertManager` - 18 edges
8. `DNSExtractor` - 17 edges
9. `SessionBuilder` - 17 edges
10. `PacketProcessor` - 13 edges

## Surprising Connections (you probably didn't know these)
- `simulation_loop()` --calls--> `generate_event()`  [INFERRED]
  netsentinel\main.py → netsentinel\simulator\traffic_gen.py
- `NetSentinel — Main FastAPI Application.  This is the entry point. It: 1. Load` --uses--> `ModelRegistry`  [INFERRED]
  netsentinel\main.py → netsentinel\models\registry.py
- `Background task that continuously generates traffic events,     runs them throu` --uses--> `ModelRegistry`  [INFERRED]
  netsentinel\main.py → netsentinel\models\registry.py
- `_process_pcap_background()` --calls--> `PacketProcessor`  [INFERRED]
  netsentinel\api\routes.py → netsentinel\extractor\pcap_reader.py
- `ModelRegistry` --uses--> `C2BeaconDetector`  [INFERRED]
  netsentinel\models\registry.py → netsentinel\models\c2_beacon.py

## Communities

### Community 0 - "Community 0"
Cohesion: 0.05
Nodes (36): DNSExtractor, DNS Extractor — Extracts DNS query/response metadata from packets.  Parses DNS, Track NXDOMAIN responses for DGA detection heuristic., Get the number of NXDOMAINs from this IP in the tracking window., Get IPs with high NXDOMAIN rates (likely DGA-infected hosts).          Useful, Extracts DNS query domains and response metadata from packets.      For each D, Args:             nxdomain_window: Seconds to track NXDOMAIN counts per IP., Process a single packet. Returns DNS event dict or None.          Handles both (+28 more)

### Community 1 - "Community 1"
Cohesion: 0.05
Nodes (39): AlertManager, Alert Manager — Creates structured alert JSON from model outputs.  Every alert, Get the N most recent alerts., Get alert statistics for the dashboard., Reset all counters and stored alerts., Creates and stores alerts from model predictions., Create a structured alert from a model prediction.                  Args:, FlowAnalyzer (+31 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (39): DDoSDetector, DDoS Detector — XGBoost ONNX Wrapper.  Input: 59 flow-level features (from CIC, Run DDoS detection on a single flow.                  Args:             featu, # IMPORTANT: For this model, label 0 = DDoS, label 1 = Benign, Run on multiple flows at once., DGADetector, EncryptedTrafficDetector, Encrypted Traffic Transformer — FT-Transformer ONNX Wrapper.  Input: 29 flow f (+31 more)

### Community 3 - "Community 3"
Cohesion: 0.08
Nodes (42): C2BeaconDetector, C2 Beacon Detector — BiLSTM + FFT ONNX Wrapper.  Input: Time-series of 100 flo, Compute 5 FFT periodicity features from inter-arrival times., Detect C2 beaconing in a time-series of flows.                  Args:, Predict if flow exhibits port scanning behavior.                  Args:, create_constant_beacon_flows(), create_jittered_beacon_flows(), create_random_flows() (+34 more)

### Community 4 - "Community 4"
Cohesion: 0.12
Nodes (24): ExfiltrationDetector, Data Exfiltration Detection using VAE (Expert 6) Dataset: CIC-Bell-DNS-EXF-2021, Detects data exfiltration via DNS tunneling using VAE reconstruction error., Initialize exfiltration detector with VAE model and scaler.                  A, Predict if DNS traffic indicates data exfiltration.                  Args:, create_benign_features(), create_download_features(), create_exfil_features() (+16 more)

### Community 5 - "Community 5"
Cohesion: 0.19
Nodes (20): App(), benign(), c2(), ddos(), dga(), emptyMitre(), encrypted(), exfil() (+12 more)

### Community 6 - "Community 6"
Cohesion: 0.17
Nodes (13): _compute_iats(), FlowState, _mean(), PacketInfo, Flow Extractor — Reconstructs bidirectional flows from raw packets.  Computes, Compute the exact 59 features the DDoS XGBoost model expects.          Feature, Minimal per-packet record used during flow accumulation., Compute the 29 features the Encrypted Traffic Transformer expects.          Fe (+5 more)

### Community 7 - "Community 7"
Cohesion: 0.17
Nodes (15): analyze_results(), check_backend_health(), create_attack_pcap(), main(), print_dashboard_instructions(), Test the REAL NetSentinel ML Pipeline  This script demonstrates the difference, Verify backend is running and models are loaded., Upload PCAP to backend for processing. (+7 more)

### Community 8 - "Community 8"
Cohesion: 0.2
Nodes (13): generate_c2_session(), generate_ddos_flow(), generate_dga_dns(), generate_event(), generate_normal_dns(), generate_normal_flow(), Traffic Generator — Synthetic normal + attack traffic for demo.  Generates eve, Generate a DDoS attack flow (SYN flood characteristics). (+5 more)

### Community 9 - "Community 9"
Cohesion: 0.22
Nodes (7): _compute_stat_features(), _encode_domain(), DGA / DNS Tunnel Detector — CNN-BiLSTM ONNX Wrapper.  Input: Domain name strin, Classify a domain name.                  Args:             domain: Full domai, Classify multiple domains., Encode domain to int array [253]., Compute 7 statistical features for a domain (matches training code).

### Community 10 - "Community 10"
Cohesion: 0.38
Nodes (6): create_pcap(), main(), Simple test - just upload PCAP and watch dashboard., Create a simple attack PCAP with COMPLETE flows., Upload PCAP to backend., upload_pcap()

### Community 11 - "Community 11"
Cohesion: 0.4
Nodes (4): api_post(), NetSentinel — Advanced Stress & Validation Tests v2.  Tests:   1. Individual, Stop simulation AND reset all counters., reset()

### Community 14 - "Community 14"
Cohesion: 0.5
Nodes (3): get_model_path(), NetSentinel Configuration — Paths, Thresholds, Constants., Get model file path. Downloads from Hugging Face if not found locally.

### Community 15 - "Community 15"
Cohesion: 1.0
Nodes (2): buildGraph(), isInternal()

### Community 16 - "Community 16"
Cohesion: 1.0
Nodes (1): Quick-start script for NetSentinel backend.

### Community 21 - "Community 21"
Cohesion: 1.0
Nodes (1): Start the traffic simulator to generate live alerts.

### Community 22 - "Community 22"
Cohesion: 1.0
Nodes (1): Stop the traffic simulator.

### Community 23 - "Community 23"
Cohesion: 1.0
Nodes (1): Upload any PCAP file to the backend.

### Community 24 - "Community 24"
Cohesion: 1.0
Nodes (1): Use a real PCAP file instead of creating one with Scapy.

## Knowledge Gaps
- **101 isolated node(s):** `Quick-start script for NetSentinel backend.`, `NetSentinel Configuration — Paths, Thresholds, Constants.`, `Get model file path. Downloads from Hugging Face if not found locally.`, `REST API Routes — Health, alerts, stats, simulation, PCAP, capture.`, `Create API routes with access to shared state.      Args:         analyzer: F` (+96 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 15`** (3 nodes): `geo.ts`, `buildGraph()`, `isInternal()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 16`** (2 nodes): `run.py`, `Quick-start script for NetSentinel backend.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 21`** (2 nodes): `Start the traffic simulator to generate live alerts.`, `start_simulator.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 22`** (2 nodes): `Stop the traffic simulator.`, `stop_simulator.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 23`** (2 nodes): `upload_pcap.py`, `Upload any PCAP file to the backend.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 24`** (2 nodes): `use_real_pcap.py`, `Use a real PCAP file instead of creating one with Scapy.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `_process_pcap_background()` connect `Community 1` to `Community 0`?**
  _High betweenness centrality (0.229) - this node is a cross-community bridge._
- **Why does `ModelRegistry` connect `Community 2` to `Community 1`, `Community 3`, `Community 4`?**
  _High betweenness centrality (0.187) - this node is a cross-community bridge._
- **Why does `PacketProcessor` connect `Community 0` to `Community 1`?**
  _High betweenness centrality (0.183) - this node is a cross-community bridge._
- **Are the 27 inferred relationships involving `C2BeaconDetector` (e.g. with `ModelRegistry` and `Model Registry — Loads all ONNX models on startup.  Usage:     registry = Mod`) actually correct?**
  _`C2BeaconDetector` has 27 INFERRED edges - model-reasoned connections that need verification._
- **Are the 23 inferred relationships involving `ModelRegistry` (e.g. with `NetSentinel — Main FastAPI Application.  This is the entry point. It: 1. Load` and `Background task that continuously generates traffic events,     runs them throu`) actually correct?**
  _`ModelRegistry` has 23 INFERRED edges - model-reasoned connections that need verification._
- **Are the 20 inferred relationships involving `ExfiltrationDetector` (e.g. with `ModelRegistry` and `Model Registry — Loads all ONNX models on startup.  Usage:     registry = Mod`) actually correct?**
  _`ExfiltrationDetector` has 20 INFERRED edges - model-reasoned connections that need verification._
- **Are the 9 inferred relationships involving `FlowExtractor` (e.g. with `PacketProcessor` and `Packet Processor — Orchestrator for the extraction pipeline.  Routes each raw`) actually correct?**
  _`FlowExtractor` has 9 INFERRED edges - model-reasoned connections that need verification._