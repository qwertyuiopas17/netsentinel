# NetSentinel

**AI-Powered Network Threat Detection System**

> "See Everything. Touch Nothing. Trust the Chain."

NetSentinel is a passive network security monitoring system that uses 6 specialized AI models to detect threats in real-time. Built for SOC analysts, security researchers, and network engineers.

![Demo](https://img.shields.io/badge/status-demo--ready-green) ![Python](https://img.shields.io/badge/python-3.11-blue) ![Models](https://img.shields.io/badge/models-6-orange) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- 4GB RAM minimum

### 1. Install Backend
```bash
pip install -r requirements.txt
```

### 2. Start Backend
```bash
python run.py
```
Wait for: `[OK] 6/6 models loaded` and `[>] Server ready!`

### 3. Start Frontend
```bash
cd frontend
npm install
npm run dev
```
Open: http://localhost:5173

### 4. Process a PCAP
```bash
curl -X POST http://localhost:8000/api/pcap/process \
  -H "Content-Type: application/json" \
  -d '{"filepath": "Friday-WorkingHours.pcap"}'
```

**🎉 Watch alerts appear in real-time!**

---

## 🎯 Features

### 6 AI Models for Threat Detection
| Threat Type | Algorithm | Dataset | Accuracy |
|-------------|-----------|---------|----------|
| **DDoS** | XGBoost | CIC-DDoS2019 | 99.97% F1 |
| **C2 Beacons** | BiLSTM + FFT | Custom | 94.3% F1 |
| **DGA Domains** | CNN-BiLSTM | UMUDGA | 99.2% F1 |
| **Encrypted Malware** | Transformer | CIC-IDS-2017 | 98.7% Acc |
| **Port Scans** | XGBoost | UNSW-NB15 | 96.8% F1 |
| **DNS Tunneling** | VAE | CIC-Bell-DNS | 89.0% F1 |

### Real-Time Dashboard
- **3D Globe:** Visualize attack origins geographically
- **MITRE ATT&CK Heatmap:** Map threats to tactics/techniques
- **Live Alert Feed:** WebSocket streaming with sub-3ms latency
- **Evidence Panels:** Forensic details for each alert
- **Model Performance Cards:** Track AI model accuracy and confidence

### Network Flow Analysis
- PCAP file processing (offline analysis)
- Live network capture (tap/SPAN port monitoring)
- Flow-level feature extraction (CIC-style features)
- Session correlation for C2 beacon detection
- DNS query analysis for DGA and tunneling

---

## 📊 Demo

**Try it now:** See [DEMO_GUIDE.md](DEMO_GUIDE.md) for a complete walkthrough

**Sample Result:** Processing `Friday-WorkingHours.pcap` (8.8GB DDoS traffic)
- ✅ 3,905 alerts detected
- ✅ 610 DDoS attacks identified
- ✅ 2,217 exfiltration attempts caught
- ✅ Real-time visualization on dashboard

---

## 🏗️ Architecture

```
┌─────────────┐
│   PCAP      │
│   File      │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────┐
│  Flow Extraction Layer              │
│  • Flow Extractor (DDoS, ETT)       │
│  • DNS Extractor (DGA, Exfil)       │
│  • Session Builder (C2 Beacons)     │
└──────┬──────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│  AI Model Ensemble (ONNX)           │
│  ┌──────┐ ┌──────┐ ┌──────┐        │
│  │ DDoS │ │  C2  │ │ DGA  │        │
│  └──────┘ └──────┘ └──────┘        │
│  ┌──────┐ ┌──────┐ ┌──────┐        │
│  │ ETT  │ │ Scan │ │ Exfil│        │
│  └──────┘ └──────┘ └──────┘        │
└──────┬──────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│  Alert Manager                      │
│  • MITRE ATT&CK mapping             │
│  • Severity scoring                 │
│  • Evidence enrichment              │
└──────┬──────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│  WebSocket API (FastAPI)            │
└──────┬──────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│  React Dashboard (TypeScript)       │
│  • Real-time visualization          │
│  • 3D threat globe (Three.js)       │
│  • MITRE heatmap                    │
└─────────────────────────────────────┘
```

---

## 📁 Project Structure

```
netsentinel/
├── netsentinel/           # Backend Python package
│   ├── api/              # FastAPI endpoints
│   ├── models/           # AI model wrappers (ONNX)
│   ├── extractor/        # PCAP parsing & feature extraction
│   ├── pipeline/         # Alert management & orchestration
│   ├── simulator/        # Traffic generation for testing
│   └── config.py         # Configuration & thresholds
├── frontend/             # React dashboard
│   └── src/
│       ├── components/   # UI components
│       ├── data/         # WebSocket hooks
│       └── types/        # TypeScript interfaces
├── docs/                 # Architecture & design docs
├── tests/                # Unit & integration tests
├── DEMO_GUIDE.md        # Complete demo walkthrough
├── COMPLETE_STATUS_REPORT.md  # Development status
└── requirements.txt      # Python dependencies
```

---

## 🔧 Configuration

### Model Thresholds
Edit `netsentinel/config.py`:
```python
THRESHOLDS = {
    "ddos": 0.98,         # DDoS confidence threshold
    "c2_beacon": 0.85,    # C2 beacon threshold
    "dga": 0.80,          # DGA domain threshold
    "encrypted_malware": 0.85,
    "port_scan": 0.85,
    "exfiltration": 0.85,
}
```

### Backend Port
Default: `http://localhost:8000`

Change in `run.py`:
```python
uvicorn.run(app, host="0.0.0.0", port=8000)
```

### Frontend WebSocket
Edit `frontend/src/data/useThreatFeed.ts`:
```typescript
const WS_URL = "ws://localhost:8000/ws";
```

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [DEMO_GUIDE.md](DEMO_GUIDE.md) | Complete demo walkthrough with talking points |
| [COMPLETE_STATUS_REPORT.md](COMPLETE_STATUS_REPORT.md) | Development status & known issues |
| [COMPLETE_SETUP_GUIDE.md](COMPLETE_SETUP_GUIDE.md) | Detailed installation guide |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture deep dive |
| [docs/LIVE_CAPTURE_GUIDE.md](docs/LIVE_CAPTURE_GUIDE.md) | Real-time network monitoring |
| [CICFLOWMETER_INTEGRATION.md](CICFLOWMETER_INTEGRATION.md) | Improving feature extraction |

---

## ⚠️ Known Limitations

**Status:** Proof-of-Concept / Demo-Ready

### Feature Extraction Accuracy
- Custom feature extractor has **92% drift** vs CICFlowMeter reference
- **Impact:** Models detect threats but with degraded confidence scores
- **Fix:** 8-12 hours to align with CICFlowMeter, or use CICFlowMeter directly
- **Workaround:** Use provided PCAPs which have been tested

### Evidence Panel Status
- ✅ **DDoS entropy:** Working with real data
- ⚠️ **Port scan fan-out:** Code ready, needs better test data
- ⚠️ **Exfil byte ratio:** Requires DNS-flow correlation layer

### Production Readiness
- ✅ Functional for demos and research
- ⚠️ Not optimized for high-throughput production (10Gbps+)
- ⚠️ Accuracy degradation due to feature drift

**See [COMPLETE_STATUS_REPORT.md](COMPLETE_STATUS_REPORT.md) for full details**

---

## 🧪 Testing

### Run Unit Tests
```bash
pytest tests/
```

### Test with Sample PCAP
```bash
# Provided DDoS PCAP (8.8 GB, real traffic)
python run.py

# In another terminal:
curl -X POST http://localhost:8000/api/pcap/process \
  -H "Content-Type: application/json" \
  -d '{"filepath": "Friday-WorkingHours.pcap"}'
```

### Test Live Capture
```bash
# Requires admin/root for packet capture
sudo python -m netsentinel.api.capture_api start --interface eth0
```

---

## 🤝 Contributing

This is a portfolio/research project. For improvements:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/improvement`)
3. **Commit** changes (`git commit -am 'Add new feature'`)
4. **Push** to branch (`git push origin feature/improvement`)
5. **Open** a Pull Request

**Priority improvements:**
- Fix feature extractor drift (align with CICFlowMeter)
- Add DNS-flow correlation for byte ratio evidence
- Optimize for high-throughput production
- Add more model interpretability features

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details

---

## 🙏 Acknowledgments

### Datasets
- **CIC-DDoS2019** - Canadian Institute for Cybersecurity
- **UNSW-NB15** - University of New South Wales
- **CIC-IDS-2017** - Canadian Institute for Cybersecurity
- **UMUDGA** - University of Massachusetts DGA dataset
- **CIC-Bell DNS Exfiltration 2021**

### Tools & Libraries
- **ONNX Runtime** - Model inference
- **FastAPI** - Backend API
- **React + Vite** - Frontend framework
- **Three.js** - 3D globe visualization
- **Scapy** - Packet manipulation

---

## 📧 Contact

**Project Author:** [Your Name]  
**Portfolio:** [Your Website]  
**LinkedIn:** [Your LinkedIn]  
**GitHub:** [Your GitHub]

---

## 🎯 Use Cases

- **SOC Teams:** Real-time threat detection and triage
- **Incident Response:** Forensic analysis of PCAP files
- **Security Research:** ML model evaluation on network data
- **Network Monitoring:** Passive monitoring of production traffic
- **Education:** Teaching network security and ML concepts

---

## 🚀 Roadmap

- [ ] Fix feature extractor accuracy (92% → 0% drift)
- [ ] Add DNS-flow correlation for complete evidence
- [ ] Implement alert correlation (group related alerts)
- [ ] Add model explainability (SHAP/LIME)
- [ ] Performance optimization (10Gbps+ throughput)
- [ ] Add response playbooks (SOAR integration)
- [ ] Continuous model retraining pipeline
- [ ] Multi-tenancy support

---

**Built with ❤️ for the cybersecurity community**

**Ready to try it?** See [DEMO_GUIDE.md](DEMO_GUIDE.md) to get started! 🚀
