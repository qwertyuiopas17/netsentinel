"""
Port Scan Detection using XGBoost (Expert 5)
Dataset: UNSW-NB15
MITRE ATT&CK: T1046 - Network Service Scanning (Discovery)
"""
import numpy as np
import onnxruntime as ort
from pathlib import Path
import json
from typing import Dict, Any


class PortScanDetector:
    """
    Detects port scanning behavior using UNSW-NB15 flow features.
    
    Key indicators:
    - High connection rate to multiple ports
    - Low packets per flow (SYN-only scans)
    - Sequential port targeting
    """
    
    def __init__(self, model_path: str = None):
        """Initialize port scan detector with ONNX model."""
        if model_path is None:
            model_path = Path(__file__).parent / "port_scan_xgboost.onnx"
        
        model_path = Path(model_path)
        
        if not model_path.exists():
            raise FileNotFoundError(f"Port Scan model not found: {model_path}")
        
        # Load ONNX model
        self.session = ort.InferenceSession(str(model_path))
        
        # Load feature names
        feature_json = model_path.parent / "port_scan_features.json"
        with open(feature_json) as f:
            features = json.load(f)
            # Remove 'id' if present
            self.feature_names = [f for f in features if f != 'id']
        
        self.threshold = 0.85
        
        print(f"[OK] Port Scan XGBoost loaded ({len(self.feature_names)} features)")
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict if flow exhibits port scanning behavior.
        
        Args:
            features: Dictionary of flow features
            
        Returns:
            Dictionary with threat, confidence, and evidence
        """
        try:
            # Extract feature vector in correct order
            X = np.array([features.get(f, 0.0) for f in self.feature_names], dtype=np.float32)
            X = X.reshape(1, -1)
            
            # ONNX inference
            input_name = self.session.get_inputs()[0].name
            outputs = self.session.run(None, {input_name: X})
            
            # Get probabilities [benign_prob, portscan_prob]
            probs = outputs[1][0]  # outputs[1] is probabilities
            conf = float(probs[1])  # Port scan probability
            
            is_threat = conf > self.threshold
            
            # Port scan heuristics (additional gating)
            rate = features.get('rate', 0)
            pkts = features.get('src_pkts', 0)
            
            # Require: high rate + low packets (SYN scan pattern)
            if rate > 0 and pkts < 10:
                is_threat = is_threat or (rate > 100 and conf > 0.7)
            
            result = {
                "threat": "Port Scan" if is_threat else "benign",
                "confidence": conf,
                "model": "port_scan_xgboost",
            }
            
            if is_threat:
                result["evidence"] = {
                    "connection_rate": float(rate),
                    "packets_per_flow": int(pkts),
                    "scan_indicator": "high_rate_low_packets"
                }
                result["mitre"] = {
                    "tactic": "Discovery",
                    "technique": "T1046",
                    "name": "Network Service Scanning"
                }
            
            return result
            
        except Exception as e:
            print(f"[!] Port Scan prediction error: {e}")
            return {
                "threat": "benign",
                "confidence": 0.0,
                "model": "port_scan_xgboost",
                "error": str(e)
            }
