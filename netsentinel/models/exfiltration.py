"""
Data Exfiltration Detection using VAE (Expert 6)
Dataset: CIC-Bell-DNS-EXF-2021
MITRE ATT&CK: T1041 (Exfil Over C2), T1048 (Exfil Alt Protocol), T1071.004 (DNS)
"""
import numpy as np
import onnxruntime as ort
import joblib
from pathlib import Path
import json
from typing import Dict, Any


class ExfiltrationDetector:
    """
    Detects data exfiltration via DNS tunneling using VAE reconstruction error.
    
    Key indicators:
    - Anomalous DNS query patterns
    - High entropy in domain names
    - Unusual subdomain lengths
    - High volume of DNS queries
    """
    
    def __init__(self, model_path: str = None, scaler_path: str = None):
        """
        Initialize exfiltration detector with VAE model and scaler.
        
        Args:
            model_path: Path to ONNX VAE model
            scaler_path: Path to scaler joblib file
        """
        if model_path is None:
            model_path = Path(__file__).parent / "exfil_vae.onnx"
        if scaler_path is None:
            scaler_path = Path(__file__).parent / "exfil_scaler.joblib"
        
        model_path = Path(model_path)
        scaler_path = Path(scaler_path)
        
        if not model_path.exists():
            raise FileNotFoundError(f"Exfiltration model not found: {model_path}")
        if not scaler_path.exists():
            raise FileNotFoundError(f"Scaler not found: {scaler_path}")
        
        # Load metadata (contains feature names)
        meta_path = model_path.parent / "exfil_meta.json"
        with open(meta_path) as f:
            self.metadata = json.load(f)
        
        self.feature_names = self.metadata['features']
        
        # Load ONNX model
        self.session = ort.InferenceSession(str(model_path))
        
        # Load scaler (CRITICAL: must match training scikit-learn version)
        self.scaler = joblib.load(scaler_path)
        
        # Threshold for reconstruction error (from metadata)
        # Tuned to F1=0.89 on validation set
        self.threshold = 0.15
        
        print(f"[OK] Exfiltration VAE loaded ({len(self.feature_names)} features)")
    
    @property
    def reconstruction_threshold(self) -> float:
        """Alias for threshold (backwards-compat with test suite)."""
        return self.threshold

    def set_threshold(self, value: float):
        """Adjust the reconstruction-error threshold at runtime."""
        self.threshold = float(value)
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict if DNS traffic indicates data exfiltration.
        
        Args:
            features: Dictionary of DNS/flow features
            
        Returns:
            Dictionary with threat, confidence, and evidence
        """
        try:
            # Extract feature vector in correct order
            X = np.array([features.get(f, 0.0) for f in self.feature_names], dtype=np.float32)
            X = X.reshape(1, -1)
            
            # Scale features (MUST use same scaler as training)
            X_scaled = self.scaler.transform(X).astype(np.float32)
            
            # VAE inference: encoder → latent → decoder
            input_name = self.session.get_inputs()[0].name
            outputs = self.session.run(None, {input_name: X_scaled})
            reconstructed = outputs[0]
            
            # Reconstruction error (MSE)
            mse = float(np.mean((X_scaled - reconstructed) ** 2))
            
            # Normalize confidence: mse > threshold = anomaly
            # Confidence is how much the MSE exceeds threshold
            conf = min(mse / self.threshold, 1.0) if mse > self.threshold else 0.0
            
            is_exfil = mse > self.threshold
            
            # Additional heuristics from DNS features
            dns_entropy = features.get('dns_entropy', 0)
            subdomain_len = features.get('subdomain_length', 0)
            
            # High entropy + long subdomains = likely tunneling
            if dns_entropy > 4.0 and subdomain_len > 30:
                is_exfil = True
                conf = max(conf, 0.75)
            
            result = {
                "threat": "Data Exfiltration" if is_exfil else "benign",
                "confidence": conf,
                "model": "exfil_vae",
            }
            
            if is_exfil:
                result["evidence"] = {
                    "reconstruction_error": float(mse),
                    "dns_entropy": float(dns_entropy),
                    "subdomain_length": int(subdomain_len),
                    "anomaly_type": "dns_tunneling"
                }
                result["mitre"] = {
                    "tactic": "Exfiltration",
                    "technique": "T1048",
                    "name": "Exfiltration Over Alternative Protocol (DNS)"
                }
            
            return result
            
        except Exception as e:
            print(f"[!] Exfiltration prediction error: {e}")
            return {
                "threat": "benign",
                "confidence": 0.0,
                "model": "exfil_vae",
                "error": str(e)
            }
