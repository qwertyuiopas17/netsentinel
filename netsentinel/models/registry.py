"""Model Registry — Loads all ONNX models on startup.

Usage:
    registry = ModelRegistry()
    registry.load_all()
    
    result = registry.ddos.predict(flow_features)
"""
import time
from antithesis.models.ddos import DDoSDetector
from antithesis.models.c2_beacon import C2BeaconDetector
from antithesis.models.dga import DGADetector
from antithesis.models.encrypted import EncryptedTrafficDetector


class ModelRegistry:
    """Loads and holds all ONNX model sessions."""
    
    def __init__(self):
        self.ddos = None
        self.c2 = None
        self.dga = None
        self.ett = None
        self._load_times = {}
    
    def load_all(self):
        """Load all models. Call once on server startup."""
        print("\n[*] Loading AI models...")
        total_start = time.time()
        
        models = [
            ("DDoS", "ddos", DDoSDetector),
            ("C2 Beacon", "c2", C2BeaconDetector),
            ("DGA", "dga", DGADetector),
            ("Encrypted Traffic", "ett", EncryptedTrafficDetector),
        ]
        
        for name, attr, cls in models:
            start = time.time()
            try:
                instance = cls()
                setattr(self, attr, instance)
                elapsed = time.time() - start
                self._load_times[name] = elapsed
            except Exception as e:
                print(f"  [FAIL] Failed to load {name}: {e}")
                self._load_times[name] = -1
        
        total_elapsed = time.time() - total_start
        loaded = sum(1 for v in self._load_times.values() if v >= 0)
        print(f"\n[OK] {loaded}/4 models loaded in {total_elapsed:.2f}s")
        
        return self
    
    def get_status(self) -> dict:
        """Return model status for the /health endpoint."""
        return {
            "models_loaded": {
                "ddos": self.ddos is not None,
                "c2_beacon": self.c2 is not None,
                "dga": self.dga is not None,
                "encrypted_traffic": self.ett is not None,
            },
            "load_times": self._load_times,
        }
