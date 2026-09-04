"""DGA / DNS Tunnel Detector — CNN-BiLSTM ONNX Wrapper (v2).

Input:  Domain name string (e.g., "xkqw8f3m.evil.com")
Output: {"threat": "DGA"|"DNS Tunnel"|"Benign", "confidence": float, ...}

v2 model (dga_cnn_bilstm_v2.onnx):
  - Single input branch: domain_chars [batch, 128] int64
  - Vocab: 0=PAD, 1=UNK, 2–39 = a-z0-9-. (vocab_size=40)
  - Classes: ['benign', 'dga', 'dns_tunnel']
  - Best macro-F1: 0.9787 (family-wise split, 27 DGA families held out)
  - Inference: ~1.85 ms/domain
"""
import numpy as np
import onnxruntime as ort

from netsentinel.config import DGA_MODEL_PATH

# ── Vocabulary ──────────────────────────────────────────────────────────────
# 0 = PAD, 1 = UNK, 2–39 = a-z 0-9 - .   (vocab_size = 40, matches training)
CHAR_VOCAB = {c: i + 2 for i, c in enumerate("abcdefghijklmnopqrstuvwxyz0123456789-.")}
MAX_DOMAIN_LEN = 128

# ── Class names (must match training order) ──────────────────────────────────
CLASS_NAMES = ["benign", "dga", "dns_tunnel"]
THREAT_DISPLAY = {"benign": "Benign", "dga": "DGA", "dns_tunnel": "DNS Tunnel"}


def _encode_domain(domain: str) -> np.ndarray:
    """Encode a domain string to a padded int64 array of length MAX_DOMAIN_LEN.

    Encoding: 0=PAD, 1=UNK for unknown chars, 2-39 for known chars.
    """
    domain = domain.lower().strip()
    encoded = [CHAR_VOCAB.get(c, 1) for c in domain[:MAX_DOMAIN_LEN]]  # 1 = UNK
    encoded += [0] * (MAX_DOMAIN_LEN - len(encoded))                   # 0 = PAD
    return np.array(encoded, dtype=np.int64)


class DGADetector:
    def __init__(self):
        self.session = ort.InferenceSession(
            DGA_MODEL_PATH,
            providers=["CPUExecutionProvider"],
        )
        inputs = self.session.get_inputs()
        self._input_name = inputs[0].name   # "domain_chars"
        print(f"  [OK] DGA Detector v2 loaded (char[{MAX_DOMAIN_LEN}], vocab={len(CHAR_VOCAB)+2}, 3 classes, macro-F1=0.9787)")

    def predict(self, domain: str) -> dict:
        """Classify a single domain name.

        Args:
            domain: Full domain string (e.g., "google.com" or "xkq8f3.xyz")

        Returns:
            dict with keys: threat, confidence, is_malicious, class_name,
                            domain, model, all_probs
        """
        char_input = _encode_domain(domain).reshape(1, MAX_DOMAIN_LEN)

        logits = self.session.run(None, {self._input_name: char_input})[0][0]

        # Softmax (model outputs raw logits)
        exp_l = np.exp(logits - np.max(logits))
        probs = exp_l / exp_l.sum()

        predicted_class = int(np.argmax(probs))
        confidence = float(probs[predicted_class])
        class_name = CLASS_NAMES[predicted_class]

        return {
            "threat": THREAT_DISPLAY[class_name],
            "confidence": confidence,
            "is_malicious": predicted_class != 0,
            "class_name": class_name,
            "domain": domain,
            "model": "dga_cnn_bilstm_v2",
            "all_probs": {
                "benign": float(probs[0]),
                "dga": float(probs[1]),
                "dns_tunnel": float(probs[2]),
            },
        }

    def predict_batch(self, domains: list) -> list:
        """Classify multiple domains. Returns list of predict() dicts."""
        return [self.predict(d) for d in domains]
