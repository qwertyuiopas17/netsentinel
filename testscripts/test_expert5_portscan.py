#!/usr/bin/env python3
"""
NetSentinel — Expert 5: Port Scan Detector Comprehensive Test Suite
====================================================================

Model: XGBoost (Binary Classification: PortScan vs Benign)
Training: 4 datasets (CIC-IDS2017, LITNET-2020, UNSW-NB15, CSE-CIC-IDS2018)
Features: 40 network flow features

Test Categories:
  T1: Infrastructure (model loading, artifact integrity)
  T2: Basic Correctness (obvious scans, obvious benign)
  T3: Industrial/Real-World (nmap-style patterns, stealth scans)
  T4: Edge Cases (zero-filled, extreme values)
  T5: Determinism Validation
  T6: Performance Benchmarking

Expected Metrics (from training):
  - Accuracy: 99.85%
  - Precision: 99.25%
  - Recall: 99.61%
  - F1 Score: 99.43%
  - ROC-AUC: 99.997%
  - Latency: 0.0175ms (P50)
  - Throughput: 57K flows/sec
"""

import json
import numpy as np
import os
import sys
import time
from pathlib import Path

# ============================================================
# Test Framework
# ============================================================
class TestSuite:
    def __init__(self):
        self.results = []
        self.current_section = ""
        self.passed_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        
    def section(self, name: str):
        self.current_section = name
        print(f"\n{'='*70}")
        print(f"  {name}")
        print(f"{'='*70}")
    
    def passed(self, name: str, detail: str = ""):
        self.results.append((self.current_section, name, "PASS", detail))
        self.passed_count += 1
        print(f"  ✓ {name}" + (f" ({detail})" if detail else ""))
    
    def failed(self, name: str, detail: str = ""):
        self.results.append((self.current_section, name, "FAIL", detail))
        self.failed_count += 1
        print(f"  ✗ {name}" + (f" ({detail})" if detail else ""))
    
    def skipped(self, name: str, detail: str = ""):
        self.results.append((self.current_section, name, "SKIP", detail))
        self.skipped_count += 1
        print(f"  [SKIP] {name}" + (f" ({detail})" if detail else ""))
    
    def print_summary(self):
        print("\n" + "="*70)
        print("  PORT SCAN DETECTOR — TEST RESULTS")
        print("="*70)
        
        total = self.passed_count + self.failed_count + self.skipped_count
        pass_rate = (self.passed_count / total * 100) if total > 0 else 0
        
        print(f"\nTotal Tests: {total}")
        print(f"Passed:  {self.passed_count}/{total} ({pass_rate:.1f}%)")
        print(f"Failed:  {self.failed_count}")
        print(f"Skipped: {self.skipped_count}")
        
        if self.failed_count > 0:
            print("\nFailed Tests:")
            for section, name, status, detail in self.results:
                if status == "FAIL":
                    print(f"  • {section}: {name}")
                    if detail:
                        print(f"    {detail}")
        
        print("\n" + "="*70)
        return self.failed_count == 0

# ============================================================
# T1: Infrastructure Tests
# ============================================================

def test_infrastructure(suite: TestSuite):
    """Test model loading and artifact integrity."""
    suite.section("T1: Infrastructure & Artifact Integrity")
    
    try:
        import onnxruntime as ort
        
        # Locate model files
        model_dir = Path("port scanning/port scan")
        model_path = model_dir / "expert5_portscan_xgboost.onnx"
        metrics_path = model_dir / "expert5_metrics.json"
        features_path = model_dir / "expert5_feature_names.json"
        
        # T1.1: Model file exists
        if not model_path.exists():
            suite.failed("Model file exists", f"Not found: {model_path}")
            return None, None, None
        suite.passed("Model file exists", f"{model_path.stat().st_size / 1024:.1f} KB")
        
        # T1.2: Metrics file exists
        if not metrics_path.exists():
            suite.failed("Metrics file exists", f"Not found: {metrics_path}")
            return None, None, None
        suite.passed("Metrics file exists")
        
        # T1.3: Feature names file exists
        if not features_path.exists():
            suite.failed("Feature names file exists", f"Not found: {features_path}")
            return None, None, None
        suite.passed("Feature names file exists")
        
        # T1.4: Load metrics
        with open(metrics_path) as f:
            metrics = json.load(f)
        suite.passed("Metrics loaded", f"Accuracy: {metrics['accuracy']:.4f}")
        
        # T1.5: Load feature names
        with open(features_path) as f:
            feature_names = json.load(f)
        n_features = len(feature_names)
        suite.passed("Feature names loaded", f"{n_features} features")
        
        # T1.6: Verify feature count matches metadata
        expected_features = metrics.get('n_features', 40)
        if n_features == expected_features:
            suite.passed("Feature count matches metadata", f"{n_features} == {expected_features}")
        else:
            suite.failed("Feature count matches metadata", f"{n_features} != {expected_features}")
        
        # T1.7: Load ONNX model
        sess = ort.InferenceSession(str(model_path), providers=['CPUExecutionProvider'])
        suite.passed("ONNX model loaded")
        
        # T1.8: Verify input/output shapes
        input_name = sess.get_inputs()[0].name
        input_shape = sess.get_inputs()[0].shape
        output_name = sess.get_outputs()[0].name
        
        if input_shape[1] == n_features:
            suite.passed("Input shape correct", f"[batch, {n_features}]")
        else:
            suite.failed("Input shape correct", f"Expected {n_features}, got {input_shape[1]}")
        
        # T1.9: Verify metrics quality
        if metrics['auc_roc'] > 0.99:
            suite.passed("ROC-AUC exceptional", f"{metrics['auc_roc']:.5f}")
        else:
            suite.failed("ROC-AUC exceptional", f"{metrics['auc_roc']:.5f} < 0.99")
        
        if metrics['f1'] > 0.99:
            suite.passed("F1 Score exceptional", f"{metrics['f1']:.4f}")
        else:
            suite.failed("F1 Score exceptional", f"{metrics['f1']:.4f} < 0.99")
        
        return sess, feature_names, metrics
        
    except Exception as e:
        suite.failed("Infrastructure test", f"Exception: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None

# ============================================================
# T2: Basic Correctness Tests
# ============================================================

def test_basic_correctness(suite: TestSuite, sess, feature_names):
    """Test obvious port scan vs benign patterns."""
    suite.section("T2: Basic Correctness")
    
    if sess is None:
        suite.skipped("All basic correctness tests", "Model not loaded")
        return
    
    input_name = sess.get_inputs()[0].name
    
    # T2.1: Obvious SYN scan (high src_pkts, low dst_pkts, many dst IPs)
    syn_scan = {name: 0.0 for name in feature_names}
    syn_scan.update({
        'src_pkts': 1000.0,      # Sent many packets
        'dst_pkts': 50.0,        # Received few responses
        'src_bytes': 60000.0,    # Small packets (SYN = 60 bytes)
        'dst_bytes': 3000.0,     # Few responses
        'rate': 500.0,           # High packet rate
        'sttl': 64.0,            # Common TTL
        'sloss': 900.0,          # Most packets lost (no response)
        'dloss': 0.0,
        'ctsrvdst': 100.0,       # Many unique destinations
        'ctdstsrcltm': 1.0       # Short time window
    })
    
    vec = np.array([[syn_scan[name] for name in feature_names]], dtype=np.float32)
    results = sess.run(None, {input_name: vec})
    prob = results[1][0, 1] if len(results[1][0]) > 1 else results[1][0, 0]
    
    if prob > 0.8:
        suite.passed("SYN scan detected", f"prob={prob:.2%}")
    else:
        suite.failed("SYN scan detected", f"prob={prob:.2%} < 80%")
    
    # T2.2: Obvious full-connect scan (completed TCP handshakes)
    full_scan = {name: 0.0 for name in feature_names}
    full_scan.update({
        'src_pkts': 300.0,
        'dst_pkts': 300.0,       # Equal packets (handshake completed)
        'src_bytes': 18000.0,
        'dst_bytes': 18000.0,
        'rate': 200.0,
        'sttl': 64.0,
        'dttl': 64.0,
        'synack': 300.0,         # Many SYN-ACK exchanges
        'ackdat': 0.0,           # No data transferred
        'ctsrvdst': 50.0,        # Many destinations
        'ctstatettl': 50.0       # Many state changes
    })
    
    vec = np.array([[full_scan[name] for name in feature_names]], dtype=np.float32)
    results = sess.run(None, {input_name: vec})
    prob = results[1][0, 1] if len(results[1][0]) > 1 else results[1][0, 0]
    
    if prob > 0.8:
        suite.passed("Full-connect scan detected", f"prob={prob:.2%}")
    else:
        suite.failed("Full-connect scan detected", f"prob={prob:.2%} < 80%")
    
    # T2.3: Benign web browsing (normal HTTP/HTTPS)
    benign_web = {name: 0.0 for name in feature_names}
    benign_web.update({
        'src_pkts': 50.0,
        'dst_pkts': 50.0,
        'src_bytes': 5000.0,
        'dst_bytes': 50000.0,    # Server sends more (HTML/images)
        'rate': 10.0,            # Normal rate
        'sttl': 64.0,
        'dttl': 64.0,
        'ackdat': 50.0,          # Data transferred
        'transdepth': 5.0,       # HTTP transactions
        'responsebodylen': 10000.0,
        'ctsrvdst': 1.0,         # Single destination
        'ctstatettl': 1.0
    })
    
    vec = np.array([[benign_web[name] for name in feature_names]], dtype=np.float32)
    results = sess.run(None, {input_name: vec})
    prob = results[1][0, 1] if len(results[1][0]) > 1 else results[1][0, 0]
    
    if prob < 0.2:
        suite.passed("Benign web traffic not flagged", f"prob={prob:.2%}")
    else:
        suite.failed("Benign web traffic not flagged", f"prob={prob:.2%} > 20%")
    
    # T2.4: Benign SSH session (long-lived, bidirectional)
    benign_ssh = {name: 0.0 for name in feature_names}
    benign_ssh.update({
        'flow_duration': 300.0,  # 5 minutes
        'src_pkts': 500.0,
        'dst_pkts': 500.0,       # Balanced
        'src_bytes': 25000.0,
        'dst_bytes': 25000.0,    # Balanced
        'rate': 1.67,            # Low rate
        'sttl': 64.0,
        'dttl': 64.0,
        'ackdat': 500.0,         # Data exchange
        'ctsrvdst': 1.0,         # Single destination
        'ctstatettl': 1.0
    })
    
    vec = np.array([[benign_ssh[name] for name in feature_names]], dtype=np.float32)
    results = sess.run(None, {input_name: vec})
    prob = results[1][0, 1] if len(results[1][0]) > 1 else results[1][0, 0]
    
    if prob < 0.2:
        suite.passed("Benign SSH session not flagged", f"prob={prob:.2%}")
    else:
        suite.failed("Benign SSH session not flagged", f"prob={prob:.2%} > 20%")

# ============================================================
# T3: Industrial/Real-World Tests
# ============================================================

def test_industrial(suite: TestSuite, sess, feature_names):
    """Test realistic scan patterns."""
    suite.section("T3: Industrial/Real-World Patterns")
    
    if sess is None:
        suite.skipped("All industrial tests", "Model not loaded")
        return
    
    input_name = sess.get_inputs()[0].name
    
    # T3.1: Nmap aggressive scan (-A)
    nmap_aggressive = {name: 0.0 for name in feature_names}
    nmap_aggressive.update({
        'src_pkts': 500.0,
        'dst_pkts': 100.0,
        'src_bytes': 30000.0,
        'dst_bytes': 6000.0,
        'rate': 250.0,           # Fast scan
        'sttl': 64.0,
        'sloss': 300.0,
        'ctsrvdst': 30.0,        # Multiple targets
        'ctstatettl': 30.0,
        'synack': 50.0
    })
    
    vec = np.array([[nmap_aggressive[name] for name in feature_names]], dtype=np.float32)
    results = sess.run(None, {input_name: vec})
    prob = results[1][0, 1] if len(results[1][0]) > 1 else results[1][0, 0]
    
    if prob > 0.7:
        suite.passed("Nmap aggressive scan detected", f"prob={prob:.2%}")
    else:
        suite.failed("Nmap aggressive scan detected", f"prob={prob:.2%} < 70%")
    
    # T3.2: Stealth scan (low rate, spaced out)
    stealth_scan = {name: 0.0 for name in feature_names}
    stealth_scan.update({
        'flow_duration': 600.0,  # Slow over 10 minutes
        'src_pkts': 200.0,
        'dst_pkts': 50.0,
        'src_bytes': 12000.0,
        'dst_bytes': 3000.0,
        'rate': 0.33,            # Very slow
        'sttl': 64.0,
        'sloss': 100.0,
        'ctsrvdst': 20.0,        # Still scanning multiple
        'ctstatettl': 20.0
    })
    
    vec = np.array([[stealth_scan[name] for name in feature_names]], dtype=np.float32)
    results = sess.run(None, {input_name: vec})
    prob = results[1][0, 1] if len(results[1][0]) > 1 else results[1][0, 0]
    
    if prob > 0.6:
        suite.passed("Stealth scan detected", f"prob={prob:.2%}")
    else:
        suite.failed("Stealth scan detected", f"prob={prob:.2%} < 60%")
    
    # T3.3: Horizontal scan (1 port, many IPs)
    horizontal_scan = {name: 0.0 for name in feature_names}
    horizontal_scan.update({
        'src_pkts': 250.0,
        'dst_pkts': 50.0,
        'src_bytes': 15000.0,
        'dst_bytes': 3000.0,
        'rate': 125.0,
        'sttl': 64.0,
        'sloss': 150.0,
        'ctsrvdst': 100.0,       # Many destinations (key indicator)
        'ctdstsrcltm': 1.0,      # Short time
        'ctsrcltm': 1.0
    })
    
    vec = np.array([[horizontal_scan[name] for name in feature_names]], dtype=np.float32)
    results = sess.run(None, {input_name: vec})
    prob = results[1][0, 1] if len(results[1][0]) > 1 else results[1][0, 0]
    
    if prob > 0.8:
        suite.passed("Horizontal scan detected", f"prob={prob:.2%}")
    else:
        suite.failed("Horizontal scan detected", f"prob={prob:.2%} < 80%")

# ============================================================
# T4: Edge Case Tests
# ============================================================

def test_edge_cases(suite: TestSuite, sess, feature_names):
    """Test extreme/malformed inputs."""
    suite.section("T4: Edge Case Robustness")
    
    if sess is None:
        suite.skipped("All edge case tests", "Model not loaded")
        return
    
    input_name = sess.get_inputs()[0].name
    
    # T4.1: All zeros
    try:
        vec = np.zeros((1, len(feature_names)), dtype=np.float32)
        results = sess.run(None, {input_name: vec})
        suite.passed("All zeros handled", "No crash")
    except Exception as e:
        suite.failed("All zeros handled", f"Crashed: {e}")
    
    # T4.2: All ones
    try:
        vec = np.ones((1, len(feature_names)), dtype=np.float32)
        results = sess.run(None, {input_name: vec})
        suite.passed("All ones handled", "No crash")
    except Exception as e:
        suite.failed("All ones handled", f"Crashed: {e}")
    
    # T4.3: Very large values
    try:
        vec = np.full((1, len(feature_names)), 1e9, dtype=np.float32)
        results = sess.run(None, {input_name: vec})
        suite.passed("Very large values handled", "No crash")
    except Exception as e:
        suite.failed("Very large values handled", f"Crashed: {e}")
    
    # T4.4: Negative values (should be impossible but test anyway)
    try:
        vec = np.full((1, len(feature_names)), -100.0, dtype=np.float32)
        results = sess.run(None, {input_name: vec})
        suite.passed("Negative values handled", "No crash")
    except Exception as e:
        suite.failed("Negative values handled", f"Crashed: {e}")
    
    # T4.5: NaN values
    try:
        vec = np.full((1, len(feature_names)), np.nan, dtype=np.float32)
        results = sess.run(None, {input_name: vec})
        suite.passed("NaN values handled", "No crash")
    except Exception as e:
        suite.failed("NaN values handled", f"Crashed: {e}")
    
    # T4.6: Inf values
    try:
        vec = np.full((1, len(feature_names)), np.inf, dtype=np.float32)
        results = sess.run(None, {input_name: vec})
        suite.passed("Inf values handled", "No crash")
    except Exception as e:
        suite.failed("Inf values handled", f"Crashed: {e}")

# ============================================================
# T5: Determinism Tests
# ============================================================

def test_determinism(suite: TestSuite, sess, feature_names):
    """Test that predictions are deterministic."""
    suite.section("T5: Determinism Validation")
    
    if sess is None:
        suite.skipped("Determinism test", "Model not loaded")
        return
    
    input_name = sess.get_inputs()[0].name
    
    # Create random test input
    np.random.seed(42)
    test_input = np.random.randn(1, len(feature_names)).astype(np.float32)
    
    # Run 10 times
    outputs = []
    for _ in range(10):
        results = sess.run(None, {input_name: test_input})
        outputs.append(results[1][0])
    
    # Check all outputs are identical
    outputs_arr = np.array(outputs)
    max_diff = np.max(np.abs(outputs_arr - outputs_arr[0]))
    
    if max_diff < 1e-6:
        suite.passed("Deterministic predictions", f"max diff={max_diff:.2e}")
    else:
        suite.failed("Deterministic predictions", f"max diff={max_diff:.2e} > 1e-6")

# ============================================================
# T6: Performance Tests
# ============================================================

def test_performance(suite: TestSuite, sess, feature_names, metrics):
    """Benchmark inference latency."""
    suite.section("T6: Performance Benchmarking")
    
    if sess is None:
        suite.skipped("All performance tests", "Model not loaded")
        return
    
    input_name = sess.get_inputs()[0].name
    
    # Generate 1000 random samples
    np.random.seed(42)
    samples = np.random.randn(1000, len(feature_names)).astype(np.float32)
    
    # Warmup
    for i in range(10):
        vec = samples[i:i+1]
        sess.run(None, {input_name: vec})
    
    # Benchmark
    latencies = []
    for i in range(1000):
        vec = samples[i:i+1]
        t0 = time.perf_counter()
        sess.run(None, {input_name: vec})
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000)  # Convert to ms
    
    p50 = np.percentile(latencies, 50)
    p95 = np.percentile(latencies, 95)
    p99 = np.percentile(latencies, 99)
    
    print(f"  Latency: P50={p50:.3f}ms, P95={p95:.3f}ms, P99={p99:.3f}ms")
    
    # T6.1: P50 latency < 1ms (should be ~0.0175ms based on training)
    if p50 < 1.0:
        suite.passed("P50 latency < 1ms", f"{p50:.3f}ms")
    else:
        suite.failed("P50 latency < 1ms", f"{p50:.3f}ms")
    
    # T6.2: P95 latency < 5ms
    if p95 < 5.0:
        suite.passed("P95 latency < 5ms", f"{p95:.3f}ms")
    else:
        suite.failed("P95 latency < 5ms", f"{p95:.3f}ms")
    
    # T6.3: Compare to reported metrics
    reported_latency = metrics.get('inference', {}).get('latency_ms', 0.0175)
    if abs(p50 - reported_latency) < reported_latency * 2:  # Within 2x
        suite.passed("Latency matches reported", f"{p50:.3f}ms vs {reported_latency:.3f}ms")
    else:
        suite.failed("Latency matches reported", f"{p50:.3f}ms vs {reported_latency:.3f}ms (>2x diff)")
    
    # T6.4: Throughput estimate
    throughput = 1000 / p50  # flows/sec
    print(f"  Estimated throughput: {throughput:.0f} flows/sec")
    
    if throughput > 10000:
        suite.passed("High throughput", f"{throughput:.0f} flows/sec")
    else:
        suite.failed("High throughput", f"{throughput:.0f} flows/sec < 10K/sec")

# ============================================================
# Main Test Runner
# ============================================================

def main():
    print("="*70)
    print("  NETSENTINEL EXPERT 5: PORT SCAN DETECTOR")
    print("  Comprehensive Test Suite")
    print("="*70)
    print("\nModel: XGBoost (Binary: PortScan vs Benign)")
    print("Training: CIC-IDS2017, LITNET-2020, UNSW-NB15, CSE-CIC-IDS2018")
    print("Expected: 99.85% accuracy, 99.997% ROC-AUC, 0.0175ms latency")
    
    suite = TestSuite()
    
    # Run all test categories
    sess, feature_names, metrics = test_infrastructure(suite)
    test_basic_correctness(suite, sess, feature_names)
    test_industrial(suite, sess, feature_names)
    test_edge_cases(suite, sess, feature_names)
    test_determinism(suite, sess, feature_names)
    test_performance(suite, sess, feature_names, metrics)
    
    # Print summary
    all_passed = suite.print_summary()
    
    # Exit with appropriate code
    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()
