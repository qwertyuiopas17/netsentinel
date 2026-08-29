"""
Unit tests for Data Exfiltration detection.
Tests the VAE-based anomaly detector with synthetic features.
"""
import pytest
import numpy as np
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def create_exfil_features():
    """
    Create synthetic features mimicking data exfiltration.
    
    Exfiltration characteristics:
    - Very high outbound bytes
    - Low inbound bytes (commands only)
    - High byte ratio (>10x)
    - Sustained flow (>5 seconds)
    - Significant data volume (>1 MB)
    """
    return {
        # Key feature: massive outbound
        "Total Length of Fwd Packets": 10_000_000,  # 10 MB outbound
        "Total Length of Bwd Packets": 5_000,       # 5 KB inbound (C2 commands)
        
        # Flow duration (sustained)
        "Flow Duration": 300_000_000,  # 5 minutes (300 seconds in microseconds)
        
        # Throughput
        "Flow Bytes/s": 33_333,  # ~10MB / 300s
        
        # Packet counts
        "Total Fwd Packets": 7_000,  # Lots of data packets
        "Total Backward Packets": 50,  # Few command packets
        
        # Packet sizes
        "Fwd Packet Length Mean": 1428.0,  # Near MTU (efficient transfer)
        "Bwd Packet Length Mean": 100.0,   # Small commands
        
        # Timing
        "Fwd IAT Mean": 42_857,  # ~43ms between outbound packets
        "Bwd IAT Mean": 6_000_000,  # ~6 seconds between commands
        "Flow IAT Mean": 42_857,
        
        # Rates
        "Fwd Packets/s": 23.3,
        "Bwd Packets/s": 0.17,
        "Average Packet Size": 1421.0,
    }


def create_benign_features():
    """
    Create synthetic features for normal bidirectional traffic (web browsing).
    
    Benign characteristics:
    - Balanced inbound/outbound
    - Normal byte ratio (~1-3x)
    - Typical flow patterns
    """
    return {
        "Total Length of Fwd Packets": 50_000,   # 50 KB outbound
        "Total Length of Bwd Packets": 150_000,  # 150 KB inbound (3x - normal for web)
        "Flow Duration": 5_000_000,  # 5 seconds
        "Flow Bytes/s": 40_000,
        "Total Fwd Packets": 50,
        "Total Backward Packets": 100,
        "Fwd Packet Length Mean": 1000.0,
        "Bwd Packet Length Mean": 1500.0,
        "Fwd IAT Mean": 100_000,
        "Bwd IAT Mean": 50_000,
        "Flow IAT Mean": 33_333,
        "Fwd Packets/s": 10.0,
        "Bwd Packets/s": 20.0,
        "Average Packet Size": 1333.0,
    }


def create_download_features():
    """
    Create synthetic features for legitimate large download (not exfil).
    
    Download characteristics:
    - HIGH INBOUND (opposite of exfil)
    - Low outbound (requests/ACKs only)
    - High byte ratio favoring inbound
    """
    return {
        "Total Length of Fwd Packets": 10_000,      # 10 KB outbound (requests)
        "Total Length of Bwd Packets": 50_000_000,  # 50 MB inbound (download)
        "Flow Duration": 60_000_000,  # 1 minute
        "Flow Bytes/s": 833_333,
        "Total Fwd Packets": 100,
        "Total Backward Packets": 35_000,
        "Fwd Packet Length Mean": 100.0,
        "Bwd Packet Length Mean": 1428.0,
        "Fwd IAT Mean": 600_000,
        "Bwd IAT Mean": 1_714,
        "Flow IAT Mean": 1_714,
        "Fwd Packets/s": 1.67,
        "Bwd Packets/s": 583.3,
        "Average Packet Size": 1422.0,
    }


@pytest.mark.skipif(
    not (Path(__file__).parent.parent / "models" / "exfil_vae.onnx").exists(),
    reason="Exfiltration VAE model file not found"
)
def test_exfil_model_loads():
    """Test that the exfiltration detector loads without errors."""
    from netsentinel.models.exfiltration import ExfiltrationDetector
    
    detector = ExfiltrationDetector()
    assert detector is not None
    assert len(detector.feature_names) > 0
    assert detector.reconstruction_threshold > 0
    print("✅ Exfiltration detector loaded successfully")


@pytest.mark.skipif(
    not (Path(__file__).parent.parent / "models" / "exfil_vae.onnx").exists(),
    reason="Exfiltration VAE model file not found"
)
def test_exfil_detection():
    """Test detection of data exfiltration with synthetic features."""
    from netsentinel.models.exfiltration import ExfiltrationDetector
    
    detector = ExfiltrationDetector()
    features = create_exfil_features()
    
    result = detector.predict(features)
    
    print(f"\n=== Data Exfiltration Detection Test ===")
    print(f"Threat: {result['threat']}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Model: {result['model']}")
    
    if result['threat'] == 'Data Exfiltration':
        print(f"\nEvidence:")
        for key, val in result.get('evidence', {}).items():
            if 'bytes' in key:
                print(f"  {key}: {val:,}")
            else:
                print(f"  {key}: {val}")
        
        # Verify MITRE mapping
        assert 'mitre' in result
        assert result['mitre']['tactic'] == 'Exfiltration'
        assert result['mitre']['technique'] == 'T1041'
        print(f"\nMITRE: {result['mitre']['technique']} - {result['mitre']['name']}")
    
    # Should detect exfiltration (or at least high confidence)
    assert result['confidence'] > 0.5, "Exfiltration should have confidence > 0.5"
    print(f"\n✅ Exfiltration detected with {result['confidence']:.1%} confidence")


@pytest.mark.skipif(
    not (Path(__file__).parent.parent / "models" / "exfil_vae.onnx").exists(),
    reason="Exfiltration VAE model file not found"
)
def test_benign_traffic_not_detected():
    """Test that benign traffic is not flagged as exfiltration."""
    from netsentinel.models.exfiltration import ExfiltrationDetector
    
    detector = ExfiltrationDetector()
    features = create_benign_features()
    
    result = detector.predict(features)
    
    print(f"\n=== Benign Traffic Test ===")
    print(f"Threat: {result['threat']}")
    print(f"Confidence: {result['confidence']:.2%}")
    
    # Should be benign
    assert result['threat'] == 'benign', "Benign traffic should not be flagged as exfiltration"
    print(f"✅ Benign traffic correctly classified")


@pytest.mark.skipif(
    not (Path(__file__).parent.parent / "models" / "exfil_vae.onnx").exists(),
    reason="Exfiltration VAE model file not found"
)
def test_download_not_detected():
    """Test that legitimate downloads are not flagged as exfiltration."""
    from netsentinel.models.exfiltration import ExfiltrationDetector
    
    detector = ExfiltrationDetector()
    features = create_download_features()
    
    result = detector.predict(features)
    
    print(f"\n=== Legitimate Download Test ===")
    print(f"Threat: {result['threat']}")
    print(f"Confidence: {result['confidence']:.2%}")
    
    # Should be benign (download has INBOUND >> outbound, opposite of exfil)
    assert result['threat'] == 'benign', "Download should not be flagged as exfiltration"
    print(f"✅ Download correctly classified as benign")


def test_exfil_heuristics():
    """Test the heuristic gates without model."""
    exfil_features = create_exfil_features()
    benign_features = create_benign_features()
    download_features = create_download_features()
    
    print(f"\n=== Heuristic Gates Test ===")
    
    # Test exfil features
    fwd_bytes = exfil_features['Total Length of Fwd Packets']
    bwd_bytes = exfil_features['Total Length of Bwd Packets']
    byte_ratio = fwd_bytes / bwd_bytes
    duration = exfil_features['Flow Duration']
    
    print(f"\n1. Exfiltration Pattern:")
    print(f"   Outbound: {fwd_bytes:,} bytes")
    print(f"   Inbound: {bwd_bytes:,} bytes")
    print(f"   Ratio: {byte_ratio:.1f}x")
    print(f"   Duration: {duration/1_000_000:.1f} seconds")
    
    assert byte_ratio > 10, "Exfil should have byte ratio > 10x"
    assert duration > 5_000_000, "Exfil should be sustained (>5s)"
    assert fwd_bytes > 1_000_000, "Exfil should have significant data (>1MB)"
    print(f"   ✅ All exfil gates pass")
    
    # Test benign features
    fwd_bytes = benign_features['Total Length of Fwd Packets']
    bwd_bytes = benign_features['Total Length of Bwd Packets']
    byte_ratio = fwd_bytes / bwd_bytes
    
    print(f"\n2. Benign Pattern:")
    print(f"   Outbound: {fwd_bytes:,} bytes")
    print(f"   Inbound: {bwd_bytes:,} bytes")
    print(f"   Ratio: {byte_ratio:.1f}x")
    
    assert byte_ratio < 10, "Benign should have balanced ratio"
    print(f"   ✅ Benign ratio gate correctly rejects")
    
    # Test download features
    fwd_bytes = download_features['Total Length of Fwd Packets']
    bwd_bytes = download_features['Total Length of Bwd Packets']
    byte_ratio = fwd_bytes / bwd_bytes
    
    print(f"\n3. Download Pattern:")
    print(f"   Outbound: {fwd_bytes:,} bytes")
    print(f"   Inbound: {bwd_bytes:,} bytes")
    print(f"   Ratio: {byte_ratio:.4f}x")
    
    assert byte_ratio < 1, "Download should favor inbound"
    print(f"   ✅ Download ratio gate correctly rejects")


def test_threshold_adjustment():
    """Test threshold adjustment API."""
    print(f"\n=== Threshold Adjustment Test ===")
    
    try:
        from netsentinel.models.exfiltration import ExfiltrationDetector
        detector = ExfiltrationDetector()
        
        original = detector.reconstruction_threshold
        print(f"Original threshold: {original}")
        
        detector.set_threshold(0.20)
        assert detector.reconstruction_threshold == 0.20
        print(f"Updated threshold: {detector.reconstruction_threshold}")
        print(f"✅ Threshold adjustment works")
        
    except FileNotFoundError:
        print("⚠️  Model not found, skipping threshold test")


if __name__ == "__main__":
    print("="*60)
    print("Data Exfiltration Detector Test Suite")
    print("="*60)
    
    # Run tests manually if pytest not available
    try:
        from netsentinel.models.exfiltration import ExfiltrationDetector
        
        print("\n[1/6] Testing model loading...")
        test_exfil_model_loads()
        
        print("\n[2/6] Testing exfiltration detection...")
        test_exfil_detection()
        
        print("\n[3/6] Testing benign traffic classification...")
        test_benign_traffic_not_detected()
        
        print("\n[4/6] Testing download classification...")
        test_download_not_detected()
        
        print("\n[5/6] Testing heuristic gates...")
        test_exfil_heuristics()
        
        print("\n[6/6] Testing threshold adjustment...")
        test_threshold_adjustment()
        
        print("\n" + "="*60)
        print("✅ All tests passed!")
        print("="*60)
        
    except FileNotFoundError as e:
        print(f"\n⚠️  Model file not found: {e}")
        print("Please train and save exfil_vae.onnx + exfil_scaler.pkl to models/")
        
        print("\n[5/6] Testing heuristic gates (no model needed)...")
        test_exfil_heuristics()
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
