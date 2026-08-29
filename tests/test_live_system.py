"""
Live system test with real PCAP file.
Tests the full pipeline: PCAP → Feature Extraction → Model Inference → Alerts
"""
import sys
import time
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent))

from netsentinel.extractor import PCAPExtractor
from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.analyzer import ThreatAnalyzer

def test_live_pcap(pcap_path: str):
    """Test full pipeline with a real PCAP file."""
    print("=" * 80)
    print("NETSENTINEL LIVE SYSTEM TEST")
    print("=" * 80)
    
    pcap_file = Path(pcap_path)
    if not pcap_file.exists():
        print(f"❌ ERROR: PCAP file not found: {pcap_path}")
        return False
    
    print(f"\n📁 PCAP File: {pcap_file.name}")
    print(f"   Size: {pcap_file.stat().st_size / (1024**3):.2f} GB")
    
    # Initialize components
    print("\n⏱️  Loading models...")
    registry = ModelRegistry()
    registry.load_all_models()
    print("✅ Models loaded")
    
    print("\n⏱️  Initializing analyzer...")
    analyzer = ThreatAnalyzer(registry)
    print("✅ Analyzer ready")
    
    # Process PCAP
    print(f"\n⏱️  Processing PCAP file: {pcap_file.name}")
    print("   (This may take a while for large files...)")
    
    start_time = time.time()
    extractor = PCAPExtractor(str(pcap_file))
    
    flow_count = 0
    alert_count = 0
    alert_types = Counter()
    
    try:
        for flow_data in extractor.extract_flows():
            flow_count += 1
            
            # Analyze flow
            alerts = analyzer.analyze_flow(flow_data)
            
            if alerts:
                alert_count += len(alerts)
                for alert in alerts:
                    alert_types[alert.get("threat_type", "unknown")] += 1
            
            # Progress update every 100 flows
            if flow_count % 100 == 0:
                elapsed = time.time() - start_time
                rate = flow_count / elapsed if elapsed > 0 else 0
                print(f"   Processed {flow_count} flows ({rate:.1f} flows/sec)...", end="\r")
        
        # Final results
        elapsed = time.time() - start_time
        print(f"\n\n{'=' * 80}")
        print("RESULTS")
        print("=" * 80)
        print(f"⏱️  Processing time: {elapsed:.2f} seconds")
        print(f"📊 Total flows: {flow_count}")
        print(f"🚨 Total alerts: {alert_count}")
        print(f"📈 Detection rate: {(alert_count/flow_count*100):.1f}%")
        
        if alert_types:
            print(f"\n🎯 Alert Breakdown:")
            for threat_type, count in alert_types.most_common():
                print(f"   {threat_type:20} {count:5} alerts")
        else:
            print("\n✅ No threats detected (clean traffic)")
        
        print("=" * 80)
        return True
        
    except Exception as e:
        print(f"\n\n❌ ERROR during processing: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_live_system.py <path_to_pcap>")
        print("\nExample:")
        print('  python test_live_system.py "Friday-WorkingHours.pcap"')
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    success = test_live_pcap(pcap_path)
    sys.exit(0 if success else 1)
