"""Flow Analyzer — Routes incoming events to the correct AI models.

This is the central orchestrator. It receives raw "events" from the 
traffic simulator and routes them to the appropriate model(s).
"""
from antithesis.models.registry import ModelRegistry
from antithesis.pipeline.alert_manager import AlertManager
from antithesis.config import THRESHOLDS


class FlowAnalyzer:
    """Routes flows to models and collects alerts."""
    
    def __init__(self, registry: ModelRegistry, alert_manager: AlertManager):
        self.registry = registry
        self.alert_manager = alert_manager
        self.flows_processed = 0
    
    def analyze_flow(self, event: dict) -> dict | None:
        """
        Analyze a single event and return an alert if threat detected.
        
        Events can be:
          - type="flow": Network flow with statistical features → DDoS + ETT
          - type="dns": DNS query → DGA detector
          - type="session": Time-series of flows → C2 Beacon
        
        Args:
            event: dict with "type" key and model-specific data
        
        Returns:
            Alert dict if threat detected, None otherwise
        """
        self.flows_processed += 1
        event_type = event.get("type", "flow")
        
        if event_type == "dns" and self.registry.dga:
            return self._analyze_dns(event)
        elif event_type == "session" and self.registry.c2:
            return self._analyze_session(event)
        elif event_type == "flow":
            return self._analyze_flow(event)
        
        return None
    
    def _analyze_dns(self, event: dict) -> dict | None:
        """Run DGA detection on a DNS query."""
        domain = event.get("domain", "")
        if not domain:
            return None
        
        result = self.registry.dga.predict(domain)
        
        # Calculate raw entropy to filter out false positives
        import math
        from collections import Counter
        parts = domain.lower().strip().split('.')
        analysis_str = '.'.join(parts[:-1]) if len(parts) > 1 else domain
        freq = Counter(analysis_str)
        total = len(analysis_str)
        entropy = -sum((c/total) * math.log2(c/total) for c in freq.values()) if total > 0 else 0
        
        # Only alert if model says malicious AND entropy is high
        if result["is_malicious"] and result["confidence"] >= THRESHOLDS["dga"] and entropy > 3.0:
            return self.alert_manager.create_alert(
                result,
                source_ip=event.get("source_ip"),
                flow_meta={"domain": domain},
            )
        return None
    
    def _analyze_session(self, event: dict) -> dict | None:
        """Run C2 Beacon detection on a flow time-series."""
        flows = event.get("flows", [])
        if not flows:
            return None
        
        result = self.registry.c2.predict(flows)
        
        if result["is_beacon"] and result["confidence"] >= THRESHOLDS["c2_beacon"]:
            return self.alert_manager.create_alert(
                result,
                source_ip=event.get("source_ip"),
                dest_ip=event.get("dest_ip"),
            )
        return None
    
    def _analyze_flow(self, event: dict) -> dict | None:
        """Run DDoS and/or ETT detection on a single flow."""
        features = event.get("features", {})
        alert = None
        
        # Try DDoS detection
        if self.registry.ddos and features:
            result = self.registry.ddos.predict(features)
            if result["is_attack"] and result["confidence"] >= THRESHOLDS["ddos"]:
                # Heuristic guard: real DDoS has high packet/byte rates
                pkt_rate = features.get("Flow Packets/s", 0)
                byte_rate = features.get("Flow Bytes/s", 0)
                if pkt_rate > 100 or byte_rate > 50000:
                    alert = self.alert_manager.create_alert(
                        result,
                        source_ip=event.get("source_ip"),
                        dest_ip=event.get("dest_ip"),
                    )
        
        # Try encrypted traffic detection (only if no DDoS detected)
        if alert is None and self.registry.ett and features:
            result = self.registry.ett.predict(features)
            if result["is_vpn"] and result["confidence"] >= THRESHOLDS["encrypted_malware"]:
                alert = self.alert_manager.create_alert(
                    result,
                    source_ip=event.get("source_ip"),
                    dest_ip=event.get("dest_ip"),
                )
        
        return alert
    
    def get_stats(self) -> dict:
        """Return pipeline statistics."""
        return {
            "flows_processed": self.flows_processed,
            **self.alert_manager.get_stats(),
        }
