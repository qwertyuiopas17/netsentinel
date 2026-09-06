"""Flow Analyzer — Routes incoming events to the correct AI models.

This is the central orchestrator. It receives raw "events" from the 
traffic simulator or extraction layer and routes them to the appropriate
model(s). Supports all 6 detection classes:

  - DDoS (flow path)
  - Encrypted Traffic / VPN (flow path)
  - Port Scan (flow path, requires UNSW-NB15 features)
  - DGA (DNS path)
  - Data Exfiltration / DNS Tunnel (DNS path, requires lexical features)
  - C2 Beacon (session path)
"""
import math
from collections import Counter, defaultdict

from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.alert_manager import AlertManager
from netsentinel.config import THRESHOLDS
from netsentinel.extractor.unsw_feature_builder import (
    build_unsw_features,
    ConnectionTracker,
)
from netsentinel.extractor.dns_feature_builder import build_dns_features


class FlowAnalyzer:
    """Routes flows to models and collects alerts."""
    
    def __init__(self, registry: ModelRegistry, alert_manager: AlertManager):
        self.registry = registry
        self.alert_manager = alert_manager
        self.flows_processed = 0

        # Connection tracker for UNSW-NB15 ct_* features (port scan)
        self._conn_tracker = ConnectionTracker()

        # DDoS evidence: track recent source IPs per destination for entropy
        self._recent_src_ips: dict[str, list[str]] = defaultdict(list)
        _MAX_SRC_IP_WINDOW = 200  # Track last 200 source IPs per target

        # Port scan evidence: track recent dst ports per source IP
        self._recent_dst_ports: dict[str, set[int]] = defaultdict(set)

        # DNS alert deduplication: suppress repeated alerts for same base domain
        self._dns_alert_times: dict[str, float] = {}  # dedup_key → last alert timestamp
        self._dns_query_counts: dict[str, int] = {}   # dedup_key → total query count
    
    def analyze_flow(self, event: dict) -> dict | None:
        """
        Analyze a single event and return an alert if threat detected.
        
        Events can be:
          - type="flow": Network flow with statistical features → DDoS + ETT + Port Scan
          - type="dns": DNS query → DGA + Exfiltration
          - type="session": Time-series of flows → C2 Beacon
        
        Args:
            event: dict with "type" key and model-specific data
        
        Returns:
            Alert dict if threat detected, None otherwise
        """
        self.flows_processed += 1
        event_type = event.get("type", "flow")
        
        if event_type == "dns" and (self.registry.dga or self.registry.exfiltration):
            return self._analyze_dns(event)
        elif event_type == "session" and self.registry.c2:
            return self._analyze_session(event)
        elif event_type == "flow":
            return self._analyze_flow(event)
        
        return None
    
    def _build_flow_meta(self, event: dict) -> dict:
        """Build 5-tuple flow_meta from event fields.
        
        The flow extractor emits source_port, dest_port, protocol at the
        top level of the event dict. The simulator puts them in features.
        We check both locations.
        """
        features = event.get("features", {})
        return {
            "src_ip":   event.get("source_ip"),
            "src_port": event.get("source_port", features.get("src_port", 0)),
            "dst_ip":   event.get("dest_ip"),
            "dst_port": event.get("dest_port", features.get("dst_port", 0)),
            "protocol": _proto_name(event.get("protocol", features.get("Protocol", 6))),
        }

    def _analyze_dns(self, event: dict) -> dict | None:
        """Run DGA detection + exfiltration detection on a DNS query.
        
        Both detectors run independently. Deduplication prevents alert spam
        by suppressing repeated alerts for the same base domain within a window.
        """
        domain = event.get("domain", "")
        if not domain:
            return None
        
        source_ip = event.get("source_ip")
        flow_meta = {"domain": domain, "src_ip": source_ip}
        
        # Extract base domain for deduplication (e.g., "xxx.www.ggy666.tk" → "ggy666.tk")
        parts = domain.lower().strip().split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        dga_alert = None
        exfil_alert = None

        # --- DGA detection ---
        if self.registry.dga:
            result = self.registry.dga.predict(domain)
            
            # Signal 1: Model prediction
            model_suspicious = result["is_malicious"] and result["confidence"] >= THRESHOLDS["dga"]
            
            # Signal 2: Entropy analysis
            analysis_str = ".".join(parts[:-1]) if len(parts) > 1 else domain
            freq = Counter(analysis_str)
            total = len(analysis_str)
            entropy = -sum((c/total) * math.log2(c/total) for c in freq.values()) if total > 0 else 0
            high_entropy = entropy > 3.0
            
            if model_suspicious and high_entropy:
                # Deduplication: only alert once per base domain per 60s window
                dedup_key = f"dga:{base_domain}:{source_ip}"
                now = event.get("timestamp", 0)
                last_alert_time = self._dns_alert_times.get(dedup_key, 0)
                
                if now - last_alert_time > 60.0:
                    self._dns_alert_times[dedup_key] = now
                    # Count how many queries we've seen for this domain
                    self._dns_query_counts[dedup_key] = self._dns_query_counts.get(dedup_key, 0) + 1
                    result["query_count"] = self._dns_query_counts[dedup_key]
                    dga_alert = self.alert_manager.create_alert(
                        result,
                        source_ip=source_ip,
                        flow_meta=flow_meta,
                    )
                else:
                    # Suppress duplicate, but still count
                    self._dns_query_counts[dedup_key] = self._dns_query_counts.get(dedup_key, 0) + 1

        # --- Exfiltration detection (DNS tunnel) ---
        if self.registry.exfiltration:
            dns_features = build_dns_features(domain)
            if dns_features:
                # Add byte counts if available
                fwd_bytes = event.get("total_fwd_bytes")
                bwd_bytes = event.get("total_bwd_bytes")
                if fwd_bytes is None:
                    fwd_bytes = event.get("features", {}).get("Fwd Packets Length Total")
                if bwd_bytes is None:
                    bwd_bytes = event.get("features", {}).get("Bwd Packets Length Total")
                if fwd_bytes is not None and bwd_bytes is not None:
                    dns_features["total_fwd_bytes"] = fwd_bytes
                    dns_features["total_bwd_bytes"] = bwd_bytes
                
                result = self.registry.exfiltration.predict(dns_features)
                
                model_detects = result.get("threat") == "Data Exfiltration"
                high_confidence = result.get("confidence", 0) >= THRESHOLDS["exfiltration"]
                
                evidence_strong = False
                if model_detects:
                    dns_entropy = result.get("dns_entropy", 0)
                    subdomain_len = result.get("subdomain_length", 0)
                    recon_error = result.get("reconstruction_error", 0)
                    
                    evidence_strong = (
                        recon_error > 1.4
                        or (dns_entropy > 4.0 and subdomain_len > 20)
                        or (dns_entropy > 5.0)
                    )
                
                if model_detects and high_confidence and evidence_strong:
                    # Deduplication for exfil too
                    dedup_key = f"exfil:{base_domain}:{source_ip}"
                    now = event.get("timestamp", 0)
                    last_alert_time = self._dns_alert_times.get(dedup_key, 0)
                    
                    if now - last_alert_time > 60.0:
                        self._dns_alert_times[dedup_key] = now
                        # Add byte_ratio for frontend
                        fwd = dns_features.get("total_fwd_bytes", 0)
                        bwd = dns_features.get("total_bwd_bytes", 0)
                        if fwd or bwd:
                            result["byte_ratio"] = {"outbound": int(fwd), "inbound": int(bwd)}
                        elif subdomain_len > 0:
                            result["byte_ratio"] = {"outbound": int(subdomain_len * 50), "inbound": 512}
                        
                        exfil_alert = self.alert_manager.create_alert(
                            result,
                            source_ip=source_ip,
                            flow_meta=flow_meta,
                        )

        # Return exfil alert preferentially (more specific), fallback to DGA
        return exfil_alert or dga_alert
    
    def _analyze_session(self, event: dict) -> dict | None:
        """Run C2 Beacon detection on a flow time-series."""
        flows = event.get("flows", [])
        if not flows:
            return None
        
        # Build flow_meta for the session
        flow_meta = {
            "src_ip":   event.get("source_ip"),
            "src_port": 0,
            "dst_ip":   event.get("dest_ip"),
            "dst_port": 0,
            "protocol": "TCP",
        }
        
        result = self.registry.c2.predict(flows)
        
        if result["is_beacon"] and result["confidence"] >= THRESHOLDS["c2_beacon"]:
            return self.alert_manager.create_alert(
                result,
                source_ip=event.get("source_ip"),
                dest_ip=event.get("dest_ip"),
                flow_meta=flow_meta,
            )
        return None
    
    def _analyze_flow(self, event: dict) -> dict | None:
        """Run DDoS, ETT, and/or Port Scan detection on a single flow.

        Hybrid routing based on extractor source:
          - extractor="cicflowmeter" → DDoS + Port Scan (zero-drift CIC features)
          - extractor="custom"       → ETT only (custom ISCX features)
          - no tag (simulator/legacy) → all models (backward compatible)
        """
        features = event.get("features", {})
        flow_meta = self._build_flow_meta(event)
        source_ip = event.get("source_ip")
        dest_ip = event.get("dest_ip")
        alert = None

        # Which extractor produced this event?
        extractor = event.get("extractor")  # "cicflowmeter", "custom", or None
        
        # Track source IPs per destination for DDoS entropy evidence
        if dest_ip and source_ip:
            src_list = self._recent_src_ips[dest_ip]
            src_list.append(source_ip)
            if len(src_list) > 200:
                self._recent_src_ips[dest_ip] = src_list[-200:]

        # Track dst ports per source for port-scan fan-out evidence
        dst_port = event.get("dest_port", features.get("dst_port", 0))
        if source_ip and dst_port:
            self._recent_dst_ports[source_ip].add(dst_port)
            # Cap the set size
            if len(self._recent_dst_ports[source_ip]) > 500:
                ports = list(self._recent_dst_ports[source_ip])
                self._recent_dst_ports[source_ip] = set(ports[-200:])

        # --- DDoS detection (CICFlowMeter features or untagged) ---
        if extractor != "custom":  # cicflowmeter or None (legacy/simulator)
            if self.registry.ddos and features:
                result = self.registry.ddos.predict(features)
                if result["is_attack"] and result["confidence"] >= THRESHOLDS["ddos"]:
                    # Heuristic guard: real DDoS has high packet/byte rates
                    pkt_rate = features.get("Flow Packets/s", features.get("flow_pkts_s", 0))
                    byte_rate = features.get("Flow Bytes/s", features.get("flow_byts_s", 0))
                    if pkt_rate > 100 or byte_rate > 50000:
                        # Add src_ip_entropy evidence
                        if dest_ip and dest_ip in self._recent_src_ips:
                            src_entropy = _shannon_entropy_of_ips(
                                self._recent_src_ips[dest_ip]
                            )
                            result["src_ip_entropy"] = round(src_entropy, 2)

                        alert = self.alert_manager.create_alert(
                            result,
                            source_ip=source_ip,
                            dest_ip=dest_ip,
                            flow_meta=flow_meta,
                        )
        
        # --- Encrypted traffic detection (custom features or untagged) ---
        if extractor != "cicflowmeter":  # custom or None (legacy/simulator)
            if alert is None and self.registry.ett and features:
                result = self.registry.ett.predict(features)
                if result["is_vpn"] and result["confidence"] >= THRESHOLDS["encrypted_malware"]:
                    alert = self.alert_manager.create_alert(
                        result,
                        source_ip=source_ip,
                        dest_ip=dest_ip,
                        flow_meta=flow_meta,
                    )

        # --- Port Scan detection (CICFlowMeter features or untagged) ---
        if extractor != "custom":  # cicflowmeter or None (legacy/simulator)
            if alert is None and self.registry.port_scan and features:
                unsw_features = build_unsw_features(event, self._conn_tracker)
                if unsw_features:
                    # Run ML model
                    result = self.registry.port_scan.predict(unsw_features)
                    
                    # Track port fan-out for evidence
                    if source_ip and source_ip in self._recent_dst_ports:
                        num_ports = len(self._recent_dst_ports[source_ip])
                        
                        # Debug: Log what ML model predicted
                        if num_ports >= 10:
                            ml_threat = result.get("threat", "Unknown")
                            ml_conf = result.get("confidence", 0)
                            print(f"[SCAN] Port scan check: {source_ip} -> {num_ports} ports, ML says: {ml_threat} @ {ml_conf:.4f}")
                        
                        ml_confidence = result.get("confidence", 0)
                        ml_detects_scan = result.get("threat") == "Port Scan"
                        
                        # Use ML model only - trust the trained model's predictions
                        should_alert = ml_detects_scan and ml_confidence >= THRESHOLDS["port_scan"]
                        
                        if should_alert:
                            # Add fan_out evidence
                            result["fan_out"] = {
                                "target_ip": dest_ip or "unknown",
                                "ports": sorted(list(self._recent_dst_ports[source_ip]))[:30],
                                "total_ports": num_ports,
                                "window": 8,
                            }
                            
                            # Add MITRE mapping
                            result["mitre"] = {
                                "tactic": "Discovery",
                                "technique": "T1046",
                                "name": "Network Service Scanning"
                            }
                            
                            alert = self.alert_manager.create_alert(
                                result,
                                source_ip=source_ip,
                                dest_ip=dest_ip,
                                flow_meta=flow_meta,
                            )


        
        return alert
    
    def get_stats(self) -> dict:
        """Return pipeline statistics."""
        return {
            "flows_processed": self.flows_processed,
            **self.alert_manager.get_stats(),
        }


# ======================================================================
# Utility functions
# ======================================================================

def _proto_name(proto) -> str:
    """Convert numeric protocol to string."""
    if isinstance(proto, str):
        return proto
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "TCP")


def _shannon_entropy_of_ips(ip_list: list[str]) -> float:
    """Compute Shannon entropy (bits) of an IP address distribution.
    
    High entropy = many distinct sources (amplified DDoS).
    Low entropy = few sources (single-source flood).
    """
    if not ip_list:
        return 0.0
    freq = Counter(ip_list)
    total = len(ip_list)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())
