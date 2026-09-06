"""CICFlowMeter Wrapper — Zero-drift feature extraction for DDoS & Port Scan.

Uses hieulw/cicflowmeter (pip install cicflowmeter) Python API to extract
the exact same features that the DDoS and Port Scan models were trained on.

Uses the Python API directly (not the CLI), so no tcpdump dependency.
"""
import logging
import os
import tempfile
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

# Maps cicflowmeter Python output names → CIC CSV names (what models expect)
CIC_NAME_MAP = {
    "flow_duration":       "Flow Duration",
    "tot_fwd_pkts":        "Total Fwd Packets",
    "tot_bwd_pkts":        "Total Backward Packets",
    "totlen_fwd_pkts":     "Fwd Packets Length Total",
    "totlen_bwd_pkts":     "Bwd Packets Length Total",
    "fwd_pkt_len_max":     "Fwd Packet Length Max",
    "fwd_pkt_len_min":     "Fwd Packet Length Min",
    "fwd_pkt_len_mean":    "Fwd Packet Length Mean",
    "fwd_pkt_len_std":     "Fwd Packet Length Std",
    "bwd_pkt_len_max":     "Bwd Packet Length Max",
    "bwd_pkt_len_min":     "Bwd Packet Length Min",
    "bwd_pkt_len_mean":    "Bwd Packet Length Mean",
    "bwd_pkt_len_std":     "Bwd Packet Length Std",
    "flow_byts_s":         "Flow Bytes/s",
    "flow_pkts_s":         "Flow Packets/s",
    "flow_iat_mean":       "Flow IAT Mean",
    "flow_iat_std":        "Flow IAT Std",
    "flow_iat_max":        "Flow IAT Max",
    "flow_iat_min":        "Flow IAT Min",
    "fwd_iat_tot":         "Fwd IAT Total",
    "fwd_iat_mean":        "Fwd IAT Mean",
    "fwd_iat_std":         "Fwd IAT Std",
    "fwd_iat_max":         "Fwd IAT Max",
    "fwd_iat_min":         "Fwd IAT Min",
    "bwd_iat_tot":         "Bwd IAT Total",
    "bwd_iat_mean":        "Bwd IAT Mean",
    "bwd_iat_std":         "Bwd IAT Std",
    "bwd_iat_max":         "Bwd IAT Max",
    "bwd_iat_min":         "Bwd IAT Min",
    "fwd_psh_flags":       "Fwd PSH Flags",
    "bwd_psh_flags":       "Bwd PSH Flags",
    "fwd_urg_flags":       "Fwd URG Flags",
    "bwd_urg_flags":       "Bwd URG Flags",
    "fwd_header_len":      "Fwd Header Length",
    "bwd_header_len":      "Bwd Header Length",
    "fwd_pkts_s":          "Fwd Packets/s",
    "bwd_pkts_s":          "Bwd Packets/s",
    "pkt_len_max":         "Packet Length Max",
    "pkt_len_min":         "Packet Length Min",
    "pkt_len_mean":        "Packet Length Mean",
    "pkt_len_std":         "Packet Length Std",
    "pkt_len_var":         "Packet Length Variance",
    "fin_flag_cnt":        "FIN Flag Count",
    "syn_flag_cnt":        "SYN Flag Count",
    "rst_flag_cnt":        "RST Flag Count",
    "psh_flag_cnt":        "PSH Flag Count",
    "ack_flag_cnt":        "ACK Flag Count",
    "urg_flag_cnt":        "URG Flag Count",
    "ece_flag_cnt":        "ECE Flag Count",
    "cwr_flag_count":      "CWE Flag Count",
    "down_up_ratio":       "Down/Up Ratio",
    "pkt_size_avg":        "Avg Packet Size",
    "fwd_seg_size_avg":    "Avg Fwd Segment Size",
    "bwd_seg_size_avg":    "Avg Bwd Segment Size",
    "subflow_fwd_pkts":    "Subflow Fwd Packets",
    "subflow_fwd_byts":    "Subflow Fwd Bytes",
    "subflow_bwd_pkts":    "Subflow Bwd Packets",
    "subflow_bwd_byts":    "Subflow Bwd Bytes",
    "init_fwd_win_byts":   "Init Fwd Win Bytes",
    "init_bwd_win_byts":   "Init Bwd Win Bytes",
    "fwd_act_data_pkts":   "Fwd Act Data Packets",
    "fwd_seg_size_min":    "Fwd Seg Size Min",
    "active_mean":         "Active Mean",
    "active_std":          "Active Std",
    "active_max":          "Active Max",
    "active_min":          "Active Min",
    "idle_mean":           "Idle Mean",
    "idle_std":            "Idle Std",
    "idle_max":            "Idle Max",
    "idle_min":            "Idle Min",
    "fwd_byts_b_avg":     "Fwd Bytes/Bulk Avg",
    "fwd_pkts_b_avg":     "Fwd Packets/Bulk Avg",
    "bwd_byts_b_avg":     "Bwd Bytes/Bulk Avg",
    "bwd_pkts_b_avg":     "Bwd Packets/Bulk Avg",
    "fwd_blk_rate_avg":   "Fwd Bulk Rate Avg",
    "bwd_blk_rate_avg":   "Bwd Bulk Rate Avg",
}

# Metadata columns to exclude from features
_META_COLS = {
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
}


class CICFlowMeterExtractor:
    """Extracts CIC-IDS flow features using the reference CICFlowMeter Python API.

    Zero covariate shift by definition — this is the same tool that
    generated the training data for DDoS and Port Scan models.

    Uses the Python API directly (not CLI), no tcpdump required.
    """

    def __init__(self):
        self._verify_installation()

    def _verify_installation(self):
        """Check cicflowmeter is importable."""
        try:
            from cicflowmeter.flow_session import FlowSession  # noqa: F401
            logger.info("[OK] CICFlowMeter Python package available")
        except ImportError:
            raise RuntimeError(
                "cicflowmeter not installed. Run: pip install cicflowmeter"
            )

    def extract_from_pcap(self, pcap_path: str, max_packets: int = 0) -> list[dict]:
        """Extract CIC-IDS flow features from a PCAP file.

        Uses the Python API: reads packets with Scapy PcapReader,
        feeds them through FlowSession, and collects flow dicts.

        Args:
            pcap_path: Absolute path to a .pcap/.pcapng file.
            max_packets: Stop after this many packets (0 = no limit).

        Returns:
            List of flow event dicts with mapped CIC CSV feature names.
        """
        if not os.path.isfile(pcap_path):
            logger.error(f"PCAP not found: {pcap_path}")
            return []

        try:
            from cicflowmeter.flow_session import FlowSession
            from scapy.utils import PcapReader
        except ImportError as e:
            logger.error(f"Import error: {e}")
            return []

        # Use a temp CSV as the output target
        tmpdir = tempfile.mkdtemp()
        csv_path = os.path.join(tmpdir, "flows.csv")

        # FlowSession uses class-level attributes set via setattr
        # (this is how the CLI does it — see cicflowmeter.sniffer.create_sniffer)
        setattr(FlowSession, "output_mode", "csv")
        setattr(FlowSession, "output", csv_path)
        setattr(FlowSession, "fields", None)
        setattr(FlowSession, "verbose", False)

        try:
            session = FlowSession()
        except Exception as e:
            logger.error(f"Failed to create FlowSession: {e}")
            return []

        # Stream packets through the session
        logger.info(f"CICFlowMeter processing: {pcap_path}")
        try:
            reader = PcapReader(pcap_path)
        except Exception as e:
            logger.error(f"Failed to open PCAP: {e}")
            return []

        pkt_count = 0
        try:
            for pkt in reader:
                pkt_count += 1
                try:
                    session.on_packet_received(pkt)
                except Exception:
                    pass  # Skip malformed packets

                if pkt_count % 50000 == 0:
                    logger.info(f"  CIC: {pkt_count} packets processed...")

                if max_packets and pkt_count >= max_packets:
                    break
        except Exception as e:
            logger.warning(f"CIC packet processing stopped: {e}")
        finally:
            if hasattr(reader, 'close'):
                reader.close()

        # Flush all remaining flows via toPacketList() (calls garbage_collect(None))
        try:
            session.toPacketList()
        except Exception:
            # toPacketList may error after deleting writer, that's OK
            pass

        logger.info(f"CIC: Processed {pkt_count} packets, reading CSV...")

        # Parse the CSV output
        events = self._csv_to_events(csv_path)

        # Cleanup
        try:
            os.remove(csv_path)
            os.rmdir(tmpdir)
        except Exception:
            pass

        return events

    def _csv_to_events(self, csv_path: str) -> list[dict]:
        """Parse CICFlowMeter CSV output into flow event dicts.

        Applies CIC_NAME_MAP to convert snake_case feature names
        to the CIC CSV format expected by the DDoS/PortScan models.
        """
        if not os.path.isfile(csv_path):
            logger.warning("CICFlowMeter CSV not created")
            return []

        try:
            df = pd.read_csv(csv_path)
        except Exception as e:
            logger.error(f"Failed to read CICFlowMeter CSV: {e}")
            return []

        if df.empty:
            logger.warning("CICFlowMeter CSV is empty")
            return []

        # Normalize column names (strip whitespace)
        df.columns = [c.strip() for c in df.columns]

        events = []
        for _, row in df.iterrows():
            try:
                src_ip = str(row.get("src_ip", "0.0.0.0"))
                dst_ip = str(row.get("dst_ip", "0.0.0.0"))
                src_port = int(row.get("src_port", 0))
                dst_port = int(row.get("dst_port", 0))
                protocol = int(row.get("protocol", 6))

                # Build feature dict with mapped names
                features = {"Protocol": protocol}
                for col in df.columns:
                    if col in _META_COLS:
                        continue
                    val = row[col]
                    try:
                        val = float(val)
                        if val != val or val == float("inf") or val == float("-inf"):
                            val = 0.0
                    except (ValueError, TypeError):
                        continue

                    # Map to CIC CSV name if known, otherwise keep original
                    mapped_name = CIC_NAME_MAP.get(col, col)
                    features[mapped_name] = val

                events.append({
                    "type": "flow",
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "source_port": src_port,
                    "dest_port": dst_port,
                    "protocol": protocol,
                    "features": features,
                    "extractor": "cicflowmeter",
                })
            except Exception as e:
                logger.debug(f"Skipping CIC row: {e}")
                continue

        logger.info(f"CICFlowMeter extracted {len(events)} flows")
        return events
