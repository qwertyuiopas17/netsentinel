# netsentinel/extractor — PCAP → Model-Ready Feature Extraction
#
# This package translates raw network packets into the exact feature
# schemas each AI model expects:
#
#   PacketProcessor  ← orchestrator (use this)
#     ├── FlowExtractor    → 59 CIC features + 29 ETT features
#     ├── DNSExtractor     → domain strings for DGA model
#     └── SessionBuilder   → 100-flow time-series for C2 model

from netsentinel.extractor.pcap_reader import PacketProcessor
from netsentinel.extractor.flow_extractor import FlowExtractor
from netsentinel.extractor.dns_extractor import DNSExtractor
from netsentinel.extractor.session_builder import SessionBuilder

__all__ = [
    "PacketProcessor",
    "FlowExtractor",
    "DNSExtractor",
    "SessionBuilder",
]
