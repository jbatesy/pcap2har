"""
pcap2har - Convert PCAP files to HAR format.

This module provides tools to parse HTTP/1.x and HTTP/2 traffic from 
packet capture files and convert them to the HTTP Archive (HAR) format.

Usage:
    # As a CLI tool
    python -m pcap2har capture.pcap -o output.har
    
    # As a library
    from pcap2har import PcapToHarConverter
    
    converter = PcapToHarConverter(keylog_file="keys.txt")
    converter.convert_to_file("capture.pcap", "output.har")
"""

from .converter import PcapToHarConverter, TransactionConverter
from .har import (
    HarBuilder,
    HarEntry,
    HarRequest,
    HarResponse,
    HarContent,
    HarHeader,
    HarCookie,
    HarTimings,
)
from .pcap_parser import PcapParser, StreamInfo, TsharkNotFoundError
from .cli import main

__version__ = "0.1.0"
__all__ = [
    # Main converter
    "PcapToHarConverter",
    "TransactionConverter",
    # HAR models
    "HarBuilder",
    "HarEntry",
    "HarRequest",
    "HarResponse",
    "HarContent",
    "HarHeader",
    "HarCookie",
    "HarTimings",
    # PCAP parser
    "PcapParser",
    "StreamInfo",
    "TsharkNotFoundError",
    # CLI
    "main",
]
