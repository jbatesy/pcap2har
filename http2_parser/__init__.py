"""
HTTP/2 Parser Module

Parse HTTP/2 streams from pcap files using tshark.

Example usage:
    from http2_parser import HTTP2Capture
    
    capture = HTTP2Capture(pcap_path, keylog_path)
    transactions = capture.get_transactions()
    
    for tx in transactions:
        print(f"{tx.request.method} {tx.request.url}")
        print(f"Response: {tx.response.status}")
        if tx.response.is_json:
            print(tx.response.json())
"""

from .models import (
    HTTP2Request,
    HTTP2Response,
    HTTP2Transaction,
)
from .capture import HTTP2Capture
from .parser import HTTP2StreamParser

__all__ = [
    'HTTP2Capture',
    'HTTP2Request',
    'HTTP2Response', 
    'HTTP2Transaction',
    'HTTP2StreamParser',
]

__version__ = '0.1.0'
