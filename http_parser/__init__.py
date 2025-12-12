"""
HTTP/1.x Parser Module

Parse HTTP/1.x streams from pcap files using tshark.

Example usage:
    from http_parser import HTTPCapture
    
    capture = HTTPCapture(pcap_path, keylog_path)
    transactions = capture.get_transactions()
    
    for tx in transactions:
        print(f"{tx.request.method} {tx.request.url}")
        print(f"Response: {tx.response.status}")
        if tx.response.is_json:
            print(tx.response.json())
"""

from .models import (
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
)
from .capture import HTTPCapture
from .parser import HTTPStreamParser

__all__ = [
    'HTTPCapture',
    'HTTPRequest',
    'HTTPResponse', 
    'HTTPTransaction',
    'HTTPStreamParser',
]

__version__ = '0.1.0'
