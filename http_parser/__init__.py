# Copyright 2025 Jesse Bate (https://github.com/jbatesy)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
