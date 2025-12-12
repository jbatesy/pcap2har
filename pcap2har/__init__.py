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
