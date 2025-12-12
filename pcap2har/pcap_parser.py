# Copyright 2023 Jesse Bate
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
PCAP file parser using tshark.

This module provides functionality to extract HTTP/1.x and HTTP/2 streams
from PCAP files using tshark (Wireshark command-line tool).
"""

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StreamInfo:
    """Information about an HTTP stream in a PCAP file."""
    tcp_stream: int
    http_version: str  # "1" or "2"
    http2_stream: Optional[int] = None  # Only for HTTP/2
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    first_frame: int = 0
    

@dataclass
class PcapParserResult:
    """Result from parsing a PCAP file."""
    http1_streams: List[StreamInfo] = field(default_factory=list)
    http2_streams: List[StreamInfo] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class TsharkNotFoundError(Exception):
    """Raised when tshark is not found on the system."""
    pass


class PcapParser:
    """
    Parser for PCAP files using tshark.
    
    Extracts HTTP/1.x and HTTP/2 streams from packet captures.
    """
    
    def __init__(self, tshark_path: str = "tshark", keylog_file: Optional[str] = None):
        """
        Initialize the PCAP parser.
        
        Args:
            tshark_path: Path to tshark executable
            keylog_file: Path to TLS key log file for decryption
        """
        self.tshark_path = tshark_path
        self.keylog_file = keylog_file
        self._verify_tshark()
    
    def _verify_tshark(self) -> None:
        """Verify that tshark is available."""
        try:
            result = subprocess.run(
                [self.tshark_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise TsharkNotFoundError(f"tshark returned error: {result.stderr}")
        except FileNotFoundError:
            raise TsharkNotFoundError(
                f"tshark not found at '{self.tshark_path}'. "
                "Please install Wireshark/tshark or specify the correct path."
            )
        except subprocess.TimeoutExpired:
            raise TsharkNotFoundError("tshark timed out during version check")
    
    