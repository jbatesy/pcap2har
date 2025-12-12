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
High-level interface for capturing and parsing HTTP/1.x traffic from pcap files.
"""

import subprocess
import json
import re
from typing import List, Iterator, Optional, Dict, Any
from .models import HTTPTransaction
from .parser import HTTPStreamParser


class HTTPCapture:
    """
    High-level interface for parsing HTTP/1.x traffic from pcap files.
    
    Example:
        capture = HTTPCapture('/path/to/file.pcap', keylog_file='/path/to/keylog.txt')
        
        # Iterate over all transactions
        for tx in capture:
            print(f"{tx.method} {tx.url} -> {tx.status}")
        
        # Filter transactions
        for tx in capture.filter(method='POST'):
            print(tx.request.body_text)
    """
    
    def __init__(
        self,
        pcap_file: str,
        keylog_file: Optional[str] = None,
        tshark_path: str = "tshark"
    ):
        """
        Initialize the HTTP capture.
        
        Args:
            pcap_file: Path to the pcap file
            keylog_file: Optional path to TLS keylog file for decryption
            tshark_path: Path to tshark executable
        """
        self.pcap_file = pcap_file
        self.keylog_file = keylog_file
        self.tshark_path = tshark_path
        
        self._streams: Optional[List[int]] = None
        self._transactions: Dict[int, HTTPTransaction] = {}
    
    def _get_tshark_base_cmd(self) -> List[str]:
        """Get base tshark command with common options."""
        cmd = [self.tshark_path, "-Q", "-2", "-r", self.pcap_file]
        
        if self.keylog_file:
            cmd.extend(["-o", f"tls.keylog_file:{self.keylog_file}"])
        
        return cmd
    
    def discover_streams(self, force: bool = False) -> List[int]:
        """
        Discover all TCP streams with HTTP traffic.
        
        Args:
            force: Force re-discovery even if already cached
            
        Returns:
            List of TCP stream numbers
        """
        if self._streams is not None and not force:
            return self._streams
        
        # Use tshark to find all TCP streams with HTTP traffic
        cmd = self._get_tshark_base_cmd() + [
            "-Y", "http",
            "-T", "fields",
            "-e", "tcp.stream"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise RuntimeError(f"tshark failed: {result.stderr}")
        
        # Parse unique stream numbers
        streams = set()
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line:
                try:
                    streams.add(int(line))
                except ValueError:
                    continue
        
        self._streams = sorted(streams)
        return self._streams
    
    def get_transaction(self, tcp_stream: int) -> HTTPTransaction:
        """
        Get or parse a transaction for a specific TCP stream.
        
        Args:
            tcp_stream: TCP stream number
            
        Returns:
            HTTPTransaction for the stream
        """
        if tcp_stream in self._transactions:
            return self._transactions[tcp_stream]
        
        # Get YAML data from tshark
        cmd = self._get_tshark_base_cmd() + [
            "-z", f"follow,http,yaml,{tcp_stream}"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise RuntimeError(f"tshark failed: {result.stderr}")
        
        # Parse the YAML output
        parser = HTTPStreamParser()
        transaction = parser.parse_yaml(result.stdout)
        transaction.tcp_stream = tcp_stream
        
        # Update host/scheme based on connection info if available
        self._enrich_transaction(transaction, tcp_stream)
        
        self._transactions[tcp_stream] = transaction
        return transaction
    
    def _enrich_transaction(self, transaction: HTTPTransaction, tcp_stream: int):
        """Enrich transaction with additional connection info."""
        # Get connection details
        cmd = self._get_tshark_base_cmd() + [
            "-Y", f"tcp.stream == {tcp_stream} and http",
            "-T", "fields",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-c", "1"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split('\t')
            if len(parts) >= 2 and transaction.request:
                # If host wasn't set from headers, use IP
                if not transaction.request.host:
                    transaction.request.host = parts[0]
                try:
                    port = int(parts[1])
                    if transaction.request.port in (0, 80, 443):
                        transaction.request.port = port
                    transaction.request.scheme = "https" if port in (443, 8443) else "http"
                except ValueError:
                    pass
    
    def __iter__(self) -> Iterator[HTTPTransaction]:
        """Iterate over all HTTP transactions in the capture."""
        streams = self.discover_streams()
        for tcp_stream in streams:
            yield self.get_transaction(tcp_stream)
    
    def __len__(self) -> int:
        """Get the number of HTTP streams."""
        return len(self.discover_streams())
    
    def filter(
        self,
        method: Optional[str] = None,
        status: Optional[int] = None,
        status_range: Optional[tuple] = None,
        host: Optional[str] = None,
        path_contains: Optional[str] = None,
        content_type: Optional[str] = None
    ) -> Iterator[HTTPTransaction]:
        """
        Filter transactions by various criteria.
        
        Args:
            method: Filter by HTTP method (GET, POST, etc.)
            status: Filter by exact status code
            status_range: Filter by status range, e.g., (200, 299)
            host: Filter by host (substring match)
            path_contains: Filter by path containing string
            content_type: Filter by response content type (substring match)
            
        Yields:
            HTTPTransaction objects matching the criteria
        """
        for tx in self:
            if method and tx.request and tx.request.method != method.upper():
                continue
            
            if status and tx.response and tx.response.status != status:
                continue
            
            if status_range and tx.response:
                if not (status_range[0] <= tx.response.status <= status_range[1]):
                    continue
            
            if host and tx.request:
                if host.lower() not in tx.request.host.lower():
                    continue
            
            if path_contains and tx.request:
                if path_contains not in tx.request.path:
                    continue
            
            if content_type and tx.response:
                if content_type.lower() not in tx.response.content_type.lower():
                    continue
            
            yield tx
    
    def get_by_url(self, url_pattern: str) -> List[HTTPTransaction]:
        """
        Find transactions matching a URL pattern.
        
        Args:
            url_pattern: Regex pattern to match against URLs
            
        Returns:
            List of matching transactions
        """
        pattern = re.compile(url_pattern)
        matches = []
        
        for tx in self:
            if tx.request and pattern.search(tx.url):
                matches.append(tx)
        
        return matches
    
    def summary(self) -> str:
        """Get a summary of all HTTP transactions."""
        lines = []
        lines.append(f"HTTP Capture: {self.pcap_file}")
        lines.append(f"Streams: {len(self)}")
        lines.append("")
        
        for tx in self:
            status = f"[{tx.status}]" if tx.response else "[No Response]"
            method = tx.method if tx.request else "???"
            url = tx.url if tx.request else "(no request)"
            
            # Truncate long URLs
            if len(url) > 80:
                url = url[:77] + "..."
            
            lines.append(f"  tcp.stream={tx.tcp_stream}: {method} {url} {status}")
        
        return '\n'.join(lines)
    
    def dump_stream(self, tcp_stream: int) -> str:
        """
        Get raw packet dump for a stream (for debugging).
        
        Args:
            tcp_stream: TCP stream number
            
        Returns:
            Formatted string showing raw packets
        """
        cmd = self._get_tshark_base_cmd() + [
            "-z", f"follow,http,yaml,{tcp_stream}"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise RuntimeError(f"tshark failed: {result.stderr}")
        
        parser = HTTPStreamParser()
        return parser.dump_packets(result.stdout)

