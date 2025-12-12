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
Parser for HTTP/1.x traffic from tshark YAML output.
"""

import yaml
import base64
import re
from typing import Optional, Tuple
from .models import HTTPRequest, HTTPResponse, HTTPTransaction


class HTTPStreamParser:
    """Parses HTTP/1.x data from tshark 'follow,http,yaml' output."""
    
    def __init__(self):
        self.request: Optional[HTTPRequest] = None
        self.response: Optional[HTTPResponse] = None
        
        # Track peers: peer 0 is typically client, peer 1 is server
        self.client_peer: int = 0
        self.server_peer: int = 1
        self.server_host: str = ""
        self.server_port: int = 443
        self.scheme: str = "https"
        
    def parse_yaml_file(self, filepath: str) -> HTTPTransaction:
        """Parse a tshark YAML file containing HTTP/1.x data."""
        with open(filepath, 'r') as f:
            return self.parse_yaml(f.read())
    
    def parse_yaml(self, yaml_content: str) -> HTTPTransaction:
        """Parse tshark YAML content and extract HTTP transaction."""
        # Parse YAML data
        data = yaml.safe_load(yaml_content)
        
        if not data:
            return HTTPTransaction(tcp_stream=0)
        
        # Handle both old format (list of packets) and new format (peers + packets)
        if isinstance(data, dict):
            # New format with peers and packets sections
            peers = data.get('peers', [])
            packets = data.get('packets', [])
            self._parse_peers_from_dict(peers)
        elif isinstance(data, list):
            # Old format: just a list of packets, parse peer info from comments
            packets = data
            self._parse_peers(yaml_content)
        else:
            return HTTPTransaction(tcp_stream=0)
        
        # Accumulate data per peer
        client_data = b""
        server_data = b""
        
        for packet in packets:
            peer = packet.get('peer', 0)
            raw_data = packet.get('data', b'')
            timestamp = packet.get('timestamp', 0.0)
            
            if isinstance(raw_data, str):
                # Already decoded by YAML
                raw_data = raw_data.encode('latin-1')
            
            if peer == self.client_peer:
                client_data += raw_data
                if self.request is None or self.request.timestamp == 0:
                    if self.request is None:
                        self.request = HTTPRequest()
                    self.request.timestamp = timestamp
            else:
                server_data += raw_data
                if self.response is None or self.response.timestamp == 0:
                    if self.response is None:
                        self.response = HTTPResponse()
                    self.response.timestamp = timestamp
        
        # Parse the accumulated data
        if client_data:
            self._parse_request(client_data)
        
        if server_data:
            self._parse_response(server_data)
        
        # Create transaction
        transaction = HTTPTransaction(
            tcp_stream=0,
            request=self.request,
            response=self.response
        )
        
        return transaction
    
    def _parse_peers_from_dict(self, peers: list):
        """Extract peer information from peers list in YAML."""
        for peer_info in peers:
            peer_num = peer_info.get('peer', 0)
            host = peer_info.get('host', '')
            port = peer_info.get('port', 0)
            
            # Heuristic: server usually has port 80 or 443
            if port in (80, 443, 8080, 8443):
                self.server_peer = peer_num
                self.client_peer = 1 - peer_num
                self.server_host = host
                self.server_port = port
                self.scheme = "https" if port in (443, 8443) else "http"
    
    def _parse_peers(self, yaml_content: str):
        """Extract peer information from YAML comments."""
        # Example: # Peer 0: 192.168.1.144:60634
        #          # Peer 1: 142.250.124.95:443
        peer_pattern = re.compile(r'# Peer (\d+): ([\d.]+):(\d+)')
        
        for match in peer_pattern.finditer(yaml_content):
            peer_num = int(match.group(1))
            ip = match.group(2)
            port = int(match.group(3))
            
            # Heuristic: server usually has port 80 or 443
            if port in (80, 443, 8080, 8443):
                self.server_peer = peer_num
                self.client_peer = 1 - peer_num
                self.server_host = ip
                self.server_port = port
                self.scheme = "https" if port in (443, 8443) else "http"
    
    def _parse_request(self, data: bytes):
        """Parse HTTP/1.x request from raw data."""
        if self.request is None:
            self.request = HTTPRequest()
        
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            text = data.decode('latin-1')
        
        # Split headers and body
        if '\r\n\r\n' in text:
            headers_section, body = text.split('\r\n\r\n', 1)
        elif '\n\n' in text:
            headers_section, body = text.split('\n\n', 1)
        else:
            headers_section = text
            body = ""
        
        lines = headers_section.split('\r\n') if '\r\n' in headers_section else headers_section.split('\n')
        
        if not lines:
            return
        
        # Parse request line: GET /path HTTP/1.1
        request_line = lines[0]
        parts = request_line.split(' ', 2)
        
        if len(parts) >= 2:
            self.request.method = parts[0]
            self.request.path = parts[1]
            if len(parts) >= 3:
                self.request.version = parts[2]
        
        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                name, value = line.split(':', 1)
                name = name.strip().lower()
                value = value.strip()
                headers[name] = value
        
        self.request.headers = headers
        
        # Extract host and scheme from headers
        host_header = headers.get('host', '')
        if host_header:
            if ':' in host_header:
                self.request.host, port_str = host_header.rsplit(':', 1)
                try:
                    self.request.port = int(port_str)
                except ValueError:
                    self.request.host = host_header
                    self.request.port = self.server_port
            else:
                self.request.host = host_header
                self.request.port = self.server_port
        else:
            self.request.host = self.server_host
            self.request.port = self.server_port
        
        self.request.scheme = self.scheme
        
        # Set body
        self.request.body = body.encode('utf-8') if body else b""
    
    def _parse_response(self, data: bytes):
        """Parse HTTP/1.x response from raw data."""
        if self.response is None:
            self.response = HTTPResponse()
        
        try:
            # Try to decode as text for headers
            # But keep binary for body
            text = data.decode('utf-8', errors='replace')
        except Exception:
            text = data.decode('latin-1')
        
        # Split headers and body
        if '\r\n\r\n' in text:
            headers_section, body_text = text.split('\r\n\r\n', 1)
            body_offset = data.find(b'\r\n\r\n') + 4
        elif '\n\n' in text:
            headers_section, body_text = text.split('\n\n', 1)
            body_offset = data.find(b'\n\n') + 2
        else:
            headers_section = text
            body_text = ""
            body_offset = len(data)
        
        lines = headers_section.split('\r\n') if '\r\n' in headers_section else headers_section.split('\n')
        
        if not lines:
            return
        
        # Parse status line: HTTP/1.1 200 OK
        status_line = lines[0]
        parts = status_line.split(' ', 2)
        
        if len(parts) >= 2:
            self.response.version = parts[0]
            try:
                self.response.status = int(parts[1])
            except ValueError:
                self.response.status = 0
            if len(parts) >= 3:
                self.response.status_text = parts[2]
            else:
                self.response.status_text = self._get_status_text(self.response.status)
        
        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                name, value = line.split(':', 1)
                name = name.strip().lower()
                value = value.strip()
                headers[name] = value
        
        self.response.headers = headers
        
        # Get body as raw bytes to preserve binary data
        if body_offset < len(data):
            self.response.body = data[body_offset:]
        else:
            self.response.body = body_text.encode('utf-8') if body_text else b""
    
    def _get_status_text(self, status: int) -> str:
        """Get default status text for common codes."""
        status_texts = {
            100: "Continue",
            101: "Switching Protocols",
            200: "OK",
            201: "Created",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }
        return status_texts.get(status, "")
    
    def dump_packets(self, yaml_content: str) -> str:
        """Output raw packet data for debugging."""
        output = []
        
        data = yaml.safe_load(yaml_content)
        
        if not data:
            return "No data found in YAML"
        
        # Handle both formats
        if isinstance(data, dict):
            peers = data.get('peers', [])
            packets = data.get('packets', [])
            self._parse_peers_from_dict(peers)
        elif isinstance(data, list):
            packets = data
            self._parse_peers(yaml_content)
        else:
            return "Invalid YAML format"
        
        output.append(f"Server peer: {self.server_peer} ({self.server_host}:{self.server_port})")
        output.append(f"Client peer: {self.client_peer}")
        output.append("")
        
        for i, packet in enumerate(packets):
            peer = packet.get('peer', 0)
            raw_data = packet.get('data', b'')
            timestamp = packet.get('timestamp', 0.0)
            index = packet.get('packet', packet.get('index', i))
            
            if isinstance(raw_data, str):
                raw_data = raw_data.encode('latin-1')
            
            direction = "CLIENT -> SERVER" if peer == self.client_peer else "SERVER -> CLIENT"
            output.append(f"=== Packet {index} ({direction}) @ {timestamp:.6f} ===")
            output.append(f"Size: {len(raw_data)} bytes")
            output.append("")
            
            # Show printable content
            try:
                text = raw_data.decode('utf-8', errors='replace')
                # Limit output
                if len(text) > 2000:
                    output.append(text[:2000])
                    output.append(f"... ({len(text) - 2000} more bytes)")
                else:
                    output.append(text)
            except Exception:
                output.append(f"<binary data: {len(raw_data)} bytes>")
            
            output.append("")
        
        return '\n'.join(output)
