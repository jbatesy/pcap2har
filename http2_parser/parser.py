"""
Parser for HTTP/2 stream data from tshark YAML output.
"""

import base64
from typing import Dict, List, Any, Optional, Tuple
import yaml

from .models import HTTP2Request, HTTP2Response, HTTP2Transaction


class HTTP2StreamParser:
    """
    Parse HTTP/2 streams from tshark YAML output.
    
    tshark's "follow,http2,yaml" feature outputs:
    - Headers as decoded text (HPACK already decoded)
    - Body data as raw bytes
    """
    
    def __init__(self, yaml_data: Optional[Dict[str, Any]] = None, yaml_string: Optional[str] = None):
        """
        Initialize parser with YAML data.
        
        Args:
            yaml_data: Already-parsed YAML dictionary
            yaml_string: Raw YAML string from tshark
        """
        if yaml_data:
            self.data = yaml_data
        elif yaml_string:
            self.data = yaml.safe_load(yaml_string) or {}
        else:
            self.data = {}
        
        self.peers: List[Dict[str, Any]] = self.data.get('peers', [])
        self.packets: List[Dict[str, Any]] = self.data.get('packets', [])
    
    @classmethod
    def from_file(cls, yaml_path: str) -> 'HTTP2StreamParser':
        """Create parser from a YAML file."""
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        return cls(yaml_data=data)
    
    @classmethod
    def from_string(cls, yaml_string: str) -> 'HTTP2StreamParser':
        """Create parser from a YAML string."""
        return cls(yaml_string=yaml_string)
    
    def parse(self, tcp_stream: int = 0, http2_stream: int = 0) -> HTTP2Transaction:
        """
        Parse the stream data into an HTTP2Transaction.
        
        Args:
            tcp_stream: TCP stream number (for metadata)
            http2_stream: HTTP/2 stream ID (for metadata)
            
        Returns:
            HTTP2Transaction with request and response
        """
        # Determine client vs server based on port
        server_peer = None
        client_peer = None
        
        for i, peer in enumerate(self.peers):
            if peer.get('port') == 443:
                server_peer = i
            else:
                client_peer = i
        
        if server_peer is None:
            server_peer = 0
        if client_peer is None:
            client_peer = 1
        
        # Parse all packets into messages
        messages = self._parse_packets(client_peer)
        
        # Assemble into transaction
        return self._assemble_transaction(messages, tcp_stream, http2_stream)
    
    def _parse_packets(self, client_peer: int) -> List[Dict[str, Any]]:
        """Parse all packets into message dicts."""
        messages = []
        
        for packet in self.packets:
            packet_num = packet.get('packet', 0)
            peer = packet.get('peer', 0)
            timestamp = packet.get('timestamp', 0.0)
            data = packet.get('data', b'')
            
            # PyYAML decodes !!binary automatically
            if isinstance(data, str):
                data = base64.b64decode(data)
            
            if not data:
                continue
            
            is_request = (peer == client_peer)
            msg = self._parse_packet_data(data, is_request, packet_num, timestamp)
            if msg:
                messages.append(msg)
        
        return messages
    
    def _parse_packet_data(self, data: bytes, is_request: bool, 
                           packet_num: int, timestamp: float) -> Optional[Dict[str, Any]]:
        """Parse a single packet's data."""
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            text = None
        
        if text and self._looks_like_headers(text):
            return self._parse_headers(text, is_request, timestamp)
        else:
            return {
                'type': 'body',
                'is_request': is_request,
                'data': data,
                'timestamp': timestamp
            }
    
    def _looks_like_headers(self, text: str) -> bool:
        """Check if text looks like HTTP/2 headers."""
        lines = text.strip().split('\n')
        if not lines:
            return False
        
        first_line = lines[0].strip()
        if first_line.startswith(':status:') or first_line.startswith(':method:'):
            return True
        
        header_like_count = 0
        for line in lines[:10]:
            line = line.strip()
            if ':' in line and not line.startswith('{') and not line.startswith('['):
                parts = line.split(':', 1)
                if len(parts) == 2 and parts[0] and parts[1]:
                    header_like_count += 1
        
        return header_like_count >= 3
    
    def _parse_headers(self, text: str, is_request: bool, timestamp: float) -> Dict[str, Any]:
        """Parse HTTP headers from text."""
        result = {
            'type': 'headers',
            'is_request': is_request,
            'timestamp': timestamp,
            'headers': {},
            'pseudo_headers': {}
        }
        
        for line in text.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Find separator
            sep_idx = line.find(': ')
            if sep_idx == -1:
                sep_idx = line.find(':')
                if sep_idx == -1:
                    continue
                if line.startswith(':'):
                    second_colon = line.find(':', 1)
                    if second_colon != -1:
                        sep_idx = second_colon
            
            name = line[:sep_idx].strip()
            value = line[sep_idx + 1:].strip()
            if value.startswith(' '):
                value = value[1:]
            
            # Pseudo-headers start with :
            if name.startswith(':'):
                result['pseudo_headers'][name] = value
            else:
                result['headers'][name.lower()] = value
        
        return result
    
    def _assemble_transaction(self, messages: List[Dict[str, Any]], 
                              tcp_stream: int, http2_stream: int) -> HTTP2Transaction:
        """Assemble parsed messages into a transaction."""
        request: Optional[HTTP2Request] = None
        response: Optional[HTTP2Response] = None
        request_body = b""
        response_body = b""
        
        for msg in messages:
            if msg['is_request']:
                if msg['type'] == 'headers':
                    pseudo = msg['pseudo_headers']
                    request = HTTP2Request(
                        method=pseudo.get(':method', ''),
                        path=pseudo.get(':path', ''),
                        authority=pseudo.get(':authority', ''),
                        scheme=pseudo.get(':scheme', 'https'),
                        headers=msg['headers'],
                        timestamp=msg['timestamp']
                    )
                elif msg['type'] == 'body':
                    request_body += msg['data']
            else:
                if msg['type'] == 'headers':
                    pseudo = msg['pseudo_headers']
                    status_str = pseudo.get(':status', '0')
                    try:
                        status = int(status_str)
                    except ValueError:
                        status = 0
                    response = HTTP2Response(
                        status=status,
                        headers=msg['headers'],
                        timestamp=msg['timestamp']
                    )
                elif msg['type'] == 'body':
                    response_body += msg['data']
        
        # Attach bodies
        if request:
            request.body = request_body
        if response:
            response.body = response_body
        
        return HTTP2Transaction(
            tcp_stream=tcp_stream,
            http2_stream=http2_stream,
            request=request,
            response=response
        )
