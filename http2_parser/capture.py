"""
HTTP/2 Capture - high-level interface for extracting HTTP/2 transactions from pcap files.
"""

import subprocess
import sys
from typing import Dict, List, Optional, Tuple, Set, Iterator, Any
import yaml

from .models import HTTP2Transaction
from .parser import HTTP2StreamParser


class HTTP2Capture:
    """
    Extract HTTP/2 transactions from a pcap file.
    
    Example:
        capture = HTTP2Capture('traffic.pcap', 'keylog.txt')
        
        # Get all transactions
        for tx in capture:
            print(f"{tx.method} {tx.url} -> {tx.status}")
        
        # Filter by host
        for tx in capture.filter(host='api.example.com'):
            print(tx.response.json())
        
        # Get specific stream
        tx = capture.get_stream(tcp_stream=15, http2_stream=1)
    """
    
    def __init__(
        self,
        pcap_path: str,
        keylog_path: Optional[str] = None,
        tshark_path: str = "tshark",
        lazy: bool = True,
    ):
        """
        Initialize HTTP/2 capture.
        
        Args:
            pcap_path: Path to the pcap file
            keylog_path: Path to the TLS keylog file for decryption (optional for plaintext/http2c)
            tshark_path: Path to tshark executable
            lazy: If True, only load streams when accessed. If False, load all immediately.
        """
        self.pcap_path = pcap_path
        self.keylog_path = keylog_path
        self.tshark_path = tshark_path
        self._streams: Optional[List[Tuple[int, int]]] = None
        self._transactions: Dict[Tuple[int, int], HTTP2Transaction] = {}
        self._loaded_all = False
        
        if not lazy:
            self.load_all()
    
    @property
    def streams(self) -> List[Tuple[int, int]]:
        """Get list of (tcp_stream, http2_stream) tuples."""
        if self._streams is None:
            self._streams = self._discover_streams()
        return self._streams
    
    def _discover_streams(self) -> List[Tuple[int, int]]:
        """Discover all HTTP/2 streams in the pcap."""
        cmd = [
            self.tshark_path,
            "-2",
            "-r", self.pcap_path,
            "-o", "tls.desegment_ssl_records:TRUE",
            "-o", "tls.desegment_ssl_application_data:TRUE",
            "-Y", "http2.streamid",
            "-T", "fields",
            "-e", "tcp.stream",
            "-e", "http2.streamid",
        ]

        if self.keylog_path:
            cmd.extend(["-o", f"tls.keylog_file:{self.keylog_path}"])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"tshark error: {e.stderr}")
        except FileNotFoundError:
            raise RuntimeError("tshark not found. Please install Wireshark/tshark.")
        
        streams: Set[Tuple[int, int]] = set()
        
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) >= 2:
                try:
                    tcp_stream = int(parts[0])
                    for h2_id in parts[1].split(','):
                        h2_id = h2_id.strip()
                        if h2_id:
                            http2_stream = int(h2_id)
                            streams.add((tcp_stream, http2_stream))
                except ValueError:
                    continue
        
        return sorted(streams, key=lambda x: (x[0], x[1]))
    
    def _follow_stream(self, tcp_stream: int, http2_stream: int) -> str:
        """Get YAML output for a specific stream."""
        cmd = [
            self.tshark_path,
            "-Q",
            "-2",
            "-r", self.pcap_path,
            "-o", "tls.desegment_ssl_records:TRUE",
            "-o", "tls.desegment_ssl_application_data:TRUE",
            "-z", f"follow,http2,yaml,{tcp_stream},{http2_stream}",
        ]

        if self.keylog_path:
            cmd.extend(["-o", f"tls.keylog_file:{self.keylog_path}"])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error following stream {tcp_stream}/{http2_stream}: {e.stderr}", file=sys.stderr)
            return ""
    
    def _load_transaction(self, tcp_stream: int, http2_stream: int) -> Optional[HTTP2Transaction]:
        """Load a single transaction."""
        key = (tcp_stream, http2_stream)
        
        if key in self._transactions:
            return self._transactions[key]
        
        yaml_output = self._follow_stream(tcp_stream, http2_stream)
        if not yaml_output.strip():
            return None
        
        try:
            data = yaml.safe_load(yaml_output)
        except yaml.YAMLError:
            return None
        
        if not data or 'packets' not in data:
            return None
        
        parser = HTTP2StreamParser(yaml_data=data)
        transaction = parser.parse(tcp_stream=tcp_stream, http2_stream=http2_stream)
        
        self._transactions[key] = transaction
        return transaction
    
    def load_all(self) -> List[HTTP2Transaction]:
        """Load all transactions from the pcap."""
        if self._loaded_all:
            return list(self._transactions.values())
        
        for tcp_stream, http2_stream in self.streams:
            self._load_transaction(tcp_stream, http2_stream)
        
        self._loaded_all = True
        return list(self._transactions.values())
    
    def get_stream(self, tcp_stream: int, http2_stream: int) -> Optional[HTTP2Transaction]:
        """Get a specific stream by TCP and HTTP/2 stream IDs."""
        return self._load_transaction(tcp_stream, http2_stream)
    
    def get_transactions(self) -> List[HTTP2Transaction]:
        """Get all transactions (loads all if not already loaded)."""
        return self.load_all()
    
    def __iter__(self) -> Iterator[HTTP2Transaction]:
        """Iterate over all transactions."""
        for tcp_stream, http2_stream in self.streams:
            tx = self._load_transaction(tcp_stream, http2_stream)
            if tx:
                yield tx
    
    def __len__(self) -> int:
        """Get number of streams."""
        return len(self.streams)
    
    def __getitem__(self, index: int) -> Optional[HTTP2Transaction]:
        """Get transaction by index."""
        if index < 0 or index >= len(self.streams):
            raise IndexError(f"Index {index} out of range")
        tcp_stream, http2_stream = self.streams[index]
        return self._load_transaction(tcp_stream, http2_stream)
    
    def filter(self, 
               host: Optional[str] = None,
               method: Optional[str] = None,
               path_contains: Optional[str] = None,
               status: Optional[int] = None,
               content_type: Optional[str] = None,
               min_body_size: Optional[int] = None) -> Iterator[HTTP2Transaction]:
        """
        Filter transactions by various criteria.
        
        Args:
            host: Filter by host/authority (exact match)
            method: Filter by HTTP method (GET, POST, etc.)
            path_contains: Filter by path substring
            status: Filter by response status code
            content_type: Filter by response content-type substring
            min_body_size: Filter by minimum response body size
            
        Yields:
            Matching HTTP2Transaction objects
        """
        for tx in self:
            if not tx.complete:
                continue
            
            if host and tx.request and tx.request.authority != host:
                continue
            
            if method and tx.request and tx.request.method != method.upper():
                continue
            
            if path_contains and tx.request and path_contains not in tx.request.path:
                continue
            
            if status is not None and tx.response and tx.response.status != status:
                continue
            
            if content_type and tx.response and content_type not in tx.response.content_type:
                continue
            
            if min_body_size is not None and tx.response and len(tx.response.body) < min_body_size:
                continue
            
            yield tx
    
    def filter_json(self) -> Iterator[HTTP2Transaction]:
        """Get only transactions with JSON responses."""
        return self.filter(content_type='json')
    
    def filter_by_host(self, host: str) -> Iterator[HTTP2Transaction]:
        """Get transactions for a specific host."""
        return self.filter(host=host)
    
    def get_hosts(self) -> Set[str]:
        """Get all unique hosts in the capture."""
        hosts = set()
        for tx in self:
            if tx.request and tx.request.authority:
                hosts.add(tx.request.authority)
        return hosts
    
    def summary(self) -> Dict[str, Any]:
        """Get a summary of the capture."""
        total = len(self.streams)
        hosts = self.get_hosts()
        
        methods: Dict[str, int] = {}
        statuses: Dict[int, int] = {}
        content_types: Dict[str, int] = {}
        
        for tx in self:
            if tx.request:
                methods[tx.request.method] = methods.get(tx.request.method, 0) + 1
            if tx.response:
                statuses[tx.response.status] = statuses.get(tx.response.status, 0) + 1
                ct = tx.response.content_type.split(';')[0].strip()
                if ct:
                    content_types[ct] = content_types.get(ct, 0) + 1
        
        return {
            'total_streams': total,
            'hosts': sorted(hosts),
            'methods': methods,
            'status_codes': statuses,
            'content_types': content_types
        }
