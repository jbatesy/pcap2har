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
Data models for HTTP/2 requests, responses, and transactions.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlparse, parse_qs, urlencode
import gzip
import json


@dataclass
class HTTP2Request:
    """Represents an HTTP/2 request."""
    
    method: str = ""
    path: str = ""
    authority: str = ""
    scheme: str = "https"
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    timestamp: float = 0.0
    
    @property
    def url(self) -> str:
        """Get the full URL."""
        if self.scheme and self.authority:
            return f"{self.scheme}://{self.authority}{self.path}"
        return self.path
    
    @property
    def host(self) -> str:
        """Get the host from authority."""
        if ':' in self.authority:
            return self.authority.split(':')[0]
        return self.authority
    
    @property
    def port(self) -> int:
        """Get the port from authority or default based on scheme."""
        if ':' in self.authority:
            try:
                return int(self.authority.split(':')[1])
            except ValueError:
                pass
        return 443 if self.scheme == 'https' else 80
    
    @property
    def query_string(self) -> str:
        """Get the query string portion of the path."""
        if '?' in self.path:
            return self.path.split('?', 1)[1]
        return ""
    
    @property
    def path_only(self) -> str:
        """Get the path without query string."""
        if '?' in self.path:
            return self.path.split('?', 1)[0]
        return self.path
    
    @property
    def query_params(self) -> Dict[str, List[str]]:
        """Parse query string into dict."""
        return parse_qs(self.query_string)
    
    @property
    def content_type(self) -> str:
        """Get the Content-Type header."""
        return self.headers.get('content-type', '')
    
    @property
    def content_length(self) -> int:
        """Get the Content-Length or body size."""
        if 'content-length' in self.headers:
            try:
                return int(self.headers['content-length'])
            except ValueError:
                pass
        return len(self.body)
    
    @property 
    def is_json(self) -> bool:
        """Check if the request body is JSON."""
        return 'json' in self.content_type.lower()
    
    @property
    def body_text(self) -> str:
        """Get the body as text."""
        try:
            return self.body.decode('utf-8')
        except UnicodeDecodeError:
            return self.body.decode('utf-8', errors='replace')
    
    def json(self) -> Any:
        """Parse the body as JSON."""
        if not self.body:
            return None
        return json.loads(self.body_text)
    
    def get_header(self, name: str, default: str = "") -> str:
        """Get a header by name (case-insensitive)."""
        return self.headers.get(name.lower(), default)
    
    def __repr__(self) -> str:
        return f"HTTP2Request({self.method} {self.url})"


@dataclass
class HTTP2Response:
    """Represents an HTTP/2 response."""
    
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    timestamp: float = 0.0
    
    @property
    def status_text(self) -> str:
        """Get human-readable status text."""
        status_texts = {
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
        return status_texts.get(self.status, "")
    
    @property
    def ok(self) -> bool:
        """Check if status is successful (2xx)."""
        return 200 <= self.status < 300
    
    @property
    def content_type(self) -> str:
        """Get the Content-Type header."""
        return self.headers.get('content-type', '')
    
    @property
    def content_encoding(self) -> str:
        """Get the Content-Encoding header."""
        return self.headers.get('content-encoding', '')
    
    @property
    def content_length(self) -> int:
        """Get the Content-Length or body size."""
        if 'content-length' in self.headers:
            try:
                return int(self.headers['content-length'])
            except ValueError:
                pass
        return len(self.body)
    
    @property
    def is_json(self) -> bool:
        """Check if the response body is JSON."""
        return 'json' in self.content_type.lower()
    
    @property
    def is_html(self) -> bool:
        """Check if the response body is HTML."""
        return 'html' in self.content_type.lower()
    
    @property
    def is_text(self) -> bool:
        """Check if the response is text-based."""
        ct = self.content_type.lower()
        return any(t in ct for t in ['text', 'json', 'xml', 'javascript', 'css'])
    
    @property
    def decompressed_body(self) -> bytes:
        """Get the body, decompressing if necessary."""
        return self._decompress(self.body, self.content_encoding)
    
    @property
    def body_text(self) -> str:
        """Get the body as text (decompressed)."""
        body = self.decompressed_body
        try:
            return body.decode('utf-8')
        except UnicodeDecodeError:
            return body.decode('utf-8', errors='replace')
    
    def json(self) -> Any:
        """Parse the body as JSON."""
        if not self.body:
            return None
        return json.loads(self.body_text)
    
    def get_header(self, name: str, default: str = "") -> str:
        """Get a header by name (case-insensitive)."""
        return self.headers.get(name.lower(), default)
    
    def _decompress(self, body: bytes, encoding: str) -> bytes:
        """Decompress body based on content-encoding."""
        if not body:
            return body
        
        if encoding == 'gzip':
            # Check if actually gzip (magic bytes 1f 8b)
            if body[:2] == b'\x1f\x8b':
                try:
                    return gzip.decompress(body)
                except Exception:
                    return body
            return body  # Already decompressed by tshark
        
        elif encoding == 'br':
            try:
                import brotli
                return brotli.decompress(body)
            except (ImportError, Exception):
                return body
        
        elif encoding == 'deflate':
            import zlib
            try:
                return zlib.decompress(body)
            except:
                try:
                    return zlib.decompress(body, -zlib.MAX_WBITS)
                except:
                    return body
        
        return body
    
    def __repr__(self) -> str:
        return f"HTTP2Response({self.status} {self.status_text})"


@dataclass
class HTTP2Transaction:
    """Represents a complete HTTP/2 request-response transaction."""
    
    tcp_stream: int
    http2_stream: int
    request: Optional[HTTP2Request] = None
    response: Optional[HTTP2Response] = None
    
    @property
    def url(self) -> str:
        """Get the request URL."""
        return self.request.url if self.request else ""
    
    @property
    def method(self) -> str:
        """Get the request method."""
        return self.request.method if self.request else ""
    
    @property
    def status(self) -> int:
        """Get the response status."""
        return self.response.status if self.response else 0
    
    @property
    def duration_ms(self) -> float:
        """Calculate transaction duration in milliseconds."""
        if self.request and self.response:
            return (self.response.timestamp - self.request.timestamp) * 1000
        return 0.0
    
    @property
    def complete(self) -> bool:
        """Check if transaction has both request and response."""
        return self.request is not None and self.response is not None
    
    def __repr__(self) -> str:
        req = f"{self.method} {self.url}" if self.request else "No request"
        resp = f"{self.status}" if self.response else "No response"
        return f"HTTP2Transaction(tcp={self.tcp_stream}, h2={self.http2_stream}, {req} -> {resp})"
