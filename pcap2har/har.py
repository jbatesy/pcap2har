"""
HAR (HTTP Archive) data models and builder.

Implements HAR 1.2 specification.
"""

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse


@dataclass
class HarCookie:
    """Represents a cookie in HAR format."""
    name: str
    value: str
    path: Optional[str] = None
    domain: Optional[str] = None
    expires: Optional[str] = None
    httpOnly: Optional[bool] = None
    secure: Optional[bool] = None
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"name": self.name, "value": self.value}
        if self.path is not None:
            result["path"] = self.path
        if self.domain is not None:
            result["domain"] = self.domain
        if self.expires is not None:
            result["expires"] = self.expires
        if self.httpOnly is not None:
            result["httpOnly"] = self.httpOnly
        if self.secure is not None:
            result["secure"] = self.secure
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarHeader:
    """Represents a header in HAR format."""
    name: str
    value: str
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"name": self.name, "value": self.value}
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarQueryString:
    """Represents a query parameter in HAR format."""
    name: str
    value: str
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"name": self.name, "value": self.value}
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarPostDataParam:
    """Represents a posted parameter in HAR format."""
    name: str
    value: Optional[str] = None
    fileName: Optional[str] = None
    contentType: Optional[str] = None
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"name": self.name}
        if self.value is not None:
            result["value"] = self.value
        if self.fileName is not None:
            result["fileName"] = self.fileName
        if self.contentType is not None:
            result["contentType"] = self.contentType
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarPostData:
    """Represents posted data in HAR format."""
    mimeType: str
    params: List[HarPostDataParam] = field(default_factory=list)
    text: Optional[str] = None
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"mimeType": self.mimeType}
        if self.params:
            result["params"] = [p.to_dict() for p in self.params]
        if self.text is not None:
            result["text"] = self.text
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarContent:
    """Represents response content in HAR format."""
    size: int
    mimeType: str
    compression: Optional[int] = None
    text: Optional[str] = None
    encoding: Optional[str] = None
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"size": self.size, "mimeType": self.mimeType}
        if self.compression is not None:
            result["compression"] = self.compression
        if self.text is not None:
            result["text"] = self.text
        if self.encoding is not None:
            result["encoding"] = self.encoding
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarRequest:
    """Represents an HTTP request in HAR format."""
    method: str
    url: str
    httpVersion: str
    cookies: List[HarCookie] = field(default_factory=list)
    headers: List[HarHeader] = field(default_factory=list)
    queryString: List[HarQueryString] = field(default_factory=list)
    postData: Optional[HarPostData] = None
    headersSize: int = -1
    bodySize: int = -1
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "method": self.method,
            "url": self.url,
            "httpVersion": self.httpVersion,
            "cookies": [c.to_dict() for c in self.cookies],
            "headers": [h.to_dict() for h in self.headers],
            "queryString": [q.to_dict() for q in self.queryString],
            "headersSize": self.headersSize,
            "bodySize": self.bodySize,
        }
        if self.postData is not None:
            result["postData"] = self.postData.to_dict()
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarResponse:
    """Represents an HTTP response in HAR format."""
    status: int
    statusText: str
    httpVersion: str
    cookies: List[HarCookie] = field(default_factory=list)
    headers: List[HarHeader] = field(default_factory=list)
    content: HarContent = field(default_factory=lambda: HarContent(size=0, mimeType=""))
    redirectURL: str = ""
    headersSize: int = -1
    bodySize: int = -1
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "status": self.status,
            "statusText": self.statusText,
            "httpVersion": self.httpVersion,
            "cookies": [c.to_dict() for c in self.cookies],
            "headers": [h.to_dict() for h in self.headers],
            "content": self.content.to_dict(),
            "redirectURL": self.redirectURL,
            "headersSize": self.headersSize,
            "bodySize": self.bodySize,
        }
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarCache:
    """Represents cache information in HAR format."""
    beforeRequest: Optional[Dict[str, Any]] = None
    afterRequest: Optional[Dict[str, Any]] = None
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if self.beforeRequest is not None:
            result["beforeRequest"] = self.beforeRequest
        if self.afterRequest is not None:
            result["afterRequest"] = self.afterRequest
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarTimings:
    """Represents timing information in HAR format."""
    send: float
    wait: float
    receive: float
    blocked: float = -1
    dns: float = -1
    connect: float = -1
    ssl: float = -1
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "blocked": self.blocked,
            "dns": self.dns,
            "connect": self.connect,
            "send": self.send,
            "wait": self.wait,
            "receive": self.receive,
            "ssl": self.ssl,
        }
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarEntry:
    """Represents an HTTP entry (request/response pair) in HAR format."""
    startedDateTime: str
    time: float
    request: HarRequest
    response: HarResponse
    cache: HarCache = field(default_factory=HarCache)
    timings: HarTimings = field(default_factory=lambda: HarTimings(send=0, wait=0, receive=0))
    pageref: Optional[str] = None
    serverIPAddress: Optional[str] = None
    connection: Optional[str] = None
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "startedDateTime": self.startedDateTime,
            "time": self.time,
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
            "cache": self.cache.to_dict(),
            "timings": self.timings.to_dict(),
        }
        if self.pageref is not None:
            result["pageref"] = self.pageref
        if self.serverIPAddress is not None:
            result["serverIPAddress"] = self.serverIPAddress
        if self.connection is not None:
            result["connection"] = self.connection
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarPageTimings:
    """Represents page timing information in HAR format."""
    onContentLoad: float = -1
    onLoad: float = -1
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "onContentLoad": self.onContentLoad,
            "onLoad": self.onLoad,
        }
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarPage:
    """Represents a page in HAR format."""
    startedDateTime: str
    id: str
    title: str
    pageTimings: HarPageTimings = field(default_factory=HarPageTimings)
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "startedDateTime": self.startedDateTime,
            "id": self.id,
            "title": self.title,
            "pageTimings": self.pageTimings.to_dict(),
        }
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarCreator:
    """Represents the creator application in HAR format."""
    name: str
    version: str
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"name": self.name, "version": self.version}
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarBrowser:
    """Represents the browser in HAR format."""
    name: str
    version: str
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"name": self.name, "version": self.version}
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass
class HarLog:
    """Represents the root HAR log object."""
    version: str = "1.2"
    creator: HarCreator = field(default_factory=lambda: HarCreator(name="pcap2har", version="0.1.0"))
    browser: Optional[HarBrowser] = None
    pages: List[HarPage] = field(default_factory=list)
    entries: List[HarEntry] = field(default_factory=list)
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "version": self.version,
            "creator": self.creator.to_dict(),
            # pages must always be present (even if empty) for Firefox DevTools compatibility
            "pages": [p.to_dict() for p in self.pages],
            "entries": [e.to_dict() for e in self.entries],
        }
        if self.browser is not None:
            result["browser"] = self.browser.to_dict()
        if self.comment is not None:
            result["comment"] = self.comment
        return result


class HarBuilder:
    """Builder for creating HAR documents from HTTP transactions."""

    def __init__(self, creator_name: str = "pcap2har", creator_version: str = "0.1.0"):
        self.log = HarLog(
            creator=HarCreator(name=creator_name, version=creator_version)
        )

    def add_entry(self, entry: HarEntry) -> None:
        """Add an entry to the HAR log."""
        self.log.entries.append(entry)

    def add_page(self, page: HarPage) -> None:
        """Add a page to the HAR log."""
        self.log.pages.append(page)

    def set_browser(self, name: str, version: str) -> None:
        """Set the browser information."""
        self.log.browser = HarBrowser(name=name, version=version)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a HAR dictionary."""
        return {"log": self.log.to_dict()}

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save(self, filepath: str, indent: int = 2) -> None:
        """Save HAR to a file."""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.to_json(indent=indent))


def parse_cookies_from_header(header_value: str) -> List[HarCookie]:
    """Parse cookies from a Cookie or Set-Cookie header."""
    cookies = []
    
    if not header_value:
        return cookies
    
    # Simple parsing for Cookie header (name=value pairs)
    for part in header_value.split(';'):
        part = part.strip()
        if '=' in part:
            name, value = part.split('=', 1)
            cookies.append(HarCookie(name=name.strip(), value=value.strip()))
    
    return cookies


def parse_set_cookie_header(header_value: str) -> Optional[HarCookie]:
    """Parse a Set-Cookie header into a HarCookie."""
    if not header_value:
        return None
    
    parts = header_value.split(';')
    if not parts:
        return None
    
    # First part is name=value
    first = parts[0].strip()
    if '=' not in first:
        return None
    
    name, value = first.split('=', 1)
    cookie = HarCookie(name=name.strip(), value=value.strip())
    
    # Parse attributes
    for part in parts[1:]:
        part = part.strip().lower()
        if part == 'httponly':
            cookie.httpOnly = True
        elif part == 'secure':
            cookie.secure = True
        elif part.startswith('path='):
            cookie.path = part[5:]
        elif part.startswith('domain='):
            cookie.domain = part[7:]
        elif part.startswith('expires='):
            cookie.expires = part[8:]
    
    return cookie


def parse_query_string(url: str) -> List[HarQueryString]:
    """Parse query string from URL."""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    
    result = []
    for name, values in query_params.items():
        for value in values:
            result.append(HarQueryString(name=name, value=value))
    
    return result


def timestamp_to_iso8601(timestamp: float) -> str:
    """Convert Unix timestamp to ISO 8601 format."""
    if timestamp <= 0:
        return datetime.now(timezone.utc).isoformat()
    dt = datetime.fromtimestamp(timestamp, timezone.utc)
    return dt.isoformat()


def is_text_content(mime_type: str) -> bool:
    """Check if content type is text-based."""
    if not mime_type:
        return False
    mime_lower = mime_type.lower()
    text_types = ['text/', 'application/json', 'application/xml', 
                  'application/javascript', 'application/x-javascript',
                  'application/xhtml', 'application/x-www-form-urlencoded']
    return any(t in mime_lower for t in text_types)


def encode_body_for_har(body: bytes, mime_type: str) -> tuple[Optional[str], Optional[str]]:
    """
    Encode body for HAR format.
    
    Returns:
        (text, encoding) - encoding is 'base64' if binary, None if text
    """
    if not body:
        return None, None
    
    if is_text_content(mime_type):
        try:
            return body.decode('utf-8'), None
        except UnicodeDecodeError:
            pass
    
    # Binary content - base64 encode
    return base64.b64encode(body).decode('ascii'), "base64"
