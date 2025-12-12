"""
Converter from HTTP transactions to HAR format.

This module converts HTTP/1.x and HTTP/2 transactions (parsed from PCAP files)
into the HAR 1.2 format.
"""

import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlencode

# Add parent directory for imports
sys.path.insert(0, '..')

from http_parser.models import HTTPRequest, HTTPResponse, HTTPTransaction
from http2_parser.models import HTTP2Request, HTTP2Response, HTTP2Transaction

from .har import (
    HarBuilder,
    HarCache,
    HarContent,
    HarCookie,
    HarEntry,
    HarHeader,
    HarPostData,
    HarPostDataParam,
    HarQueryString,
    HarRequest,
    HarResponse,
    HarTimings,
    encode_body_for_har,
    parse_cookies_from_header,
    parse_query_string,
    parse_set_cookie_header,
    timestamp_to_iso8601,
)
from .pcap_parser import PcapParser


class TransactionConverter:
    """Converts HTTP transactions to HAR entries."""
    
    def convert_http1(
        self,
        transaction: HTTPTransaction,
        server_ip: Optional[str] = None,
        connection_id: Optional[str] = None,
    ) -> Optional[HarEntry]:
        """
        Convert an HTTP/1.x transaction to a HAR entry.
        
        Args:
            transaction: The HTTP/1.x transaction
            server_ip: Optional server IP address
            connection_id: Optional connection identifier
            
        Returns:
            HarEntry or None if transaction is incomplete
        """
        if not transaction.request:
            return None
        
        req = transaction.request
        resp = transaction.response
        
        # Build request
        har_request = self._build_http1_request(req)
        
        # Build response
        har_response = self._build_http1_response(resp) if resp else self._empty_response()
        
        # Calculate timing
        if req.timestamp and resp and resp.timestamp:
            total_time = (resp.timestamp - req.timestamp) * 1000  # ms
        else:
            total_time = 0
        
        har_timings = HarTimings(
            send=0,
            wait=total_time if total_time > 0 else 0,
            receive=0,
        )
        
        entry = HarEntry(
            startedDateTime=timestamp_to_iso8601(req.timestamp),
            time=total_time,
            request=har_request,
            response=har_response,
            cache=HarCache(),
            timings=har_timings,
            serverIPAddress=server_ip,
            connection=connection_id or str(transaction.tcp_stream),
        )
        
        return entry
    
    def convert_http2(
        self,
        transaction: HTTP2Transaction,
        server_ip: Optional[str] = None,
        connection_id: Optional[str] = None,
    ) -> Optional[HarEntry]:
        """
        Convert an HTTP/2 transaction to a HAR entry.
        
        Args:
            transaction: The HTTP/2 transaction
            server_ip: Optional server IP address
            connection_id: Optional connection identifier
            
        Returns:
            HarEntry or None if transaction is incomplete
        """
        if not transaction.request:
            return None
        
        req = transaction.request
        resp = transaction.response
        
        # Build request
        har_request = self._build_http2_request(req)
        
        # Build response
        har_response = self._build_http2_response(resp) if resp else self._empty_response()
        
        # Calculate timing
        if req.timestamp and resp and resp.timestamp:
            total_time = (resp.timestamp - req.timestamp) * 1000  # ms
        else:
            total_time = 0
        
        har_timings = HarTimings(
            send=0,
            wait=total_time if total_time > 0 else 0,
            receive=0,
        )
        
        conn_str = connection_id or f"{transaction.tcp_stream}:{transaction.http2_stream}"
        
        entry = HarEntry(
            startedDateTime=timestamp_to_iso8601(req.timestamp),
            time=total_time,
            request=har_request,
            response=har_response,
            cache=HarCache(),
            timings=har_timings,
            serverIPAddress=server_ip,
            connection=conn_str,
        )
        
        return entry
    
    def _build_http1_request(self, req: HTTPRequest) -> HarRequest:
        """Build HAR request from HTTP/1.x request."""
        # Headers
        headers = [HarHeader(name=k, value=v) for k, v in req.headers.items()]
        
        # Cookies
        cookies = []
        cookie_header = req.headers.get('cookie', '')
        if cookie_header:
            cookies = parse_cookies_from_header(cookie_header)
        
        # Query string
        query_string = parse_query_string(req.url)
        
        # Post data
        post_data = None
        if req.body:
            post_data = self._build_post_data(req.body, req.content_type)
        
        # Calculate sizes
        headers_text = self._format_http1_request_headers(req)
        headers_size = len(headers_text.encode('utf-8'))
        body_size = len(req.body) if req.body else 0
        
        return HarRequest(
            method=req.method,
            url=req.url,
            httpVersion=req.version,
            cookies=cookies,
            headers=headers,
            queryString=query_string,
            postData=post_data,
            headersSize=headers_size,
            bodySize=body_size,
        )
    
    def _build_http2_request(self, req: HTTP2Request) -> HarRequest:
        """Build HAR request from HTTP/2 request."""
        # Headers (HTTP/2 uses lowercase)
        headers = [HarHeader(name=k, value=v) for k, v in req.headers.items()]
        
        # Cookies
        cookies = []
        cookie_header = req.headers.get('cookie', '')
        if cookie_header:
            cookies = parse_cookies_from_header(cookie_header)
        
        # Query string
        query_string = parse_query_string(req.url)
        
        # Post data
        post_data = None
        if req.body:
            post_data = self._build_post_data(req.body, req.content_type)
        
        # HTTP/2 doesn't have traditional headers size
        body_size = len(req.body) if req.body else 0
        
        return HarRequest(
            method=req.method,
            url=req.url,
            httpVersion="HTTP/2.0",
            cookies=cookies,
            headers=headers,
            queryString=query_string,
            postData=post_data,
            headersSize=-1,  # Not applicable for HTTP/2
            bodySize=body_size,
        )
    
    def _build_http1_response(self, resp: HTTPResponse) -> HarResponse:
        """Build HAR response from HTTP/1.x response."""
        # Headers
        headers = [HarHeader(name=k, value=v) for k, v in resp.headers.items()]
        
        # Cookies from Set-Cookie headers
        cookies = []
        set_cookie = resp.headers.get('set-cookie', '')
        if set_cookie:
            cookie = parse_set_cookie_header(set_cookie)
            if cookie:
                cookies.append(cookie)
        
        # Content
        content = self._build_content(resp.decompressed_body, resp.content_type)
        
        # Redirect URL
        redirect_url = resp.headers.get('location', '')
        
        # Calculate sizes
        headers_text = self._format_http1_response_headers(resp)
        headers_size = len(headers_text.encode('utf-8'))
        body_size = len(resp.body) if resp.body else 0
        
        return HarResponse(
            status=resp.status,
            statusText=resp.status_text,
            httpVersion=resp.version,
            cookies=cookies,
            headers=headers,
            content=content,
            redirectURL=redirect_url,
            headersSize=headers_size,
            bodySize=body_size,
        )
    
    def _build_http2_response(self, resp: HTTP2Response) -> HarResponse:
        """Build HAR response from HTTP/2 response."""
        # Headers
        headers = [HarHeader(name=k, value=v) for k, v in resp.headers.items()]
        
        # Cookies from Set-Cookie headers
        cookies = []
        set_cookie = resp.headers.get('set-cookie', '')
        if set_cookie:
            cookie = parse_set_cookie_header(set_cookie)
            if cookie:
                cookies.append(cookie)
        
        # Content
        content = self._build_content(resp.decompressed_body, resp.content_type)
        
        # Redirect URL
        redirect_url = resp.headers.get('location', '')
        
        body_size = len(resp.body) if resp.body else 0
        
        return HarResponse(
            status=resp.status,
            statusText=resp.status_text,
            httpVersion="HTTP/2.0",
            cookies=cookies,
            headers=headers,
            content=content,
            redirectURL=redirect_url,
            headersSize=-1,  # Not applicable for HTTP/2
            bodySize=body_size,
        )
    
    def _empty_response(self) -> HarResponse:
        """Create an empty response for incomplete transactions."""
        return HarResponse(
            status=0,
            statusText="",
            httpVersion="",
            content=HarContent(size=0, mimeType=""),
        )
    
    def _build_post_data(self, body: bytes, content_type: str) -> HarPostData:
        """Build HAR postData from request body."""
        mime_type = content_type.split(';')[0].strip() if content_type else ""
        
        # Try to decode as text
        try:
            text = body.decode('utf-8')
        except UnicodeDecodeError:
            # Binary data - base64 encode
            import base64
            text = base64.b64encode(body).decode('ascii')
        
        params: List[HarPostDataParam] = []
        
        # Parse URL-encoded form data
        if 'application/x-www-form-urlencoded' in content_type.lower():
            try:
                parsed = parse_qs(text, keep_blank_values=True)
                for name, values in parsed.items():
                    for value in values:
                        params.append(HarPostDataParam(name=name, value=value))
            except Exception:
                pass
        
        return HarPostData(
            mimeType=mime_type or "application/octet-stream",
            params=params,
            text=text,
        )
    
    def _build_content(self, body: bytes, content_type: str) -> HarContent:
        """Build HAR content from response body."""
        mime_type = content_type.split(';')[0].strip() if content_type else ""
        
        text, encoding = encode_body_for_har(body, mime_type)
        
        return HarContent(
            size=len(body),
            mimeType=mime_type or "application/octet-stream",
            text=text,
            encoding=encoding,
        )
    
    def _format_http1_request_headers(self, req: HTTPRequest) -> str:
        """Format HTTP/1.x request headers as raw text."""
        lines = [f"{req.method} {req.path} {req.version}"]
        for name, value in req.headers.items():
            lines.append(f"{name}: {value}")
        lines.append("")
        lines.append("")
        return "\r\n".join(lines)
    
    def _format_http1_response_headers(self, resp: HTTPResponse) -> str:
        """Format HTTP/1.x response headers as raw text."""
        lines = [f"{resp.version} {resp.status} {resp.status_text}"]
        for name, value in resp.headers.items():
            lines.append(f"{name}: {value}")
        lines.append("")
        lines.append("")
        return "\r\n".join(lines)


class PcapToHarConverter:
    """
    Main converter for PCAP files to HAR format.
    
    Uses tshark to extract HTTP streams and converts them to HAR format.
    """
    
    def __init__(
        self,
        tshark_path: str = "tshark",
        keylog_file: Optional[str] = None,
        include_response_body: bool = True,
    ):
        """
        Initialize the converter.
        
        Args:
            tshark_path: Path to tshark executable
            keylog_file: Path to TLS key log file for decryption
            include_response_body: Whether to include response bodies in HAR
        """
        # Use PcapParser only to verify tshark availability and to preserve existing exception type.
        self.pcap_parser = PcapParser(tshark_path=tshark_path, keylog_file=keylog_file)
        self.transaction_converter = TransactionConverter()
        self.include_response_body = include_response_body
        self.tshark_path = tshark_path
        self.keylog_file = keylog_file
    
    def convert(
        self,
        pcap_file: str,
        progress: bool = False,
        parallel: bool = False,
        parallel_workers: Optional[int] = None,
    ) -> HarBuilder:
        """
        Convert a PCAP file to HAR format.
        
        Args:
            pcap_file: Path to the PCAP file
            
        Returns:
            HarBuilder with all converted entries
        """
        builder = HarBuilder()
        processed = 0
        total = 0
        progress_lock = threading.Lock()

        def emit_progress():
            if not progress or total == 0:
                return
            pct = int((processed / total) * 100)
            sys.stderr.write(f"\rProcessing streams: {processed}/{total} ({pct}%)")
            sys.stderr.flush()

        def advance_progress():
            nonlocal processed
            with progress_lock:
                processed += 1
                emit_progress()
        
        # HTTP/1.x via high-level capture (handles discovery and follow internally)
        try:
            from http_parser.capture import HTTPCapture
            http1_capture = HTTPCapture(
                pcap_file,
                keylog_file=self.keylog_file,
                tshark_path=self.tshark_path,
            )
            http1_streams = http1_capture.discover_streams()
            total += len(http1_streams)

            http1_lock = threading.Lock()

            def handle_http1(tcp_stream: int) -> Optional[HarEntry]:
                with http1_lock:
                    tx = http1_capture.get_transaction(tcp_stream)
                if not tx.request:
                    return None
                if tx.response and not self.include_response_body:
                    tx.response.body = b""
                return self.transaction_converter.convert_http1(
                    tx,
                    server_ip=tx.request.host or None,
                    connection_id=str(tx.tcp_stream),
                )

            if parallel and http1_streams:
                max_workers = parallel_workers if parallel_workers and parallel_workers > 0 else None
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    futures = {pool.submit(handle_http1, s): s for s in http1_streams}
                    for future in as_completed(futures):
                        try:
                            entry = future.result()
                            if entry:
                                builder.add_entry(entry)
                        finally:
                            advance_progress()
            else:
                for tcp_stream in http1_streams:
                    entry = handle_http1(tcp_stream)
                    if entry:
                        builder.add_entry(entry)
                    advance_progress()
        except Exception as e:
            print(f"Warning: Failed to process HTTP/1 streams: {e}", file=sys.stderr)
        
        # HTTP/2 via high-level capture
        try:
            from http2_parser.capture import HTTP2Capture
            http2_capture = HTTP2Capture(
                pcap_path=pcap_file,
                keylog_path=self.keylog_file,
                tshark_path=self.tshark_path,
                lazy=True,
            )
            http2_streams = list(http2_capture.streams)
            total += len(http2_streams)

            http2_lock = threading.Lock()

            def handle_http2(pair: tuple) -> Optional[HarEntry]:
                tcp_stream, http2_stream = pair
                with http2_lock:
                    tx = http2_capture.get_stream(tcp_stream, http2_stream)
                if not tx or not tx.request:
                    return None
                if tx.response and not self.include_response_body:
                    tx.response.body = b""
                return self.transaction_converter.convert_http2(
                    tx,
                    server_ip=tx.request.host or tx.request.authority,
                    connection_id=f"{tx.tcp_stream}:{tx.http2_stream}",
                )

            if parallel and http2_streams:
                max_workers = parallel_workers if parallel_workers and parallel_workers > 0 else None
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    futures = {pool.submit(handle_http2, pair): pair for pair in http2_streams}
                    for future in as_completed(futures):
                        try:
                            entry = future.result()
                            if entry:
                                builder.add_entry(entry)
                        finally:
                            advance_progress()
            else:
                for pair in http2_streams:
                    entry = handle_http2(pair)
                    if entry:
                        builder.add_entry(entry)
                    advance_progress()
        except Exception as e:
            print(f"Warning: Failed to process HTTP/2 streams: {e}", file=sys.stderr)
        
        if progress and total > 0:
            sys.stderr.write("\n")
        
        # Sort entries by start time (fall back to original order if timestamps absent)
        builder.log.entries.sort(key=lambda e: e.startedDateTime or "")
        
        return builder
    
    def convert_to_file(
        self,
        pcap_file: str,
        output_file: str,
        indent: int = 2,
        progress: bool = False,
        parallel: bool = False,
        parallel_workers: Optional[int] = None,
    ) -> None:
        """
        Convert a PCAP file and save to HAR file.
        
        Args:
            pcap_file: Path to the PCAP file
            output_file: Path to the output HAR file
            indent: JSON indentation level
        """
        builder = self.convert(
            pcap_file,
            progress=progress,
            parallel=parallel,
            parallel_workers=parallel_workers,
        )
        builder.save(output_file, indent=indent)
    
    def convert_to_json(
        self,
        pcap_file: str,
        indent: int = 2,
        progress: bool = False,
        parallel: bool = False,
        parallel_workers: Optional[int] = None,
    ) -> str:
        """
        Convert a PCAP file and return as JSON string.
        
        Args:
            pcap_file: Path to the PCAP file
            indent: JSON indentation level
            
        Returns:
            HAR document as JSON string
        """
        builder = self.convert(
            pcap_file,
            progress=progress,
            parallel=parallel,
            parallel_workers=parallel_workers,
        )
        return builder.to_json(indent=indent)
