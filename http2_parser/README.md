# http2_parser

A Python module for parsing HTTP/2 traffic from pcap files using tshark.

## Installation

```bash
pip install pyyaml
```

Requires `tshark` (Wireshark CLI) to be installed and available in PATH.

## Quick Start

```python
from http2_parser import HTTP2Capture

# Load a pcap file with TLS keylog for decryption
capture = HTTP2Capture('traffic.pcap', 'keylog.txt')

# Iterate over all HTTP/2 transactions
for tx in capture:
    print(f"{tx.request.method} {tx.request.url}")
    print(f"  Status: {tx.response.status}")
    
    # Parse JSON responses automatically
    if tx.response.is_json:
        data = tx.response.json()
        print(f"  Data: {data}")
```

## API Reference

### HTTP2Capture

High-level interface for extracting HTTP/2 transactions from pcap files.

```python
capture = HTTP2Capture(pcap_path, keylog_path, lazy=True)
```

**Parameters:**
- `pcap_path`: Path to the pcap file
- `keylog_path`: Path to the TLS keylog file (for decrypting HTTPS)
- `lazy`: If `True` (default), streams are loaded on-demand. If `False`, all streams are loaded immediately.

**Properties & Methods:**

| Method | Description |
|--------|-------------|
| `len(capture)` | Number of HTTP/2 streams |
| `capture[i]` | Get transaction by index |
| `for tx in capture` | Iterate all transactions |
| `capture.streams` | List of `(tcp_stream, http2_stream)` tuples |
| `capture.get_stream(tcp, h2)` | Get specific stream by IDs |
| `capture.get_transactions()` | Get all transactions as list |
| `capture.load_all()` | Force load all streams |
| `capture.filter(...)` | Filter transactions (see below) |
| `capture.filter_json()` | Get only JSON responses |
| `capture.filter_by_host(host)` | Filter by host |
| `capture.get_hosts()` | Get all unique hosts |
| `capture.summary()` | Get capture statistics |

**Filtering:**

```python
# Filter by multiple criteria
for tx in capture.filter(
    host='api.example.com',      # Exact host match
    method='POST',               # HTTP method
    path_contains='/api/',       # Path substring
    status=200,                  # Response status
    content_type='json',         # Content-type substring
    min_body_size=100            # Minimum body size
):
    print(tx)
```

---

### HTTP2Transaction

Represents a complete HTTP/2 request-response pair.

```python
tx = capture.get_stream(tcp_stream=18, http2_stream=1)
```

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `tcp_stream` | `int` | TCP stream number |
| `http2_stream` | `int` | HTTP/2 stream ID |
| `request` | `HTTP2Request` | The request object |
| `response` | `HTTP2Response` | The response object |
| `url` | `str` | Shortcut to `request.url` |
| `method` | `str` | Shortcut to `request.method` |
| `status` | `int` | Shortcut to `response.status` |
| `duration_ms` | `float` | Transaction duration in ms |
| `complete` | `bool` | Has both request and response |

---

### HTTP2Request

Represents an HTTP/2 request.

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `method` | `str` | HTTP method (GET, POST, etc.) |
| `url` | `str` | Full URL |
| `path` | `str` | Path with query string |
| `path_only` | `str` | Path without query string |
| `query_string` | `str` | Query string portion |
| `query_params` | `dict` | Parsed query parameters |
| `authority` | `str` | Host:port |
| `host` | `str` | Hostname only |
| `port` | `int` | Port number |
| `scheme` | `str` | `http` or `https` |
| `headers` | `dict` | Request headers (lowercase keys) |
| `body` | `bytes` | Raw request body |
| `body_text` | `str` | Body as UTF-8 string |
| `content_type` | `str` | Content-Type header |
| `content_length` | `int` | Body size |
| `is_json` | `bool` | Is JSON content type |
| `timestamp` | `float` | Request timestamp |

**Methods:**

```python
# Get header (case-insensitive)
req.get_header('Content-Type')
req.get_header('x-custom', default='none')

# Parse JSON body
data = req.json()
```

---

### HTTP2Response

Represents an HTTP/2 response.

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `status` | `int` | HTTP status code |
| `status_text` | `str` | Status text (e.g., "OK") |
| `ok` | `bool` | True if status is 2xx |
| `headers` | `dict` | Response headers (lowercase keys) |
| `body` | `bytes` | Raw response body |
| `body_text` | `str` | Body as UTF-8 (decompressed) |
| `decompressed_body` | `bytes` | Decompressed body bytes |
| `content_type` | `str` | Content-Type header |
| `content_encoding` | `str` | Content-Encoding header |
| `content_length` | `int` | Body size |
| `is_json` | `bool` | Is JSON content type |
| `is_html` | `bool` | Is HTML content type |
| `is_text` | `bool` | Is text-based content |
| `timestamp` | `float` | Response timestamp |

**Methods:**

```python
# Get header (case-insensitive)
resp.get_header('Content-Type')

# Parse JSON body (auto-decompresses gzip/br/deflate)
data = resp.json()
```

---

### HTTP2StreamParser

Low-level parser for tshark YAML output. Use this if you already have YAML data.

```python
from http2_parser import HTTP2StreamParser

# From file
parser = HTTP2StreamParser.from_file('stream.yaml')
tx = parser.parse(tcp_stream=0, http2_stream=0)

# From string
parser = HTTP2StreamParser.from_string(yaml_content)
tx = parser.parse()

# From dict
parser = HTTP2StreamParser(yaml_data=data)
tx = parser.parse()
```

---

## Examples

### Extract all API calls

```python
from http2_parser import HTTP2Capture

capture = HTTP2Capture('app.pcap', 'keys.txt')

for tx in capture.filter(path_contains='/api/'):
    print(f"{tx.method} {tx.url}")
    if tx.response.is_json:
        print(f"  Response: {tx.response.json()}")
```

### Find authentication tokens

```python
for tx in capture:
    auth = tx.request.get_header('authorization')
    if auth:
        print(f"{tx.url}: {auth[:50]}...")
```

### Analyze response times

```python
slow_requests = []
for tx in capture:
    if tx.complete and tx.duration_ms > 1000:
        slow_requests.append((tx.duration_ms, tx.url))

for duration, url in sorted(slow_requests, reverse=True)[:10]:
    print(f"{duration:.0f}ms - {url}")
```

### Export JSON responses

```python
import json

for tx in capture.filter_json():
    filename = f"response_{tx.tcp_stream}_{tx.http2_stream}.json"
    with open(filename, 'w') as f:
        json.dump(tx.response.json(), f, indent=2)
```

### Get capture summary

```python
summary = capture.summary()
print(f"Total streams: {summary['total_streams']}")
print(f"Hosts: {summary['hosts']}")
print(f"Methods: {summary['methods']}")
print(f"Status codes: {summary['status_codes']}")
```

---

## TLS Keylog File

To decrypt HTTPS traffic, you need a TLS keylog file. This can be generated by:

1. **Chrome/Firefox**: Set environment variable `SSLKEYLOGFILE=/path/to/keylog.txt` before starting the browser

2. **curl**: Use `--ssl-keylog-file keylog.txt`

3. **Mobile apps**: Use a proxy like mitmproxy or tools that extract keys from app memory

The keylog file format is:
```
CLIENT_RANDOM <hex> <hex>
```

---

## Requirements

- Python 3.8+
- PyYAML
- tshark (Wireshark CLI tool)
- Optional: `brotli` for Brotli decompression
