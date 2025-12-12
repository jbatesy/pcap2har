# HTTP/1.x Parser

A Python module for parsing HTTP/1.x traffic from pcap files using tshark.

## Features

- Parse HTTP/1.x requests and responses from pcap files
- TLS decryption support via keylog files
- Automatic decompression (gzip, brotli, deflate)
- JSON parsing utilities
- Stream filtering and searching
- Transaction matching (request-response pairs)

## Requirements

- Python 3.8+
- tshark (Wireshark command-line tool)
- PyYAML

Optional:
- brotli (for Brotli decompression)

## Installation

```bash
pip install pyyaml
# Optional: pip install brotli
```

## Usage

### Basic Usage

```python
from http_parser import HTTPCapture

# Create a capture (with optional TLS decryption)
capture = HTTPCapture(
    '/path/to/capture.pcap',
    keylog_file='/path/to/keylog.txt'
)

# Iterate over all transactions
for tx in capture:
    print(f"{tx.method} {tx.url} -> {tx.status}")
```

### Working with Requests

```python
for tx in capture:
    if tx.request:
        req = tx.request
        
        # Access request properties
        print(f"Method: {req.method}")
        print(f"URL: {req.url}")
        print(f"Path: {req.path}")
        print(f"Host: {req.host}")
        print(f"Query params: {req.query_params}")
        
        # Access headers
        print(f"Content-Type: {req.content_type}")
        auth = req.get_header('authorization')
        
        # Access body
        if req.is_json:
            data = req.json()
        else:
            text = req.body_text
```

### Working with Responses

```python
for tx in capture:
    if tx.response:
        resp = tx.response
        
        # Access response properties
        print(f"Status: {resp.status} {resp.status_text}")
        print(f"Content-Type: {resp.content_type}")
        
        # Body is automatically decompressed
        if resp.is_json:
            data = resp.json()
            print(data)
        elif resp.is_text:
            print(resp.body_text)
```

### Filtering Transactions

```python
# Filter by method
for tx in capture.filter(method='POST'):
    print(tx.url)

# Filter by status
for tx in capture.filter(status=200):
    print(tx.url)

# Filter by status range
for tx in capture.filter(status_range=(400, 499)):
    print(f"{tx.status} {tx.url}")

# Filter by host
for tx in capture.filter(host='api.example.com'):
    print(tx.url)

# Filter by path
for tx in capture.filter(path_contains='/api/'):
    print(tx.url)

# Combined filters
for tx in capture.filter(method='POST', status=201):
    print(tx.url)
```

### Finding Specific Transactions

```python
# Find by URL pattern (regex)
transactions = capture.get_by_url(r'/api/v\d+/users')
for tx in transactions:
    print(tx.url)

# Get specific stream
tx = capture.get_transaction(tcp_stream=13)
print(f"{tx.method} {tx.url}")
```

### Summary and Debugging

```python
# Print summary of all transactions
print(capture.summary())

# Debug raw packets for a stream
print(capture.dump_stream(tcp_stream=13))
```

### Low-Level Parser Usage

```python
from http_parser import HTTPStreamParser

# Parse from tshark YAML output
parser = HTTPStreamParser()

# From file
tx = parser.parse_yaml_file('/path/to/stream.yaml')

# From string
tx = parser.parse_yaml(yaml_content)

# Debug raw packets
print(parser.dump_packets(yaml_content))
```

## API Reference

### HTTPCapture

Main interface for working with pcap files.

#### Constructor
- `pcap_file`: Path to the pcap file
- `keylog_file`: Optional path to TLS keylog file
- `tshark_path`: Path to tshark executable (default: "tshark")

#### Methods
- `discover_streams()`: Find all TCP streams with HTTP traffic
- `get_transaction(tcp_stream)`: Get transaction for a specific stream
- `filter(...)`: Filter transactions by criteria
- `get_by_url(pattern)`: Find transactions matching URL regex
- `summary()`: Get text summary of all transactions
- `dump_stream(tcp_stream)`: Get raw packet dump for debugging

### HTTPRequest

Represents an HTTP/1.x request.

#### Properties
- `method`: HTTP method (GET, POST, etc.)
- `path`: Request path including query string
- `version`: HTTP version (e.g., "HTTP/1.1")
- `headers`: Dict of headers (lowercase keys)
- `body`: Raw body bytes
- `url`: Full URL (scheme://host:port/path)
- `host`: Host from Host header
- `port`: Port number
- `scheme`: "http" or "https"
- `path_only`: Path without query string
- `query_string`: Query string portion
- `query_params`: Parsed query parameters
- `content_type`: Content-Type header
- `is_json`: True if JSON content type
- `body_text`: Body as string
- `json()`: Parse body as JSON

### HTTPResponse

Represents an HTTP/1.x response.

#### Properties
- `status`: Status code (e.g., 200)
- `status_text`: Status text (e.g., "OK")
- `version`: HTTP version
- `headers`: Dict of headers (lowercase keys)
- `body`: Raw body bytes
- `ok`: True if status is 2xx
- `content_type`: Content-Type header
- `content_encoding`: Content-Encoding header
- `is_json`: True if JSON content type
- `is_html`: True if HTML content type
- `is_text`: True if text-based content
- `decompressed_body`: Body after decompression
- `body_text`: Body as string (decompressed)
- `json()`: Parse body as JSON

### HTTPTransaction

Represents a request-response pair.

#### Properties
- `tcp_stream`: TCP stream number
- `request`: HTTPRequest object (or None)
- `response`: HTTPResponse object (or None)
- `url`: Shortcut to request.url
- `method`: Shortcut to request.method
- `status`: Shortcut to response.status
- `duration_ms`: Time from request to response
- `complete`: True if both request and response present

## Differences from HTTP/2

HTTP/1.x differs from HTTP/2 in several ways:

1. **No stream multiplexing**: HTTP/1.x uses one TCP connection per request (or sequential requests with keep-alive)
2. **No pseudo-headers**: Uses standard `Host` header instead of `:authority`, etc.
3. **Text-based protocol**: Request/response lines are human-readable
4. **No header compression**: Headers are plain text

This module handles these differences transparently, providing a similar API to the http2_parser module.

## Example: Extract API Responses

```python
from http_parser import HTTPCapture

capture = HTTPCapture('traffic.pcap', keylog_file='keylog.txt')

# Find all JSON API responses
for tx in capture.filter(content_type='json', method='POST'):
    if tx.response and tx.response.ok:
        print(f"\n{tx.url}")
        print(tx.response.json())
```

## Example: Analyze Request Headers

```python
from http_parser import HTTPCapture

capture = HTTPCapture('traffic.pcap')

for tx in capture:
    if tx.request:
        print(f"\n{tx.method} {tx.url}")
        for name, value in tx.request.headers.items():
            print(f"  {name}: {value}")
```
