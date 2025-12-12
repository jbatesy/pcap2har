# pcap2har

A CLI tool to convert PCAP files into HAR (HTTP Archive) 1.2 format using `tshark`.

## Description

This tool wraps the `tshark` binary to parse PCAP files, decrypt TLS traffic (if a keylog file is provided), and output HTTP Archive (HAR) 1.2 formatted JSON containing HTTP/1.x and HTTP/2 traffic information. It uses Pydantic models to validate and structure the data according to the HAR specification.

## Prerequisites

- Python 3.8+
- [Wireshark / tshark](https://www.wireshark.org/download.html) must be installed and available in your system PATH.

## Installation

1. Clone the repository.
2. Install the Python dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the tool using `main.py`:

```bash
python main.py <pcap_file> [options]
```

### Arguments

- `pcap_file`: Path to the input PCAP file (required).

### Options

- `-k, --keylog <path>`: Path to the TLS keylog file for decrypting SSL/TLS traffic.
- `-o, --output <path>`: Path to the output file. If not provided, a summary is printed to stdout.
- `-f, --format <format>`: Output format: `har` (default, HAR 1.2 format) or `raw` (raw tshark JSON).
- `--help`: Show the help message and exit.

### Examples

Convert a PCAP to HAR format:
```bash
python main.py capture.pcap -k ssl_keys.log -o output.har
```

Convert to raw JSON format:
```bash
python main.py capture.pcap -k ssl_keys.log -o output.json --format raw
```

Process without TLS decryption:
```bash
python main.py capture.pcap -o output.har
```

## Project Structure

- `pcap2har/`: Main package.
  - `models.py`: Pydantic data models representing tshark packet structure.
  - `har_models.py`: Pydantic data models for HAR 1.2 format.
  - `converter.py`: Logic for executing `tshark` and parsing the output.
  - `transformer.py`: Transforms tshark packets into HAR format.
  - `cli.py`: CLI implementation using `click`.
- `main.py`: Entry point script.
- `tests/`: Integration tests.

## HAR Format

The tool outputs HTTP Archive (HAR) 1.2 format, which includes:

- **Requests**: HTTP method, URL, headers, query parameters, cookies
- **Responses**: Status code, headers, content, cookies
- **Metadata**: Server IP addresses, timestamps (ISO 8601)
- **Timings**: Set to 0 or -1 as PCAP files don't contain detailed timing breakdowns

### Implementation Details

1. **HTTP/1.x**: Decodes hex-encoded HTTP data from tshark's `-x` output to extract headers and body
2. **HTTP/2**: Parses HTTP/2 pseudo-headers and regular headers from tshark fields
3. **Timings**: Uses -1 for unavailable timing fields (blocked, dns, connect, ssl) per HAR spec
4. **Pages**: Omitted as PCAP files don't contain page grouping information
5. **Request/Response Pairing**: Uses tshark's `http.response_in` and `http2.response_in` fields to match pairs
