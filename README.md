# pcap2har

A CLI tool to convert PCAP files into HAR (HTTP Archive) 1.2 format using `tshark`.

## Description

This tool wraps the `tshark` binary to parse PCAP files, decrypt TLS traffic (if a keylog file is provided), and output HTTP Archive (HAR) 1.2 formatted JSON containing HTTP/1.x and HTTP/2 traffic information.

Most HTTP analysis tools will have a pathway to import a HAR file, useful when you're capturing TLS keys and don't want to use Wireshark to decrypt & view the traffic.

## Prerequisites

- Python 3.8+
- [tshark](https://www.wireshark.org/download.html) available on PATH

Common tshark installs:
- macOS: `brew install wireshark`
- Debian/Ubuntu: `sudo apt install tshark`
- Windows: install Wireshark (tshark is included)

## Installation

```bash
git clone https://github.com/<your-org>/pcap2har.git
cd pcap2har
python -m venv .venv && source .venv/bin/activate  # optional but recommended
pip install -r requirements.txt
```

## CLI usage

```bash
python -m pcap2har PCAP_FILE [options]
```

Key options:
- `PCAP_FILE` (positional): input capture to read
- `-o, --output FILE`: write HAR to a file (default: stdout)
- `-k, --keylog FILE`: TLS key log for decrypting HTTPS
- `--tshark PATH`: custom tshark executable
- `--indent N`: JSON indent (use `0` for compact)
- `--no-body`: drop response bodies from output
- `--progress`: toggle progress indicator (on by default)
- `--parallel`: process streams in parallel; `--workers N` to control pool size
- `-v, --verbose`: extra logging; `-q, --quiet`: suppress non-essential output

Examples:

```bash
# Stream to stdout with progress
python -m pcap2har capture.pcap --progress

# Write to file with TLS decryption
python -m pcap2har encrypted.pcap -k ssl_keys.log -o output.har

# Compact output without bodies
python -m pcap2har capture.pcap --no-body --indent 0 -o output.har

# Parallelize stream processing
python -m pcap2har capture.pcap --parallel --workers 4 -o output.har
```

Exit codes: `0` success, `1` generic failure, `2` tshark missing, `130` interrupted.

## Python API

```python
from pcap2har import PcapToHarConverter

converter = PcapToHarConverter(keylog_file="keys.txt", include_response_body=True)

# Write straight to a file
converter.convert_to_file("capture.pcap", "output.har", indent=2, progress=True)

# Get JSON as a string (indent=0 yields compact JSON)
har_json = converter.convert_to_json(
    "capture.pcap",
    indent=2,
    progress=False,
    parallel=True,
    parallel_workers=4,
)
print(har_json[:200])

# Work with the builder if you need to inspect entries
builder = converter.convert("capture.pcap", progress=True)
print(f"entries: {len(builder.log.entries)}")
```

## TLS key log tips

Generate a key log and feed it to the CLI with `--keylog`:

```bash
export SSLKEYLOGFILE=$PWD/keylog.txt
firefox https://example.com
python -m pcap2har capture.pcap --keylog $SSLKEYLOGFILE -o decrypted.har
```

curl: `curl --ssl-keylog-file $PWD/keylog.txt https://example.com`

## HAR output

- HAR version 1.2 with minimal timing fields (blocked/dns/connect/ssl are -1 when unavailable)
- Entries are sorted by `startedDateTime`; page grouping is omitted
- Response bodies can be excluded with `--no-body` or `include_response_body=False`

## Project layout

- [main.py](main.py): shim entrypoint that invokes the CLI
- [pcap2har/cli.py](pcap2har/cli.py): argparse-based CLI surface
- [pcap2har/converter.py](pcap2har/converter.py): coordinates tshark parsing and HAR building
- [pcap2har/har.py](pcap2har/har.py): HAR 1.2 data classes and builder helpers
- [pcap2har/pcap_parser.py](pcap2har/pcap_parser.py): tshark availability checks (legacy parser stub)
- [http_parser](http_parser) and [http2_parser](http2_parser): protocol-specific parsing helpers
