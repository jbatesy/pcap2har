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
Command-line interface for pcap2har.
"""

import argparse
import os
import sys
from typing import Optional

from .converter import PcapToHarConverter
from .pcap_parser import TsharkNotFoundError


def main(args: Optional[list] = None) -> int:
    """
    Main entry point for the pcap2har CLI.
    
    Args:
        args: Command-line arguments (defaults to sys.argv[1:])
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = argparse.ArgumentParser(
        prog="pcap2har",
        description="Convert PCAP files to HAR (HTTP Archive) format.",
        epilog="Examples:\n"
               "  pcap2har capture.pcap -o output.har\n"
               "  pcap2har encrypted.pcap --keylog keys.txt -o output.har\n"
               "  pcap2har capture.pcap  # outputs to stdout",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "pcap_file",
        metavar="PCAP_FILE",
        help="Path to the input PCAP file",
    )
    
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output HAR file (default: stdout)",
    )
    
    parser.add_argument(
        "-k", "--keylog",
        metavar="FILE",
        help="Path to TLS key log file for decrypting HTTPS traffic",
    )
    
    parser.add_argument(
        "--tshark",
        metavar="PATH",
        default="tshark",
        help="Path to tshark executable (default: tshark)",
    )
    
    parser.add_argument(
        "--indent",
        metavar="N",
        type=int,
        default=2,
        help="JSON indentation level (default: 2, use 0 for compact output)",
    )
    
    parser.add_argument(
        "--no-body",
        action="store_true",
        help="Exclude response bodies from the HAR output",
    )

    parser.add_argument(
        "--progress",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Show a simple progress bar while processing (default: on)",
    )

    parser.add_argument(
        "--parallel",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Process streams in parallel (may increase CPU/tshark usage)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=2,
        metavar="N",
        help="Number of parallel workers when --parallel is enabled (default: auto)",
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress warnings and non-essential output",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )
    
    parsed_args = parser.parse_args(args)
    
    # Validate input file
    if not os.path.exists(parsed_args.pcap_file):
        print(f"Error: PCAP file not found: {parsed_args.pcap_file}", file=sys.stderr)
        return 1
    
    # Validate keylog file if specified
    if parsed_args.keylog and not os.path.exists(parsed_args.keylog):
        print(f"Error: Key log file not found: {parsed_args.keylog}", file=sys.stderr)
        return 1
    
    try:
        # Create converter
        converter = PcapToHarConverter(
            tshark_path=parsed_args.tshark,
            keylog_file=parsed_args.keylog,
            include_response_body=not parsed_args.no_body,
        )
        
        if parsed_args.verbose:
            print(f"Processing: {parsed_args.pcap_file}", file=sys.stderr)
        if parsed_args.quiet:
            parsed_args.progress = False
        
        # Convert
        if parsed_args.output:
            converter.convert_to_file(
                parsed_args.pcap_file,
                parsed_args.output,
                indent=parsed_args.indent,
                progress=parsed_args.progress,
                parallel=parsed_args.parallel,
                parallel_workers=parsed_args.workers if parsed_args.workers > 0 else None,
            )
            if parsed_args.verbose:
                print(f"Output written to: {parsed_args.output}", file=sys.stderr)
        else:
            # Output to stdout
            indent = parsed_args.indent if parsed_args.indent > 0 else None
            har_json = converter.convert_to_json(
                parsed_args.pcap_file,
                indent=indent or 0,
                progress=parsed_args.progress,
                parallel=parsed_args.parallel,
                parallel_workers=parsed_args.workers if parsed_args.workers > 0 else None,
            )
            print(har_json)
        
        return 0
        
    except TsharkNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("\nPlease install Wireshark/tshark or specify the path with --tshark", file=sys.stderr)
        return 2
        
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130
        
    except Exception as e:
        if parsed_args.verbose:
            import traceback
            traceback.print_exc()
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
