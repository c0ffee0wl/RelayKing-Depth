#!/usr/bin/env python3
"""
RelayKing - NTLM & Kerberos Relay Detection Tool
Main entry point
"""

import sys
import time
from core.banner import print_banner
from core.config import parse_arguments
from core.scanner import RelayKingScanner
from output.formatters import OutputFormatter


def generate_relay_list(results):
    """
    Generate a list of relay targets in URI format for NTLMRelayX.

    Format: protocol://hostname (or protocol://hostname:port/path for HTTP/HTTPS)
    Example: smb://dc01.domain.local, http://sccm.domain.local:80/ccm_system_windowsauth

    For HTTP/HTTPS, includes the full NTLM-enabled path since relaying to web root won't work.

    Args:
        results: Scan results dict

    Returns:
        List of URI strings for relayable targets
    """
    relay_targets = []
    seen = set()  # Track seen targets to avoid duplicates

    # Protocol URI mapping for NTLMRelayX
    protocol_uri_map = {
        'smb': 'smb',
        'ldap': 'ldap',
        'ldaps': 'ldaps',
        'http': 'http',
        'https': 'https',
        'mssql': 'mssql',
        'imap': 'imap',
        'imaps': 'imaps',
        'smtp': 'smtp',
    }

    # Default ports for protocols
    default_ports = {
        'http': 80,
        'https': 443,
    }

    # Iterate through all host results
    for host, protocol_results in results.get('results', {}).items():
        for protocol, result in protocol_results.items():
            # Skip metadata and non-protocol results
            if protocol.startswith('_') or protocol in ['webdav', 'ntlm_reflection']:
                continue

            # Check if this protocol is relayable
            if hasattr(result, 'is_relayable') and result.is_relayable():
                # Get the URI scheme for this protocol
                uri_scheme = protocol_uri_map.get(protocol.lower())
                if uri_scheme:
                    # For HTTP/HTTPS, include the full NTLM-enabled paths
                    if protocol.lower() in ['http', 'https']:
                        ntlm_paths = result.additional_info.get('ntlm_paths', [])
                        port = result.port if hasattr(result, 'port') else default_ports.get(protocol.lower(), 80)

                        if ntlm_paths:
                            # Add each NTLM-enabled path as a separate target
                            for path in ntlm_paths:
                                target_uri = f"{uri_scheme}://{host}:{port}{path}"
                                if target_uri not in seen:
                                    relay_targets.append(target_uri)
                                    seen.add(target_uri)
                        else:
                            # Fallback to just host:port if no paths found (shouldn't happen if relayable)
                            target_uri = f"{uri_scheme}://{host}:{port}"
                            if target_uri not in seen:
                                relay_targets.append(target_uri)
                                seen.add(target_uri)
                    else:
                        # For other protocols, just use protocol://host
                        target_uri = f"{uri_scheme}://{host}"
                        if target_uri not in seen:
                            relay_targets.append(target_uri)
                            seen.add(target_uri)

    return sorted(relay_targets)


def _run() -> int:
    """Run the scanner and return an exit code"""

    # Print banner
    print_banner()

    # Parse arguments
    config = parse_arguments()

    # Create and run scanner
    try:
        # Start timer
        start_time = time.time()

        scanner = RelayKingScanner(config)
        results = scanner.scan()

        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        results['scan_duration'] = elapsed_time

        # File extension mapping
        format_extensions = {
            'plaintext': '.txt',
            'json': '.json',
            'xml': '.xml',
            'csv': '.csv',
            'grep': '.grep',
            'markdown': '.md'
        }

        # Generate outputs for each format
        outputs_written = []
        for output_format in config.output_formats:
            formatted_output = OutputFormatter.format(results, output_format)

            # Write to file or stdout
            if config.output_file:
                # Generate filename with appropriate extension
                base_name = config.output_file
                extension = format_extensions.get(output_format, '.txt')
                output_path = base_name + extension

                try:
                    with open(output_path, 'w') as f:
                        f.write(formatted_output)
                    outputs_written.append(output_path)
                except Exception as e:
                    print(f"\n[!] Error writing {output_format} to {output_path}: {e}")
            else:
                # Only print to stdout if single format (avoid mixed output)
                if len(config.output_formats) == 1:
                    print("\n" + formatted_output)
                else:
                    print(f"\n[!] Multiple formats specified but no --output-file provided")
                    print(f"[!] Use --output-file to save outputs to files")
                    break

        # Report written files
        if outputs_written:
            print(f"\n[+] Results written to:")
            for path in outputs_written:
                print(f"    - {path}")

        # Generate relay list for NTLMRelayX if requested
        if config.gen_relay_list:
            relay_list = generate_relay_list(results)
            if relay_list:
                try:
                    with open(config.gen_relay_list, 'w') as f:
                        f.write('\n'.join(relay_list) + '\n')
                    print(f"\n[+] Relay target list written to: {config.gen_relay_list}")
                    print(f"    Contains {len(relay_list)} relayable target(s)")
                except Exception as e:
                    print(f"\n[!] Error writing relay list to {config.gen_relay_list}: {e}")
            else:
                print(f"\n[*] No relayable targets found for relay list")

        return 0

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        if config.verbose >= 2:
            import traceback
            traceback.print_exc()
        return 1


def main():
    """Entry point for both direct execution and console_scripts"""
    sys.exit(_run())


if __name__ == "__main__":
    main()
