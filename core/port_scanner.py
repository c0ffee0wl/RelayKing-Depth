"""
Fast Port Scanner
Ultra-fast, no-frills port scanning for protocol detection
"""

import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set


class FastPortScanner:
    """Ultra-fast port scanner with no fingerprinting"""

    # Protocol to port mapping
    PROTOCOL_PORTS = {
        'smb': 445,
        'http': 80,
        'https': 443,
        'ldap': 389,
        'ldaps': 636,
        'mssql': 1433,
        'smtp': 25,
        'imap': 143,
        'imaps': 993,
        'rpc': 135,
        'winrm': 5985,
        'winrms': 5986,
    }

    def __init__(self, timeout: float = 0.1):
        """
        Initialize scanner

        Args:
            timeout: Socket timeout in seconds (default 0.1 = 100ms)
        """
        self.timeout = timeout

    def scan_host(self, host: str, ports: List[int]) -> Set[int]:
        """
        Fast scan multiple ports on a single host

        Args:
            host: Target hostname or IP
            ports: List of ports to scan

        Returns:
            Set of open ports
        """
        open_ports = set()

        for port in ports:
            if self._check_port(host, port):
                open_ports.add(port)

        return open_ports

    def scan_hosts(self, targets: List[str], protocols: List[str], threads: int = 50) -> Dict[str, Set[int]]:
        """
        Fast scan multiple hosts for protocol ports

        Args:
            targets: List of target hostnames/IPs
            protocols: List of protocols to check
            threads: Number of concurrent scans (default 50)

        Returns:
            Dict of {host: set(open_ports)}
        """
        # Get unique ports for the specified protocols
        ports_to_scan = set()
        for protocol in protocols:
            if protocol in self.PROTOCOL_PORTS:
                ports_to_scan.add(self.PROTOCOL_PORTS[protocol])

        if not ports_to_scan:
            return {}

        ports_list = list(ports_to_scan)
        results = {}
        total_targets = len(targets)

        # Scan all hosts in parallel with progress tracking
        start_time = time.time()
        completed_count = 0
        last_update = 0

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_host = {
                executor.submit(self.scan_host, host, ports_list): host
                for host in targets
            }

            for future in as_completed(future_to_host):
                host = future_to_host[future]
                completed_count += 1

                try:
                    open_ports = future.result()
                    results[host] = open_ports
                except Exception:
                    results[host] = set()

                # Progress update every 50 hosts or every 5 seconds
                elapsed = time.time() - start_time
                if completed_count % 50 == 0 or elapsed - last_update > 5:
                    pct = (completed_count / total_targets) * 100
                    sys.stdout.write(f"\r[*] Port scan progress: {completed_count}/{total_targets} ({pct:.0f}%) - {elapsed:.1f}s elapsed")
                    sys.stdout.flush()
                    last_update = elapsed

        # Final progress update
        elapsed = time.time() - start_time
        sys.stdout.write(f"\r[*] Port scan progress: {completed_count}/{total_targets} (100%) - {elapsed:.1f}s elapsed\n")
        sys.stdout.flush()

        return results

    def _check_port(self, host: str, port: int) -> bool:
        """
        Check if a single port is open

        Args:
            host: Target hostname or IP
            port: Port number

        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def get_port_for_protocol(self, protocol: str) -> int:
        """Get the port number for a given protocol"""
        return self.PROTOCOL_PORTS.get(protocol)

    def should_scan_protocol(self, protocol: str, open_ports: Set[int]) -> bool:
        """
        Check if a protocol should be scanned based on open ports

        Args:
            protocol: Protocol name
            open_ports: Set of open ports on the target

        Returns:
            True if protocol's port is open, False otherwise
        """
        port = self.get_port_for_protocol(protocol)
        return port in open_ports if port else False
