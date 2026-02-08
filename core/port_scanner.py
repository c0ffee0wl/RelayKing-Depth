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

    def __init__(self, timeout: float = 0.5):
        """
        Initialize scanner

        Args:
            timeout: Socket timeout in seconds (default 0.5 = 500ms)
        """
        self.timeout = timeout

    def scan_host(self, ip: str, ports: List[int]) -> Set[int]:
        """
        Fast scan multiple ports on a single host by IP

        Args:
            ip: Target IP address
            ports: List of ports to scan

        Returns:
            Set of open ports
        """
        open_ports = set()

        for port in ports:
            if self._check_port(ip, port):
                open_ports.add(port)

        return open_ports

    def scan_hosts(self, targets: List[str], protocols: List[str],
                   threads: int = 50, hostname_ip_map: Dict[str, str] = None) -> Dict[str, Set[int]]:
        """
        Fast scan multiple hosts for protocol ports

        Args:
            targets: List of target hostnames/IPs
            protocols: List of protocols to check
            threads: Number of concurrent scans (default 50)
            hostname_ip_map: Optional dict mapping hostnames to resolved IPs

        Returns:
            Dict of {host: set(open_ports)} keyed by original hostname
        """
        if hostname_ip_map is None:
            hostname_ip_map = {}

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
            future_to_host = {}
            for host in targets:
                # Use resolved IP if available, otherwise fall back to hostname
                scan_ip = hostname_ip_map.get(host, host)
                future = executor.submit(self.scan_host, scan_ip, ports_list)
                future_to_host[future] = host

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

    def _check_port(self, ip: str, port: int) -> bool:
        """
        Check if a single port is open

        Args:
            ip: Target IP address
            port: Port number

        Returns:
            True if port is open, False otherwise
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
        except Exception:
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

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
