"""
Additional Protocol Detectors
SMTP, IMAP, WINRM, etc.
"""

import socket
from .base_detector import BaseDetector, ProtocolResult


class SMTPDetector(BaseDetector):
    """Detector for SMTP protocol"""

    def detect(self, host: str, port: int = 25, target_ip: str = None) -> ProtocolResult:
        """Detect SMTP configuration"""

        connect_to = self._resolve_ip(host, target_ip)
        result = self._create_result('smtp', host, port)

        try:
            with socket.create_connection((connect_to, port), timeout=self._get_timeout()) as sock:
                # Receive banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                result.available = True
                result.additional_info['banner'] = banner.strip()

                # Send EHLO
                sock.sendall(b'EHLO relayking\r\n')
                response = sock.recv(4096).decode('utf-8', errors='ignore')

                # Check for AUTH support
                if 'AUTH' in response.upper():
                    result.additional_info['auth_supported'] = True

                    # Check for NTLM
                    if 'NTLM' in response.upper():
                        result.additional_info['ntlm_auth'] = True

                # SMTP doesn't typically enforce signing like SMB
                # But we note if STARTTLS is available
                if 'STARTTLS' in response.upper():
                    result.additional_info['starttls'] = True

                sock.sendall(b'QUIT\r\n')

        except socket.timeout:
            result.error = 'Connection timeout'
        except socket.error as e:
            result.error = f'Socket error: {e}'
        except Exception as e:
            result.error = str(e)

        return result


class IMAPDetector(BaseDetector):
    """Detector for IMAP protocol"""

    def detect(self, host: str, port: int = 143, use_ssl: bool = False, target_ip: str = None) -> ProtocolResult:
        """Detect IMAP configuration"""

        connect_to = self._resolve_ip(host, target_ip)
        protocol = 'imaps' if use_ssl else 'imap'
        result = self._create_result(protocol, host, port if port != 143 else (993 if use_ssl else 143))

        try:
            # Adjust port for IMAPS
            if use_ssl and port == 143:
                port = 993

            sock = socket.create_connection((connect_to, port), timeout=self._get_timeout())

            if use_ssl:
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            result.available = True
            result.additional_info['banner'] = banner.strip()

            # Check capabilities
            sock.sendall(b'A001 CAPABILITY\r\n')
            response = sock.recv(4096).decode('utf-8', errors='ignore')

            if 'AUTH=NTLM' in response.upper():
                result.additional_info['ntlm_auth'] = True

            if 'STARTTLS' in response.upper():
                result.additional_info['starttls'] = True

            sock.sendall(b'A002 LOGOUT\r\n')
            sock.close()

        except socket.timeout:
            result.error = 'Connection timeout'
        except socket.error as e:
            result.error = f'Socket error: {e}'
        except Exception as e:
            result.error = str(e)

        return result


class WINRMDetector(BaseDetector):
    """Detector for WINRM/WINRMS protocol"""

    def detect(self, host: str, port: int = 5985, use_ssl: bool = False, target_ip: str = None) -> ProtocolResult:
        """Detect WINRM configuration"""

        connect_to = self._resolve_ip(host, target_ip)
        protocol = 'winrms' if use_ssl else 'winrm'
        result = self._create_result(protocol, host, port if port != 5985 else (5986 if use_ssl else 5985))

        # Adjust port for WINRMS
        if use_ssl and port == 5985:
            port = 5986

        try:
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Build URL (use resolved IP for connection)
            scheme = 'https' if use_ssl else 'http'
            url = f"{scheme}://{connect_to}:{port}/wsman"

            # Try to connect
            response = requests.get(
                url,
                timeout=self._get_timeout(),
                verify=False,
                allow_redirects=False,
                headers={'Host': host}
            )

            # WINRM should respond with 401 and WWW-Authenticate header
            if response.status_code == 401:
                result.available = True

                if 'WWW-Authenticate' in response.headers:
                    auth_header = response.headers['WWW-Authenticate']
                    if 'Negotiate' in auth_header or 'Kerberos' in auth_header:
                        result.additional_info['kerberos_auth'] = True
                    if 'NTLM' in auth_header:
                        result.additional_info['ntlm_auth'] = True

                # This is absolutely braindead. Needs to be fixed.
                if use_ssl:
                    result.epa_enforced = True
                    result.channel_binding = True

        except requests.exceptions.Timeout:
            result.error = 'Connection timeout'
        except requests.exceptions.ConnectionError:
            result.error = 'Connection refused'
        except Exception as e:
            result.error = str(e)

        return result


class IMAPSDetector(IMAPDetector):
    """Detector specifically for IMAPS"""

    def detect(self, host: str, port: int = 993, target_ip: str = None) -> ProtocolResult:
        """Detect IMAPS configuration"""
        return super().detect(host, port, use_ssl=True, target_ip=target_ip)


class WINRMSDetector(WINRMDetector):
    """Detector specifically for WINRMS"""

    def detect(self, host: str, port: int = 5986, target_ip: str = None) -> ProtocolResult:
        """Detect WINRMS configuration"""
        return super().detect(host, port, use_ssl=True, target_ip=target_ip)
