"""
ADCS (Active Directory Certificate Services) Detector
Detects ADCS servers using /certsrv/ endpoint and LDAP enumeration
"""

import requests
import urllib3


class ADCSDetector:
    """Detector for ADCS servers"""

    def __init__(self, config):
        self.config = config
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def detect_via_http(self, host: str) -> dict:
        """
        Detect ADCS by checking /certsrv/ endpoint on HTTP and HTTPS
        ADCS should return 401 Unauthorized
        """
        result = {
            'is_adcs': False,
            'http_certsrv': False,
            'https_certsrv': False,
            'method': None
        }

        # Check HTTP (port 80)
        if self._check_certsrv(host, 80, False):
            result['http_certsrv'] = True
            result['is_adcs'] = True
            result['method'] = 'HTTP /certsrv/'

        # Check HTTPS (port 443)
        if self._check_certsrv(host, 443, True):
            result['https_certsrv'] = True
            result['is_adcs'] = True
            if not result['method']:
                result['method'] = 'HTTPS /certsrv/'

        return result

    def _check_certsrv(self, host: str, port: int, use_ssl: bool) -> bool:
        """Check if /certsrv/ endpoint returns 401"""
        try:
            scheme = 'https' if use_ssl else 'http'
            url = f"{scheme}://{host}:{port}/certsrv/"

            response = requests.get(
                url,
                timeout=self.config.timeout,
                verify=False,
                allow_redirects=False
            )

            # ADCS /certsrv/ should return 401 Unauthorized
            if response.status_code == 401:
                # Check for NTLM or Negotiate in WWW-Authenticate
                if 'WWW-Authenticate' in response.headers:
                    auth_header = response.headers['WWW-Authenticate']
                    if 'NTLM' in auth_header or 'Negotiate' in auth_header:
                        return True

            return False

        except:
            return False

    @staticmethod
    def enumerate_adcs_via_ldap(config) -> list:
        """
        Enumerate ADCS servers from LDAP
        Search under CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
        """
        adcs_servers = []

        if not config.domain:
            return adcs_servers

        try:
            from ldap3 import Server, Connection, NTLM, ALL, SUBTREE
            import socket

            # Determine DC IP
            dc_ip = config.dc_ip
            if not dc_ip:
                try:
                    dc_ip = socket.gethostbyname(config.domain)
                except:
                    return adcs_servers

            # Connect to LDAP
            ldap_port = 636 if config.use_ldaps else 389
            server = Server(dc_ip, port=ldap_port, use_ssl=config.use_ldaps, get_info=ALL)

            # Build credentials
            if config.null_auth:
                conn = Connection(server, auto_bind=True)
            else:
                user = f"{config.domain}\\{config.username}"
                conn = Connection(server, user=user, password=config.password,
                                authentication=NTLM, auto_bind=True)

            # Build search base for PKI Services
            domain_parts = config.domain.split('.')
            config_dn = ','.join([f"DC={part}" for part in domain_parts])
            search_base = f"CN=Public Key Services,CN=Services,CN=Configuration,{config_dn}"

            # Search for enrollment services (Certificate Authorities)
            conn.search(
                search_base=search_base,
                search_filter='(objectClass=pKIEnrollmentService)',
                search_scope=SUBTREE,
                attributes=['dNSHostName', 'name', 'cn']
            )

            for entry in conn.entries:
                if entry.dNSHostName:
                    hostname = str(entry.dNSHostName)
                    if hostname not in adcs_servers:
                        adcs_servers.append(hostname)

            conn.unbind()

        except ImportError:
            pass  # ldap3 not available
        except Exception as e:
            if config.verbose >= 2:
                print(f"[!] Error enumerating ADCS from LDAP: {e}")

        return adcs_servers
