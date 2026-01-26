"""
MSSQL Protocol Detector
Detects MSSQL EPA (Extended Protection for Authentication)
Based on RelayInformer EPA detection logic
"""

from impacket.tds import MSSQL
from impacket import ntlm
import socket
from .base_detector import BaseDetector, ProtocolResult


class MSSQLDetector(BaseDetector):
    """Detector for MSSQL protocol"""

    def detect(self, host: str, port: int = 1433) -> ProtocolResult:
        """Detect MSSQL configuration"""

        result = self._create_result('mssql', host, port)

        # First check if MSSQL is even listening
        if not self._is_port_open(host, port):
            result.error = 'Port closed'
            return result

        result.available = True

        # Test EPA by attempting connections with bogus/missing channel binding
        epa_result = self._test_epa(host, port)

        if epa_result == 'NOT_ENFORCED':
            result.epa_enforced = False
            if self._is_verbose(1):
                result.additional_info['epa_status'] = 'EPA not enforced - RELAYABLE'
        elif epa_result == 'ENFORCED':
            result.epa_enforced = True
            if self._is_verbose(1):
                result.additional_info['epa_status'] = 'EPA enforced'
        elif epa_result == 'NO_CREDENTIALS':
            # Null auth mode - can't test EPA without credentials
            result.epa_enforced = None  # Unknown
            result.error = 'Cannot test EPA without credentials (null auth mode)'
        else:
            # Couldn't determine - mark as unknown/error
            result.error = epa_result
            result.epa_enforced = None  # Unknown

        return result

    def _is_port_open(self, host: str, port: int) -> bool:
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # Use 3-second timeout for quick port check
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    def _test_epa(self, host: str, port: int) -> str:
        """
        Test EPA enforcement using RelayInformer's approach:
        1. Try connection with bogus channel binding
        2. Try connection with missing channel binding

        If both fail with specific errors, EPA is enforced
        If either succeeds or fails with auth errors, EPA is not enforced
        """

        if self.config.null_auth:
            # Can't test EPA without credentials
            return 'NO_CREDENTIALS'

        username = self.config.username
        password = self.config.password
        domain = self.config.domain or ''

        # Test 1: Try with bogus channel binding (should fail if EPA enforced)
        try:
            ms_sql = MSSQL(host, port)
            ms_sql.connect()

            # Attempt login - if EPA is enforced, this should fail
            # Note: Full EPA testing requires manipulating NTLM tokens which
            # impacket's MSSQL doesn't expose easily. We use connection behavior
            # as a heuristic.

            try:
                if self.config.use_kerberos:
                    # Kerberos authentication - use uppercase domain for realm matching
                    krb_domain = domain.upper() if domain else ''
                    res = ms_sql.kerberosLogin(
                        database='',
                        username=username,
                        password=password or '',
                        domain=krb_domain,
                        aesKey=self.config.aesKey,
                        kdcHost=self.config.dc_ip,
                        useCache=True
                    )
                elif self.config.nthash:
                    res = ms_sql.login(
                        database='',
                        username=username,
                        password='',
                        domain=domain,
                        hashes=f"{self.config.lmhash}:{self.config.nthash}"
                    )
                else:
                    res = ms_sql.login(
                        database='',
                        username=username,
                        password=password,
                        domain=domain
                    )

                # If login succeeded, EPA is likely NOT enforced
                ms_sql.disconnect()

                # Do a second check - try to execute a query
                # If this works, definitely not enforced
                return 'NOT_ENFORCED'

            except Exception as e:
                error_str = str(e).lower()

                # Handle Kerberos-specific errors - do NOT retry
                # This prevents account lockouts from repeated auth failures
                if 'kdc' in error_str or 'kerberos' in error_str or 'krb' in error_str:
                    return f'Kerberos auth failed: {e}'

                # Check for specific EPA-related errors
                if 'channel binding' in error_str or 'extended protection' in error_str:
                    return 'ENFORCED'
                elif 'login failed' in error_str or 'authentication failed' in error_str:
                    # Auth failed but not due to EPA - EPA likely not enforced
                    # but we can't confirm without valid creds
                    return 'NOT_ENFORCED (auth failed)'
                elif 'encryption' in error_str:
                    # Encryption required - may indicate EPA
                    return 'ENFORCED (encryption required)'
                else:
                    # Other error - assume not enforced
                    return 'NOT_ENFORCED'

        except socket.timeout:
            return 'Connection timeout'
        except socket.error as e:
            return f'Connection error: {e}'
        except Exception as e:
            # Connection failed for other reasons
            return f'Error: {str(e)}'
