"""
RPC Protocol Detector
Detects MS-RPC endpoints and authentication requirements
"""

from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
import socket
from .base_detector import BaseDetector, ProtocolResult


class RPCDetector(BaseDetector):
    """Detector for MS-RPC protocol"""

    def detect(self, host: str, port: int = 135, target_ip: str = None) -> ProtocolResult:
        """
        Detect RPC configuration by testing authentication levels

        Tests in order: CONNECT -> CALL -> PKT_INTEGRITY -> PKT_PRIVACY
        The lowest level that succeeds determines if signing is required
        """

        connect_to = self._resolve_ip(host, target_ip)
        result = self._create_result('rpc', host, port)

        try:
            # Build RPC connection string (use resolved IP for TCP)
            string_binding = f'ncacn_ip_tcp:{connect_to}[{port}]'

            if self.config.null_auth:
                username = ''
                password = ''
                domain = ''
                lmhash = ''
                nthash = ''
                use_kerberos = False
                aesKey = None
                dc_ip = None
            else:
                username = self.config.username
                password = self.config.password
                domain = self.config.domain or ''
                lmhash = self.config.lmhash
                nthash = self.config.nthash
                use_kerberos = self.config.should_use_kerberos(host)
                aesKey = self.config.aesKey
                dc_ip = self.config.dc_ip

            # Test authentication levels in order (lowest to highest)
            # CONNECT (2) = no signing
            # CALL (3) = no signing
            # PKT_INTEGRITY (5) = signing required
            # PKT_PRIVACY (6) = encryption required
            auth_levels_to_test = [
                (RPC_C_AUTHN_LEVEL_CONNECT, 'CONNECT', False),       # No signing
                (RPC_C_AUTHN_LEVEL_CALL, 'CALL', False),             # No signing
                (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, 'PKT_INTEGRITY', True),  # Signing
                (RPC_C_AUTHN_LEVEL_PKT_PRIVACY, 'PKT_PRIVACY', True),      # Encryption
            ]

            lowest_accepted_level = None
            signing_required = None

            for auth_level, level_name, requires_signing in auth_levels_to_test:
                try:
                    # Create fresh transport for each test
                    rpc_transport = transport.DCERPCTransportFactory(string_binding)
                    rpc_transport.set_connect_timeout(self._get_timeout())

                    # Set credentials if provided
                    if use_kerberos:
                        rpc_transport.set_credentials(username, password or '', domain, lmhash, nthash, aesKey)
                        rpc_transport.set_kerberos(True, dc_ip)
                    elif nthash:
                        rpc_transport.set_credentials(username, '', domain, lmhash, nthash)
                    elif username:
                        rpc_transport.set_credentials(username, password, domain)

                    # Connect and set auth level
                    dce = rpc_transport.get_dce_rpc()
                    dce.set_auth_level(auth_level)
                    dce.connect()

                    # Try to bind to EPM interface
                    dce.bind(epm.MSRPC_UUID_PORTMAP)

                    # Success! This is the lowest accepted level
                    lowest_accepted_level = level_name
                    signing_required = requires_signing
                    result.available = True
                    result.signing_required = signing_required
                    result.additional_info['min_auth_level'] = level_name

                    if self._is_verbose(3):
                        print(f"[*] RPC on {host}: Accepted auth level {level_name} (signing={'required' if signing_required else 'not required'})")

                    dce.disconnect()
                    break  # Stop testing once we find the lowest accepted level

                except DCERPCException as e:
                    # This auth level was rejected, try next one
                    error_str = str(e).lower()
                    # Handle Kerberos-specific errors - do NOT continue testing
                    # This prevents account lockouts from repeated auth failures
                    if 'kdc' in error_str or 'kerberos' in error_str or 'krb' in error_str:
                        result.error = f'Kerberos auth failed: {e}'
                        result.additional_info['auth_method'] = 'kerberos_failed'
                        result.available = False
                        return result  # Stop testing - Kerberos error means no valid ticket

                    if 'access_denied' in error_str or 'logon_failure' in error_str:
                        # Auth failed - might need higher auth level
                        continue
                    else:
                        # Other DCE error - port might be filtered or not RPC
                        if self._is_verbose(3):
                            print(f"[*] RPC on {host}: DCE error at {level_name}: {e}")
                        continue
                except socket.error as e:
                    # Connection failed - port not open or filtered
                    result.error = f'Socket error: {e}'
                    break
                except Exception as e:
                    # Check for Kerberos errors in generic exceptions
                    error_str = str(e).lower()
                    if 'kdc' in error_str or 'kerberos' in error_str or 'krb' in error_str:
                        result.error = f'Kerberos auth failed: {e}'
                        result.additional_info['auth_method'] = 'kerberos_failed'
                        result.available = False
                        return result  # Stop testing - Kerberos error

                    # Unexpected error - continue to next level
                    if self._is_verbose(3):
                        print(f"[*] RPC on {host}: Error at {level_name}: {e}")
                    continue

            # If no auth level succeeded, RPC is either unavailable or inconclusive
            if lowest_accepted_level is None:
                result.available = False
                result.signing_required = None  # Inconclusive
                if not result.error:
                    result.error = 'Could not determine RPC auth level (all levels rejected or connection failed)'

            # Check if anonymous access worked (null auth with low level)
            if not username and not password and result.available and not signing_required:
                result.anonymous_allowed = True

        except socket.timeout:
            result.error = 'Connection timeout'
            result.available = False
        except Exception as e:
            result.error = str(e)
            result.available = False

        return result

    def _query_endpoints(self, host: str, target_ip: str = None) -> list:
        """Query RPC endpoint mapper for available endpoints"""
        connect_to = self._resolve_ip(host, target_ip)
        try:
            string_binding = f'ncacn_ip_tcp:{connect_to}[135]'
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            rpc_transport.set_connect_timeout(self._get_timeout())

            dce = rpc_transport.get_dce_rpc()
            dce.connect()

            # Bind to endpoint mapper
            dce.bind(epm.MSRPC_UUID_PORTMAP)

            # Get endpoint map
            resp = epm.hept_lookup(dce, inquiry_type=epm.RPC_C_EP_ALL_ELTS)

            endpoints = []
            for entry in resp:
                try:
                    # Extract endpoint info
                    binding = epm.PrintStringBinding(entry['tower']['Floors'])
                    uuid = str(entry['tower']['Floors'][0])
                    endpoints.append({
                        'uuid': uuid,
                        'binding': binding
                    })
                except Exception:
                    pass

            dce.disconnect()
            return endpoints

        except Exception as e:
            if self._is_verbose(3):
                print(f"[!] Error querying EPM on {host}: {e}")
            return []
