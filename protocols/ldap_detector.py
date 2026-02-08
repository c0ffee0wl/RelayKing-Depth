"""
LDAP/LDAPS Protocol Detector
Detects LDAP signing and channel binding requirements
"""

from typing import Optional
from ldap3 import Server, Connection, NTLM, SIMPLE, ANONYMOUS, ALL, Tls
import ssl
from .base_detector import BaseDetector, ProtocolResult


class LDAPDetector(BaseDetector):
    """Detector for LDAP/LDAPS protocols"""

    def detect(self, host: str, port: int = 389, use_ssl: bool = False, target_ip: str = None) -> ProtocolResult:
        """Detect LDAP configuration using RelayInformer-style detection"""

        connect_to = self._resolve_ip(host, target_ip)
        protocol = 'ldaps' if use_ssl else 'ldap'
        result = self._create_result(protocol, host, port)

        # Check if port is open first
        if not self._is_port_open(host, port, target_ip=target_ip):
            result.error = 'Port closed'
            return result

        try:
            # Check signing and channel binding BEFORE attempting auth
            # This works regardless of whether we have credentials or not
            result.signing_required = self._check_ldap_signing(connect_to)

            if use_ssl:
                result.channel_binding = self._check_ldaps_channel_binding(connect_to)
                # Note if channel binding couldn't be determined due to null auth
                if result.channel_binding is None and self.config.null_auth:
                    result.additional_info['channel_binding_note'] = 'Cannot test channel binding without credentials (--null-auth mode)'
            else:
                result.channel_binding = False  # No channel binding on non-SSL

            # Create TLS object for LDAPS
            tls = None
            if use_ssl:
                tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

            # Create server (use resolved IP for connection)
            server = Server(
                connect_to,
                port=port,
                use_ssl=use_ssl,
                tls=tls,
                get_info=ALL,
                connect_timeout=self._get_timeout()
            )

            # Try authenticated bind (optional - signing/channel binding already determined)
            if not self.config.null_auth:
                # Mark as available since we've already confirmed LDAP is responding
                result.available = True

                # Use Kerberos authentication if --kerberos flag is set (or --krb-dc-only for DCs)
                if self.config.should_use_kerberos(host):
                    result.additional_info['auth_method'] = 'kerberos'
                    try:
                        # Use impacket for Kerberos LDAP authentication
                        from impacket.ldap import ldap as ldap_impacket

                        ldap_url = f"{'ldaps' if use_ssl else 'ldap'}://{connect_to}"
                        ldap_conn = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=self.config.domain, dstIp=connect_to)

                        # Kerberos login - use uppercase domain for realm matching, useCache for ccache
                        krb_domain = self.config.domain.upper() if self.config.domain else ''
                        ldap_conn.kerberosLogin(
                            user=self.config.username,
                            password=self.config.password or '',
                            domain=krb_domain,
                            lmhash=self.config.lmhash,
                            nthash=self.config.nthash,
                            aesKey=self.config.aesKey,
                            kdcHost=self.config.dc_ip,
                            useCache=True
                        )

                        if self._is_verbose(2):
                            result.additional_info['kerberos_auth'] = 'success'
                    except Exception as e:
                        error_str = str(e)
                        if self._is_verbose(2):
                            result.additional_info['bind_error'] = error_str
                        # Handle Kerberos-specific errors - do NOT fallback to NTLM
                        # This prevents account lockouts from repeated auth failures
                        krb_error = error_str.lower()
                        if 'kdc' in krb_error or 'kerberos' in krb_error or 'krb' in krb_error:
                            result.error = f'Kerberos auth failed: {error_str}'
                            result.additional_info['auth_method'] = 'kerberos_failed'
                            # Return early - don't retry with NTLM
                            return result
                else:
                    # NTLM authentication (existing logic)
                    result.additional_info['auth_method'] = 'ntlm'
                    try:
                        user = f"{self.config.domain}\\{self.config.username}"
                        conn = Connection(
                            server,
                            user=user,
                            password=self.config.password or '',
                            authentication=NTLM
                        )

                        if conn.bind():
                            # Bind successful - get server info if in verbose mode
                            if self._is_verbose(2) and server.info:
                                result.additional_info['naming_contexts'] = str(server.info.naming_contexts)
                                result.additional_info['vendor'] = str(server.info.vendor_name) if server.info.vendor_name else None
                            conn.unbind()
                        else:
                            # Bind failed - check if it's a credential issue
                            result_str = str(conn.result)
                            if "data 52e" in result_str or "data 532" in result_str:
                                result.error = 'Invalid credentials'
                            # Otherwise, signing/channel binding likely caused failure, which we've already detected
                    except Exception as e:
                        # Connection error - don't override the signing/channel binding results
                        if self._is_verbose(2):
                            result.additional_info['bind_error'] = str(e)

            else:
                # Null auth mode - test if anonymous access works
                # Signing/channel binding already checked before this point
                conn = Connection(server, authentication=ANONYMOUS)
                if conn.bind():
                    result.available = True
                    result.anonymous_allowed = True
                    conn.unbind()
                else:
                    # Anonymous bind failed - port is open but can't test further
                    result.available = True

        except Exception as e:
            result.error = str(e)

        return result

    def _check_ldap_signing(self, host: str) -> Optional[bool]:
        """
        Check if LDAP signing is enforced by attempting bind with signing=False
        Returns True if signing is required, False if not required, None if unknown
        """
        try:
            from impacket.ldap import ldap as ldap_impacket

            if self._is_verbose(3):
                import sys
                print(f"[DEBUG] LDAP signing check: host={host}, domain={self.config.domain}", file=sys.stderr)

            # Try to bind to regular LDAP (non-SSL) without signing
            ldap_url = f"ldap://{host}"
            # Create connection - by default impacket doesn't enforce signing
            # Note: avoid passing signing= kwarg as it's not supported in all impacket versions
            ldap_conn = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=self.config.domain, dstIp=host)

            # Attempt login with just domain (no credentials)
            # We just want to see if strongerAuthRequired error occurs
            ldap_conn.login(domain=self.config.domain or "")

            # If we get here without error, signing is NOT required
            if self._is_verbose(3):
                import sys
                print(f"[DEBUG] LDAP signing check: SUCCESS - signing NOT required", file=sys.stderr)
            return False

        except Exception as e:
            error_str = str(e).lower()

            if self._is_verbose(3):
                import sys
                print(f"[DEBUG] LDAP signing check: Exception: {type(e).__name__}: {e}", file=sys.stderr)

            if "strongerauthrequired" in error_str or "stronger" in error_str:
                # Signing is enforced
                if self._is_verbose(3):
                    import sys
                    print(f"[DEBUG] LDAP signing check: ENFORCED", file=sys.stderr)
                return True
            elif "ntlm" in error_str and ("disabled" in error_str or "not supported" in error_str or "unavailable" in error_str):
                # NTLM authentication is disabled - can't determine signing requirement
                if self._is_verbose(3):
                    import sys
                    print(f"[DEBUG] LDAP signing check: NTLM disabled - returning None", file=sys.stderr)
                return None
            else:
                # Other error - can't reliably determine signing requirement
                # Conservative: return None (unknown) rather than assuming not required
                if self._is_verbose(3):
                    import sys
                    print(f"[DEBUG] LDAP signing check: Unknown error - returning None", file=sys.stderr)
                return None

    def _check_ldaps_channel_binding(self, host: str) -> Optional[bool]:
        """
        Check LDAPS channel binding enforcement using ldap3 (like RelayInformer)
        Returns True if enforced, False if not enforced, None if unknown

        Uses ldap3 because it doesn't auto-calculate channel binding,
        unlike impacket which silently handles it for us.

        NOTE: This test REQUIRES credentials. Cannot test channel binding with --null-auth.
        """
        try:
            # Must have credentials for this test (password or hash)
            if self.config.null_auth:
                return None  # Cannot test channel binding without credentials

            if not self.config.username:
                return None

            # Need either password or NTLM hash
            if not self.config.password and not self.config.nthash:
                return None

            # Use ldap3 for the test (like RelayInformer does)
            # ldap3 won't auto-calculate channel binding, so we get accurate results
            tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            ldap_server = Server(host, use_ssl=True, port=636, get_info=ALL, tls=tls)
            user = f"{self.config.domain}\\{self.config.username}"

            # Use password if available, otherwise can't use ldap3 for hash auth easily
            # ldap3 doesn't natively support pass-the-hash for NTLM
            if not self.config.password:
                # For hash authentication, we cannot use ldap3 - return None
                return None

            ldap_conn = Connection(ldap_server, user=user, password=self.config.password, authentication=NTLM)

            # Try to bind - ldap3 with NTLM won't send channel binding by default
            if not ldap_conn.bind():
                # Bind failed - check the error
                result_str = str(ldap_conn.result)

                # Check for channel binding error (SEC_E_BAD_BINDINGS)
                if "data 80090346" in result_str:
                    return True

                # Check for invalid credentials (AD error code 52e)
                elif "data 52e" in result_str:
                    return False

                # Other error - likely NTLM disabled
                else:
                    return None
            else:
                # Bind succeeded - channel binding is NOT enforced
                ldap_conn.unbind()
                return False

        except Exception:
            # Connection failed - can't determine
            return None


class LDAPSDetector(LDAPDetector):
    """Detector specifically for LDAPS"""

    def detect(self, host: str, port: int = 636, target_ip: str = None) -> ProtocolResult:
        """Detect LDAPS configuration"""
        return super().detect(host, port, use_ssl=True, target_ip=target_ip)
