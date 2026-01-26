"""
WebDAV/WebClient Detector
Detects if the WebClient service is running (DAV RPC SERVICE pipe)
Based on NetExec webdav module logic
"""

from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport


class WebDAVDetector:
    """Detector for WebDAV/WebClient service"""

    def __init__(self, config):
        self.config = config

    def detect(self, host: str) -> dict:
        """
        Detect WebDAV/WebClient service

        Returns:
            dict with 'enabled' bool and optional 'error' str
        """
        result = {
            'enabled': False,
            'error': None
        }

        try:
            # Try to connect to the DAV RPC SERVICE pipe
            # This technique is from @tifkin_
            # The pipe is: \\pipe\\DAV RPC SERVICE

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

            # Connect to SMB
            conn = SMBConnection(host, host, timeout=self.config.timeout)

            try:
                # Login - use Kerberos if specified
                if use_kerberos:
                    krb_domain = domain.upper() if domain else ''
                    try:
                        conn.kerberosLogin(username, password, krb_domain, lmhash, nthash, aesKey, dc_ip, useCache=True)
                    except Exception as krb_err:
                        # Handle Kerberos-specific errors - do NOT fallback to NTLM
                        krb_error = str(krb_err).lower()
                        if 'kdc' in krb_error or 'kerberos' in krb_error or 'krb' in krb_error:
                            result['error'] = f'Kerberos auth failed: {krb_err}'
                            return result
                        raise
                elif nthash:
                    conn.login(username, '', domain, lmhash, nthash)
                else:
                    conn.login(username, password, domain)

                # Try to open the DAV RPC SERVICE pipe in IPC$
                # If this succeeds, WebClient is running
                try:
                    tid = conn.connectTree('IPC$')

                    # Try to open the DAV RPC SERVICE pipe
                    try:
                        fid = conn.openFile(tid, 'DAV RPC SERVICE', desiredAccess=0x12019f, shareMode=0x7)
                        # If we get here, the pipe exists and WebClient is running
                        result['enabled'] = True

                        # Close the file handle
                        conn.closeFile(tid, fid)

                    except Exception as e:
                        # Pipe doesn't exist - WebClient not running
                        error_str = str(e).lower()
                        if 'status_object_name_not_found' in error_str or 'object_name_not_found' in error_str:
                            result['enabled'] = False
                        else:
                            # Other error
                            result['error'] = f'Pipe check failed: {e}'

                    conn.disconnectTree(tid)

                except Exception as e:
                    result['error'] = f'IPC$ connection failed: {e}'

                conn.close()

            except Exception as e:
                error_str = str(e).lower()
                if 'status_logon_failure' in error_str or 'access_denied' in error_str:
                    result['error'] = 'Authentication failed'
                else:
                    result['error'] = str(e)

        except Exception as e:
            result['error'] = str(e)

        return result
