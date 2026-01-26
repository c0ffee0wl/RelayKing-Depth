"""
Base Protocol Detector
Abstract base class for all protocol detectors
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class ProtocolResult:
    """Result from protocol detection"""
    protocol: str
    host: str
    port: int
    available: bool = False
    signing_required: Optional[bool] = False
    epa_enforced: Optional[bool] = False
    channel_binding: Optional[bool] = False
    ntlmv1_supported: bool = False
    anonymous_allowed: bool = False
    version: Optional[str] = None
    error: Optional[str] = None
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def is_relayable(self) -> bool:
        """
        Check if this protocol is relayable (no protections) for CONVENTIONAL NTLM relay.

        Note: This does NOT apply to NTLM reflection attacks (CVE-2025-33073) which have
        different requirements and are handled separately.

        Protocol-specific relay requirements:
        - LDAPS: Channel binding alone prevents conventional relay (even without signing)
                 Signing alone does NOT prevent relay to LDAPS
        - LDAP:  Signing prevents relay. Channel binding on plaintext LDAP forces upgrade
                 to LDAPS, effectively preventing relay.
        - HTTP:  Always relayable (plaintext, no channel binding possible)
        - HTTPS: EPA (channel binding) prevents relay
        - SMB:   Signing prevents relay
        - MSSQL: EPA prevents relay
        - Others: Signing prevents relay
        """
        if not self.available:
            return False

        # Protocol-specific logic
        protocol_lower = self.protocol.lower()

        # LDAPS: Channel binding alone is sufficient to prevent conventional relay
        if protocol_lower == 'ldaps':
            # If NTLMv1 is supported/enabled, channel binding is irrelevant (NTLMv1 doesn't support it)
            if self.ntlmv1_supported:
                # With NTLMv1, only signing matters (can bypass channel binding with --remove-mic)
                if self.signing_required is None:
                    return False  # Conservative
                return not self.signing_required

            # With NTLMv2, channel binding ALONE prevents conventional relay
            # Even if signing is not required, channel binding stops the relay
            if self.channel_binding is None:
                return False  # Conservative - couldn't determine

            # If channel binding is enforced, NOT relayable (regardless of signing)
            if self.channel_binding:
                return False

            # Channel binding not enforced - relayable!
            return True

        # LDAP (plaintext port 389): Signing OR channel binding requirement prevents relay
        elif protocol_lower == 'ldap':
            # If NTLMv1 is supported/enabled, channel binding is irrelevant
            if self.ntlmv1_supported:
                if self.signing_required is None:
                    return False  # Conservative
                return not self.signing_required

            # Check signing first
            if self.signing_required is None:
                return False  # Conservative

            if self.signing_required:
                return False  # Signing enforced = not relayable

            # Channel binding on plaintext LDAP = forces upgrade to LDAPS = not relayable
            # Note: channel_binding for LDAP means the server requires channel binding,
            # which can't be satisfied on plaintext, so connections must upgrade
            if self.channel_binding:
                return False

            # Neither signing nor channel binding enforced - relayable!
            return True

        # HTTP: Always relayable (plaintext, no channel binding possible)
        elif protocol_lower == 'http':
            # HTTP is always relayable - no channel binding possible on plaintext
            return True

        # HTTPS: EPA (channel binding) prevents relay
        elif protocol_lower == 'https':
            if self.epa_enforced is None:
                return False  # Conservative - couldn't determine
            return not self.epa_enforced

        # MSSQL: EPA (Extended Protection) prevents relay
        elif protocol_lower == 'mssql':
            if self.epa_enforced is None:
                return False  # Conservative - couldn't determine (e.g., null auth mode)
            return not self.epa_enforced

        # SMB, RPC, SMTP, IMAP, WinRM, etc: Signing prevents relay
        else:
            if self.signing_required is None:
                return False  # Conservative
            return not self.signing_required


class BaseDetector(ABC):
    """Base class for protocol detectors"""

    def __init__(self, config):
        self.config = config

    @abstractmethod
    def detect(self, host: str) -> ProtocolResult:
        """
        Detect protocol configuration on target host

        Args:
            host: Target hostname or IP

        Returns:
            ProtocolResult with detection findings
        """
        pass

    def _create_result(self, protocol: str, host: str, port: int, **kwargs) -> ProtocolResult:
        """Helper to create a ProtocolResult"""
        return ProtocolResult(protocol=protocol, host=host, port=port, **kwargs)

    def _get_timeout(self) -> int:
        """Get connection timeout from config"""
        return self.config.timeout

    def _is_verbose(self, level: int = 1) -> bool:
        """Check if verbose output is enabled at given level"""
        return self.config.verbose >= level

    def _is_port_open(self, host: str, port: int) -> bool:
        """Check if a port is open"""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # Use 3-second timeout for quick port check
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
