"""
Tier-0 Asset Detector
Detects SCCM, ADCS (Certificate Authorities), and Exchange servers via LDAP queries
"""

from typing import Set


class Tier0Detector:
    """Detects tier-0 assets (SCCM, ADCS, Exchange) in Active Directory"""

    def __init__(self, ldap_connection, domain):
        """
        Initialize Tier0Detector

        Args:
            ldap_connection: Active LDAP connection object
            domain: Domain name (for building search base)
        """
        self.ldap_connection = ldap_connection
        self.domain = domain
        self.search_base = self._get_search_base()

    def _get_search_base(self) -> str:
        """Convert domain name to LDAP DN format"""
        # Convert domain.local to DC=domain,DC=local
        return ','.join([f'DC={part}' for part in self.domain.split('.')])

    def detect_all(self) -> Set[str]:
        """
        Detect all tier-0 assets

        Returns:
            Set of hostnames (lowercase) that are tier-0 assets
        """
        tier0_hosts = set()

        # Detect SCCM servers
        sccm_hosts = self.detect_sccm()
        tier0_hosts.update(sccm_hosts)

        # Detect ADCS servers
        adcs_hosts = self.detect_adcs()
        tier0_hosts.update(adcs_hosts)

        # Detect Exchange servers
        exchange_hosts = self.detect_exchange()
        tier0_hosts.update(exchange_hosts)

        return tier0_hosts

    def detect_sccm(self) -> Set[str]:
        """
        Detect SCCM servers via LDAP query
        Based on SCCMHunter logic

        Returns:
            Set of SCCM server hostnames (lowercase)
        """
        sccm_hosts = set()

        try:
            # Query for SCCM site objects
            # Based on: https://github.com/garrettfoster13/sccmhunter
            search_filter = "(objectclass=mssmssite)"

            self.ldap_connection.search(
                self.search_base,
                search_filter,
                attributes=['mSSMSSiteCode', 'mSSMSMPName', 'mSSMSSiteSystemList', 'mSSMSDefaultMP']
            )

            for entry in self.ldap_connection.entries:
                # Extract management point names
                if hasattr(entry, 'mSSMSMPName') and entry.mSSMSMPName:
                    for mp in entry.mSSMSMPName:
                        hostname = self._extract_hostname(str(mp))
                        if hostname:
                            sccm_hosts.add(hostname.lower())

                # Extract site system list
                if hasattr(entry, 'mSSMSSiteSystemList') and entry.mSSMSSiteSystemList:
                    for system in entry.mSSMSSiteSystemList:
                        hostname = self._extract_hostname(str(system))
                        if hostname:
                            sccm_hosts.add(hostname.lower())

                # Extract default management point
                if hasattr(entry, 'mSSMSDefaultMP') and entry.mSSMSDefaultMP:
                    for mp in entry.mSSMSDefaultMP:
                        hostname = self._extract_hostname(str(mp))
                        if hostname:
                            sccm_hosts.add(hostname.lower())

            if sccm_hosts:
                print(f"[+] Found {len(sccm_hosts)} SCCM server(s)")

        except Exception as e:
            print(f"[-] Error detecting SCCM: {e}")

        return sccm_hosts

    def detect_adcs(self) -> Set[str]:
        """
        Detect ADCS (Certificate Authority) servers via LDAP query
        Based on Certipy logic

        Returns:
            Set of ADCS server hostnames (lowercase)
        """
        adcs_hosts = set()

        try:
            # Query for pKIEnrollmentService objects (Certificate Authorities)
            # Based on: https://github.com/ly4k/Certipy
            search_filter = "(&(objectClass=pKIEnrollmentService))"
            config_path = f"CN=Configuration,{self.search_base}"
            search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_path}"

            self.ldap_connection.search(
                search_base,
                search_filter,
                attributes=['dNSHostName', 'cn', 'name']
            )

            for entry in self.ldap_connection.entries:
                # Extract DNS hostname
                if hasattr(entry, 'dNSHostName') and entry.dNSHostName:
                    hostname = str(entry.dNSHostName.value)
                    adcs_hosts.add(hostname.lower())

            if adcs_hosts:
                print(f"[+] Found {len(adcs_hosts)} ADCS server(s)")

        except Exception as e:
            print(f"[-] Error detecting ADCS: {e}")

        return adcs_hosts

    def detect_exchange(self) -> Set[str]:
        """
        Detect Exchange servers via group membership query

        Returns:
            Set of Exchange server hostnames (lowercase)
        """
        exchange_hosts = set()

        try:
            # Query for "Exchange Trusted Subsystem" group members
            # All Exchange servers are typically members of this group
            search_filter = "(cn=Exchange Trusted Subsystem)"

            self.ldap_connection.search(
                self.search_base,
                search_filter,
                attributes=['member']
            )

            for entry in self.ldap_connection.entries:
                if hasattr(entry, 'member') and entry.member:
                    # Get all members of the group
                    for member_dn in entry.member:
                        # Query the member to get computer object details
                        try:
                            self.ldap_connection.search(
                                self.search_base,
                                f"(distinguishedName={member_dn})",
                                attributes=['objectClass', 'dNSHostName', 'cn']
                            )

                            for member_entry in self.ldap_connection.entries:
                                # Check if it's a computer object
                                if hasattr(member_entry, 'objectClass') and 'computer' in [str(c).lower() for c in member_entry.objectClass]:
                                    if hasattr(member_entry, 'dNSHostName') and member_entry.dNSHostName:
                                        hostname = str(member_entry.dNSHostName.value)
                                        exchange_hosts.add(hostname.lower())
                        except Exception:
                            continue

            if exchange_hosts:
                print(f"[+] Found {len(exchange_hosts)} Exchange server(s)")

        except Exception as e:
            print(f"[-] Error detecting Exchange: {e}")

        return exchange_hosts

    def _extract_hostname(self, value: str) -> str:
        """
        Extract hostname from various LDAP attribute formats

        Args:
            value: String value from LDAP attribute

        Returns:
            Full hostname (FQDN preferred) or empty string
        """
        # Handle ["DISPLAY=\\\\HOSTNAME\\..."] format
        if '\\\\' in value:
            parts = value.split('\\\\')
            if len(parts) >= 2:
                hostname = parts[1].split('\\')[0]
                # Try to return FQDN if we can construct it
                if '.' not in hostname and self.domain:
                    return f"{hostname}.{self.domain}"
                return hostname

        # Handle direct hostname/FQDN - return the full value (don't strip to short name)
        if '.' in value and not value.startswith('CN='):
            return value  # Return full FQDN instead of just first part

        # Handle short hostname
        if value and not value.startswith('CN='):
            # Append domain to make FQDN
            if self.domain:
                return f"{value}.{self.domain}"
            return value

        return ''
