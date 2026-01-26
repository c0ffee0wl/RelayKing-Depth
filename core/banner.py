"""
RelayKing Banner
ASCII art and branding
"""

# ANSI color codes
RED = '\033[31m'  # Darker red
KING_RED = '\033[38;5;124m'  # Even darker red for KING
TEAL = '\033[96m'
RESET = '\033[0m'

def print_banner():
    """Print the RelayKing ASCII banner"""
    banner = f"""
██████╗ ███████╗██╗      █████╗ ██╗   ██╗{KING_RED}██╗  ██╗██╗███╗   ██╗ ██████╗{RESET}
██╔══██╗██╔════╝██║     ██╔══██╗╚██╗ ██╔╝{KING_RED}██║ ██╔╝██║████╗  ██║██╔════╝{RESET}
██████╔╝█████╗  ██║     ███████║ ╚████╔╝ {KING_RED}█████╔╝ ██║██╔██╗ ██║██║  ███╗{RESET}
██╔══██╗██╔══╝  ██║     ██╔══██║  ╚██╔╝  {KING_RED}██╔═██╗ ██║██║╚██╗██║██║   ██║{RESET}
██║  ██║███████╗███████╗██║  ██║   ██║   {KING_RED}██║  ██╗██║██║ ╚████║╚██████╔╝{RESET}
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   {KING_RED}╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝{RESET}

{RED}Dominate the domain. Relay to royalty.{RESET}

    NTLM & Kerberos Relay | Signing/EPA/Channel Binding Enumeration
    NTLMv1/WebDAV/Unauth Coercion/NTLM Reflection Detection

    Version 1.0 | by {TEAL}Logan Diomedi - Depth Security (www.depthsecurity.com){RESET}
"""
    print(banner)
