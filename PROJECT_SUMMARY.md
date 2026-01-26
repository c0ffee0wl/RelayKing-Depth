# RelayKing - Project Summary

## Overview
RelayKing is a comprehensive NTLM & Kerberos relay detection tool built to identify relay attack opportunities in Active Directory environments. It provides extensive protocol detection, coercion vulnerability assessment, and relay path analysis.

## Project Structure

```
relayking/
├── relayking.py                    # Main entry point
├── setup.py                        # Installation script
├── requirements.txt                # Python dependencies
├── LICENSE                         # MIT License
├── README.md                       # Project documentation
├── USAGE.md                        # Detailed usage guide
├── .gitignore                      # Git ignore rules
├── targets.txt.example             # Example targets file
│
├── core/                           # Core functionality
│   ├── __init__.py
│   ├── banner.py                   # ASCII art banner
│   ├── config.py                   # Configuration & argument parsing
│   ├── target_parser.py            # Target parsing (CIDR, ranges, AD enum)
│   ├── scanner.py                  # Main scanning orchestration
│   └── relay_analyzer.py           # Relay path analysis
│
├── protocols/                      # Protocol-specific detectors
│   ├── __init__.py
│   ├── base_detector.py            # Base detector class
│   ├── smb_detector.py             # SMB/SMB2/SMB3 detection
│   ├── http_detector.py            # HTTP/HTTPS detection
│   ├── ldap_detector.py            # LDAP/LDAPS detection
│   ├── mssql_detector.py           # MSSQL detection
│   └── additional_detectors.py     # SMTP/IMAP/WINRM detection
│
├── detectors/                      # Specialized detectors
│   ├── __init__.py
│   ├── webdav_detector.py          # WebDAV/WebClient detection
│   ├── ntlm_reflection.py          # NTLM reflection detection
│   └── coercion.py                 # Coercion vulnerability detection
│
└── output/                         # Output formatters
    ├── __init__.py
    └── formatters.py               # Multi-format output support
```

## Key Components

### 1. Core Modules

#### Banner (`core/banner.py`)
- ASCII art banner with branding
- Displayed on tool startup

#### Configuration (`core/config.py`)
- Command-line argument parsing
- Configuration management
- Validation of user inputs

#### Target Parser (`core/target_parser.py`)
- Parse targets from various formats:
  - Individual IPs/hostnames
  - CIDR notation (e.g., 10.0.0.0/24)
  - IP ranges (e.g., 10.0.0.1-254)
  - Text files
- Active Directory computer enumeration via LDAP
- Target deduplication

#### Scanner (`core/scanner.py`)
- Main orchestration engine
- Multi-threaded scanning
- Protocol detection coordination
- WebDAV detection
- NTLM reflection detection
- Coercion vulnerability detection
- Results aggregation

#### Relay Analyzer (`core/relay_analyzer.py`)
- Identifies viable relay attack paths
- Prioritizes by impact (critical/high/medium/low)
- Cross-protocol relay detection
- NTLMv1 relay path analysis
- SCCM/ADCS server identification

### 2. Protocol Detectors

#### Base Detector (`protocols/base_detector.py`)
- Abstract base class for all detectors
- Common interface for protocol detection
- Standardized result format (ProtocolResult dataclass)

#### SMB Detector (`protocols/smb_detector.py`)
- SMB/SMB2/SMB3 version detection
- Signing requirement check
- Channel binding support (SMB 3.1.1+)
- NTLMv1 support detection
- Anonymous/null session testing

#### HTTP Detector (`protocols/http_detector.py`)
- HTTP/HTTPS support
- EPA (Extended Protection) detection
- Channel binding detection (HTTPS)
- NTLM authentication presence
- SSL/TLS information gathering

#### LDAP Detector (`protocols/ldap_detector.py`)
- LDAP/LDAPS support
- Signing requirement check
- Channel binding detection (LDAPS)
- Domain Controller identification
- Anonymous bind testing

#### MSSQL Detector (`protocols/mssql_detector.py`)
- MSSQL service detection
- EPA enforcement check
- Encryption/channel binding detection

#### Additional Detectors (`protocols/additional_detectors.py`)
- SMTP detection
- IMAP/IMAPS detection
- WINRM/WINRMS detection

### 3. Specialized Detectors

#### WebDAV Detector (`detectors/webdav_detector.py`)
- WebClient service detection
- Uses DAV RPC Service pipe method
- Based on NetExec webdav module logic
- Critical for coercion attack identification

#### NTLM Reflection Detector (`detectors/ntlm_reflection.py`)
- Identifies NTLM reflection vulnerabilities
- Checks SMB signing status
- Checks HTTP EPA status
- Analyzes reflection attack paths

#### Coercion Detector (`detectors/coercion.py`)
- PetitPotam (MS-EFSRPC) detection
- PrinterBug (MS-RPRN/SpoolService) detection
- DFSCoerce (MS-DFSNM) detection
- Null authentication coercion support
- Authenticated coercion support
- Relay path integration

### 4. Output Formatters

#### Multi-Format Support (`output/formatters.py`)
- **Plaintext**: Human-readable format with sections
- **JSON**: Structured data for programmatic use
- **XML**: Hierarchical data format
- **CSV**: Spreadsheet-compatible format
- **Grep-able**: One-line-per-result for easy filtering
- **Markdown**: Documentation-ready format with tables

## Technical Implementation Details

### Threading Model
- Uses `concurrent.futures.ThreadPoolExecutor`
- Configurable thread pool size (default: 10)
- Thread-safe result aggregation
- Graceful exception handling per thread

### Error Handling
- Try-catch blocks around all network operations
- Graceful degradation (partial results on errors)
- Detailed error reporting in verbose mode
- Connection timeouts (configurable, default: 5s)

### Dependencies
- **Impacket**: Protocol implementations (SMB, LDAP, MSSQL, RPC)
- **Requests**: HTTP/HTTPS operations
- **dnspython**: DNS resolution
- **ldap3**: LDAP operations (backup option)
- **pyasn1**: ASN.1 encoding/decoding

### Detection Logic

#### Signing Detection
- SMB: Uses Impacket's `isSigningRequired()` method
- LDAP: Heuristic based on anonymous bind + DC detection
- HTTP: N/A (uses EPA instead)

#### EPA Detection
- HTTP/HTTPS: Checks for channel binding requirements
- MSSQL: Attempts connection with/without EPA
- Conservative approach (assumes enabled when uncertain)

#### Channel Binding Detection
- SMB: SMB 3.1.1+ dialect detection
- LDAPS: Assumed enabled for modern servers
- HTTPS: TLS channel binding capability check

#### WebDAV Detection
- Attempts to open `DAV RPC SERVICE` pipe in IPC$
- Based on @tifkin_'s technique
- Works with both authenticated and null sessions

#### Coercion Detection
- Connects to specific RPC pipes:
  - `\pipe\efsrpc` for PetitPotam
  - `\pipe\spoolss` for PrinterBug
  - `\pipe\netdfs` for DFSCoerce
- Works with null auth (PetitPotam, DFSCoerce) or credentials

### Relay Path Analysis Algorithm

1. **Identify Sources**: Find protocols without signing/EPA
2. **Identify Destinations**: Find accessible protocols
3. **Cross-Reference**: Match sources to destinations
4. **Prioritize**: Assign impact levels
5. **Filter**: Remove impossible/redundant paths
6. **Output**: Present sorted by priority

Priority calculation:
- LDAP/LDAPS without protections: CRITICAL
- SMB/MSSQL without protections: HIGH
- HTTP/HTTPS without EPA: MEDIUM
- Other protocols: LOW
- Cross-host relay: +1 priority
