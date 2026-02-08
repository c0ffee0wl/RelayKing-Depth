# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

RelayKing is an NTLM relay detection and enumeration tool for Active Directory pentesting/auditing. It scans multiple protocols (SMB, LDAP, HTTP, MSSQL, RPC, etc.) to identify relay attack paths, signing/EPA/channel-binding enforcement, NTLMv1 support, WebDAV services, NTLM reflection vulnerabilities (CVE-2025-33073), and coercion vectors (PetitPotam, PrinterBug, DFSCoerce).

## Setup & Running

```bash
virtualenv --python=python3 .venv && source .venv/bin/activate
pip3 install -r requirements.txt
python3 relayking.py -h
python3 verify_installation.py   # validates deps, modules, syntax
```

There are no tests, linters, or CI/CD pipelines. `verify_installation.py` is the only validation tool.

## Architecture

**Entry point:** `relayking.py` → `main()` parses args, creates `RelayKingScanner`, runs scan, formats output, optionally generates ntlmrelayx relay list.

**Data flow:**
```
relayking.py
  → core/config.py        parse_arguments() → RelayKingConfig dataclass
  → core/scanner.py        RelayKingScanner.scan() orchestrates everything
    → core/target_parser.py   TargetParser: CIDR/range/file/AD-LDAP enumeration + DNS resolution
    → core/port_scanner.py    FastPortScanner: optional pre-scan (--proto-portscan)
    → protocols/*_detector.py  Per-protocol detection (SMB, LDAP, HTTP, MSSQL, RPC, etc.)
    → detectors/*              WebDAV, NTLMv1, NTLM Reflection, Coercion checks
    → core/relay_analyzer.py   RelayAnalyzer: identifies relay paths + impact ratings
  → output/formatters.py    Multi-format output (plaintext, json, xml, csv, grep, markdown)
```

**Key design pattern:** All protocol detectors inherit from `BaseDetector` (in `protocols/base_detector.py`) and implement `detect(host, target_ip=None) → ProtocolResult`. The `ProtocolResult` dataclass has an `is_relayable()` method with protocol-specific logic. The scanner passes resolved IPs separately from hostnames so that hostnames are preserved for Kerberos SPN / SMB negotiation while IPs are used for TCP connections.

**Hostname-to-IP mapping:** `TargetParser.hostname_ip_map` stores DNS-resolved IPs (using the custom `-ns` nameserver if provided via dnspython). This mapping is passed through to the port scanner and all protocol detectors so that custom DNS resolution works end-to-end, not just for the DNS validation step.

**Threading model:** `--threads` (default 10) controls main scanner parallelism. HTTP path enumeration spawns 20 sub-threads per main thread. Port scanning uses 50 threads. NTLMReflectionDetector uses a shared ThreadPoolExecutor(3) with a Semaphore(2) to avoid SMB session exhaustion.

## Important Conventions

- Protocol detectors receive both `host` (hostname for protocol negotiation) and `target_ip` (resolved IP for TCP). For impacket's `SMBConnection`: `SMBConnection(remoteName=host, remoteHost=target_ip)`.
- `RelayKingConfig` is a dataclass, not a dict. Access fields directly (e.g., `config.username`, `config.timeout`).
- `--audit` mode enumerates computers from AD via LDAP using `--dc-ip` directly, then DNS-resolves their `dNSHostName` attributes.
- Kerberos auth uses `config.should_use_kerberos(host)` to decide per-host. `--krb-dc-only` limits Kerberos to DC connections only.
- Coercion detectors distinguish between null-auth (real vulnerability) and authenticated coercion (expected behavior).
- Relay impact levels: CRITICAL (LDAP/LDAPS, ADCS), HIGH (SMB, MSSQL, WebDAV, NTLM reflection), MEDIUM (HTTP/HTTPS), LOW (other).

## Known Limitations

- SMTP, IMAP, WinRM detectors are WIP (partial implementation).
- Unauthenticated EPA/CB checks for MSSQL, HTTPS, WinRMS, LDAPS are unreliable.
- RPC detection can behave unexpectedly on Windows 11 hosts (impacket limitation).
- Tier-0 severity detection may under-rate some relay paths; manual review recommended.
- The tool is very noisy (SIEM/EDR alerts expected in `--audit` mode). Not OPSEC-safe.
