# Host Enumeration Bash Script

This Bash wrapper script automates the enumeration of a single host using tools like `enum4linux`, `enum4linux-ng`, `netexec`, and LDAP query tools. It intelligently checks for open ports, tests connectivity, and runs enumeration commands only when relevant services (SMB, LDAP, MSSQL, WinRM) are available. The script supports optional credentials and domain input for authenticated enumeration and saves results in a structured output directory.

⚠️ **Important**: Use this script only with explicit permission to scan the target system. Unauthorized scanning may be illegal and violate network policies.

## Features

- **Mandatory Input**: Target IP address.
- **Optional Inputs**: Username, password, and domain name for authenticated enumeration.
- **Port Checking**: Scans for open ports (SMB: 137, 138, 139, 445; LDAP: 389, 636; MSSQL: 1433; WinRM: 5985, 5986) before running tools.
- **Connectivity Testing**: Verifies host reachability using `ping`.
- **Supported Tools**:
  - `enum4linux -a`: Comprehensive SMB enumeration.
  - `enum4linux-ng`: Modern SMB enumeration.
  - `netexec smb`: Enumerates shares, RID brute-forcing, and spiders shares for files (e.g., `*.txt`, `*.conf`).
  - `netexec ldap`, `mssql`, `winrm`: Runs specific modules if respective ports are open.
  - `ldapsearch` and `nmap --script=ldap-rootdse`: Queries LDAP for hidden passwords and usernames when LDAP ports are open.
- **Output Management**: Saves results in a directory (`enum_results_<IP>`) with separate files for each tool.
- **Optimizations**: Limits scans to open ports, uses timeouts, and focuses on relevant file patterns for spidering.

## Prerequisites

- **Operating System**: Linux with Bash (tested on Ubuntu/Debian).
- **Tools**:
  - `enum4linux`
  - `enum4linux-ng`
  - `netexec` (formerly `crackmapexec`)
  - `ldapsearch` (part of `ldap-utils`)
  - `nmap`
- **Dependencies**: Bash with `/dev/tcp` support for port checking.
- **Permissions**: Run as a user with sufficient privileges for network scanning.

Install dependencies on Debian/Ubuntu:
```bash
sudo apt update
sudo apt install enum4linux nmap ldap-utils
pip install enum4linux-ng netexec# ADScanner
Scanning ADs for CTFs
