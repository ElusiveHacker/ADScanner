# Active Directory Enumeration Bash Script

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
```
Clone the repository:
```bash
git clone https://github.com/<your-username>/host-enum-script.git
cd ADScanner
```
Make the script executable:
```bash
chmod +x ADScanner.sh
```
Usage

Run the script with the mandatory IP address and optional credentials/domain:

./ADScanner.sh -i <IP> [-u <username>] [-p <password>] [-d <domain>]

Options

-i <IP>: Target IP address (mandatory).

-u <username>: Username for authenticated enumeration (optional).

-p <password>: Password for authenticated enumeration (optional).

-d <domain>: Domain name (e.g., EXAMPLE.COM) (optional).

Examples

Basic enumeration (no credentials):

./ADScanner.sh -i 192.168.1.100

Authenticated enumeration with domain:

./ADScanner.sh -i 192.168.1.100 -u "admin" -p "Password123" -d "EXAMPLE.COM"

Output

Results are saved in a directory named enum_results_<IP> with files like:

enum4linux-445.output

netexec_smb_shares-445.output

ldapsearch-389.output

Notes
The script assumes tools are in the system’s PATH.

Anonymous LDAP binds are attempted if no credentials are provided, which may yield limited results.

Customize port lists or tool options (e.g., file patterns for netexec --spider) in the script as needed.

Extend the script by adding tools like smbclient or additional netexec modules.

Troubleshooting
Tool not found: Ensure all required tools are installed and accessible.

Port check fails: Verify network connectivity and firewall settings.

Permission denied: Run the script with sudo if necessary for network operations.

Contributing
Contributions are welcome! Please:
Fork the repository.

Create a feature branch (git checkout -b feature/YourFeature).

Commit changes (git commit -m "Add YourFeature").

Push to the branch (git push origin feature/YourFeature).

Open a pull request.

License
This project is licensed under the MIT License. See the LICENSE file for details.
Disclaimer
This script is for educational and authorized testing purposes only. Unauthorized use against systems you do not own or have permission to scan may violate laws and policies. The author is not responsible for misuse or damages caused by this script.


