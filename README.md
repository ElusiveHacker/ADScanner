# Active Directory Enumeration Bash Script

This Bash wrapper script automates the enumeration of a single host using tools like `enum4linux`, `enum4linux-ng`, `netexec`, and LDAP query tools. It intelligently checks for open ports, tests connectivity, and runs enumeration commands only when relevant services (SMB, LDAP, MSSQL, WinRM) are available. The script supports optional credentials and domain input for authenticated enumeration and saves results in a structured output directory. This is very important, in order to increase speed in a CTF and even certificates, such as CREST Registered Tester and OSCP and OSCP+. Since all exames are not moving to proper Active Directory enumeration.

## Cheetsheets used to write the tool
-  NetExec: https://pentesting.site/cheat-sheets/netexec/
-  StationX: https://www.stationx.net/netexec-cheat-sheet/
-  BlWasp: https://github.com/BlWasp/NetExec-Cheatsheet
-  Netexec Wiki: https://www.netexec.wiki/getting-started/selecting-and-using-a-protocol

⚠️ **Important**: Use this script only with explicit permission to scan the target system. Unauthorized scanning may be illegal and violate network policies.

# ADScanner.sh

A powerful Bash-based **Active Directory enumeration tool** designed for penetration testers and red teamers. `ADScanner.sh` automates the enumeration of a Windows domain environment using tools like `netexec`, `enum4linux`, `impacket`, `nmap`, and others.

---

## 🚀 Features

- Auto-detects open ports using `nmap`
- Modular execution based on open services
- Supports SMB, LDAP, WinRM, MSSQL, FTP, SSH enumeration
- Kerberoasting support using Impacket's `GetUserSPNs`
- Output logs and reports organized in `tool_outputs/`
- Consolidated report log
- Quiet mode for cleaner output
- Configurable via `config.sh` (optional)
---

| Option    | Description               |
| --------- | ------------------------- |
| `-i`      | Target IP address         |
| `-u`      | Username                  |
| `-p`      | Password                  |
| `-d`      | Domain name               |
| `--quiet` | Suppress output to stdout |

---
## ⚙️ Usage 
```
sudo ./ADScanner.sh -i <IP_ADDRESS> -u <USERNAME> -p <PASSWORD> -d <DOMAIN>
```
---
## 📁 Output

    - Tool-specific outputs are saved in: tool_outputs/

    - Consolidated log: ADScanner.log

    - Final summary report: YYYYMMDD_HHMM_report.txt
---

## 📦 Requirements

- Bash version **5.2.37**
- Root privileges (`sudo`)
- Tools:
  - `nmap`
  - `netexec` (successor of CrackMapExec)
  - `enum4linux` and `enum4linux-ng`
  - `impacket-GetUserSPNs`
  - `ntpdate` (for clock sync)
  - `smbclient` (optional fallback for time sync)

Ensure all tools are installed and in your `$PATH`.

---

## 🛠️ Installation

```bash
git clone https://github.com/yourusername/ADScanner.sh.git
cd ADScanner.sh
chmod +x ADScanner.sh
```

## Notes
- The script assumes tools are in the system’s PATH.

- Anonymous LDAP binds are attempted if no credentials are provided, which may yield limited results.

- Customize port lists or tool options (e.g., file patterns for netexec --spider) in the script as needed.

- Extend the script by adding tools like smbclient or additional netexec modules.

## Troubleshooting

- Tool not found: Ensure all required tools are installed and accessible.

- Port check fails: Verify network connectivity and firewall settings.

- Permission denied: Run the script with sudo if necessary for network operations.

## Contributing

Contributions are welcome! Please:

- Fork the repository.

- Create a feature branch (git checkout -b feature/YourFeature).

- Commit changes (git commit -m "Add YourFeature").

- Push to the branch (git push origin feature/YourFeature).

- Open a pull request.

## License
This project is licensed under the Apache 2 License. See the LICENSE file for details.

## Disclaimer
This script is for educational and authorized testing purposes only. Unauthorized use against systems you do not own or have permission to scan may violate laws and policies. The author is not responsible for misuse or damages caused by this script.


