
# ADScanner.sh - Active Directory Enumeration Script

`ADScanner.sh` is a powerful Bash script designed for Active Directory enumeration during internal penetration testing or red team engagements. It wraps and automates tools such as **netexec**, **Impacket**, and **nmap** to extract information, detect vulnerabilities, and streamline reporting.

---

## 🚀 Features

- 🔐 SMB, LDAP, Kerberos, MSSQL, and WinRM enumeration via `netexec`
- 🧰 Impacket tool integrations (Kerberoasting, AS-REP roasting, SID bruteforce, etc.)
- 🔎 Nmap TCP port scanning with automatic module execution based on open ports
- 📡 Host availability and time synchronization with domain controllers
- 🧾 Log and structured report generation
- 🧩 Configurable via `config.sh` (optional)
- 🔕 Quiet mode for clean output in automation pipelines

---

## 📦 Dependencies

Make sure the following tools are installed:

- `bash` (v5+ recommended)
- `nmap`
- `netexec` (preferred over `crackmapexec`)
- `impacket` (Python-based tools like `GetUserSPNs.py`, `GetNPUsers.py`, etc.)
- `ntpdate`
- `nc` (netcat)

---

## 🛠️ Usage

```bash
sudo ./ADScanner.sh [options]
```

### Options

| Flag          | Description                                      |
|---------------|--------------------------------------------------|
| `-i <IP>`     | Target Domain Controller IP (required)          |
| `-u <USER>`   | Username for authentication (optional)          |
| `-p <PASS>`   | Password for authentication (optional)          |
| `-d <DOMAIN>` | Domain name (e.g., example.local) (optional)    |
| `-k <KDCHOST>`| KDC hostname (for Kerberos auth) (optional)     |
| `-f <ADFQDN>` | AD FQDN (Kerberos ticketing) (optional)         |
| `--quiet`     | Quiet mode (minimal terminal output)            |
| `-h, --help`  | Display help                                     |

### Example

```bash
sudo ./ADScanner.sh -i 192.168.1.10 -u admin -p Passw0rd -d example.local -k dc.example.local -f example.local
```

---

## 🔍 Modules Executed

### ✅ Netexec - SMB (NTLM & Kerberos)

- User/group enumeration
- Password policies
- Vulnerability modules:
  - `gpp_password`, `spooler`, `webdav`, `printnightmare`, `ms17-010`
  - `zerologon`, `veeam`, `coerce_plus`, `enum_ca`, `enum_av`
- Hash & secrets dumping (SAM, LSA, NTDS.dit)

### ✅ Netexec - LDAP

- Trusts, sites, subnets, PSOs
- LAPS retrieval
- Password attribute hunting (`userPassword`, `unixUserPassword`)
- Group membership
- DACL read for privilege escalation

### ✅ Impacket Integration

The script automates execution of key Impacket tools when credentials are available:

| Tool                | Description                                              |
|---------------------|----------------------------------------------------------|
| `GetUserSPNs.py`    | Kerberoasting - lists SPNs with Kerberos auth enabled    |
| `GetNPUsers.py`     | AS-REP Roasting (users with `Do not require preauth`)    |
| `lookupsid.py`      | SID bruteforce and enumeration                           |
| `samrdump.py`       | Dumps user/group info from DC over SMB                   |
| `secretsdump.py`    | Dumps NTDS/SAM/LSA hashes (Admin required)               |
| `wmiexec.py`        | Remote command execution via WMI                         |

Execution is conditional based on port availability and credentials.

---

## 📁 Output

- Tool results saved in `tool_outputs/`
- Combined report: `YYYYMMDD_HHMM_report.txt`
- Log file: `ADScanner.log`

---

## 🧩 Configuration

You can create a `config.sh` file in the script directory to predefine values such as:

```bash
IP="192.168.1.10"
USERNAME="admin"
PASSWORD="Passw0rd"
DOMAIN="example.local"
KDCHOST="dc.example.local"
ADFQDN="example.local"
```

---

## ⚠️ Disclaimer

This script is for **authorized security assessments** and **educational purposes only**. Unauthorized use is prohibited.

---

## 🧠 Credits

- [Impacket](https://github.com/fortra/impacket)
- [Netexec](https://github.com/Pennyw0rth/NetExec)
- [Nmap](https://nmap.org)

---

## 🧪 To Do

- Add BloodHound data collection support
- LDAP brute-force options
- HTML report output
