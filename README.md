# ADScanner.sh 🧠🔍

**ADScanner.sh** is an advanced Bash script designed to perform modular Active Directory enumeration against a Domain Controller using tools like `netexec`, `nmap`, and `ntpdate`. It handles pre-checks, port scanning, Kerberos setup, time synchronization, and optional credential-based enumeration.

> ⚠️ Requires **root privileges** for full functionality.

---

## 📦 Features

- 🔒 Active Directory Enumeration via `netexec`
- 🔐 Kerberos Configuration (`/etc/krb5.conf`)
- 🕒 Clock Synchronization using `ntpdate`
- 🚪 Port Scanning with `nmap`
- 📄 Clean output logs and structured report files
- ⚙️ Configurable via `config.sh`
- 💬 Quiet mode for silent operation

---

## 🧰 Requirements

- `bash` (Tested on GNU Bash 5.2.37)
- `nmap`
- `netexec` (formerly `crackmapexec`)
- `ntpdate`
- `netcat`
- `impacket`
- `ldapsearch`
- Root access (or `sudo`)
- (Optional) `config.sh` for persistent configuration

---

## 🚀 Usage

```bash
sudo ./ADScanner.sh -i <IP> -u <useranem> -p <password> -d <domain> -f <fqdn>
```

| Flag         | Description                                                     |
| ------------ | ----------------------------------------------------------------|
| `-i <IP>`    | Target IP address of the Domain Controller (required)           |
| `-u`         | Username for authentication (optional)                          |
| `-p`         | Password for authentication (optional)                          |
| `-d`         | Domain name e.g., example.local (optional)                      |
| `-k`         | KDC hostname for Kerberos authentication (required for kerberos)|
| `-f`         | AD FQDN required for Kerberos ticketing (required for kerberos) |
| `--quiet`         | Suppress most terminal output (optional)                   |
| ` -h, --help` | Show this help message and exit |

## Install dependencies (example for Debian-based distros)
```bash
sudo apt update
sudo apt install nmap ntpdate ldap-utils jq python3-impacket bloodhound-python
pip install git+https://github.com/byt3bl33d3r/CrackMapExec.git
```

