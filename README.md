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
- Root access (or `sudo`)
- (Optional) `config.sh` for persistent configuration

---

## 🚀 Usage

```bash
sudo ./ADScanner.sh [options]
```

| Flag         | Description                                  |
| ------------ | -------------------------------------------- |
| `-t`         | Target IP or hostname (required)             |
| `-u`         | Username                                     |
| `-p`         | Password                                     |
| `-d`         | Domain name                                  |
| `-o`         | Output directory (optional)                  |
| `--fullscan` | Enables all modules (SMB, LDAP, MSSQL, etc.) |
| `-v`         | Verbose mode                                 |
| `-q`         | Quiet mode                                   |

## Install dependencies (example for Debian-based distros)
```bash
sudo apt update
sudo apt install nmap ntpdate ldap-utils jq python3-impacket bloodhound-python
pip install git+https://github.com/byt3bl33d3r/CrackMapExec.git
```

