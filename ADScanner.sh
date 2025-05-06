#!/bin/bash

# Bash wrapper script for enumerating a single host using SMB, LDAP, MSSQL, and WinRM tools

# Function to display usage
usage() {
    echo "Usage: $0 -i <IP> [-u <username>] [-p <password>] [-d <domain>]"
    echo "  -i  Target IP address (mandatory)"
    echo "  -u  Username (optional)"
    echo "  -p  Password (optional)"
    echo "  -d  Domain name (optional)"
    exit 1
}

# Function to check if a tool is installed
check_tool() {
    local tool=$1
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: $tool is not installed. Please install it and try again."
        exit 1
    fi
}

# Check for required tools
check_tool "enum4linux"
check_tool "enum4linux-ng"
check_tool "netexec"
check_tool "ldapsearch"
check_tool "nmap"

# Parse command-line arguments
while getopts "i:u:p:d:" opt; do
    case $opt in
        i) IP="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        d) DOMAIN="$OPTARG"
           DOMAIN_OPT="-D $DOMAIN"
           ;;
        \?) usage ;;
    esac
done

# Check if IP is provided
if [ -z "$IP" ]; then
    echo "Error: IP address is mandatory."
    usage
fi

# Define common ports
SMB_PORTS="137,138,139,445"
LDAP_PORTS="389,636"
MSSQL_PORT="1433"
WINRM_PORT="5985,5986"

# Output directory for results
OUTPUT_DIR="enum_results_$IP"
mkdir -p "$OUTPUT_DIR"

# Function to check if a port is open
check_port() {
    local host=$1
    local port=$2
    timeout 2 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null && return 0 || return 1
}

# Function to test connectivity
test_connectivity() {
    local host=$1
    if ping -c 1 -W 2 "$host" > /dev/null 2>&1; then
        echo "[+] Host $host is reachable"
        return 0
    else
        echo "[-] Host $host is not reachable"
        exit 1
    fi
}

# Function to run command if port is open
run_if_port_open() {
    local tool=$1
    local ports=$2
    local cmd=$3
    local IFS=','
    for port in $ports; do
        if check_port "$IP" "$port"; then
            echo "[+] Running $tool on port $port..."
            eval "$cmd" | tee -a "$OUTPUT_DIR/$tool-$port.output"
            return 0
        fi
    done
    echo "[-] No open ports for $tool ($ports)"
    return 1
}

# Function to run LDAP queries if LDAP is open
run_ldap_queries() {
    local ldap_open=false
    for port in $(echo "$LDAP_PORTS" | tr ',' ' '); do
        if check_port "$IP" "$port"; then
            ldap_open=true
            echo "[+] Running LDAP queries on port $port..."
            # Run ldapsearch
            ldapsearch_cmd="ldapsearch -H ldap://$IP:$port -x -b '' -s base '(objectclass=*)' *"
            if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
                ldapsearch_cmd="$ldapsearch_cmd -D '$USERNAME' -w '$PASSWORD'"
            fi
            eval "$ldapsearch_cmd" | tee -a "$OUTPUT_DIR/ldapsearch-$port.output"
            # Run nmap rootdse script
            nmap_cmd="nmap --script=ldap-rootdse -p $port $IP"
            eval "$nmap_cmd" | tee -a "$OUTPUT_DIR/nmap-ldap-rootdse-$port.output"
        fi
    done
    if ! $ldap_open; then
        echo "[-] No open LDAP ports ($LDAP_PORTS)"
    fi
}

# Test connectivity
test_connectivity "$IP"

# Prepare netexec credentials
NETEXEC_CREDS=""
if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
    NETEXEC_CREDS="-u '$USERNAME' -p '$PASSWORD'"
fi
if [ -n "$DOMAIN" ]; then
    NETEXEC_CREDS="$NETEXEC_CREDS $DOMAIN_OPT"
fi

# Run enum4linux
run_if_port_open "enum4linux" "$SMB_PORTS" "enum4linux -a $IP"

# Run enum4linux-ng
run_if_port_open "enum4linux-ng" "$SMB_PORTS" "enum4linux-ng $IP"

# Run netexec commands
run_if_port_open "netexec_smb_shares" "$SMB_PORTS" "netexec smb $IP $NETEXEC_CREDS --shares"
run_if_port_open "netexec_smb_rid" "$SMB_PORTS" "netexec smb $IP $NETEXEC_CREDS --rid-brute"
run_if_port_open "netexec_smb_spider" "$SMB_PORTS" "netexec smb $IP $NETEXEC_CREDS --spider / --depth 5 --pattern *.txt,*.conf,*.ini,*.bak"

# Run netexec LDAP module
run_if_port_open "netexec_ldap" "$LDAP_PORTS" "netexec ldap $IP $NETEXEC_CREDS -M whoami -M domain-users"

# Run netexec MSSQL module
run_if_port_open "netexec_mssql" "$MSSQL_PORT" "netexec mssql $IP $NETEXEC_CREDS -M whoami -M databases"

# Run netexec WinRM module
run_if_port_open "netexec_winrm" "$WINRM_PORT" "netexec winrm $IP $NETEXEC_CREDS -M whoami -x 'whoami'"

# Run LDAP-specific queries
run_ldap_queries

echo "[+] Enumeration complete. Results saved in $OUTPUT_DIR"
