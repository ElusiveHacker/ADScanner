#!/bin/bash

# Bash wrapper script for enumerating a single host using SMB, LDAP, MSSQL, and WinRM tools
# Outputs results to individual files and a consolidated report

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
           DOMAIN_OPT="-d $DOMAIN"
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

# Output directory and report file
OUTPUT_DIR="enum_results_$IP"
REPORT_FILE="$OUTPUT_DIR/report_$IP.txt"
mkdir -p "$OUTPUT_DIR"

# Initialize report file
{
    echo "Enumeration Report for $IP"
    echo "Generated on: $(date)"
    echo "============================================================="
    echo ""
} > "$REPORT_FILE"

# Function to append to report
append_to_report() {
    local section=$1
    local content=$2
    {
        echo "=== $section ==="
        echo "$content"
        echo ""
    } >> "$REPORT_FILE"
}

# Function to synchronize system clock with Active Directory domain controller
sync_time_with_AD() {
    local host=$1
    local ntp_tool="rdate"
    local ntp_port=123
    local max_attempts=3
    local attempt=3
    local output=""

    # Check if ntpdate is installed
    if ! command -v "$ntp_tool" >/dev/null 2>&1; then
        output="Error: $ntp_tool is not installed. Install it with 'sudo apt install ntpdate'."
        echo "[-] $output"
        append_to_report "Clock Synchronization" "$output"
        return 1
    fi

    # Check if NTP port is open
    if ! check_udp_port "$host" "$ntp_port"; then
        output="Error: NTP port $ntp_port is not open on $host. Time synchronization skipped."
        echo "[-] $output"
        append_to_report "Clock Synchronization" "$output"
        return 1
    fi

    # Check if sudo is needed (non-root user)
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

    # Attempt time synchronization
    echo "[+] Synchronizing clock with $host using $ntp_tool..."
    while [ $attempt -le $max_attempts ]; do
        output=$($sudo_cmd $ntp_tool -s "$host" 2>&1)
        if [ $? -eq 0 ]; then
            output="Successfully synchronized clock with $host.\n$output"
            echo "[+] $output"
            append_to_report "Clock Synchronization" "$output"
            return 0
        fi
        echo "[-] Attempt $attempt/$max_attempts failed: $output"
        sleep 2
        ((attempt++))
    done

    output="Error: Failed to synchronize clock with $host after $max_attempts attempts.\nLast error: $output"
    echo "[-] $output"
    append_to_report "Clock Synchronization" "$output"
    return 1
}

# Function to check if a tcp port is open
check_tcp_port() {
    local host=$1
    local port=$2
    timeout 2 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null && return 0 || return 1
}

# Function to check if a tcp port is open
check_udp_port() {
    local host=$1
    local port=$2
    timeout 2 bash -c "echo > /dev/udp/$host/$port" 2>/dev/null && return 0 || return 1
}

# Function to test connectivity
test_connectivity() {
    local host=$1
    if ping -c 1 -W 2 "$host" > /dev/null 2>&1; then
        echo "[+] Host $host is reachable"
        append_to_report "Connectivity Check" "Host $host is reachable"
        return 0
    else
        echo "[-] Host $host is not reachable"
        append_to_report "Connectivity Check" "Host $host is not reachable"
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
        if check_tcp_port "$IP" "$port"; then
            echo "[+] Running $tool on port $port..."
            output=$(eval "$cmd" 2>&1)
            echo "$output" | tee -a "$OUTPUT_DIR/$tool-$port.output"
            append_to_report "$tool (Port $port)" "$output"
            return 0
        fi
    done
    echo "[-] No open ports for $tool ($ports)"
    append_to_report "$tool" "No open ports found ($ports)"
    return 1
}

# Function to run netexec with credentials or fallback attempts
run_netexec_if_port_open() {
    local module=$1
    local ports=$2
    local base_cmd=$3
    local high_priv=$4
    local display_module=${module#smb_}  # Remove smb_ prefix for report
    display_module=${display_module#ldap_}  # Remove ldap_ prefix for report
    local IFS=','
    for port in $ports; do
        if check_tcp_port "$IP" "$port"; then
            echo "[+] Running netexec $display_module on port $port..."
            # Check if credentials are provided
            if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
                echo "[+] Trying provided credentials: $USERNAME"
                cmd="$base_cmd -u '$USERNAME' -p '$PASSWORD' $DOMAIN_OPT"
                output=$(eval "$cmd" 2>&1)
                if [[ "$output" == *"STATUS_ACCESS_DENIED"* ]] && [ "$high_priv" == "true" ]; then
                    output="$output\n[!] Warning: High privilege module likely failed due to insufficient permissions."
                fi
                echo "$output" | tee -a "$OUTPUT_DIR/netexec_${module}_provided-$port.output"
                append_to_report "NetExec $display_module (Provided Credentials, Port $port)" "$output"
            elif [ "$high_priv" != "true" ]; then
                # Try blank username and password for low privilege modules
                echo "[+] Trying blank username and password"
                cmd="$base_cmd -u '' -p '' $DOMAIN_OPT"
                output=$(eval "$cmd" 2>&1)
                echo "$output" | tee -a "$OUTPUT_DIR/netexec_${module}_blank-$port.output"
                append_to_report "NetExec $display_module (Blank Credentials, Port $port)" "$output"
                # Try guest with blank password
                echo "[+] Trying username 'guest' with blank password"
                cmd="$base_cmd -u 'guest' -p '' $DOMAIN_OPT"
                output=$(eval "$cmd" 2>&1)
                echo "$output" | tee -a "$OUTPUT_DIR/netexec_${module}_guest_blank-$port.output"
                append_to_report "NetExec $display_module (Guest/Blank, Port $port)" "$output"
                # Try guest with password 'guest'
                echo "[+] Trying username 'guest' with password 'guest'"
                cmd="$base_cmd -u 'guest' -p 'guest' $DOMAIN_OPT"
                output=$(eval "$cmd" 2>&1)
                echo "$output" | tee -a "$OUTPUT_DIR/netexec_${module}_guest_guest-$port.output"
                append_to_report "NetExec $display_module (Guest/Guest, Port $port)" "$output"
            else
                echo "[-] Skipping high privilege module $display_module (requires credentials)"
                append_to_report "NetExec $display_module" "Skipped high privilege module (requires credentials)"
            fi
            return 0
        fi
    done
    echo "[-] No open ports for netexec $display_module ($ports)"
    append_to_report "NetExec $display_module" "No open ports found ($ports)"
    return 1
}

# Function to run LDAP queries if LDAP is open
run_ldap_queries() {
    local ldap_open=false
    for port in $(echo "$LDAP_PORTS" | tr ',' ' '); do
        if check_tcp_port "$IP" "$port"; then
            ldap_open=true
            echo "[+] Running LDAP queries on port $port..."
            # Try anonymous bind first
            ldapsearch_cmd="ldapsearch -H ldap://$IP:$port -x -b '' -s base '(objectclass=*)' *"
            output=$(eval "$ldapsearch_cmd" 2>&1)
            if [[ "$output" == *"Invalid credentials"* ]] && [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
                echo "[+] Trying authenticated LDAP bind with provided credentials..."
                ldapsearch_cmd="$ldapsearch_cmd -D '$USERNAME' -w '$PASSWORD'"
                output=$(eval "$ldapsearch_cmd" 2>&1)
            fi
            if [[ "$output" == *"Can't contact LDAP server"* ]]; then
                output="$output\n[!] Warning: LDAPS connection failed, check SSL/TLS configuration."
            fi
            echo "$output" | tee -a "$OUTPUT_DIR/ldapsearch-$port.output"
            append_to_report "ldapsearch (Port $port)" "$output"
            # Run nmap rootdse script
            nmap_cmd="nmap --script=ldap-rootdse -p $port $IP"
            output=$(eval "$nmap_cmd" 2>&1)
            echo "$output" | tee -a "$OUTPUT_DIR/nmap-ldap-rootdse-$port.output"
            append_to_report "nmap ldap-rootdse (Port $port)" "$output"
        fi
    done
    if ! $ldap_open; then
        echo "[-] No open LDAP ports ($LDAP_PORTS)"
        append_to_report "LDAP Queries" "No open LDAP ports ($LDAP_PORTS)"
    fi
}

# Test connectivity
test_connectivity "$IP"

# Synchronize clock with AD
sync_time_with_AD "$IP" || echo "[!] Warning: Clock synchronization failed, some modules may not work."

# Run enum4linux
run_if_port_open "enum4linux" "$SMB_PORTS" "enum4linux -a $IP"

# Run enum4linux-ng
run_if_port_open "enum4linux-ng" "$SMB_PORTS" "enum4linux-ng $IP"

# Run netexec commands with credential handling
run_netexec_if_port_open "smb_shares" "$SMB_PORTS" "netexec smb $IP --shares" "false"
run_netexec_if_port_open "smb_rid" "$SMB_PORTS" "netexec smb $IP --rid-brute" "false"
run_netexec_if_port_open "smb_spider" "$SMB_PORTS" "netexec smb $IP --spider / --depth 5 --pattern *.txt,*.conf,*.ini,*.bak" "false"

# Run netexec low privilege SMB modules
low_priv_modules=(
    "coerce_plus"
    "enum_av"
    "enum_ca"
    "gpp_autologin"
    "gpp_password"
    "nopac"
    "spooler"
    "webdav"
    "zerologon"
)
for module in "${low_priv_modules[@]}"; do
    module_name=$(echo "$module" | cut -d' ' -f1)
    run_netexec_if_port_open "smb_${module_name}" "$SMB_PORTS" "netexec smb $IP -M $module" "false"
done

# Run netexec high privilege SMB modules (only with provided credentials)
# Excluded modules requiring options: keepass_trigger, rdp, wdigest
high_priv_modules=(
    "enum_dns"
    "firefox"
    "get_netconnections"
    "handlekatz"
    "hash_spider"
    "iis"
    "impersonate"
    "install_elevated"
    "lsassy"
    "masky"
    "msol"
    "nanodump"
    "ntdsutil"
    "ntlmv1"
    "pi"
    "procdump"
    "rdcman"
    "reg-query"
    "runasppl"
    "uac"
    "wcc"
    "winscp"
)
for module in "${high_priv_modules[@]}"; do
    run_netexec_if_port_open "smb_${module}" "$SMB_PORTS" "netexec smb $IP -M $module" "true"
done

# Run netexec LDAP modules
ldap_modules=(
    "whoami"
    "get-desc-users"
    "user-desc"
    "get-userPassword"
    "get-unixUserPassword"
)
for module in "${ldap_modules[@]}"; do
    run_netexec_if_port_open "ldap_${module}" "$LDAP_PORTS" "netexec ldap $IP -M $module" "false"
done

# Run netexec MSSQL module
run_netexec_if_port_open "mssql" "$MSSQL_PORT" "netexec mssql $IP -M whoami -M databases" "false"

# Run netexec WinRM module
run_netexec_if_port_open "winrm" "$WINRM_PORT" "netexec winrm $IP -M whoami -x 'whoami'" "false"

# Run LDAP-specific queries
run_ldap_queries

echo "[+] Enumeration complete. Results saved in $OUTPUT_DIR"
echo "[+] Consolidated report saved to $REPORT_FILE"
append_to_report "Summary" "Enumeration complete. Individual results saved in $OUTPUT_DIR"
