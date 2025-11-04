#!/bin/bash
# scripts/nmap_scan.sh
# Comprehensive Nmap Scanning Suite - Network Security Assessment Tool
# WARNING: Use only on authorized targets with proper permission

set -euo pipefail

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================

readonly SCRIPT_VERSION="1.0"
readonly SCRIPT_NAME="NMAP-SCANNER"
readonly OUTPUT_DIR="./nmap-results"
readonly LOG_FILE="$OUTPUT_DIR/nmap-scan-$(date +%Y%m%d-%H%M%S).log"
readonly VIEW_RESULTS_SCRIPT="./scripts/view_scan_results.sh"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# ============================================================================
# COLOR DEFINITIONS
# ============================================================================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Global variables
TARGET=""
CHOICE=""
SCAN_MODE=""
OUTPUT_PREFIX=""
SUDO_REQUIRED=false
SCAN_COMMAND=""

# ============================================================================
# DISPLAY FUNCTIONS
# ============================================================================

print_banner() {
    clear
    echo -e "${BLUE}${BOLD}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                       ║
║  ███╗   ██╗███╗   ███╗ █████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗        ║
║  ████╗  ██║████╗ ████║██╔══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║        ║
║  ██╔██╗ ██║██╔████╔██║███████║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║        ║
║  ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║        ║
║  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║         ███████║╚██████╗██║  ██║██║ ╚████║        ║
║  ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝        ║
║                                                                                       ║
║                        Network Security Assessment Tool v2.0                         ║
║                                                                                       ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    echo -e "${CYAN}${BOLD}System Information:${NC}"
    echo -e "${CYAN}Version: ${WHITE}$SCRIPT_VERSION${NC}"
    echo -e "${CYAN}User: ${WHITE}$(whoami)${NC}"
    echo -e "${CYAN}Privileges: ${WHITE}$([ "$EUID" -eq 0 ] && echo "ROOT" || echo "USER")${NC}"
    echo -e "${CYAN}Nmap Version: ${WHITE}$(nmap --version 2>/dev/null | head -1 | cut -d' ' -f3 || echo "NOT FOUND")${NC}"
    echo -e "${CYAN}Output Directory: ${WHITE}$OUTPUT_DIR${NC}\n"
}

print_header() {
    echo -e "\n${MAGENTA}${BOLD}"
    echo -e "╔═══════════════════════════════════════════════════════════════════════════════╗"
    printf "║ %-77s ║\n" "$1"
    echo -e "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
}

print_success() {
    echo -e "${GREEN}${BOLD}✓ $1${NC}"
}

print_info() {
    echo -e "${BLUE}${BOLD}ℹ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}${BOLD}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}${BOLD}✗ $1${NC}"
}

# ============================================================================
# TARGET ACQUISITION
# ============================================================================

get_target() {
    print_header "Target Specification"
    
    echo -e "${CYAN}${BOLD}Supported target formats:${NC}"
    echo -e "  • Single IP: 192.168.1.100"
    echo -e "  • IP Range: 192.168.1.1-254"
    echo -e "  • CIDR: 192.168.1.0/24"
    echo -e "  • Hostname: example.com"
    echo -e "  • Multiple: 192.168.1.1,192.168.1.5,example.com\n"
    
    while true; do
        echo -ne "${CYAN}Enter target: ${NC}"
        read -r TARGET
        
        if [ -z "$TARGET" ]; then
            print_error "Target cannot be empty"
            continue
        fi
        
        if validate_target "$TARGET"; then
            break
        else
            print_error "Invalid target format"
            continue
        fi
    done
    
    print_success "Target set: $TARGET"
}

validate_target() {
    local target="$1"
    
    # Basic validation patterns
    if [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || \
       [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}-[0-9]{1,3}$ ]] || \
       [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]] || \
       [[ $target =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || \
       [[ $target =~ , ]]; then
        return 0
    fi
    
    return 1
}

# ============================================================================
# SCAN MENU
# ============================================================================

show_menu() {
    print_header "Scan Configuration Menu"
    
    echo -e "${GREEN}${BOLD}Basic Scans:${NC}"
    echo -e "  [1] Quick Scan (Top 1000 ports)"
    echo -e "  [2] Full TCP Scan (All 65535 ports)"
    echo -e "  [3] UDP Scan (Top 1000 UDP ports)"
    echo -e "  [4] Service Version Detection"
    echo -e "  [5] OS Detection"
    
    echo -e "\n${YELLOW}${BOLD}Advanced Scans:${NC}"
    echo -e "  [6] Comprehensive Scan (TCP + UDP + Version + OS)"
    echo -e "  [7] Stealth SYN Scan"
    echo -e "  [8] Aggressive Scan (All techniques)"
    echo -e "  [9] Vulnerability Scan (NSE scripts)"
    echo -e "  [10] Web Application Scan"
    
    echo -e "\n${CYAN}${BOLD}Specialized Scans:${NC}"
    echo -e "  [11] Database Services Scan"
    echo -e "  [12] SMB/NetBIOS Scan"
    echo -e "  [13] SSL/TLS Analysis"
    echo -e "  [14] Custom Scan Builder"
    
    echo -e "\n${RED}${BOLD}High-Risk & Intrusive Scans:${NC}"
    echo -e "  [15] Firewall Evasion Scan (Fragment + Decoy)"
    echo -e "  [16] Timing Attack Scan (T5 Insane)"
    echo -e "  [17] All NSE Scripts Scan (Dangerous)"
    echo -e "  [18] Brute Force Services Scan"
    echo -e "  [19] DoS Detection Scan"
    echo -e "  [20] Exploit Enumeration Scan"
    echo -e "  [21] Network Flooding Scan"
    echo -e "  [22] Advanced Evasion Techniques"
    echo -e "  [23] Full Intrusion Attempt"
    echo -e "  [24] System Fingerprinting Extreme"
    echo -e "  [25] Backdoor Detection Scan"
    echo -e "  [26] Protocol Fuzzing Scan"
    echo -e "  [27] Maximum Stealth Infiltration"
    echo -e "  [28] Complete Infrastructure Mapping"
    
    echo -e "\n${WHITE}${BOLD}Control:${NC}"
    echo -e "  [0] Exit"
    
    echo -ne "\n${CYAN}Select scan type [0-28]: ${NC}"
    read -r CHOICE
}

# ============================================================================
# SCAN BUILDERS
# ============================================================================

build_scan() {
    OUTPUT_PREFIX="$OUTPUT_DIR/scan-$(date +%Y%m%d-%H%M%S)"
    
    case $CHOICE in
        1) # Quick Scan
            SCAN_MODE="Quick Scan"
            SCAN_COMMAND="nmap -sS --top-ports 1000 -oA $OUTPUT_PREFIX $TARGET"
            ;;
        2) # Full TCP Scan
            SCAN_MODE="Full TCP Scan"
            SCAN_COMMAND="nmap -sS -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        3) # UDP Scan
            SCAN_MODE="UDP Scan"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sU --top-ports 1000 -oA $OUTPUT_PREFIX $TARGET"
            ;;
        4) # Service Version Detection
            SCAN_MODE="Service Version Detection"
            SCAN_COMMAND="nmap -sS -sV --top-ports 1000 -oA $OUTPUT_PREFIX $TARGET"
            ;;
        5) # OS Detection
            SCAN_MODE="OS Detection"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sS -O --top-ports 1000 -oA $OUTPUT_PREFIX $TARGET"
            ;;
        6) # Comprehensive Scan
            SCAN_MODE="Comprehensive Scan"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sS -sU -sV -O -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        7) # Stealth SYN Scan
            SCAN_MODE="Stealth SYN Scan"
            SCAN_COMMAND="nmap -sS -T2 --top-ports 1000 -oA $OUTPUT_PREFIX $TARGET"
            ;;
        8) # Aggressive Scan
            SCAN_MODE="Aggressive Scan"
            SCAN_COMMAND="nmap -A -T4 -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        9) # Vulnerability Scan
            SCAN_MODE="Vulnerability Scan"
            SCAN_COMMAND="nmap -sS -sV --script vuln --top-ports 1000 -oA $OUTPUT_PREFIX $TARGET"
            ;;
        10) # Web Application Scan
            SCAN_MODE="Web Application Scan"
            SCAN_COMMAND="nmap -sS -sV --script http-* -p 80,443,8080,8443 -oA $OUTPUT_PREFIX $TARGET"
            ;;
        11) # Database Services Scan
            SCAN_MODE="Database Services Scan"
            SCAN_COMMAND="nmap -sS -sV -p 1433,1521,3306,5432,27017 --script *sql*,*db* -oA $OUTPUT_PREFIX $TARGET"
            ;;
        12) # SMB/NetBIOS Scan
            SCAN_MODE="SMB/NetBIOS Scan"
            SCAN_COMMAND="nmap -sS -sV -p 135,139,445 --script smb* -oA $OUTPUT_PREFIX $TARGET"
            ;;
        13) # SSL/TLS Analysis
            SCAN_MODE="SSL/TLS Analysis"
            SCAN_COMMAND="nmap -sS -sV -p 443,993,995 --script ssl* -oA $OUTPUT_PREFIX $TARGET"
            ;;
        14) # Custom Scan Builder
            build_custom_scan
            return 0
            ;;
        15) # Firewall Evasion Scan
            SCAN_MODE="Firewall Evasion Scan"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sS -f -D RND:10 --source-port 53 --data-length 25 -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        16) # Timing Attack Scan
            SCAN_MODE="Timing Attack Scan (T5 Insane)"
            SCAN_COMMAND="nmap -sS -T5 --min-rate 5000 --max-retries 1 -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        17) # All NSE Scripts Scan
            SCAN_MODE="All NSE Scripts Scan (Dangerous)"
            SCAN_COMMAND="nmap -sS -sV --script all --script-timeout 30s -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        18) # Brute Force Services Scan
            SCAN_MODE="Brute Force Services Scan"
            SCAN_COMMAND="nmap -sS -sV --script brute,auth -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6000 -oA $OUTPUT_PREFIX $TARGET"
            ;;
        19) # DoS Detection Scan
            SCAN_MODE="DoS Detection Scan"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sS --script dos,broadcast-dhcp-discover,smb-flood --max-parallelism 1 -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        20) # Exploit Enumeration Scan
            SCAN_MODE="Exploit Enumeration Scan"
            SCAN_COMMAND="nmap -sS -sV --script exploit,intrusive --script-timeout 60s -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        21) # Network Flooding Scan
            SCAN_MODE="Network Flooding Scan"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sS -sU --flood --max-rate 10000 --min-rate 1000 -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        22) # Advanced Evasion Techniques
            SCAN_MODE="Advanced Evasion Techniques"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sS -f -ff -D RND:20 --source-port 53,80,443 --data-length 50 --spoof-mac 0 --badsum -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        23) # Full Intrusion Attempt
            SCAN_MODE="Full Intrusion Attempt"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sS -sU -sV -O -A --script intrusive,exploit,brute,malware --script-timeout 120s -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        24) # System Fingerprinting Extreme
            SCAN_MODE="System Fingerprinting Extreme"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sS -O --osscan-limit --osscan-guess --fuzzy -sV --version-intensity 9 -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        25) # Backdoor Detection Scan
            SCAN_MODE="Backdoor Detection Scan"
            SCAN_COMMAND="nmap -sS -sV --script backdoor,malware,trojan -p 1-65535 -oA $OUTPUT_PREFIX $TARGET"
            ;;
        26) # Protocol Fuzzing Scan
            SCAN_MODE="Protocol Fuzzing Scan"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sS -sU -sO --script unusual-port,fingerprint-strings --data-string 'AAAAAAAAAAAAAAAA' -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        27) # Maximum Stealth Infiltration
            SCAN_MODE="Maximum Stealth Infiltration"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sS -T1 -f -ff -D RND:50 --source-port 53 --data-length 100 --spoof-mac 0 --randomize-hosts --scan-delay 10s -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        28) # Complete Infrastructure Mapping
            SCAN_MODE="Complete Infrastructure Mapping"
            SUDO_REQUIRED=true
            SCAN_COMMAND="nmap -sS -sU -sV -O -A --traceroute --script discovery,safe,intrusive,exploit --script-timeout 300s -p- -oA $OUTPUT_PREFIX $TARGET"
            ;;
        0) # Exit
            print_info "Exiting..."
            exit 0
            ;;
        *)
            print_error "Invalid selection: $CHOICE"
            return 1
            ;;
    esac
    
    return 0
}

build_custom_scan() {
    print_header "Custom Scan Builder"
    
    local custom_flags=""
    local custom_ports=""
    local custom_scripts=""
    
    # Scan type
    echo -e "${YELLOW}Select scan type:${NC}"
    echo -e "  [1] TCP SYN (-sS)     [2] TCP Connect (-sT)"
    echo -e "  [3] UDP (-sU)         [4] TCP+UDP (-sS -sU)"
    echo -ne "${CYAN}Choice [1-4]: ${NC}"
    read -r scan_type
    
    case $scan_type in
        1) custom_flags="-sS" ;;
        2) custom_flags="-sT" ;;
        3) custom_flags="-sU"; SUDO_REQUIRED=true ;;
        4) custom_flags="-sS -sU"; SUDO_REQUIRED=true ;;
        *) custom_flags="-sS" ;;
    esac
    
    # Port selection
    echo -e "\n${YELLOW}Select port range:${NC}"
    echo -e "  [1] Top 100           [2] Top 1000"
    echo -e "  [3] All ports         [4] Custom range"
    echo -ne "${CYAN}Choice [1-4]: ${NC}"
    read -r port_choice
    
    case $port_choice in
        1) custom_ports="--top-ports 100" ;;
        2) custom_ports="--top-ports 1000" ;;
        3) custom_ports="-p-" ;;
        4) 
            echo -ne "${CYAN}Enter port range: ${NC}"
            read -r custom_range
            custom_ports="-p $custom_range"
            ;;
        *) custom_ports="--top-ports 1000" ;;
    esac
    
    # Additional options
    echo -ne "\n${CYAN}Enable version detection? [y/N]: ${NC}"
    read -r version_detect
    [[ $version_detect =~ ^[Yy]$ ]] && custom_flags+=" -sV"
    
    echo -ne "${CYAN}Enable OS detection? [y/N]: ${NC}"
    read -r os_detect
    [[ $os_detect =~ ^[Yy]$ ]] && { custom_flags+=" -O"; SUDO_REQUIRED=true; }
    
    echo -ne "${CYAN}Enable default scripts? [y/N]: ${NC}"
    read -r default_scripts
    [[ $default_scripts =~ ^[Yy]$ ]] && custom_flags+=" -sC"
    
    OUTPUT_PREFIX="$OUTPUT_DIR/custom-scan-$(date +%Y%m%d-%H%M%S)"
    SCAN_MODE="Custom Scan"
    
    SCAN_COMMAND="nmap $custom_flags $custom_ports -oA $OUTPUT_PREFIX $TARGET"
    
    echo -e "\n${GREEN}Custom command: ${YELLOW}$SCAN_COMMAND${NC}\n"
}

# ============================================================================
# SCAN EXECUTION
# ============================================================================

execute_scan() {
    print_header "Scan Execution"
    
    # Pre-flight checks
    if ! command -v nmap &> /dev/null; then
        print_error "Nmap not found! Install with: apt-get install nmap"
        exit 1
    fi
    
    if [ "$SUDO_REQUIRED" = true ] && [ "$EUID" -ne 0 ]; then
        print_warning "This scan requires root privileges"
        echo -ne "${YELLOW}Continue without root? [y/N]: ${NC}"
        read -r continue_limited
        if [[ ! $continue_limited =~ ^[Yy]$ ]]; then
            print_info "Restart with: sudo $0"
            exit 1
        fi
    fi
    
    # Display scan info
    echo -e "${CYAN}Target: ${WHITE}$TARGET${NC}"
    echo -e "${CYAN}Mode: ${WHITE}$SCAN_MODE${NC}"
    echo -e "${CYAN}Output: ${WHITE}${OUTPUT_PREFIX}.*${NC}"
    echo -e "${CYAN}Command: ${YELLOW}$SCAN_COMMAND${NC}\n"
    
    echo -ne "${YELLOW}Proceed with scan? [Y/n]: ${NC}"
    read -r proceed
    if [[ $proceed =~ ^[Nn]$ ]]; then
        print_info "Scan cancelled"
        return 1
    fi
    
    # Execute scan
    print_info "Starting scan..."
    local start_time=$(date +%s)
    
    # Ensure output directory exists
    mkdir -p "$(dirname "$OUTPUT_PREFIX")"
    
    # Execute the scan and capture both stdout and stderr
    if eval "$SCAN_COMMAND" 2>&1 | tee "$LOG_FILE"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        # Verify that output files were created
        if [ -f "${OUTPUT_PREFIX}.nmap" ] || [ -f "${OUTPUT_PREFIX}.xml" ] || [ -f "${OUTPUT_PREFIX}.gnmap" ]; then
            print_success "Scan completed in ${duration} seconds"
            return 0
        else
            print_error "Scan completed but no output files were generated"
            print_info "Check the log file: $LOG_FILE"
            return 1
        fi
    else
        print_error "Scan failed"
        print_info "Check the log file: $LOG_FILE"
        return 1
    fi
}

# ============================================================================
# RESULTS PROCESSING
# ============================================================================

process_results() {
    print_header "Results Analysis"
    
    # Check for any output files
    local found_files=false
    local primary_file=""
    
    # Check for different output formats in order of preference
    for ext in nmap xml gnmap; do
        if [ -f "${OUTPUT_PREFIX}.$ext" ]; then
            found_files=true
            if [ -z "$primary_file" ]; then
                primary_file="${OUTPUT_PREFIX}.$ext"
            fi
        fi
    done
    
    if [ "$found_files" = false ]; then
        print_error "No results files found at ${OUTPUT_PREFIX}.*"
        print_info "Checking for alternative output locations..."
        
        # Look for any nmap output files in the output directory
        local alt_files=$(find "$OUTPUT_DIR" -name "*.nmap" -o -name "*.xml" -o -name "*.gnmap" 2>/dev/null | head -5)
        if [ -n "$alt_files" ]; then
            print_info "Found alternative output files:"
            echo "$alt_files"
            echo -ne "${CYAN}Use the most recent file for analysis? [Y/n]: ${NC}"
            read -r use_alt
            if [[ ! $use_alt =~ ^[Nn]$ ]]; then
                primary_file=$(echo "$alt_files" | head -1)
                print_info "Using: $primary_file"
            else
                return 1
            fi
        else
            print_error "No nmap output files found in $OUTPUT_DIR"
            print_info "Check the log file for errors: $LOG_FILE"
            return 1
        fi
    fi
    
    # Display summary using the primary file
    echo -e "${GREEN}${BOLD}Scan Summary:${NC}"
    echo -e "${CYAN}Primary results file: ${WHITE}$primary_file${NC}"
    
    # Initialize open_ports as integer
    local open_ports=0
    
    # Count open ports based on file type and content
    if [ -f "$primary_file" ] && [ -s "$primary_file" ]; then
        if [[ "$primary_file" == *.nmap ]]; then
            # Count lines containing "open" but not "filtered" or "closed"
            open_ports=$(grep -c "^[0-9]*/.*open" "$primary_file" 2>/dev/null || echo "0")
        elif [[ "$primary_file" == *.xml ]]; then
            # Count XML elements with state="open"
            open_ports=$(grep -c 'state="open"' "$primary_file" 2>/dev/null || echo "0")
        elif [[ "$primary_file" == *.gnmap ]]; then
            # Count open ports in gnmap format
            open_ports=$(grep -o "[0-9]*/open/" "$primary_file" 2>/dev/null | wc -l || echo "0")
        fi
    fi
    
    # Ensure open_ports is a valid integer (remove any whitespace/newlines)
    open_ports=$(echo "$open_ports" | tr -d '[:space:]')
    
    # Validate that open_ports is numeric
    if ! [[ "$open_ports" =~ ^[0-9]+$ ]]; then
        open_ports=0
    fi
    
    echo -e "${CYAN}Open ports found: ${WHITE}$open_ports${NC}"
    
    # Display open ports if any found
    if [ "$open_ports" -gt 0 ]; then
        echo -e "\n${GREEN}${BOLD}Open Ports:${NC}"
        if [[ "$primary_file" == *.nmap ]]; then
            grep "^[0-9]*/.*open" "$primary_file" 2>/dev/null | head -20 || echo "  ${YELLOW}Unable to parse open ports from nmap file${NC}"
        elif [[ "$primary_file" == *.xml ]]; then
            grep 'state="open"' "$primary_file" 2>/dev/null | sed 's/.*portid="\([^"]*\)".*protocol="\([^"]*\)".*/  \2\/\1 open/' | head -20 || echo "  ${YELLOW}Unable to parse open ports from XML file${NC}"
        elif [[ "$primary_file" == *.gnmap ]]; then
            grep -o "[0-9]*/open/[^/,]*" "$primary_file" 2>/dev/null | sed 's|/open/| |' | head -20 || echo "  ${YELLOW}Unable to parse open ports from gnmap file${NC}"
        fi
    else
        echo -e "${YELLOW}No open ports detected${NC}"
        
        # Provide diagnostic information for empty results
        if [ -f "$primary_file" ]; then
            local file_size=$(stat -c%s "$primary_file" 2>/dev/null || echo "0")
            if [ "$file_size" -eq 0 ]; then
                echo -e "${YELLOW}The results file is empty. Possible causes:${NC}"
                echo -e "  • Target host is down or unreachable"
                echo -e "  • All ports are filtered by firewall"
                echo -e "  • Network connectivity issues"
                echo -e "  • Scan was interrupted or failed"
                echo -e "  • Insufficient permissions for scan type"
            else
                echo -e "${YELLOW}Results file contains data but no open ports found${NC}"
                echo -e "  • All scanned ports may be closed or filtered"
                echo -e "  • Target may be using port knocking or stealth techniques"
            fi
        fi
    fi
    
    # Service information (only for .nmap files with content)
    if [[ "$primary_file" == *.nmap ]] && [ -s "$primary_file" ] && grep -q "Service detection\|VERSION" "$primary_file" 2>/dev/null; then
        echo -e "\n${CYAN}${BOLD}Service Information:${NC}"
        grep -A 5 "Service detection\|VERSION" "$primary_file" 2>/dev/null | head -10
    fi
    
    # OS information (only for .nmap files with content)
    if [[ "$primary_file" == *.nmap ]] && [ -s "$primary_file" ] && grep -q "OS details\|Running:" "$primary_file" 2>/dev/null; then
        echo -e "\n${MAGENTA}${BOLD}OS Detection:${NC}"
        grep "OS details\|Running:" "$primary_file" 2>/dev/null
    fi
    
    # Output files summary
    echo -e "\n${CYAN}${BOLD}Output Files:${NC}"
    for ext in xml nmap gnmap; do
        if [ -f "${OUTPUT_PREFIX}.$ext" ]; then
            local size=$(du -h "${OUTPUT_PREFIX}.$ext" 2>/dev/null | cut -f1 || echo "unknown")
            local status=""
            if [ ! -s "${OUTPUT_PREFIX}.$ext" ]; then
                status=" ${YELLOW}(empty)${NC}"
            fi
            echo -e "  ${GREEN}${OUTPUT_PREFIX}.$ext${NC} (${size})${status}"
        fi
    done
    
    # Log file information
    if [ -f "$LOG_FILE" ]; then
        local log_size=$(du -h "$LOG_FILE" 2>/dev/null | cut -f1 || echo "unknown")
        local log_status=""
        if [ ! -s "$LOG_FILE" ]; then
            log_status=" ${YELLOW}(empty)${NC}"
        fi
        echo -e "  ${BLUE}$LOG_FILE${NC} (${log_size})${log_status}"
    fi
    
    # Analysis commands
    echo -e "\n${BLUE}${BOLD}Analysis Commands:${NC}"
    if [ -s "$primary_file" ]; then
        echo -e "  View results: ${WHITE}cat \"$primary_file\"${NC}"
        if [[ "$primary_file" == *.nmap ]]; then
            echo -e "  Open ports: ${WHITE}grep '^[0-9]*/.*open' \"$primary_file\"${NC}"
        fi
        if [ -f "${OUTPUT_PREFIX}.xml" ] && [ -s "${OUTPUT_PREFIX}.xml" ]; then
            echo -e "  XML parsing: ${WHITE}Use \"${OUTPUT_PREFIX}.xml\" for automated tools${NC}"
        fi
    else
        echo -e "  ${YELLOW}Results file is empty - check scan parameters and target reachability${NC}"
    fi
    
    if [ -f "$LOG_FILE" ] && [ -s "$LOG_FILE" ]; then
        echo -e "  View log: ${WHITE}cat \"$LOG_FILE\"${NC}"
    else
        echo -e "  ${YELLOW}Log file is empty or missing${NC}"
    fi
    
    # Troubleshooting section for failed scans
    if [ "$open_ports" -eq 0 ] && ([ ! -s "$primary_file" ] || [ ! -f "$primary_file" ]); then
        echo -e "\n${YELLOW}${BOLD}Troubleshooting Tips:${NC}"
        echo -e "  • Verify target is reachable: ${WHITE}ping \"$TARGET\"${NC}"
        echo -e "  • Check network connectivity and DNS resolution"
        echo -e "  • Try a basic ping scan: ${WHITE}nmap -Pn \"$TARGET\"${NC}"
        echo -e "  • Ensure proper permissions for the selected scan type"
        echo -e "  • Check firewall settings on both source and target"
        echo -e "  • Verify target format is correct"
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    print_banner
    
    # Get target
    get_target
    
    # Menu loop
    while true; do
        show_menu
        
        if [[ "$CHOICE" =~ ^[0-9]+$ ]] && [ "$CHOICE" -ge 0 ] && [ "$CHOICE" -le 28 ]; then
            if [ "$CHOICE" == "0" ]; then
                print_info "Goodbye!"
                exit 0
            fi
            break
        else
            print_error "Invalid selection. Choose 0-28."
            sleep 2
        fi
    done
    
    # Build and execute scan
    print_info "Building scan configuration..."
    if build_scan; then
        if [ -n "$SCAN_COMMAND" ] && execute_scan; then
            process_results
            print_success "Scan operation completed successfully!"
        else
            print_error "Scan operation failed"
            exit 1
        fi
    else
        print_error "Failed to build scan configuration"
        exit 1
    fi
}

# Cleanup on exit
trap 'echo -e "\n${RED}Scan interrupted${NC}"; exit 130' INT TERM

# Run main function
main "$@"
