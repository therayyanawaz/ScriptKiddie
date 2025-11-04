#!/bin/bash
# scripts/view_scan_results.sh
# Helper script to view and analyze Nmap scan results

if [ $# -eq 0 ]; then
    echo "Usage: $0 <scan-output-file>"
    echo ""
    echo "Examples:"
    echo "  $0 ./nmap-results/scan-20251104-194413.nmap"
    echo "  $0 ./nmap-results/scan-20251104-194413.xml"
    echo ""
    echo "Or find latest scan:"
    echo "  $0 \$(ls -t ./nmap-results/*.nmap | head -1)"
    exit 1
fi

SCAN_FILE="$1"
BASE_NAME="${SCAN_FILE%.*}"

# Colors
GREEN='\033[0;32m'
BRIGHT_GREEN='\033[1;32m'
CYAN='\033[0;36m'
BRIGHT_CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BRIGHT_RED='\033[1;31m'
NC='\033[0m'

echo -e "${BRIGHT_CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BRIGHT_CYAN}  NMAP SCAN RESULTS ANALYSIS${NC}"
echo -e "${BRIGHT_CYAN}═══════════════════════════════════════════════════════════════${NC}\n"

# Check if file exists
if [ ! -f "$SCAN_FILE" ]; then
    echo -e "${BRIGHT_RED}Error: File not found: $SCAN_FILE${NC}"
    exit 1
fi

# Detect file type
if [[ "$SCAN_FILE" == *.xml ]]; then
    echo -e "${CYAN}Detected: XML format${NC}\n"
    analyze_xml "$SCAN_FILE"
elif [[ "$SCAN_FILE" == *.nmap ]]; then
    echo -e "${CYAN}Detected: Normal format${NC}\n"
    analyze_nmap "$SCAN_FILE"
elif [[ "$SCAN_FILE" == *.gnmap ]]; then
    echo -e "${CYAN}Detected: Grepable format${NC}\n"
    analyze_gnmap "$SCAN_FILE"
else
    echo -e "${YELLOW}Unknown format, attempting to analyze as .nmap file${NC}\n"
    analyze_nmap "$SCAN_FILE"
fi

analyze_nmap() {
    local file="$1"
    
    echo -e "${BRIGHT_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BRIGHT_GREEN}  OPEN PORTS & SERVICES${NC}"
    echo -e "${BRIGHT_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    grep -E '^[0-9]+/(tcp|udp).*open' "$file" 2>/dev/null | while read line; do
        echo -e "${BRIGHT_GREEN}  ✅ $line${NC}"
    done
    
    local open_count=$(grep -cE '^[0-9]+/(tcp|udp).*open' "$file" 2>/dev/null || echo "0")
    echo -e "\n${CYAN}Total Open Ports: $open_count${NC}\n"
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  VERSION INFORMATION${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    grep -E "(Service detection|Service Info|Version:|Service fingerprint)" "$file" 2>/dev/null | head -20 | while read line; do
        echo -e "${CYAN}  🔍 $line${NC}"
    done
    
    echo -e "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  OS DETECTION${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    grep -E "(OS details|OS detection|Running:|OS CPE)" "$file" 2>/dev/null | head -10 | while read line; do
        echo -e "${YELLOW}  💻 $line${NC}"
    done
    
    echo -e "\n${BRIGHT_RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BRIGHT_RED}  VULNERABILITIES & SECURITY ISSUES${NC}"
    echo -e "${BRIGHT_RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    local vuln_count=$(grep -icE "(vuln|cve|exploit|vulnerable)" "$file" 2>/dev/null || echo "0")
    if [ "$vuln_count" -gt 0 ]; then
        grep -iE "(vuln|cve|exploit|vulnerable)" "$file" 2>/dev/null | head -30 | while read line; do
            echo -e "${BRIGHT_RED}  🚨 $line${NC}"
        done
    else
        echo -e "${YELLOW}  ⚠️  No obvious vulnerabilities detected in scan output${NC}"
    fi
}

analyze_xml() {
    local file="$1"
    
    if command -v xmlstarlet &> /dev/null; then
        echo -e "${BRIGHT_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BRIGHT_GREEN}  OPEN PORTS & SERVICES${NC}"
        echo -e "${BRIGHT_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
        
        xmlstarlet sel -t -m "//port[state/@state='open']" \
            -v "concat(@portid, '/', @protocol, ' - ', service/@name, ' ', service/@version, ' ', service/@product)" \
            -n "$file" 2>/dev/null | while read line; do
            echo -e "${BRIGHT_GREEN}  ✅ $line${NC}"
        done
    elif command -v python3 &> /dev/null; then
        python3 << EOF
import xml.etree.ElementTree as ET
import sys

try:
    tree = ET.parse("$file")
    root = tree.getroot()
    
    print("\n${BRIGHT_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}")
    print("${BRIGHT_GREEN}  OPEN PORTS & SERVICES${NC}")
    print("${BRIGHT_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n")
    
    open_count = 0
    for host in root.findall('.//host'):
        for port in host.findall('.//port'):
            state = port.find('.//state')
            if state is not None and state.get('state') == 'open':
                portid = port.get('portid')
                protocol = port.get('protocol')
                service = port.find('.//service')
                service_name = service.get('name') if service is not None else 'unknown'
                version = service.get('version') if service is not None else ''
                product = service.get('product') if service is not None else ''
                
                info = f"{portid}/{protocol} - {service_name}"
                if version:
                    info += f" {version}"
                if product:
                    info += f" ({product})"
                
                print(f"${BRIGHT_GREEN}  ✅ {info}${NC}")
                open_count += 1
    
    print(f"\n${CYAN}Total Open Ports: {open_count}${NC}\n")
    
except Exception as e:
    print(f"${BRIGHT_RED}Error parsing XML: {e}${NC}", file=sys.stderr)
    sys.exit(1)
EOF
    else
        echo -e "${YELLOW}XML parsing tools not available. Install xmlstarlet or use Python.${NC}"
        echo -e "${YELLOW}Falling back to grep-based analysis...${NC}\n"
        analyze_nmap "${BASE_NAME}.nmap"
    fi
}

analyze_gnmap() {
    local file="$1"
    
    echo -e "${BRIGHT_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BRIGHT_GREEN}  OPEN PORTS${NC}"
    echo -e "${BRIGHT_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    grep "open" "$file" 2>/dev/null | awk '{print $2, $3}' | while read line; do
        echo -e "${BRIGHT_GREEN}  ✅ $line${NC}"
    done
}

# Run analysis
if [[ "$SCAN_FILE" == *.xml ]]; then
    analyze_xml "$SCAN_FILE"
elif [[ "$SCAN_FILE" == *.nmap ]]; then
    analyze_nmap "$SCAN_FILE"
else
    analyze_gnmap "$SCAN_FILE"
fi

echo -e "\n${BRIGHT_CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BRIGHT_CYAN}  QUICK COMMANDS${NC}"
echo -e "${BRIGHT_CYAN}═══════════════════════════════════════════════════════════════${NC}\n"

echo -e "${CYAN}View full output:${NC}"
echo -e "  cat ${SCAN_FILE}\n"

if [ -f "${BASE_NAME}.xml" ]; then
    echo -e "${CYAN}Parse XML:${NC}"
    echo -e "  xmlstarlet sel -t -m \"//port[state/@state='open']\" -v \"@portid\" ${BASE_NAME}.xml\n"
fi

if [ -f "${BASE_NAME}.gnmap" ]; then
    echo -e "${CYAN}Extract open ports (grepable):${NC}"
    echo -e "  grep open ${BASE_NAME}.gnmap\n"
fi

