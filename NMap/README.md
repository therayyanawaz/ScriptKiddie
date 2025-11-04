# 🔍 NMAP Scanning Suite

<div align="center">

**A comprehensive, highly intrusive, and aggressive Nmap scanning toolkit designed for exhaustive network security assessment**

[![Version](https://img.shields.io/badge/version-1.0-blue.svg)](https://github.com/therayyanawaz/ScriptKiddie)
[![Bash](https://img.shields.io/badge/bash-4.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Nmap](https://img.shields.io/badge/nmap-required-red.svg)](https://nmap.org/)
[![License](https://img.shields.io/badge/license-Use%20Responsibly-yellow.svg)](LICENSE)

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Warning](#-critical-warnings)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [⚠️ Critical Warnings](#️-critical-warnings)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Scan Options](#-scan-options)
- [Output Formats](#-output-formats)
- [Results Analysis](#-results-analysis)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [Documentation](#-documentation)
- [License & Disclaimer](#-license--disclaimer)

---

## 🎯 Overview

The **NMAP Scanning Suite** is a powerful, interactive command-line tool that provides 28+ specialized scanning profiles for comprehensive network security assessment. Built with Bash and leveraging Nmap's full capabilities, this toolkit enables security professionals to perform exhaustive enumeration, vulnerability detection, OS fingerprinting, and advanced evasion techniques through an intuitive menu-driven interface.

### Key Highlights

- **28+ Pre-configured Scan Profiles** - From quick reconnaissance to maximum intrusiveness
- **Interactive Menu System** - User-friendly CLI with color-coded output
- **Real-time Progress Display** - Live scan monitoring with visual feedback
- **Automatic Results Parsing** - Intelligent analysis of scan outputs
- **Multi-format Output** - XML, normal, grepable, and log formats
- **Comprehensive Documentation** - Detailed guides and examples

---

## ✨ Features

### 🎛️ Interactive Scanning Interface

- **ASCII Art Banner** - Professional visual presentation
- **System Information Display** - Nmap version, privileges, user context
- **Color-coded Output** - Green (success), Red (vulnerabilities), Yellow (warnings), Cyan (info)
- **Real-time Animated Progress** - Live scan status with colorization
- **Authorization Check** - Legal compliance reminder

### 🔬 Scan Capabilities

#### Standard Scans
- **Quick Scan** - Top 1000 ports, fast reconnaissance
- **Full TCP Scan** - Complete TCP port enumeration (0-65535)
- **UDP Scan** - UDP port discovery and enumeration
- **Service Version Detection** - Detailed service fingerprinting
- **OS Detection** - Operating system identification

#### Advanced Scans
- **Comprehensive Scan** - TCP + UDP + Version + OS detection
- **Stealth SYN Scan** - Low-intensity timing template
- **Aggressive Scan** - Maximum data collection (-A flag)
- **Vulnerability Scan** - NSE vuln scripts execution
- **Web Application Scan** - HTTP-specific enumeration

#### Specialized Scans
- **Database Services** - SQL, MongoDB, PostgreSQL detection
- **SMB/NetBIOS** - Windows network enumeration
- **SSL/TLS Analysis** - Certificate and encryption assessment
- **Custom Scan Builder** - User-defined scan profiles
- **Firewall Evasion** - Fragmentation, decoy, spoofing techniques

#### Extreme Scans
- **Timing Attack (T5)** - Insane speed template
- **All NSE Scripts** - Complete script execution
- **Brute Force Services** - Authentication testing
- **DoS Detection** - Denial-of-service vulnerability checks
- **Exploit Enumeration** - Exploit framework integration
- **Network Flooding** - High-rate packet transmission
- **Advanced Evasion** - Multiple evasion techniques combined
- **Full Intrusion Attempt** - Maximum aggressiveness
- **System Fingerprinting Extreme** - Deep OS analysis
- **Backdoor Detection** - Malware and trojan scanning
- **Protocol Fuzzing** - Unusual port and protocol testing
- **Maximum Stealth Infiltration** - Slow, evasive scanning
- **Complete Infrastructure Mapping** - Full network discovery

### 📊 Results Analysis

- **Automatic Parsing** - XML, normal, and grepable format support
- **Open Ports Summary** - Quick enumeration of discovered services
- **Version Information** - Service and product identification
- **OS Detection Results** - Operating system details and accuracy
- **Vulnerability Insights** - CVE and exploit findings
- **Structured Reports** - Organized output sections

### 🛠️ Utility Scripts

- **`nmap_scan.sh`** - Main interactive scanning script
- **`view_scan_results.sh`** - Results analysis and visualization tool

---

## ⚠️ Critical Warnings

### 🚨 Legal & Ethical Considerations

> **IMPORTANT:** This tool is designed for **authorized security testing only**. Unauthorized scanning is **illegal** and may result in:
> - Criminal charges under computer fraud laws
> - Civil liability
> - Fines and imprisonment
> - Permanent criminal record

**✅ You MUST:**
- Have explicit written permission from the target owner
- Only scan systems you own or are authorized to test
- Understand local and international computer crime laws
- Use responsibly and ethically

**❌ You MUST NOT:**
- Scan systems without authorization
- Use for malicious purposes
- Violate terms of service
- Conduct unauthorized penetration testing

### ⚡ Technical Warnings

- **Root Privileges Required** - Many scan options require `sudo` for raw socket access
- **Network Visibility** - Extremely intrusive scans will be detected by IDS/IPS systems
- **Resource Intensive** - Can consume significant bandwidth and target system resources
- **Time Consuming** - Comprehensive scans can take hours or days to complete
- **System Impact** - May overwhelm target systems or trigger security responses

---

## 📦 Installation

### Prerequisites

- **Nmap** - Core scanning engine
  ```bash
  # Debian/Ubuntu/Kali
  sudo apt update && sudo apt install -y nmap
  
  # RHEL/CentOS
  sudo yum install -y nmap
  
  # macOS
  brew install nmap
  ```

- **Bash** - Version 4.0 or higher
  ```bash
  bash --version  # Should be >= 4.0
  ```

- **Optional Dependencies** (for enhanced parsing)
  ```bash
  # XML parsing (recommended)
  sudo apt install -y xmlstarlet
  
  # Python3 (alternative XML parser)
  sudo apt install -y python3
  ```

### Setup

1. **Clone or download the repository**
   ```bash
   git clone https://github.com/therayyanawaz/ScriptKiddie.git
   cd ScriptKiddie/NMap
   ```

2. **Make scripts executable**
   ```bash
   chmod +x scripts/*.sh
   ```

3. **Verify Nmap installation**
   ```bash
   nmap --version
   ```

4. **Test the script**
   ```bash
   ./scripts/nmap_scan.sh
   ```

---

## 🚀 Quick Start

### Basic Usage

1. **Launch the interactive scanner**
   ```bash
   ./scripts/nmap_scan.sh
   ```

2. **Enter target information**
   - IP address (e.g., `192.168.1.1`)
   - IP range (e.g., `192.168.1.0/24`)
   - Hostname (e.g., `example.com`)

3. **Select scan type from the menu**
   - Choose from 28+ available scan profiles
   - Each option displays expected duration and intrusiveness level

4. **Monitor progress**
   - Real-time animated progress indicators
   - Color-coded status updates
   - Estimated completion times
