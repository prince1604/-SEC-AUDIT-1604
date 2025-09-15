<pre>
███╗   ███╗ ██████╗ ██████╗ ██╗██╗     ███████╗    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗██╗     ██╗███████╗████████╗
████╗ ████║██╔═══██╗██╔══██╗██║██║     ██╔════╝    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██║     ██║██╔════╝╚══██╔══╝
██╔████╔██║██║   ██║██████╔╝██║██║     █████╗      ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝     ██║     ███████║█████╗  ██║     █████╔╝ ██║     ██║███████╗   ██║   
██║╚██╔╝██║██║   ██║██╔══██╗██║██║     ██╔══╝      ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝      ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██║     ██║╚════██║   ██║   
██║ ╚═╝ ██║╚██████╔╝██████╔╝██║███████╗███████╗    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║       ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║███████║   ██║   
╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝╚══════╝    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝        ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝╚══════╝   ╚═╝   
</pre>

# 🔍 Mobile Security Checklist: Advanced Termux & iSH Commands

![Mobile Security](https://img.shields.io/badge/Level-Intermediate%20Users-yellow)
![Platform](https://img.shields.io/badge/Platform-Termux%20|%20iSH-blue)
![Privacy](https://img.shields.io/badge/Privacy-Advanced%20Checks-success)

## 📖 Advanced Command Guide
- [Termux Setup & Basics](#-termux-setup--basics-android)
- [Network Analysis Commands](#-network-analysis-commands)
- [System Investigation](#-system-investigation-commands)
- [iSH Setup & Basics](#-ish-setup--basics-ios)
- [Step-by-Step Investigation](#-step-by-step-investigation-guide)
- [Interpreting Results](#-interpreting-your-results)
- [Emergency Commands](#-emergency-commands)

---

## 🐧 Termux Setup & Basics (Android)

### Initial Setup
1. **Install Termux** from F-Droid (recommended) or Play Store
2. **Update packages** after installation:
```bash
pkg update && pkg upgrade -y
```
3. **Install essential tools**:
```bash
pkg install curl wget net-tools termux-api nmap python python-pip nodejs -y
```

### Basic Termux Commands
```bash
# Check device information
termux-info

# Check battery status
termux-battery-status

# Check device location (if enabled)
termux-location

# Check telephony information
termux-telephony-deviceinfo

# List storage devices
termux-storage-list
```

---

## 🌐 Network Analysis Commands

### Active Connections Check
```bash
# Show all active network connections
netstat -tuln

# Show detailed connection information
netstat -ant

# Monitor connections in real-time
watch -n 2 netstat -ant

# Check DNS resolution
nslookup google.com
dig google.com

# Test network connectivity
ping -c 4 google.com
```

### Advanced Network Scanning
```bash
# Scan your local network (replace with your network)
nmap -sP 192.168.1.0/24

# Scan for open ports on your device
nmap localhost

# Check network interfaces
ip addr show

# Monitor network traffic (requires root for full functionality)
tcpdump -i any -c 10
```

### Wi-Fi Analysis
```bash
# Get Wi-Fi connection information
termux-wifi-connectioninfo

# Scan for available Wi-Fi networks
termux-wifi-scaninfo

# Check signal strength
termux-wifi-scaninfo | grep -E "SSID|level"
```

---

## 🔍 System Investigation Commands

### Process Monitoring
```bash
# List all running processes
ps -A

# Show process tree
pstree

# Monitor system resources
top

# Check CPU usage
mpstat

# Monitor memory usage
free -h
```

### Package and App Analysis
```bash
# List all installed packages
pm list packages

# List third-party apps only
pm list packages -3

# Get detailed info about a specific app
dumpsys package com.example.app | head -50

# Check app permissions
dumpsys package com.example.app | grep permission

# List running services
dumpsys activity services
```

### File System Checks
```bash
# Check storage usage
df -h

# Check for large files
du -h /data/data | sort -rh | head -20

# Search for suspicious files
find /sdcard -name "*.apk" -o -name "*.sh" -o -name "*.py"

# Check download directory
ls -la ~/storage/downloads/
```

---

## 🍎 iSH Setup & Basics (iOS)

### Initial iSH Setup
1. **Install iSH** from App Store
2. **Update package list**:
```bash
apk update
```
3. **Install essential tools**:
```bash
apk add curl wget net-tools nmap python3 py3-pip nodejs npm vim
```

### Basic iSH Commands
```bash
# Check system information
uname -a

# Check disk usage
df -h

# Check running processes
ps aux

# Monitor system resources
top
```

### Network Commands for iSH
```bash
# Check network interfaces
ifconfig

# Test connectivity
ping -c 4 google.com

# Check DNS resolution
nslookup google.com

# Scan local network (limited functionality)
nmap -sn 192.168.1.0/24
```

---

## 🔎 Step-by-Step Investigation Guide

### Phase 1: Initial Assessment
```bash
# 1. Check battery status
termux-battery-status

# 2. Check network connections
netstat -ant

# 3. Check running processes
ps -A

# 4. Check installed apps
pm list packages -3
```

### Phase 2: Deep Investigation
```bash
# 1. Monitor network traffic in real-time
watch -n 5 netstat -ant

# 2. Check for suspicious processes
ps -A | grep -E '(curl|wget|nc|netcat|ssh|python|perl)'

# 3. Analyze app permissions
dumpsys package | grep -A5 -B5 "permission"

# 4. Check system logs (limited without root)
logcat -d | tail -50
```

### Phase 3: Advanced Checks
```bash
# 1. Check for hidden files
find /sdcard -name ".*" -type f

# 2. Analyze APK files in download folder
find /sdcard -name "*.apk" -exec ls -la {} \;

# 3. Check for suspicious scripts
find /sdcard -name "*.sh" -o -name "*.py" -o -name "*.js"

# 4. Monitor system resource usage over time
top -n 1 -b | head -20
```

---

## 📊 Interpreting Your Results

### Network Connections to Watch For
- **Unknown IP addresses** especially foreign countries
- **Strange port numbers** (especially high-numbered ports)
- **Persistent connections** that don't close
- **Unexpected outgoing connections**

### Suspicious Processes
- **Unknown process names**
- **Processes running as unusual users**
- **High CPU/memory usage** from unknown processes
- **Processes with random or scrambled names**

### App Red Flags
- **Apps with excessive permissions**
- **Apps from unknown developers**
- **Apps that can't be uninstalled normally**
- **Apps that reappear after uninstallation**

---

## 🚨 Emergency Commands

### Immediate Isolation
```bash
# Enable airplane mode (requires termux-api)
termux-wifi-enable false
termux-telephony-call "*#*#4636#*#*"  # Opens testing menu

# Kill suspicious processes
pkill -f "suspicious_process_name"

# Force stop an app
am force-stop com.suspicious.app
```

### Forensic Data Collection
```bash
# Create incident report directory
mkdir ~/security_audit_$(date +%Y%m%d_%H%M%S)

# Save network information
netstat -ant > ~/security_audit/network_connections.txt

# Save process list
ps -A > ~/security_audit/running_processes.txt

# Save installed apps list
pm list packages -3 > ~/security_audit/installed_apps.txt

# Package the evidence
tar -czf security_evidence.tar.gz ~/security_audit/
```

### System Protection
```bash
# Revoke internet access from suspicious apps
# (Note: Requires root for full functionality)

# Monitor system activity continuously
watch -n 10 'date; netstat -ant; echo; ps -A | head -20'

# Set up periodic scanning
while true; do netstat -ant | grep -E '(192.168|10.|172.)' >> network_log.txt; sleep 30; done
```

---

## ⚠️ Important Notes & Limitations

### Termux Limitations (Without Root)
- Cannot access other apps' data
- Limited system log access
- Cannot monitor all processes
- Limited network interception capabilities

### iSH Limitations (iOS Restrictions)
- Heavy sandboxing restrictions
- No access to iOS system files
- Limited network capabilities
- Cannot monitor other apps

### Safety Precautions
1. **Don't run unknown scripts** from untrusted sources
2. **Be careful with system commands** - some can disrupt your device
3. **Backup important data** before making changes
4. **Understand what each command does** before executing

---

## 🛠️ Additional Tools to Install

### For Termux (Android):
```bash
# Network monitoring
pkg install termux-monitor

# System information
pkg install proot neofetch

# Forensic tools
pip install forensic-adb

# Security scanners
pkg install lynis
```

### For iSH (iOS):
```bash
# Additional tools
apk add openssh-client openssh-keygen

# Security utilities
apk add file

# Monitoring tools
apk add htop
```

---

## 📚 Learning Resources

### Termux Documentation:
- [Termux Wiki](https://wiki.termux.com)
- [Termux GitHub](https://github.com/termux)

### iSH Documentation:
- [iSH GitHub](https://github.com/ish-app/ish)

### Mobile Security Guides:
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Security Bulletin](https://source.android.com/security/bulletin)

---

**🔐 Remember:** These commands are for educational purposes and security auditing of your own devices only. Always ensure you have proper authorization before investigating any device.

**📱 Stay Vigilant | 🔍 Monitor Regularly | 🛡️ Protect Your Digital Life**

*Created for educational purposes by prince1604 - Use responsibly and ethically*