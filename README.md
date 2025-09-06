```text
!     .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------. 
!    | .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |
!    | |    _______   | || |  _________   | || |     ______   | || |              | || |      __      | || | _____  _____ | || |  ________    | || |     _____    | || |  _________   | |
!    | |   /  ___  |  | || | |_   ___  |  | || |   .' ___  |  | || |              | || |     /  \     | || ||_   _||_   _|| || | |_   ___ `.  | || |    |_   _|   | || | |  _   _  |  | |
!    | |  |  (__ \_|  | || |   | |_  \_|  | || |  / .'   \_|  | || |    ______    | || |    / /\ \    | || |  | |    | |  | || |   | |   `. \ | || |      | |     | || | |_/ | | \_|  | |
!    | |   '.___`-.   | || |   |  _|  _   | || |  | |         | || |   |______|   | || |   / ____ \   | || |  | '    ' |  | || |   | |    | | | || |      | |     | || |     | |      | |
!    | |  |`\____) |  | || |  _| |___/ |  | || |  \ `.___.'\  | || |              | || | _/ /    \ \_ | || |   \ `--' /   | || |  _| |___.' / | || |     _| |_    | || |    _| |_     | |
!    | |  |_______.'  | || | |_________|  | || |   `._____.'  | || |              | || ||____|  |____|| || |    `.__.'    | || | |________.'  | || |    |_____|   | || |   |_____|    | |
!    | |              | || |              | || |              | || |              | || |              | || |              | || |              | || |              | || |              | |
!    | '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |
!     '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  


# 🛡️ SEC-AUDIT: Cross-Platform Ethical Hacking & Security Response Guide

A **complete step-by-step cybersecurity checklist** to check if your **Linux, macOS, or Windows** system is hacked — and how to respond.  
This guide is designed for **beginners, intermediate users, and cybersecurity professionals**.

📌 Keywords: *how to check if laptop is hacked, security checklist for Linux, macOS, Windows, system compromise audit, malware removal, cybersecurity hardening*

✍️ Author: **prince1604**

---

## 🚨 Step 1: Confirm If Your System Is Compromised

### 👤 Check Users & Logins
- **Linux / macOS**
  ```bash
  who                         # show current logins
  w                           # detailed session info
  last -i                     # recent login history with IP
  grep -vE "nologin|false" /etc/passwd   # valid accounts
  awk -F: '($3 == 0) {print}' /etc/passwd   # users with root privileges
  ```
- **Windows (PowerShell)**
  ```powershell
  query user
  Get-EventLog Security | where {$_.EventID -eq 4624}   # successful logins
  Get-EventLog Security | where {$_.EventID -eq 4625}   # failed logins
  net user
  ```

👉 Unknown users or suspicious IP addresses = **possible intrusion**.

---

### 🌐 Check Network Connections
- **Linux / macOS**
  ```bash
  ss -tulnp                # listening ports with processes
  netstat -ano             # active connections
  lsof -i -P -n            # open internet sockets
  sudo tcpdump -i any port 80 or port 443   # live traffic capture (advanced)
  ```
- **Windows (PowerShell)**
  ```powershell
  netstat -ano
  Get-NetTCPConnection
  Get-NetUDPEndpoint
  ```

👉 Unexpected remote IPs or ports = **red flag**.

---

### ⚙️ Check Running Processes
- **Linux / macOS**
  ```bash
  ps aux --sort=-%cpu | head -20     # top CPU consumers
  ps aux --sort=-%mem | head -20     # top memory consumers
  top                               # live process monitor
  htop                              # improved monitor (if installed)
  pgrep -lf "ssh|nc|perl|python"    # search for suspicious backdoor processes
  ```
- **Windows**
  ```powershell
  tasklist
  Get-Process
  Get-WmiObject Win32_Process | Select-Object ProcessId,Name,CommandLine
  ```

👉 Unknown processes running as **root/admin** = **critical warning**.

---

### 🕵️ Check Persistence & Backdoors
- **Linux / macOS**
  ```bash
  crontab -l                          # user cron jobs
  ls -lah /etc/cron* /var/spool/cron/ # system cron jobs
  ls ~/.ssh/                          # SSH keys
  systemctl list-unit-files --state=enabled
  systemctl list-timers --all         # scheduled timers
  ```
- **Windows**
  ```powershell
  Get-ScheduledTask
  Get-CimInstance Win32_StartupCommand
  Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq "Auto" }
  ```

👉 Look for malicious cron jobs, startup tasks, or SSH keys.

---

### 🧪 Check System Logs & Rootkits
- **Linux**
  ```bash
  sudo apt install chkrootkit rkhunter -y
  sudo chkrootkit
  sudo rkhunter --check
  journalctl -xe | less
  grep "Failed password" /var/log/auth.log
  grep "Accepted password" /var/log/auth.log
  sudo debsums -s                      # check for modified system binaries
  ```
- **macOS**
  - Use [KnockKnock](https://objective-see.org/products/knockknock.html), built-in XProtect.  
  - Check logs:
    ```bash
    log show --predicate 'eventMessage contains "login"' --info
    ```
- **Windows**
  - Use **Windows Defender**, Malwarebytes.  
  - Check logs:
    ```powershell
    Get-WinEvent -LogName Security | where {$_.Id -in 4624,4625} | Format-Table TimeCreated,Id,Message -AutoSize
    ```

👉 Evidence of backdoors, modified binaries, or malware = **likely hacked**.

---

### 💾 Check File Integrity (Advanced)
- **Linux**
  ```bash
  sudo apt install aide -y
  sudo aideinit
  sudo aide --check
  ```
- **Windows**
  ```powershell
  Get-FileHash C:\Windows\System32\*.exe -Algorithm SHA256
  ```

👉 Compare hashes to verify integrity of system files.

---

### 🧠 Memory & Forensic Checks (Advanced)
- **Linux**
  ```bash
  sudo apt install volatility -y     # memory forensics
  sudo volatility -f /proc/kcore linux_pslist
  ```
- **Windows**
  - Use **RAMMap** or **Volatility** for forensic analysis.  
  - Dump memory:
    ```powershell
    rundll32.exe sysdm.cpl,EditEnvironmentVariables
    ```

---

## 🛡️ Step 2: Contain the Threat

1. 🔌 **Disconnect from Wi-Fi/Ethernet** immediately.  
2. 💾 **Backup only trusted personal files** (docs, photos). Avoid executables/scripts.  
3. ❌ **Kill suspicious sessions**:
   - Linux/macOS:
     ```bash
     sudo pkill -KILL -u <username>
     ```
   - Windows:
     ```powershell
     logoff <session_id>
     ```

---

## 🔒 Step 3: Secure & Clean

### ✅ Update & Patch
- **Linux**
  ```bash
  sudo apt update && sudo apt full-upgrade -y
  sudo apt autoremove -y
  ```
- **macOS**
  ```bash
  softwareupdate --install --all
  ```
- **Windows**
  ```powershell
  Install-WindowsUpdate
  ```

---

### 🔑 Change All Passwords
```bash
passwd    # Linux/macOS
```
- Use strong passwords: **14+ characters, upper/lower/symbols/numbers**.  
- Change **system + online accounts** (email, banking, social).  

---

### 🚫 Lock Down Remote Access
- Disable SSH if unused:
  ```bash
  sudo systemctl stop ssh
  sudo systemctl disable ssh
  ```
- Enable firewall:
  - Linux:
    ```bash
    sudo apt install ufw -y
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw enable
    sudo ufw status verbose
    ```
  - Windows/macOS: Enable built-in firewall.

---

### 👥 Secure Accounts
- List all users:
  ```bash
  cut -d: -f1 /etc/passwd   # Linux/macOS
  ```
- Lock root account (Linux/macOS):
  ```bash
  sudo passwd -l root
  ```
- Delete suspicious users:
  ```bash
  sudo deluser <username>
  ```
- Windows:
  ```powershell
  net user
  net user <username> /delete
  ```

---

### 🔄 Enable Automatic Updates
- **Linux**
  ```bash
  sudo apt install unattended-upgrades -y
  sudo dpkg-reconfigure unattended-upgrades
  ```
- **macOS/Windows**: Enable automatic updates.

---

### 🖥️ Browser & Application Security
- Remove unknown extensions/add-ons.  
- Reset browser to defaults if hijacked.  
- Update apps (Chrome, Firefox, Edge, Office, Adobe).  
- Run antivirus scans on downloaded files.  

---

### 🧰 Advanced Security Tools
- **Linux**: `auditd`, `fail2ban`, `tripwire`, `clamav`, `lynis`  
- **macOS**: KnockKnock, BlockBlock, Little Snitch firewall, Objective-See suite  
- **Windows**: Sysinternals Suite, Autoruns, Process Explorer, OSQuery  

---

## 💣 Step 4: If Strongly Compromised

- 📂 Backup **personal files only** (no system files).  
- 💿 **Wipe the disk** and reinstall your OS (Linux, macOS, Windows).  
- 🛡️ Re-harden system after reinstall:
  - Enable firewall  
  - Create non-admin daily user  
  - Use password manager + 2FA  
  - Regularly audit system logs  

---

## 🌟 Security Best Practices

- 🛑 Don’t run unknown scripts or executables.  
- 🔑 Use unique passwords + 2FA for all accounts.  
- 🔄 Keep OS & software updated.  
- 🔥 Configure a firewall (UFW, pf, Windows Firewall).  
- 🕵️ Monitor logs weekly.  
- 📡 Consider IDS/IPS tools (Snort, Suricata).  
- 🧩 Encrypt your disk (BitLocker, FileVault, LUKS).  
- 📊 Regular vulnerability scans with `nmap`, `openvas`, or Nessus.  

---

## 📚 Resources

- [CIS Security Benchmarks](https://www.cisecurity.org/cis-benchmarks)  
- [MITRE ATT&CK Framework](https://attack.mitre.org/)  
- [Windows Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/)  
- [ClamAV Antivirus](https://www.clamav.net/)  
- [Objective-See macOS Security Tools](https://objective-see.org/products.html)  
- [Lynis Security Auditing Tool](https://cisofy.com/lynis/)  

---

⚠️ **Note**: Sometimes a “hacked” feeling may just be lag, misbehaving apps, or hardware issues. But if suspicious, always **audit logs, processes, and connections first**.  

---

