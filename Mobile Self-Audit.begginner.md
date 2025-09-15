<pre>
.|'''|      /.\     '||''''|'||''''|   '||\   /||`.|''''|,'||'''|,|''||''|'||    '||''''|        /.\    '||   ||`'||'''|.|''||''||''||''| 
||         // \\     ||  .   ||   .     ||\\.//|| ||    || ||   ||   ||    ||     ||   .        // \\    ||   ||  ||   ||   ||      ||    
`|'''|,   //...\\    ||''|   ||'''|     ||     || ||    || ||;;;;    ||    ||     ||'''|       //...\\   ||   ||  ||   ||   ||      ||    
 .   ||  //     \\   ||      ||         ||     || ||    || ||   ||   ||    ||     ||          //     \\  ||   ||  ||   ||   ||      ||    
 |...|'.//       \\..||.    .||....|   .||     ||.`|....|'.||...|'|..||..|.||...|.||....|   .//       \\.`|...|' .||...|'|..||..|  .||.   
</pre>

# 🔍 Safe mobile Audit: Protect Your Android & iOS Devices

![Mobile Security](https://img.shields.io/badge/Level-Beginner%20Friendly-green)
![Platform](https://img.shields.io/badge/Platform-Android%20|%20iOS-blue)
![Privacy](https://img.shields.io/badge/Privacy-Protection%20Guide-success)

## 📖 Table of Contents
- [Warning Signs Your Phone Might Be Hacked](#-warning-signs-your-phone-might-be-hacked)
- [Step-by-Step Security Check](#-step-by-step-security-check)
- [Android-Specific Checks](#-android-specific-checks)
- [iOS-Specific Checks](#-ios-specific-checks)
- [Immediate Action Plan](#-immediate-action-plan)
- [Proactive Protection](#-proactive-protection)
- [Emergency Measures](#-emergency-measures)
- [Resources & Tools](#-resources--tools)

---

## 🤔 Warning Signs Your Phone Might Be Hacked

Your phone might be compromised if you notice:

- **Rapid battery drain** even with normal usage
- **Unusually high data consumption** without reason
- **Phone gets hot** when not in use
- **Strange pop-ups** or ads appearing frequently
- **Apps crashing** unexpectedly
- **Unfamiliar apps** appearing on your device
- **Slow performance** despite good hardware
- **Unexpected reboots** or shutdowns
- **Unusual messages** sent from your accounts

---

## 🔍 Step-by-Step Security Check

### 1. Check Your Accounts First
Before checking your phone, verify if your accounts have been compromised:
- Visit **[Have I Been Pwned](https://haveibeenpwned.com)** 
- Enter your email address and phone number
- See if your information appears in any data breaches
- **Action:** If compromised, change passwords immediately

### 2. Review Installed Apps
**For Android and iOS:**
1. Open your Settings app
2. Go to "Apps" or "General > iPhone Storage"
3. Scroll through the complete list
4. Look for:
   - Apps you don't recognize
   - Apps with suspicious names
   - Duplicate system apps
   - Apps with excessive permissions

### 3. Check Battery Usage
**Android:**
- Settings > Battery > Battery Usage
- See which apps use the most power
- Look for unfamiliar apps high on the list

**iOS:**
- Settings > Battery
- Check battery usage by app
- Tap "Show Activity" to see background activity

### 4. Monitor Data Usage
**Android:**
- Settings > Network & Internet > Data Usage
- Check which apps use mobile data
- Look for suspicious data consumption

**iOS:**
- Settings > Cellular
- Scroll to see cellular data by app
- Reset statistics monthly to track trends

### 5. Review App Permissions
**Android:**
- Settings > Apps > [App Name] > Permissions
- Ask: Does this app need this permission?
- Revoke unnecessary permissions

**iOS:**
- Settings > Privacy & Security
- Review each category (Location, Contacts, etc.)
- See which apps have access
- Revoke access for suspicious apps

---

## 🤖 Android-Specific Checks

### Critical Security Settings
1. **Google Play Protect**
   - Settings > Security > Google Play Protect
   - Ensure "Scan apps with Play Protect" is ON
   - Run regular scans

2. **Install Unknown Apps**
   - Settings > Apps > Special app access > Install unknown apps
   - Ensure no browsers or messengers have permission enabled
   - Only enable temporarily when needed

3. **Device Admin Apps**
   - Settings > Security > Device admin apps
   - Ensure only trusted apps have this privilege
   - Malware can use this to prevent removal

4. **Accessibility Services**
   - Settings > Accessibility
   - Review all services enabled
   - Only trusted apps should have access

### Using Termux for Basic Checks
Termux is a safe Android terminal app available on Play Store:

```bash
# List installed packages
pm list packages

# List third-party apps only
pm list packages -3

# Get app details
dumpsys package [app.package.name] | grep "version\|userId"

# Check network connections (basic)
netstat -t
```

---

## 🍎 iOS-Specific Checks

### Critical Security Settings
1. **Device Management**
   - Settings > General > VPN & Device Management
   - Check for unknown profiles
   - Remove any suspicious management profiles

2. **Background App Refresh**
   - Settings > General > Background App Refresh
   - Disable for apps that don't need it
   - Saves battery and reduces attack surface

3. **Safety Check**
   - Settings > Privacy & Security > Safety Check
   - Review app access and emergency contacts
   - Reset system permissions if needed

4. **App Store Security**
   - Settings > App Store
   - Enable "App Downloads" to require password
   - Keep "Offload Unused Apps" enabled

### Using iSH for Basic Checks
iSH is a Linux shell for iOS available on App Store:

```bash
# Update package list
apk update

# Install basic tools
apk add curl

# Check network connectivity
ping google.com

# Download and check files
curl -O https://example.com/file.txt
```

---

## 🚨 Immediate Action Plan

### If You Suspect Compromise:
1. **Enable Airplane Mode** - Immediately cut off all connections
2. **Check Recent Apps** - Review recently installed/updated apps
3. **Review Account Activity** - Check Google/Apple account for suspicious activity
4. **Change Critical Passwords** - Especially email and financial accounts
5. **Run Security Scans** - Use built-in security features

### Suspicious App Detected:
1. **Force Stop** the app first
2. **Clear Storage/Cache** for the app
3. **Uninstall** the application
4. **Reboot** your device
5. **Check if problem persists**

---

## 🛡️ Proactive Protection

### Essential Security Habits
1. **Regular Updates**
   - Keep your operating system updated
   - Update apps regularly
   - Security patches fix known vulnerabilities

2. **App Source Control**
   - Only download from official stores (Play Store, App Store)
   - Read reviews before installing
   - Check app permissions before installing

3. **Network Security**
   - Use trusted Wi-Fi networks only
   - Consider using a VPN on public networks
   - Enable private DNS (dns.adguard.com)

4. **Backup Strategy**
   - Regular backups to cloud services
   - Local backups for critical data
   - Test restoration process periodically

### Advanced Protection (Optional)
- **Antivirus Apps**: Bitdefender, Malwarebytes, Norton
- **Firewall Apps**: NetGuard (Android)
- **Privacy Browsers**: Brave, Firefox Focus
- **Password Managers**: Bitwarden, LastPass

---

## 💣 Emergency Measures

### When to Factory Reset
Consider a full reset if:
- Your phone shows multiple warning signs
- You've found confirmed malware
- Performance issues persist after cleaning
- You suspect deep system compromise

### How to Reset Safely
**Before Reset:**
1. Backup important data (photos, contacts)
2. Export authenticator codes if using 2FA
3. Note down important app configurations

**Reset Process:**
**Android:**
- Settings > System > Reset options > Erase all data
- Remove SD card if present
- Confirm and wait for process to complete

**iOS:**
- Settings > General > Transfer or Reset iPhone > Erase All Content and Settings
- Enter passcode and Apple ID password to confirm

**After Reset:**
- Set up as new device (don't restore backup)
- Reinstall apps manually from official stores
- Restore personal data from clean backups
- Reconfigure security settings

---

## 🛠️ Resources & Tools

### Free Online Scanners
- **[VirusTotal](https://www.virustotal.com)** - Scan files and URLs
- **[Koodous](https://koodous.com)** - Android app analysis
- **[Have I Been Pwned](https://haveibeenpwned.com)** - Data breach checking

### Official Security Guides
- [Google Android Security Center](https://www.android.com/security-center/)
- [Apple iOS Security Guide](https://support.apple.com/guide/security/welcome/web)

### Recommended Apps
- **Authy** - Two-factor authentication
- **Bitwarden** - Password manager
- **NetGuard** - Android firewall
- **Signal** - Private messaging

---

## ⚠️ Important Disclaimer

This guide is for educational purposes only. The information provided is intended to help users protect their devices and privacy. Always ensure you have legal permission to access and test any device. The author is not responsible for any misuse of this information.

**Remember:** If you suspect serious compromise, consider consulting with a professional cybersecurity service.

---

**📱 Stay Safe | 🔒 Protect Your Privacy | 🛡️ Be Cyber Smart**

*Created with care for mobile users worldwide by prince1604*