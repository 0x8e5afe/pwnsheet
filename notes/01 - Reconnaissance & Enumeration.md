# Reconnaissance & Enumeration

## 🎯 Goal
Build a complete, repeatable picture of each target: live hosts, open ports, services, versions, web surfaces, file shares, domains, and protocols. Work through this file top-to-bottom for every subnet and every host. Record everything in the templates at the end.

## Table of Contents

1. [Host Discovery](#1-host-discovery-per-subnet)
2. [Port Scanning](#2-port-scanning)
3. [Service Enumeration](#3-service-enumeration-per-open-port)
4. [Web Application Reconnaissance](#4-web-application-reconnaissance)
5. [SMB / NetBIOS Enumeration](#5-smb-netbios-enumeration)
6. [NFS Enumeration](#6-nfs-enumeration)
7. [LDAP / Directory Services](#7-ldap-directory-services-discovery)
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
18. [Documentation and Hypotheses](#18-documentation-and-hypotheses)

---

## 📋 Phase Checklist

### Host Discovery

- [ ] **ICMP sweep/ARP discovery/TCP ping** → [1.1](#11-icmp-sweeparp-discoverytcp-ping)
- [ ] **Reachability confirmation from attack VM** → [1.2](#12-reachability-confirmation)
- [ ] **Network pattern analysis (servers vs workstations)** → [1.3](#13-network-pattern-analysis)

### Port Scanning

- [ ] **Full TCP scan (-p-) + default scripts + versions** → [2.1](#21-full-tcp-scan-mandatory-per-host)
- [ ] **Top UDP ports (≥100) + critical UDP list** → [2.2](#22-udp-scan-essential)
- [ ] **Parse results and save per-host** → [2.3](#23-saving-results)
- [ ] **Vulnerability scan** → [2.4](#24-vulnerability-scanning)

### Service Enumeration

- [ ] **Banner grabbing for each open service** → [3.1](#31-manual-banner-grabbing)
- [ ] **Service versions documented** → [3.2](#32-version-confirmation)
- [ ] **Basic manual checks (defaults / anonymous / weak configs)** → [3.3](#33-baseline-checks-by-service)

### Web Reconnaissance

- [ ] **Tech stack identification** → [4.1](#41-initial-fingerprinting)
- [ ] **Directory / endpoint discovery (multiple tools)** → [4.2](#42-directory-endpoint-discovery)
- [ ] **Special files (robots, sitemap, backups)** → [4.3](#43-special-files-and-backups)
- [ ] **Attack surface mapping (auth, upload, params, APIs, vhosts)** → [4.4](#44-attack-surface-mapping)
- [ ] **CMS scanning** → [4.5](#45-cms-scanning)
- [ ] **Vulnerability scanning** → [4.6](#46-web-vulnerability-scanning)

### SMB / NetBIOS

- [ ] **Shares enumerated (anon + auth)** → [5.1](#51-share-listing)
- [ ] **Permissions documented (read/write)** → [5.2](#52-permissions-and-content-sweep)
- [ ] **User / group info collected** → [5.3](#53-usersgroupsos)
- [ ] **NetExec/CrackMapExec enumeration** → [5.4](#54-netexeccrackmapexec-enumeration)
- [ ] **SMB vulnerability checks** → [5.5](#55-smb-vulnerability-checks)

### NFS

- [ ] **Exports enumerated (showmount, rpcinfo)** → [6.1](#61-detect-rpcnfs-and-list-exports)
- [ ] **Mountable shares + permissions checked** → [6.2](#62-mount-shares-and-verify-access)
- [ ] **Shares mounted and searched for data** → [6.3](#63-search-for-sensitive-data)
- [ ] **no_root_squash / weak export options checked** → [6.4](#64-no_root_squash-export-misconfig-checks)

### LDAP / Directory Services

- [ ] **Naming contexts / domain structure** → [7.1](#71-rootdse-and-naming-contexts)
- [ ] **Users / groups / computers enumeration** → [7.2](#72-users-groups-computers)
- [ ] **Domain info and DC identification** → [7.3](#73-dc-domain-role-confirmation)

### SNMP

- [ ] **Community strings discovered** → [8.1](#81-community-discovery)
- [ ] **System, users, processes, network extracted** → [8.2](#82-walk-important-oids)

### DNS

- [ ] **Zone transfer attempts** → [9.1](#91-zone-transfers)
- [ ] **Subdomain enumeration** → [9.2](#92-subdomain-enumeration)
- [ ] **NS/SOA/MX/TXT + domain map** → [9.3](#93-record-sweep)

### FTP

- [ ] **Anonymous login check** → [10.1](#101-anonymous-login-check)
- [ ] **Version vulnerability check** → [10.2](#102-version-and-vulnerability-check)
- [ ] **File enumeration and download** → [10.3](#103-file-enumeration)

### SSH

- [ ] **Version and algorithm enumeration** → [11.1](#111-version-and-algorithm-enumeration)
- [ ] **Authentication methods** → [11.2](#112-authentication-methods)
- [ ] **Brute force (if applicable)** → [11.3](#113-brute-force-if-applicable)

### SMTP

- [ ] **User enumeration (VRFY/EXPN/RCPT)** → [12.1](#121-user-enumeration)
- [ ] **Open relay check** → [12.2](#122-open-relay-check)

### POP3/IMAP

- [ ] **Banner and capabilities** → [13.1](#131-banner-and-capabilities)
- [ ] **Authentication and enumeration** → [13.2](#132-authentication-and-enumeration)

### RPC

- [ ] **RPC service enumeration** → [14.1](#141-rpc-service-enumeration)
- [ ] **RPC client enumeration** → [14.2](#142-rpc-client-enumeration)

### Databases

- [ ] **MSSQL enumeration** → [15.1](#151-mssql-enumeration)
- [ ] **MySQL enumeration** → [15.2](#152-mysql-enumeration)
- [ ] **PostgreSQL enumeration** → [15.3](#153-postgresql-enumeration)

### RDP/VNC

- [ ] **RDP enumeration** → [16.1](#161-rdp-enumeration)
- [ ] **VNC enumeration** → [16.2](#162-vnc-enumeration)

### Active Directory

- [ ] **Domain enumeration** → [17.1](#171-domain-enumeration)
- [ ] **User and group enumeration** → [17.2](#172-user-and-group-enumeration)
- [ ] **Kerberos enumeration** → [17.3](#173-kerberos-enumeration)

### Documentation

- [ ] **Suspected OS & role documented** → [18.1](#181-suspected-os-and-role)
- [ ] **Attack hypotheses formulated** → [18.2](#182-attack-hypotheses)
- [ ] **Note Findings** → [18.3](#183-host-notes-repeat-per-host), [18.4](#184-network-inventory-per-subnet)

---

## Quick Reference Commands

### Essential One-Liners

```bash
# Fast TCP scan all ports
sudo nmap -Pn -sS -p- --min-rate 10000 <RHOST>
```

```bash
# Service scan on discovered ports
sudo nmap -sC -sV -p <PORTS> <RHOST>
```

```bash
# UDP top ports
sudo nmap -sU --top-ports 20 <RHOST>
```

```bash
# SMB null session
smbclient -L //<RHOST> -N && enum4linux -a <RHOST>
```

```bash
# LDAP anonymous
ldapsearch -x -H ldap://<RHOST> -s base
```

```bash
# Web directory brute
gobuster dir -u http://<RHOST>/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
```

```bash
# SNMP walk
snmpwalk -v2c -c public <RHOST>
```

```bash
# Zone transfer
dig axfr <DOMAIN> @<NS>
```

```bash
# Rustscan fast all-ports scan, chaining into nmap
rustscan -a <RHOST> --ulimit 5000 -- -sV -sC -oA rustscan_nmap_<RHOST>
```

```bash
# Naabu fast TCP port discovery
naabu -host <RHOST> -p - -rate 20000 -o naabu_<RHOST>.txt
```

```bash
# HTTP probing on many hosts from a file
httpx -l hosts_http.txt -status-code -title -tech-detect -o httpx_hosts_http.txt
```

```bash
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
```

```bash
# Web enumeration
which gobuster feroxbuster ffuf nikto whatweb wpscan
```

```bash
# SMB tools
which smbclient smbmap enum4linux enum4linux-ng rpcclient
```

```bash
# Network tools
which snmpwalk onesixtyone ldapsearch
```

```bash
# Password attacks
which hydra medusa
```

```bash
# AD tools
which bloodhound-python kerbrute impacket-GetNPUsers impacket-GetUserSPNs
```

```bash
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
echo "$RHOST <HOSTNAME>" | sudo tee -a /etc/hosts
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
```

```bash
# Extract live IPs (grep on gnmap)
grep "Status: Up" recon_hosts_icmp.gnmap | cut -d " " -f 2 > live_hosts.txt
```

```bash
# Alternative: ping sweep with fping
fping -a -g <SUBNET>/24 2>/dev/null > live_hosts.txt
```

If ICMP is blocked:

```bash
# TCP SYN ping on common ports across the subnet
nmap -sn -PS21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3389,5900,8080 \
  <SUBNET>/24 -oA recon_hosts_tcp
```

```bash
# TCP ACK ping on common ports (useful for stateful firewalls)
nmap -sn -PA21,22,80,443 <SUBNET>/24 -oA recon_hosts_tcp_ack
```

If you are on the same L2 (local network), add ARP discovery:

```bash
# ARP discovery with Nmap (fastest for local networks)
nmap -sn -PR <SUBNET>/24 -oA recon_hosts_arp
```

```bash
# ARP discovery of local network with arp-scan
sudo arp-scan -l
```

```bash
# ARP discovery of specific subnet with arp-scan
sudo arp-scan <SUBNET>/24
```

If discovery is totally blocked:

```bash
# Assume single host is up and scan without ping
nmap -Pn 10.11.1.5 -oA recon_host_10.11.1.5_noping
```

```bash
# Scan entire subnet as up hosts with top 1000 ports
nmap -Pn -sS --top-ports 1000 <SUBNET>/24 -oA recon_noping_top1000
```

NetBIOS discovery (when SMB/NetBIOS suspected):

```bash
# NetBIOS scan of subnet with nbtscan
nbtscan <SUBNET>/24
```

```bash
# Recursive NetBIOS scan of subnet with nbtscan
nbtscan -r <SUBNET>/24
```

```bash
# Lookup NetBIOS names for a single host
nmblookup -A <RHOST>
```

```bash
# SMB discovery across subnet with NetExec (nxc)
nxc smb <SUBNET>/24
```

```bash
# SMB discovery across subnet with netexec
netexec smb <SUBNET>/24
```

### 1.2 Reachability confirmation

For every "up" host, validate from your VM:

```bash
# Ping host to confirm basic reachability
ping -c 2 <RHOST>
```

```bash
# Run traceroute to identify network path to host
traceroute -n <RHOST>
```

```bash
# Check if host responds on common TCP ports
nc -zv <RHOST> 22 80 443 445 2>&1
```

When ping fails but scan suggests presence, keep host anyway.

### 1.3 Network pattern analysis

From live hosts list, roughly cluster likely roles:

```bash
# Quick top-ports/service scan across live hosts to guess roles
nmap -sS -sV -T4 --top-ports 200 -iL live_hosts.txt -oA nmap_top200_all
```

```bash
# OS fingerprinting against live hosts to guess operating systems
nmap -O --osscan-guess -iL live_hosts.txt -oA nmap_os_guess_all
```

```bash
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
```

```bash
# Fast TCP all-ports sweep with Masscan
sudo masscan -p1-65535 <RHOST> --rate=1000 -oL masscan_<RHOST>.txt
```

**Detailed scan on discovered ports:**

```bash
# Extract open TCP ports from fast Nmap scan into a comma-separated list
grep -E '^[0-9]+/tcp.*open' nmap_fast_tcp_<RHOST>.nmap | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//' > tcp_ports.txt
```

```bash
# Run detailed Nmap scan with default scripts and version detection on discovered ports
sudo nmap -sC -sV -p $(cat tcp_ports.txt) <RHOST> -oA nmap_detailed_tcp_<RHOST>
```

```bash
# Run full comprehensive TCP scan with aggressive detection on all ports
sudo nmap -A -T4 -sC -sV -p- <RHOST> -oA nmap_full_tcp_<RHOST>
```

**Alternative comprehensive approaches:**

```bash
# Standard thorough TCP scan with default scripts and version detection
sudo nmap -Pn -sC -sV -p- -oN alltcp.txt <RHOST>
```

```bash
# Service scan with maximum version detection intensity
sudo nmap -sV --version-intensity 9 -p- <RHOST> -oA nmap_versions_<RHOST>
```

```bash
# Aggressive TCP scan using only discovery scripts
sudo nmap -A -T4 -p- -sS -sV -oN initial --script discovery <RHOST>
```

### 2.2 UDP scan (essential)

UDP scanning is slow but critical for finding services like SNMP, DNS, TFTP:

```bash
# UDP scan of top 100 ports (recommended minimum)
sudo nmap -sU --top-ports 100 <RHOST> -oA nmap_udp_top100_<RHOST>
```

```bash
# UDP scan of top 20 ports with scripts and service detection
sudo nmap -Pn -sU -sV -sC --top-ports=20 -oN top_20_udp_nmap.txt <RHOST>
```

```bash
# UDP scan of critical high-value ports
sudo nmap -sU -p 53,67,68,69,123,161,162,500,514,520,623,624,631,1900,4500,5353 <RHOST> -oA nmap_udp_critical_<RHOST>
```

```bash
# Targeted UDP scan with service detection on key ports
sudo nmap -sU -sV -p 53,69,123,161,500 <RHOST> -oA nmap_udp_services_<RHOST>
```

### 2.3 Saving results

Create organized folder structure:

```bash
# Create organized recon directory structure for the host
mkdir -p recon/<RHOST>/{nmap,web,smb,notes}
```

```bash
# Move all scan files for this host into the Nmap directory
mv *<RHOST>* recon/<RHOST>/nmap/
```

```bash
# Copy host and port lists into the host recon directory
cp live_hosts.txt tcp_ports.txt recon/<RHOST>/
```

### 2.4 Vulnerability scanning

```bash
# Run Nmap vulnerability scripts against all discovered services
sudo nmap -A -T4 -sC -sV --script vuln <RHOST> -oA nmap_vuln_tcp_<RHOST>
```

```bash
# Check SMB services for known vulnerabilities
sudo nmap --script smb-vuln* -p 139,445 <RHOST>
```

```bash
# Check HTTPS service for Heartbleed and related SSL issues
sudo nmap --script ssl-heartbleed -p 443 <RHOST>
```

```bash
# Update Nuclei templates
nuclei -ut
```

```bash
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
```

```bash
# HTTP banner #1
echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc -nv <RHOST> 80
```

```bash
# HTTP banner #2
curl -I http://<RHOST>/
```

```bash
# HTTP banner #3
curl -s http://<RHOST>/ | head -50
```

```bash
# HTTPS banner
curl -k -I https://<RHOST>/
```

```bash
# Telnet for interactive services
telnet <RHOST> <PORT>
```

```bash
# Verbose curl for headers (HTTP)
curl -v http://<RHOST>/
```

```bash
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
```

```bash
# Verbose SSH to enumerate supported authentication mechanisms
ssh -v <RHOST> 2>&1 | grep "Authentications that can continue"
```

```bash
# Nmap SSH enumeration: algorithms, host keys, authentication methods
nmap -p 22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods <RHOST>
```

**FTP (21):**

```bash
# Connect to FTP (try anonymous login)
ftp <RHOST> # Try: anonymous / anonymous
```

```bash
# Nmap FTP enumeration
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst <RHOST>
```

**SMTP (25):**

```bash
# Banner grab and testing with Netcat
nc -nv <RHOST> 25 # Tru: HELO test, VRFY root, EXPN admin
```

```bash
# Telnet for interactive SMTP commands
telnet <RHOST> 25
```

**RPC/NFS hints:**

```bash
# Enumerate RPC services
rpcinfo -p <RHOST>
```

```bash
# Nmap RPC enumeration
nmap -p 111 --script rpcinfo <RHOST>
```

### 3.4 TLS/SSL enumeration

Focus on protocol support, cipher strength, certificate issues, and obvious SSL/TLS vulnerabilities.

```bash
# Nmap cipher suites + certificate info
nmap -p 443,8443,9443 --script ssl-enum-ciphers,ssl-cert <RHOST>
```

```bash
# Check for common SSL/TLS vulns
nmap -p 443 --script ssl-heartbleed,ssl-poodle,ssl-dh-params <RHOST>
```

```bash
# testssl.sh quick profile (very verbose but excellent overview)
testssl.sh --fast --sneaky https://<RHOST>/
```

```bash
# Focus on protocols and known vulns only
testssl.sh --fast --sneaky --protocols --vulnerable https://<RHOST>/
```


```bash
# sslscan summary
sslscan --no-failed --show-certificate <RHOST>:443
```

```bash
# sslyze (if installed)
sslyze --regular <RHOST>:443
```


## 4. Web Application Reconnaissance

Treat every HTTP(S) port as separate (80, 443, 8080, 8443, etc.).

### 4.1 Initial fingerprinting

```bash
# Whatweb fingerprinting #1
whatweb -a 3 http://<RHOST>:<PORT>/
```

```bash
# Whatweb fingerprinting #3
whatweb -a 4 http://<RHOST>:<PORT>/
```

```bash
# Whatweb fingerprinting #3
whatweb -a 3 https://<RHOST>:<PORT>/
```

```bash
# Headers and redirects #1
curl -I http://<RHOST>:<PORT>/
```

```bash
# Headers and redirects #2
curl -k -I https://<RHOST>:<PORT>/
```

```bash
# Headers and redirects #3
curl -v http://<RHOST>:<PORT>/ 2>&1 | head -50
```

```bash
# Nmap HTTP scripts #1
nmap -p <PORT> --script http-headers,http-methods,http-title <RHOST>
```

```bash
# Nmap HTTP scripts #1
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
```

```bash
# With common wordlist
gobuster dir -u http://<RHOST>:<PORT>/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt -t 50 -o web_gobuster_common.txt
```

```bash
# Ignore SSL errors
gobuster dir -u https://<RHOST>:<PORT>/ \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -k -t 50
```

```bash
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
```

```bash
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
```

```bash
# Basic directory fuzzing with extensions
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -u http://<RHOST>:<PORT>/FUZZ \
  -e .php,.html,.txt,.bak,.zip,.log
```

```bash
# Recursive scanning
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -u http://<RHOST>:<PORT>/FUZZ -recursion
```

```bash
# VHost fuzzing
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://<RHOST>:<PORT>/ -H "Host: FUZZ.<DOMAIN>" -fs <BASE_SIZE>
```

```bash
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
```

```bash
# Basic directory fuzzing with extensions and authentication
dirsearch -u http://<RHOST>:<PORT>/ -x 403,400,404,401 \
  -r -R 2 --auth=<USER>:<PASS> --auth-type=basic
```

**Dirb:**

```bash
# Basic directory fuzzing
dirb http://<RHOST>:<PORT>/ /usr/share/wordlists/dirb/common.txt
```

```bash
# Directory fuzzing with huge wordlist
dirb http://<RHOST>:<PORT>/ /usr/share/dirb/wordlists/big.txt -o dirb_output.txt
```

### 4.3 Special files and backups

```bash
# Check common special files
for file in robots.txt sitemap.xml crossdomain.xml .well-known/security.txt; do
  echo "=== $file ===" && curl -s "http://<RHOST>:<PORT>/$file" | head -50
done
```

```bash
# Check for backup files
for ext in bak old tmp backup zip tar.gz sql; do
  curl -s -o /dev/null -w "%{http_code}" "http://<RHOST>:<PORT>/index.$ext"
done
```

```bash
# Git exposure check #1
curl -s http://<RHOST>:<PORT>/.git/HEAD
```

```bash
# Git exposure check #2
curl -s http://<RHOST>:<PORT>/.git/config
```

```bash
# SVN exposure
curl -s http://<RHOST>:<PORT>/.svn/entries
```

```bash
# DS_Store (Mac)
curl -s http://<RHOST>:<PORT>/.DS_Store
```

```bash
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
```

```bash
# Aggressive plugin detection
wpscan --url http://<RHOST>/ --plugins-detection aggressive
```

```bash
# Full enumeration with API token
wpscan --url http://<RHOST>/ --enumerate vp,vt,tt,cb,dbe,u,m \
  --plugins-detection aggressive --plugins-version-detection aggressive
```

```bash
# Brute force login
wpscan --url http://<RHOST>/ -U <USERNAME> -P /usr/share/wordlists/rockyou.txt
```

```bash
# Ignore SSL errors
wpscan --url https://<RHOST>/ --disable-tls-checks --enumerate u,t,p
```

**Joomla:**

```bash
# Basic Joomla scan against the target
joomscan -u http://<RHOST>/
```

```bash
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
```

```bash
# Nikto with max scan time and text output
nikto -h http://<RHOST>:<PORT>/ -maxtime 30m -o nikto_<RHOST>.txt
```

```bash
# Nikto with tuning and HTML report
nikto -h http://<RHOST>:<PORT>/ -Tuning 123bde -o report.html -Format htm
```

```bash
# Through proxy
nikto -useproxy http://<PROXY_IP>:3128 -h http://<RHOST>/
```

---

## 5. SMB / NetBIOS Enumeration

### 5.1 Share listing

**Anonymous enumeration:**

```bash
# List SMB shares on the target using a null session
smbclient -L //<RHOST> -N
```

```bash
# List SMB shares on the target explicitly using an empty username and null session
smbclient -L //<RHOST>/ -U '' -N
```

```bash
# Enumerate shares/permissions on the target host
smbmap -H <RHOST>
```

```bash
# Enumerate shares/permissions using the username "anonymous"
smbmap -H <RHOST> -u anonymous
```

```bash
# Enumerate shares/permissions using empty username and empty password
smbmap -H <RHOST> -u '' -p ''
```


```bash
# Recursively list accessible directories/files across shares (can be noisy)
smbmap -H <RHOST> -R
```

```bash
# Attempt to connect to the IPC$ share with a null session
smbclient //<RHOST>/IPC$ -N
```

```bash
# Attempt to connect to the ADMIN$ share with a null session
smbclient //<RHOST>/ADMIN$ -N
```

```bash
# Attempt to connect to the C$ administrative share with a null session
smbclient //<RHOST>/C$ -N
```

**Authenticated enumeration:**

```bash
# Authenticated smbmap enumeration (user/pass)
smbmap -H <RHOST> -u '<USER>' -p '<PASS>'
```

```bash
# Authenticated smbmap enumeration with an explicit domain
smbmap -H <RHOST> -u '<USER>' -p '<PASS>' -d <DOMAIN>
```

```bash
# Connect to a specific SMB share using user%pass syntax
smbclient //<RHOST>/<SHARE> -U '<USER>%<PASS>'
```

```bash
# Recursive smbmap listing, limited to 5 levels deep
smbmap -H <RHOST> -u '<USER>' -p '<PASS>' -R --depth 5
```

**Null session attempt:**

```bash
# Null session connect to RPC endpoint (no user, no password)
rpcclient -U "" -N <RHOST>

```bash
# Enumerate domain users via RPC using null session
rpcclient -U "" <RHOST> -N -c "enumdomusers"

```bash
# Enumerate domain groups via RPC using null session
rpcclient -U "" <RHOST> -N -c "enumdomgroups"
```

### 5.2 Permissions and content sweep

**In smbclient prompt:**

```bash
# Connect to the share (drops into smb: \> prompt)
smbclient //<RHOST>/<SHARE> -U '<USER>%<PASS>'
```

```bash
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
```

```bash
# Quick string sweep for readable artifacts (min length 8)
strings -n 8 *
```

```bash
# Grep for common secret keywords (case-insensitive, recursive, with line numbers)
grep -RniE "pass|pwd|secret|token|key|cred" .
```

```bash
# Find common config/text files, then search for lines/files mentioning "password"
find . -name "*.txt" -o -name "*.xml" -o -name "*.ini" -o -name "*.conf" | xargs grep -l password
```

**Mount SMB share:**

```bash
# Create a local mountpoint for the SMB share
mkdir /tmp/share
```

```bash
# Mount SMB share interactively (may prompt for creds depending on target)
sudo mount -t cifs //<RHOST>/<SHARE> /tmp/share
```

```bash
# Mount SMB share with explicit credentials (non-interactive)
sudo mount -t cifs -o 'username=<USER>,password=<PASSWORD>' //<RHOST>/<SHARE> /tmp/share
```

### 5.3 Users/groups/OS

**Enum4linux:**

```bash
# Full enum4linux sweep; save output to a file
enum4linux -a <RHOST> | tee enum4linux_<RHOST>.txt
```

```bash
# Enumerate users
enum4linux -U <RHOST> 
```

```bash
# Enumerate groups
enum4linux -G <RHOST>
```

```bash
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
```

```bash
# Nmap comprehensive SMB enumeration
nmap -p 445 --script "smb-enum-*" <RHOST>
```

```bash
# Nmap SMB Version detection
nmap -p 139,445 --script smb-protocols <RHOST>
```

Here's the reformatted content with 2 NetExec examples and the rest using CrackMapExec:

### 5.4 NetExec/CrackMapExec enumeration

```bash
# Run NetExec (nxc alias) SMB module against the target (basic info + default checks)
nxc smb <RHOST>
```

```bash
# Run NetExec SMB module with null session
nxc smb <RHOST> -u '' -p ''
```

```bash
# Run CrackMapExec SMB module against the target
crackmapexec smb <RHOST>
```

```bash
# Authenticate to SMB and enumerate active SMB sessions on the target
crackmapexec smb <RHOST> -u '' -p '' --sessions
```

```bash
# Authenticate to SMB and enumerate users currently logged on to the target
crackmapexec smb <RHOST> -u '' -p '' --loggedon-users
```

```bash
# Spider shares for files
crackmapexec smb <RHOST> -u '' -p '' -M spider_plus
```

```bash
# Password spray
crackmapexec smb <RHOST> -u users.txt -p '' --continue-on-success
```

### 5.5 SMB vulnerability checks

```bash
# Check for EternalBlue (MS17-010) vulnerability
nmap -p 445 --script smb-vuln-ms17-010 <RHOST>
```

```bash
# Check for MS08-067 (NetAPI) SMB vulnerability
nmap -p 445 --script smb-vuln-ms08-067 <RHOST>
```

```bash
# Check for CVE-2017-7494 (Samba remote code execution via writable share)
nmap -p 445 --script smb-vuln-cve-2017-7494 <RHOST>
```

```bash
# Check for all SMB vulnerabilities
nmap -p 139,445 --script smb-vuln* <RHOST>
```

```bash
# Check signing (Nmap)
nmap -p 445 --script smb-security-mode <RHOST>
```

```bash
# Check signing (NetExec)
nxc smb <RHOST> --gen-relay-list relay.txt
```

---

## 6. NFS Enumeration

### 6.1 Detect RPC/NFS and list exports

```bash
# Scan common RPC/NFS ports and run rpcinfo NSE
nmap -p 111,2049,32769 --script rpcinfo <RHOST> -oA nmap_rpc_<RHOST>
```

```bash
# List RPC programs/versions/ports via portmapper
rpcinfo -p <RHOST>
```

```bash
# Quick RPC reachability/info check
rpcinfo <RHOST>
```

```bash
# List exported NFS filesystems
showmount -e <RHOST>
```

```bash
# Show clients and their mount points (if exposed)
showmount -a <RHOST>  
```

```bash
# Show only export directory names
showmount -d <RHOST>  
```

```bash
# Run NFS NSE scripts (list, exports, filesystem stats)
nmap -p 111 --script nfs-ls,nfs-showmount,nfs-statfs <RHOST>
```

### 6.2 Mount shares and verify access

```bash
# Create a local mount point directory
sudo mkdir -p /mnt/nfs/<RHOST>/<SHARE_NAME>
```

```bash
# Mount the NFS export with default settings
sudo mount -t nfs <RHOST>:/<EXPORT> /mnt/nfs/<RHOST>/<SHARE_NAME>
```

```bash
# Mount forcing NFSv3 and disabling locking (common for compatibility)
sudo mount -t nfs -o nolock,vers=3 <RHOST>:/<EXPORT> /mnt/nfs/<RHOST>/<SHARE_NAME>
```

```bash
# Mount forcing NFSv2 (legacy targets)
sudo mount -t nfs -o nolock,vers=2 <RHOST>:/<EXPORT> /mnt/nfs/<RHOST>/<SHARE_NAME>
```

```bash
# Confirm mounts and usage
df -h | grep nfs
```

```bash
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
```

```bash
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

## 7. LDAP / Directory Services Discovery

### 7.1 RootDSE and naming contexts

```bash
# Anonymous bind - base info #1
ldapsearch -x -h <RHOST> -s base
```

```bash
# Anonymous bind - base info #2
ldapsearch -x -h <RHOST> -s base namingcontexts
```

```bash
# Anonymous bind - base info #3
ldapsearch -x -H ldap://<RHOST> -s base
```

```bash
# Get supported controls
ldapsearch -x -h <RHOST> -s base supportedControl
```

```bash
# Get supported extensions
ldapsearch -x -h <RHOST> -s base supportedExtension
```

```bash
# Nmap LDAP scripts #1
nmap -p 389,636 --script ldap-rootdse <RHOST>
```

```bash
# Nmap LDAP scripts #2
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
```

```bash
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
```

```bash
# DNS SRV records for DC #1
dig _ldap._tcp.<DOMAIN> SRV
```

```bash
# DNS SRV records for DC #2
dig _kerberos._tcp.<DOMAIN> SRV
```

---

## 8. SNMP Enumeration

### 8.1 Community discovery

```bash
# Onesixtyone community string brute force #1
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <RHOST>
```

```bash
# Onesixtyone community string brute force #2
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <RHOST>
```

```bash
# Multiple hosts
onesixtyone -c community.txt -i hosts.txt
```

```bash
# snmp-check (public)
snmp-check <RHOST> -c public
```

```bash
# snmp-check (private)
snmp-check <RHOST> -c private
```

```bash
# Nmap SNMP brute force
nmap -sU -p 161 --script snmp-brute <RHOST>
```

### 8.2 Walk important OIDs

```bash
# SNMP walk version 1
snmpwalk -v1 -c public <RHOST>
```

```bash
# SNMP walk version 2c
snmpwalk -v2c -c public <RHOST>
```

```bash
# SNMP walk entire MIB tree
snmpwalk -v2c -c public <RHOST> .1
```

```bash
# System information OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.1
```

```bash
# Network interfaces OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.2.2 
```

```bash
# Running processes OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.25.4.2.1.2
```

```bash
# Host resources OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.25.1
```

```bash
# Installed software OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.25.6.3.1.2 
```

```bash
# Windows user accounts OID
snmpwalk -v1 -c public <RHOST> 1.3.6.1.4.1.77.1.2.25
```

```bash
# Windows domain OID
snmpwalk -v2c -c public <RHOST> 1.3.6.1.4.1.77.1.4.1
```

```bash
# Extended enumeration with snmp-check
snmp-check -v2c -c public <RHOST> -w
```

```bash
# Bulk get for faster enumeration
snmpbulkwalk -v2c -c public <RHOST>
```

**Extract specific info:**

```bash
# Get hostname
snmpget -v2c -c public <RHOST> 1.3.6.1.2.1.1.5.0
```

```bash
# Get system description
snmpget -v2c -c public <RHOST> 1.3.6.1.2.1.1.1.0
```

```bash
# Get uptime
snmpget -v2c -c public <RHOST> 1.3.6.1.2.1.1.3.0
```

---

## 9. DNS Enumeration

### 9.1 Zone transfers

```bash
# Get nameservers using dig
dig ns <DOMAIN> @<DNS_SERVER> +short
```

```bash
# Get nameservers using Cloudflare DNS
dig ns <DOMAIN> @1.1.1.1 +short
```

```bash
# Get nameservers using host
host -t ns <DOMAIN>
```

```bash
# Attempt zone transfer with dig
dig axfr <DOMAIN> @<NS_SERVER>
```

```bash
# Attempt zone transfer alternate syntax
dig axfr @<DNS_SERVER> <DOMAIN>
```

```bash
# Attempt zone transfer with host
host -l <DOMAIN> <NS_SERVER>
```

```bash
# Loop through all nameservers for zone transfer
for ns in $(dig ns <DOMAIN> +short); do
  echo "Trying AXFR against $ns"
  dig axfr <DOMAIN> @$ns
done
```

```bash
# Zone transfer using dnsrecon
dnsrecon -d <DOMAIN> -t axfr
```

### 9.2 Subdomain enumeration

**Wordlist brute force:**

```bash
# Gobuster DNS enumeration
gobuster dns -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -o dns_gobuster_<DOMAIN>.txt
```

```bash
# DNSrecon brute force
dnsrecon -d <DOMAIN> -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt
```

```bash
# Fierce subdomain scanner
fierce --domain <DOMAIN>
```

```bash
# Fierce with custom DNS server
fierce --domain <DOMAIN> --dns-servers <DNS_SERVER>
```

```bash
# Wfuzz DNS fuzzing
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://<DOMAIN>" -H "Host: FUZZ.<DOMAIN>" --hc 404
```

**OSINT/passive:**

```bash
# Sublist3r passive enumeration
sublist3r -d <DOMAIN> -o subdomains_<DOMAIN>.txt
```

```bash
# Amass passive enumeration
amass enum -passive -d <DOMAIN> -o amass_passive.txt
```

```bash
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
```

```bash
# Query all record types
dig <DOMAIN> ANY +noall +answer
```

```bash
# Get MX records
dig <DOMAIN> MX +short
```

```bash
# Get TXT records
dig <DOMAIN> TXT +short
```

```bash
# Get MX records with host
host -t mx <DOMAIN>
```

```bash
# Get TXT records with host
host -t txt <DOMAIN>
```

```bash
# Reverse DNS lookup
dig -x <IP_ADDRESS>
```

```bash
# Reverse DNS with host
host <IP_ADDRESS>
```

```bash
# Check SPF record
dig txt <DOMAIN> | grep "v=spf"
```

```bash
# Check DMARC record
dig txt _dmarc.<DOMAIN>
```

---

## 10. FTP Enumeration

### 10.1 Anonymous login check

```bash
# Automated anonymous login check with nmap
nmap -p 21 --script ftp-anon <RHOST>
```

```bash
# Anonymous login with lftp
lftp <RHOST>
```

### 10.2 Version and vulnerability check

```bash
# Banner grab with netcat
nc -nv <RHOST> 21
```

```bash
# Version detection with nmap
nmap -sV -p 21 <RHOST>
```

```bash
# FTP enumeration scripts
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor <RHOST>
```

```bash
# FTP vulnerability scan
nmap -p 21 --script ftp-vuln* <RHOST>
```

```bash
# Search for vsftpd exploits
searchsploit vsftpd
```

```bash
# Search for proftpd exploits
searchsploit proftpd
```

### 10.3 File enumeration

```bash
# Recursive download with wget
wget -r ftp://anonymous:anonymous@<RHOST>/
```

```bash
# Mirror FTP directory
wget -m --no-passive ftp://anonymous:anonymous@<RHOST>/
```

---

## 11. SSH Enumeration

### 11.1 Version and algorithm enumeration

```bash
# SSH banner grab with netcat
nc -nv <RHOST> 22
```

```bash
# SSH banner grab with telnet
telnet <RHOST> 22
```

```bash
# SSH version detection
nmap -sV -p 22 <RHOST>
```

```bash
# Enumerate SSH algorithms
nmap -p 22 --script ssh2-enum-algos <RHOST>
```

```bash
# Get SSH host key
nmap -p 22 --script ssh-hostkey <RHOST>
```

```bash
# SSH key scan
ssh-keyscan <RHOST>
```

### 11.2 Authentication methods

```bash
# Check authentication methods
ssh -o PreferredAuthentications=none -o ConnectTimeout=5 <RHOST>
```

```bash
# Verbose authentication check
ssh -v <RHOST> 2>&1 | grep "Authentications that can continue"
```

```bash
# Nmap authentication methods scan
nmap -p 22 --script ssh-auth-methods <RHOST>
```

```bash
# Public key acceptance test
nmap -p 22 --script ssh-publickey-acceptance <RHOST>
```

### 11.3 Brute force (if applicable)

```bash
# Hydra SSH single user
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ssh://<RHOST>
```

```bash
# Hydra SSH user and password lists
hydra -L users.txt -P passwords.txt ssh://<RHOST> -t 4
```

```bash
# Medusa SSH brute force
medusa -h <RHOST> -u <USER> -P /usr/share/wordlists/rockyou.txt -M ssh
```

```bash
# NetExec SSH brute force
nxc ssh <RHOST> -u <USER> -p /usr/share/wordlists/rockyou.txt
```

---

## 12. SMTP Enumeration

### 12.1 User enumeration

```bash
# SMTP connection with netcat
nc -nv <RHOST> 25
```

```bash
# SMTP connection with telnet
telnet <RHOST> 25
```

```bash
# SMTP enumeration scripts
nmap -p 25 --script smtp-commands,smtp-enum-users <RHOST>
```

```bash
# SMTP user enumeration with multiple methods
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <RHOST>
```

```bash
# SMTP user enum with VRFY
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <RHOST>
```

```bash
# SMTP user enum with EXPN
smtp-user-enum -M EXPN -U users.txt -t <RHOST>
```

```bash
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
```

```bash
# POP3 connection with telnet
telnet <RHOST> 110
```

```bash
# POP3S secure connection
openssl s_client -connect <RHOST>:995 -quiet
```

```bash
# IMAP connection with netcat
nc -nv <RHOST> 143
```

```bash
# IMAP connection with telnet
telnet <RHOST> 143
```

```bash
# IMAPS secure connection
openssl s_client -connect <RHOST>:993 -quiet
```

```bash
# Nmap POP3/IMAP capabilities
nmap -p 110,143,993,995 --script pop3-capabilities,imap-capabilities <RHOST>
```

### 13.2 Authentication and enumeration

```bash
# Hydra POP3 brute force
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <RHOST> pop3
```

```bash
# Hydra IMAP brute force
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <RHOST> imap
```

---

## 14. RPC Enumeration

### 14.1 RPC service enumeration

```bash
# List RPC services detailed
rpcinfo -p <RHOST>
```

```bash
# List RPC services
rpcinfo <RHOST>
```

```bash
# Nmap RPC enumeration
nmap -p 111 --script rpcinfo <RHOST>
```

```bash
# Nmap RPC with version detection
nmap -sV -p 111 --script=rpcinfo <RHOST>
```

### 14.2 RPC client enumeration

```bash
# Connect with null session
rpcclient -U "" -N <RHOST>
```

```bash
# Enumerate domain users one-liner
rpcclient -U "" <RHOST> -N -c "enumdomusers" 2>/dev/null
```

```bash
# Enumerate domain groups one-liner
rpcclient -U "" <RHOST> -N -c "enumdomgroups" 2>/dev/null
```

```bash
# RPC enumeration with credentials
rpcclient -U '<USER>%<PASS>' <RHOST> -c "enumdomusers"
```

---

## 15. Database Enumeration

### 15.1 MSSQL enumeration

```bash
# Nmap MSSQL info script
nmap -p 1433 --script ms-sql-info <RHOST>
```

```bash
# Nmap MSSQL config script
nmap -p 1433 --script ms-sql-config <RHOST>
```

```bash
# Nmap MSSQL empty password check
nmap -p 1433 --script ms-sql-empty-password <RHOST>
```

```bash
# Nmap MSSQL NTLM info
nmap -p 1433 --script ms-sql-ntlm-info <RHOST>
```

```bash
# Nmap MSSQL brute force
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt <RHOST>
```

```bash
# Impacket mssqlclient Windows auth
impacket-mssqlclient <USER>@<RHOST> -windows-auth
```

```bash
# Impacket mssqlclient with credentials
impacket-mssqlclient <DOMAIN>/<USER>:<PASS>@<RHOST>
```

```bash
# sqsh MSSQL client
sqsh -S <RHOST> -U <USER> -P <PASS>
```

```bash
# NetExec MSSQL authentication
nxc mssql <RHOST> -u <USER> -p <PASS>
```

```bash
# NetExec MSSQL query execution
nxc mssql <RHOST> -u <USER> -p <PASS> -q "SELECT name FROM master.dbo.sysdatabases"
```

### 15.2 MySQL enumeration

```bash
# MySQL connection with password
mysql -h <RHOST> -u root -p
```

```bash
# MySQL connection without password
mysql -h <RHOST> -u root
```

```bash
# Nmap MySQL info script
nmap -p 3306 --script mysql-info <RHOST>
```

```bash
# Nmap MySQL empty password check
nmap -p 3306 --script mysql-empty-password <RHOST>
```

```bash
# Nmap MySQL enumeration
nmap -p 3306 --script mysql-enum <RHOST>
```

```bash
# Nmap MySQL brute force
nmap -p 3306 --script mysql-brute --script-args userdb=users.txt,passdb=passwords.txt <RHOST>
```

### 15.3 PostgreSQL enumeration

```bash
# PostgreSQL connection
psql -h <RHOST> -U <USER> -d <DATABASE>
```

```bash
# Nmap PostgreSQL brute force
nmap -p 5432 --script pgsql-brute <RHOST>
```

---

## 16. RDP/VNC Enumeration

### 16.1 RDP enumeration

```bash
# Nmap RDP encryption enumeration
nmap -p 3389 --script rdp-enum-encryption <RHOST>
```

```bash
# Nmap RDP NTLM info
nmap -p 3389 --script rdp-ntlm-info <RHOST>
```

```bash
# Nmap RDP MS12-020 vulnerability check
nmap -p 3389 --script rdp-vuln-ms12-020 <RHOST>
```

```bash
# RDP connection with rdesktop
rdesktop <RHOST>
```

```bash
# RDP connection with xfreerdp
xfreerdp /v:<RHOST> /u:<USER> /p:<PASS>
```

```bash
# RDP connection ignoring certificate
xfreerdp /v:<RHOST> /u:<USER> /p:<PASS> /cert:ignore
```

```bash
# Hydra RDP brute force
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt rdp://<RHOST>
```

```bash
# NetExec RDP brute force
nxc rdp <RHOST> -u <USER> -p /usr/share/wordlists/rockyou.txt
```

### 16.2 VNC enumeration

```bash
# Nmap VNC info script
nmap -p 5900 --script vnc-info <RHOST>
```

```bash
# Nmap VNC brute force
nmap -p 5900 --script vnc-brute <RHOST>
```

```bash
# VNC connection with display
vncviewer <RHOST>:<DISPLAY>
```

```bash
# VNC connection on port 5900
vncviewer <RHOST>::5900
```

```bash
# Hydra VNC brute force
hydra -s 5900 -P /usr/share/wordlists/rockyou.txt vnc://<RHOST>
```

---

## 17. Active Directory Enumeration

### 17.1 Domain enumeration

```bash
# Get domain info with nxc
nxc smb <RHOST>
```

```bash
# Get shares with null session
nxc smb <RHOST> -u '' -p '' --shares
```

```bash
# LDAP naming contexts
ldapsearch -x -H ldap://<DC_IP> -s base namingcontexts
```

```bash
# BloodHound data collection
bloodhound-python -c All -u '<USER>' -p '<PASS>' -d <DOMAIN> -dc <DC_HOSTNAME> -ns <DC_IP>
```

```bash
# Get domain SID
rpcclient -U '<USER>%<PASS>' <RHOST> -c "lsaquery"
```

### 17.2 User and group enumeration

```bash
# Enumerate domain users with nxc
nxc smb <DC_IP> -u '<USER>' -p '<PASS>' --users
```

```bash
# Enumerate domain groups with nxc
nxc smb <DC_IP> -u '<USER>' -p '<PASS>' --groups
```

```bash
# RID brute force with nxc
nxc smb <DC_IP> -u '<USER>' -p '<PASS>' --rid-brute
```

```bash
# Enumerate users with rpcclient
rpcclient -U '<USER>%<PASS>' <DC_IP> -c "enumdomusers"
```

```bash
# Enumerate groups with rpcclient
rpcclient -U '<USER>%<PASS>' <DC_IP> -c "enumdomgroups"
```

```bash
# LDAP user enumeration
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'DC=<DOMAIN>,DC=local' '(objectClass=user)' sAMAccountName
```

```bash
# Impacket AD user enumeration
impacket-GetADUsers -all -dc-ip <DC_IP> '<DOMAIN>/<USER>:<PASS>'
```

### 17.3 Kerberos enumeration

```bash
# Kerbrute user enumeration
kerbrute userenum -d <DOMAIN> --dc <DC_IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

```bash
# Kerbrute password spray
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt '<PASSWORD>'
```

```bash
# AS-REP roasting without credentials
impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <DC_IP> -format hashcat
```

```bash
# AS-REP roasting with credentials
impacket-GetNPUsers '<DOMAIN>/<USER>:<PASS>' -dc-ip <DC_IP> -request
```

```bash
# Kerberoasting
impacket-GetUserSPNs '<DOMAIN>/<USER>:<PASS>' -dc-ip <DC_IP> -request
```

```bash
# Nmap Kerberos user enumeration
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='<DOMAIN>',userdb=users.txt <DC_IP>
```

---

## 18. Documentation and Hypotheses

### 18.1 Suspected OS and role

Infer OS/role from:

- TTL values (64=Linux, 128=Windows, 255=Cisco/Network)
- Window size and TCP options
- Service banners
- Open port combinations
- Web stack technologies

**OS Fingerprinting commands:**

```bash
# Nmap OS detection #1
sudo nmap -O <RHOST>
```

```bash
# Nmap OS detection #1
sudo nmap -O --osscan-guess <RHOST>
```

```bash
# TTL-based guess
ping -c 1 <RHOST> | grep ttl
```

```bash
# p0f passive fingerprinting
p0f -i eth0
```


State confidence (high/medium/low) in notes.

### 18.2 Attack hypotheses

For each host, list likely entry points by evidence:

- Exposed file share containing credentials
- Outdated public service version with known CVE
- Weak export permissions (NFS no_root_squash)
- Web app with upload or LFI surface
- Default credentials on service
- Misconfigured permissions
- Anonymous access enabled

Keep hypotheses short and testable.

### 18.3 Host notes (repeat per host)

Use this exact template:

```markdown
# Host: <RHOST>

## Basic Information
- IP Address: <RHOST>
- Hostname: <if any>
- Suspected OS: <guess + evidence>
- Role: <guess + evidence>

## Port Scan Results
### TCP
| Port | Service | Version | Notes |
|------|---------|---------|-------|
|      |         |         |       |

### UDP
| Port | Service | Version | Notes |
|------|---------|---------|-------|
|      |         |         |       |

## Service Enumeration Findings
- SSH:
- FTP:
- SMB:
- NFS:
- LDAP:
- SNMP:
- SMTP:
- Databases:
- Other:

## Web Findings
Per port/vhost note:
- URL:
- Title/Stack:
- Interesting paths:
- Special files:
- Parameters/APIs:
- Auth/upload surfaces:
- CMS type and version:

## Shares / Exports Findings
- SMB shares:
- NFS exports:
- FTP/WebDAV/etc:

## Credentials Found
| Username | Password | Source | Service |
|----------|----------|--------|---------|
|          |          |        |         |

## Initial Attack Vectors
1.
2.
3.

## Vulnerability Assessment
| Service | Vulnerability | CVE | Exploit Available |
|---------|---------------|-----|-------------------|
|         |               |     |                   |

## Next Steps
- [ ] ...
- [ ] ...
```

---

### 18.4 Network Inventory (per subnet)

```markdown
# Network: <SUBNET>

## Host Inventory
| IP | Hostname | OS | Role | Key Services | Priority |
|----|----------|----|----- |--------------|----------|
|    |          |    |      |              |          |

## Relationships / Notes
- Domain(s):
- Trusts:
- North–south dependencies (web→db, app→ldap):
- Shared storage:
- Network segmentation:

## Credentials Collected
| Username | Password/Hash | Domain | Source |
|----------|---------------|--------|--------|
|          |               |        |        |

## Critical Findings
1.
2.
3.

## Attack Path Summary
```




