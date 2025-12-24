# Testing Timeline

## 2024-01-15 (Day 1)
**09:00** - Kickoff call with client, received credentials
**10:30** - Initial external reconnaissance started
**11:45** - Discovered portal.acme.com and api.acme.com
**14:00** - Found exposed API documentation at /docs
**15:30** - Identified SQL injection in search functionality
**16:00** - Confirmed IDOR vulnerability in order API
**17:00** - End of day 1

## 2024-01-16 (Day 2)
**09:00** - VPN access established
**10:00** - Internal network scan initiated (10.10.10.0/24)
**12:00** - Discovered 15 live hosts
**13:30** - Found exposed MySQL on 10.10.10.15
**14:45** - SSH bruteforce successful: webadmin/Welcome123
**16:30** - Extracted database credentials from config files
**17:00** - End of day 2

## 2024-01-17 (Day 3)
**09:00** - Started Active Directory enumeration
**10:30** - LDAP anonymous bind confirmed
**11:45** - Discovered Kerberoastable service accounts
**13:00** - Successfully performed ASREPRoasting
**14:30** - Cracked hash: testuser/Summer2023!
**15:00** - Lateral movement to file server (10.10.10.25)
**16:00** - Found sensitive files in shared folders
**17:00** - End of day 3

## 2024-01-18 (Day 4)
**09:00** - Ran SharpHound for BloodHound collection
**10:30** - Analyzed attack paths to Domain Admins
**12:00** - Found GenericAll on IT-ADMINS group
**13:30** - Attempted privilege escalation (in progress)
**15:00** - Documented all findings so far
**16:30** - Client status update call
**17:00** - End of day 4

## Key Findings Summary
- 4 Critical vulnerabilities
- 3 High severity issues
- 6 Medium severity issues
- 10+ credentials compromised
- Path to Domain Admin identified (not fully exploited per ROE)

## Notes
- All testing within approved hours
- Client notified of critical SQL injection immediately
- No disruptions or outages caused
- Remaining time for report writing and final validation
