# AD Attacks

## Kerberoasting
- Successfully requested TGS for SQLSVC account
- Hash: $krb5tgs$23$*sqlsvc$ACME.LOCAL...
- Cracking in progress with hashcat
- Backup service account also Kerberoastable

## ASREPRoasting
- Found 8 accounts with "PreAuth not required"
- Successfully retrieved AS-REP hash for TESTUSER
- Hash cracked: Summer2023!
- Account has limited privileges

## Lateral Movement
- Pass-the-hash with JSMITH credentials successful
- Accessed 10.10.10.25 (file server) via SMB
- RDP to workstations using compromised accounts
- PSExec working on systems without AV

## Privilege Escalation
- GenericAll permission found on IT-ADMINS group
- Potential path: Add user to IT-ADMINS -> WriteOwner on DA
- Unquoted service path on 10.10.10.25: C:\\Program Files\\Custom Service\\service.exe
- Scheduled task running as SYSTEM with writable binary

## Notes
- LSASS dumps from workstations yielded 5 new credentials
- Mimikatz detected and blocked by Windows Defender on newer systems
- Considering DCSync attack if DA access achieved
