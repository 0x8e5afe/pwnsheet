# BloodHound Results

**Collection Date:** 2024-01-18
**Method:** SharpHound.exe from compromised workstation

## High-Value Targets
- DA group has 3 members
- Administrator account LastLogon: 2024-01-10
- SQL Service account has SPN (Kerberoastable)

## Attack Paths
- JSMITH@ACME.LOCAL -> GenericAll on IT-ADMINS group
- IT-ADMINS -> WriteOwner on DOMAIN ADMINS
- SQLSVC account -> Owns critical servers

## Notes
- Domain trusts: None external
- Shortest path to DA: 3 hops from current user
- High-value Kerberoastable accounts: SQLSVC, BACKUPSVC
