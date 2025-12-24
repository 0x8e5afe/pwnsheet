# AD Enumeration

## Domain Info
- Domain: ACME.LOCAL
- DC: DC01.ACME.LOCAL (10.10.10.50)
- Functional level: Windows Server 2016

## Users
- Total: 247 users
- Interesting:
  - Administrator (never expires)
  - SQLSVC (password never expires, PreAuth not required)
  - BACKUPSVC (Kerberoastable)
  - 15 users with "Password never expires"
  - 8 users with "PreAuth not required"

## Groups
- Domain Admins: 3 members
- Enterprise Admins: 1 member
- IT-ADMINS: 12 members (excessive privileges)
- SQL-ADMINS: 5 members

## Computers
- Total: 89 computers
- 12 workstations (Windows 10/11)
- 8 servers (Windows Server 2016-2019)
- 3 computers haven't logged in for 180+ days

## Notes
- Default domain password policy: 8 chars, 90 day expiry
- No fine-grained password policies
- LLMNR/NBT-NS enabled network-wide
