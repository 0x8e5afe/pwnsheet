# Credentials

| Source | Username | Password/Hash | Type | Tested On | Works |
|--------|----------|---------------|------|-----------|-------|
| Initial | testuser | P@ssw0rd123 | Plaintext | VPN | ✓ |
| Initial | demo@acme.com | Demo2024! | Plaintext | Web Portal | ✓ |
| SQL Injection | admin | admin123 | Plaintext | portal.acme.com | ✓ |
| SSH Bruteforce | webadmin | Welcome123 | Plaintext | 10.10.10.15 | ✓ |
| File Share | ACME\\jsmith | Password1! | Plaintext | Domain | ✓ |
| LSASS Dump | ACME\\schen | $NT$8846f7e... | NTLM Hash | Domain | ✓ |
| ASREPRoast | ACME\\testuser | Summer2023! | Plaintext | Domain | ✓ (limited) |
| Kerberoast | ACME\\sqlsvc | [cracking...] | TGS Hash | Domain | Pending |
| Config File | db_admin | MySql_P@ss_2024 | Plaintext | 10.10.10.15:3306 | ✓ |
| .htpasswd | apiuser | Api2024Access! | Plaintext | api.acme.com | ✓ |

## Notes
- jsmith password reused on multiple systems
- schen account is member of IT-ADMINS group (high value)
- Database credentials found in /var/www/html/config.php
- Many users follow pattern: Season+Year!
