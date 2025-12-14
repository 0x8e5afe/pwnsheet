let currentPhase = null;
let parameters = {};
let phases = {};
let currentContent = '';
let checkboxStates = new Map();
let filteredParameters = null;
let activeCodeBlock = null;
let activeCodeBlockIndex = null;
let codeBlockParamMap = [];
let outsideClickListenerAttached = false;
let suppressParamPanelRender = false;
let paramSearchTerm = '';
let resetToastTimeout = null;
let codeBlockWrappers = [];
let selectionCopyHandlerAttached = false;
let lastCopiedSelection = '';
let lastCopiedWrapper = null;
let lastCopiedAt = 0;

const CHECKBOX_STORAGE_KEY = 'checkboxStates';
const PARAMS_STORAGE_KEY = 'parameters';
const PARAM_TOKEN_REGEX = /(<[A-Z_0-9]+>|{{[A-Z_0-9]+}})/g;

// CONSTANTS CHANGED: Using %% delimiters and a safe separator to avoid Markdown collisions (tables/backticks)
const PARAM_MARKER_START = '%%PWN_START%%';
const PARAM_MARKER_END = '%%PWN_END%%';
// Use a separator without pipes to avoid Markdown table splitting inside inline code/backticks
const PARAM_SEPARATOR = '%%PVAL%%';
const PARAM_SEPARATOR_REGEX = escapeRegex(PARAM_SEPARATOR);

document.addEventListener('DOMContentLoaded', () => {
    injectStyles(); // Ensures green color is always loaded
    loadMarkdownFiles();
    setupEventListeners();
    setupMarkedOptions();
    updateResetButtonVisibility();
    
    // Smooth fade in
    document.body.style.opacity = '0';
    requestAnimationFrame(() => {
        document.body.style.transition = 'opacity 0.3s ease';
        document.body.style.opacity = '1';
    });
});

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// FIX: Force Green Styles with High Specificity
function injectStyles() {
    const styleId = 'pwn-dynamic-styles';
    if (!document.getElementById(styleId)) {
        const style = document.createElement('style');
        style.id = styleId;
        style.textContent = `
            /* Target the token specifically */
            span.param-token {
                color: rgb(0, 255, 30) !important; /* Bright Green */
                font-weight: bold;
                display: inline-block;
                text-shadow: 0 0 2px rgba(46, 204, 113, 0.2);
            }
            
            /* Ensure it overrides code block syntax highlighting */
            .code-block code span.param-token,
            pre code span.param-token {
                color: rgb(0, 255, 30) !important;
            }
        `;
        document.head.appendChild(style);
    }
}

function setupMarkedOptions() {
    const renderer = new marked.Renderer();
    const originalLinkRenderer = renderer.link;
    
    renderer.link = function(href, title, text) {
        const html = originalLinkRenderer.call(this, href, title, text);
        const isExternal = /^https?:\/\//i.test(href);
        if (!isExternal) {
            return html;
        }
        return html.replace(/^<a /, '<a target="_blank" rel="noopener noreferrer" ');
    };
    
    marked.setOptions({
        renderer: renderer,
        breaks: true,
        gfm: true
    });
}

function setupEventListeners() {
    document.getElementById('togglePanelBtn').addEventListener('click', toggleRightPanel);

    const scrollTopBtn = document.getElementById('scrollTopBtn');
    const contentArea = document.getElementById('contentArea');
    
    contentArea.addEventListener('scroll', () => {
        if (contentArea.scrollTop > 300) {
            scrollTopBtn.classList.add('visible');
        } else {
            scrollTopBtn.classList.remove('visible');
        }
    });

    scrollTopBtn.addEventListener('click', () => {
        contentArea.scrollTo({ top: 0, behavior: 'smooth' });
    });

    const newAssessmentBtn = document.getElementById('newAssessmentBtn');
    if (newAssessmentBtn) {
        newAssessmentBtn.addEventListener('click', resetAssessment);
    }

    const downloadKitBtn = document.getElementById('downloadKitBtn');
    const skeletonMenu = document.getElementById('skeletonMenu');

    if (downloadKitBtn && skeletonMenu) {
        downloadKitBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            skeletonMenu.classList.toggle('show');
        });

        skeletonMenu.querySelectorAll('.skeleton-option').forEach((option) => {
            option.addEventListener('click', (e) => {
                e.stopPropagation();
                const templateType = option.dataset.template || 'empty';
                skeletonMenu.classList.remove('show');
                downloadSkeletonZip(templateType);
            });
        });

        document.addEventListener('click', (e) => {
            if (!skeletonMenu.contains(e.target) && !downloadKitBtn.contains(e.target)) {
                skeletonMenu.classList.remove('show');
            }
        });
    }

    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            e.preventDefault();
            resetAssessment();
        }
    });
}

async function downloadSkeletonZip(templateType = 'empty') {
    const downloadBtn = document.getElementById('downloadKitBtn');
    if (!downloadBtn || typeof JSZip === 'undefined') {
        console.error('JSZip is not available; cannot build the notes kit.');
        return;
    }

    const originalLabel = downloadBtn.innerHTML;
    downloadBtn.disabled = true;
    downloadBtn.innerHTML = '<i class="bi bi-hourglass-split" aria-hidden="true"></i><span>Building kit...</span>';

    try {
        const zip = new JSZip();
        const basePath = 'pwnsheet-skeleton/';
        const skeletonFiles = buildNotesSkeleton(templateType);

        Object.entries(skeletonFiles).forEach(([path, content]) => {
            const normalizedContent = content.startsWith('\n') ? content.slice(1) : content;
            zip.file(basePath + path, normalizedContent);
        });

        const blob = await zip.generateAsync({ type: 'blob' });
        const downloadLink = document.createElement('a');
        downloadLink.href = URL.createObjectURL(blob);
        downloadLink.download = `pwnsheet-skeleton-${templateType}.zip`;
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
        setTimeout(() => URL.revokeObjectURL(downloadLink.href), 1200);
    } catch (error) {
        console.error('Failed to build the notes kit zip', error);
    } finally {
        downloadBtn.disabled = false;
        downloadBtn.innerHTML = originalLabel;
    }
}

function buildNotesSkeleton(templateType = 'empty') {
    if (templateType === 'prefilled') {
        return {
'README.md': `# Pentest Notes

Quick reference structure for engagement notes.

- **info.md** - engagement details, scope, contacts
- **web/** - web application notes (one file per app)
- **infra/** - infrastructure/host notes (one file per host)
- **AD/** - Active Directory enumeration and attack notes
- **credentials.md** - all credentials found during testing
- **screenshots/** - screenshots and proof-of-concept files
- **findings/** - one file per finding with full details
- **timeline.md** - chronological log of testing activities
`,

'info.md': `# Engagement Information

**Client:** Acme Corporation
**Engagement Type:** [x] Black-box [ ] Grey-box [ ] White-box
**Start Date:** 2024-01-15
**Deadline:** 2024-01-26

## Scope
**In Scope:**
- *.acme.com
- 10.10.10.0/24
- vpn.acme.com

**Out of Scope:**
- acme-dev.com
- 192.168.1.0/24

## Contacts
| Role | Name | Contact |
|------|------|---------|
| Primary | John Smith | john.smith@acme.com |
| Technical | Sarah Chen | sarah.chen@acme.com |

## Credentials Provided
| System | Username | Password | Notes |
|--------|----------|----------|-------|
| VPN | testuser | P@ssw0rd123 | Read-only access |
| Web Portal | demo@acme.com | Demo2024! | Limited user account |

## Notes
- Testing allowed Mon-Fri 9AM-5PM EST
- No DoS/resource exhaustion tests
- Notify before credential stuffing attempts
`,

'web/portal.acme.com.md': `# Web App - Customer Portal

**URL:** https://portal.acme.com
**Tech Stack:** React, Node.js, PostgreSQL
**Auth:** JWT tokens

## Recon
- Endpoints:
  - /api/v1/users
  - /api/v1/orders
  - /api/v1/admin (403)
- Parameters: id, email, order_id, user_token
- Upload points: /profile/avatar, /orders/receipt

## Testing Notes
- JWT tokens don't expire
- User enumeration possible via /api/v1/users?email=
- File upload accepts .php files but doesn't execute

## Interesting Findings
- IDOR on /api/v1/orders?id=
- SQL injection in search parameter (needs more testing)
- Missing rate limiting on login
`,

'web/api.acme.com.md': `# Web App - REST API

**URL:** https://api.acme.com
**Tech Stack:** Python Flask, MongoDB
**Auth:** API keys in headers

## Recon
- Endpoints:
  - /v2/customers
  - /v2/payments
  - /v2/reports
  - /health (leaks version info)
- Parameters: api_key, format, limit, offset
- Upload points: None

## Testing Notes
- API documentation exposed at /docs
- GraphQL endpoint at /graphql with introspection enabled
- Old API v1 still accessible with deprecated endpoints

## Interesting Findings
- Broken access control on /v2/reports endpoint
- GraphQL allows querying all user data
- API keys visible in error messages
`,

'infra/10.10.10.15.md': `# Host - Web Server

**IP:** 10.10.10.15
**OS:** Ubuntu 20.04 LTS
**Access Level:** User shell via SSH

## Open Ports
| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 8.2p1 |
| 80 | HTTP | Apache 2.4.41 |
| 443 | HTTPS | Apache 2.4.41 |
| 3306 | MySQL | MySQL 5.7.33 |

## Notes
- Weak SSH password: webadmin/Welcome123
- MySQL accessible from external network
- Apache running as www-data
- Found backup script in /opt/backup.sh (world-readable)

## Files/Loot
- /etc/apache2/.htpasswd (hashes cracked)
- /var/www/html/config.php (DB credentials)
- /home/webadmin/.bash_history (interesting commands)
`,

'infra/10.10.10.25.md': `# Host - File Server

**IP:** 10.10.10.25
**OS:** Windows Server 2019
**Access Level:** Domain user access via SMB

## Open Ports
| Port | Service | Version |
|------|---------|---------|
| 135 | RPC | Microsoft Windows RPC |
| 139 | NetBIOS | Microsoft Windows netbios-ssn |
| 445 | SMB | Microsoft Windows Server 2019 |
| 3389 | RDP | Microsoft Terminal Services |

## Notes
- SMB signing not required
- Guest access enabled on \\\\10.10.10.25\\Public
- RDP allows Network Level Authentication bypass
- Found sensitive documents in shared folders

## Files/Loot
- \\\\10.10.10.25\\Public\\passwords.xlsx
- \\\\10.10.10.25\\IT\\vpn-config.ovpn
- \\\\10.10.10.25\\HR\\employee-data-2024.csv
`,

'infra/10.10.10.50.md': `# Host - Domain Controller

**IP:** 10.10.10.50
**OS:** Windows Server 2019
**Access Level:** None yet

## Open Ports
| Port | Service | Version |
|------|---------|---------|
| 53 | DNS | Microsoft DNS |
| 88 | Kerberos | Microsoft Windows Kerberos |
| 135 | RPC | Microsoft Windows RPC |
| 389 | LDAP | Microsoft Windows Active Directory LDAP |
| 445 | SMB | Microsoft Windows Server 2019 |
| 3389 | RDP | Microsoft Terminal Services |

## Notes
- Domain: ACME.LOCAL
- Vulnerable to Zerologon (CVE-2020-1472) - NOT TESTED per ROE
- LDAP anonymous bind enabled
- SMB signing required (good)

## Files/Loot
- None yet
`,

'AD/bloodhound.md': `# BloodHound Results

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
`,

'AD/enum.md': `# AD Enumeration

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
`,

'AD/attacks.md': `# AD Attacks

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
`,

'credentials.md': `# Credentials

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
`,

'screenshots/.gitkeep': ``,

'findings/sqli-portal-search.md': `# SQL Injection in Customer Portal Search

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
   \`' OR 1=1 UNION SELECT NULL,username,password,email,NULL FROM users--\`
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
`,

'findings/idor-order-access.md': `# IDOR Allowing Access to Other Users' Orders

**Severity:** High
**CVSS3:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
**Component:** portal.acme.com - Order API
**Status:** Confirmed

## Description

The order retrieval endpoint at /api/v1/orders is vulnerable to Insecure Direct Object Reference (IDOR). An authenticated user can access any other user's order details by simply modifying the 'id' parameter in the request. No authorization checks are performed to verify that the order belongs to the requesting user.

## Impact

- Unauthorized access to all customer orders (237,000+ orders in database)
- Exposure of sensitive customer information (names, addresses, phone numbers)
- Exposure of order details and purchase history
- Potential for competitor intelligence gathering
- Privacy violation and GDPR/compliance concerns

## Steps to Reproduce

1. Log in as a regular user (demo@acme.com / Demo2024!)
2. Navigate to "My Orders" and note your order ID (e.g., 15234)
3. Intercept the request to /api/v1/orders?id=15234
4. Change the ID parameter to another value (e.g., id=1)
5. Observe that another user's order details are returned

## Request

~~~http
GET /api/v1/orders?id=1 HTTP/1.1
Host: portal.acme.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Cookie: session=abc123def456
~~~

## Response

~~~http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "order_id": 1,
  "user_id": 5891,
  "customer_name": "Sarah Johnson",
  "email": "sarah.j@example.com",
  "phone": "+1-555-0142",
  "shipping_address": "123 Main St, Seattle, WA 98101",
  "items": [
    {"product": "Laptop Pro 15", "quantity": 1, "price": 2499.99}
  ],
  "total": 2499.99,
  "status": "shipped",
  "order_date": "2024-01-10"
}
~~~

## Screenshots

- screenshots/idor-own-order.png
- screenshots/idor-other-user-order.png
- screenshots/idor-sequential-access.png

## Remediation

1. **Immediate:** Implement server-side authorization checks
2. **Short-term:**
   - Verify order ownership: Check if order.user_id matches authenticated user_id
   - Return 403 Forbidden for unauthorized access attempts
   - Use non-sequential, unpredictable order identifiers (UUIDs)
3. **Long-term:**
   - Implement consistent authorization middleware across all endpoints
   - Add comprehensive access control testing to CI/CD pipeline
   - Conduct security code review of all API endpoints
   - Implement rate limiting to prevent mass enumeration

## References

- OWASP IDOR: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- CWE-639: Authorization Bypass Through User-Controlled Key
- MITRE ATT&CK T1083: File and Directory Discovery
`,

'findings/graphql-introspection.md': `# GraphQL Introspection and Mass Data Exposure

**Severity:** High
**CVSS3:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
**Component:** api.acme.com - GraphQL endpoint
**Status:** Confirmed

## Description

The GraphQL API endpoint at /graphql has introspection enabled and lacks proper authorization controls. An unauthenticated attacker can discover the complete API schema including sensitive queries and mutations, then execute queries to extract all customer data, payment information, and internal business intelligence.

## Impact

- Complete API schema disclosure revealing all data models
- Mass extraction of customer data without authentication
- Access to payment information and financial records
- Exposure of internal business metrics and reporting data
- Potential for data exfiltration at scale

## Steps to Reproduce

1. Send introspection query to https://api.acme.com/graphql
2. Parse schema to identify sensitive queries
3. Execute query to extract all user data
4. Observe 50,000+ customer records returned without authentication

## Request

~~~http
POST /graphql HTTP/1.1
Host: api.acme.com
Content-Type: application/json

{
  "query": "query { allUsers { id email name address phone creditCardLast4 totalSpent } }"
}
~~~

## Response

~~~http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "allUsers": [
      {
        "id": "1",
        "email": "customer1@example.com",
        "name": "John Doe",
        "address": "456 Oak Ave, Portland, OR 97201",
        "phone": "+1-555-0198",
        "creditCardLast4": "4532",
        "totalSpent": 15234.56
      },
      ...
    ]
  }
}
~~~

## Screenshots

- screenshots/graphql-introspection-query.png
- screenshots/graphql-schema-dump.png
- screenshots/graphql-data-extraction.png
- screenshots/graphql-50k-users.png

## Remediation

1. **Immediate:** Disable GraphQL introspection in production
2. **Short-term:**
   - Implement authentication requirements for all queries
   - Add field-level authorization checks
   - Implement query depth limiting
   - Add rate limiting and query complexity analysis
3. **Long-term:**
   - Deploy GraphQL-specific security middleware
   - Implement allow-list of approved queries
   - Add comprehensive logging and monitoring
   - Regular security audits of GraphQL resolvers

## References

- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- CWE-497: Exposure of Sensitive System Information
- GraphQL Security Best Practices
`,

'findings/jwt-no-expiration.md': `# JWT Tokens Without Expiration

**Severity:** Medium
**CVSS3:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)
**Component:** portal.acme.com - Authentication
**Status:** Confirmed

## Description

JWT tokens issued by the authentication system do not include an expiration claim (exp). Once a user logs in, their token remains valid indefinitely. If a token is compromised (through XSS, man-in-the-middle, or other means), an attacker can use it to maintain persistent access without the user's knowledge.

## Impact

- Stolen tokens provide indefinite access to user accounts
- No automatic session termination after user logout
- Increased window of opportunity for token theft exploitation
- Inability to force re-authentication for security updates
- Compliance violations (session timeout requirements)

## Steps to Reproduce

1. Log in to portal.acme.com with valid credentials
2. Intercept and decode the JWT token from Authorization header
3. Observe the absence of 'exp' claim in token payload
4. Wait 24+ hours without any activity
5. Use the same token to access authenticated endpoints
6. Observe successful authentication with old token

## Request

~~~http
GET /api/v1/profile HTTP/1.1
Host: portal.acme.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMzQsInVzZXJuYW1lIjoiZGVtbyIsInJvbGUiOiJ1c2VyIn0.xxxxx
~~~

**Decoded Token Payload:**
~~~json
{
  "userId": 1234,
  "username": "demo",
  "role": "user"
}
~~~

## Response

~~~http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "userId": 1234,
  "username": "demo",
  "email": "demo@acme.com",
  "role": "user"
}
~~~

## Screenshots

- screenshots/jwt-token-decoded.png
- screenshots/jwt-no-expiration.png
- screenshots/jwt-old-token-working.png

## Remediation

1. **Immediate:** Implement JWT expiration (exp claim)
   - Recommended: 15-60 minutes for access tokens
   - Implement refresh token mechanism for extended sessions
2. **Short-term:**
   - Add token revocation capability
   - Implement token blacklist for logout
   - Add 'iat' (issued at) and 'nbf' (not before) claims
3. **Long-term:**
   - Implement sliding session expiration
   - Add device/IP binding to tokens
   - Monitor for suspicious token usage patterns
   - Regular token security audits
`,

'timeline.md': `# Testing Timeline

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
`
        };
    }

    return {
'README.md': `# Pentest Notes

Quick reference structure for engagement notes.

- **info.md** - engagement details, scope, contacts
- **web/** - web application notes (one file per app)
- **infra/** - infrastructure/host notes (one file per host)
- **AD/** - Active Directory enumeration and attack notes
- **credentials.md** - all credentials found during testing
- **screenshots/** - screenshots and proof-of-concept files
- **findings/** - one file per finding with full details
- **timeline.md** - chronological log of testing activities
`,

'info.md': `# Engagement Information

**Client:**
**Engagement Type:** [ ] Black-box [ ] Grey-box [ ] White-box
**Start Date:**
**Deadline:**

## Scope
**In Scope:**
- 

**Out of Scope:**
- 

## Contacts
| Role | Name | Contact |
|------|------|---------|
| Primary |  |  |
| Technical |  |  |

## Credentials Provided
| System | Username | Password | Notes |
|--------|----------|----------|-------|
|        |          |          |       |

## Notes
- 
`,

'web/portal.acme.com.md': `# Web App - <name>

**URL:**
**Tech Stack:**
**Auth:**

## Recon
- Endpoints:
- Parameters:
- Upload points:

## Testing Notes
- 

## Interesting Findings
- 
`,

'web/api.acme.com.md': `# Web App - <name or API>

**URL:**
**Tech Stack:**
**Auth:**

## Recon
- Endpoints:
- Parameters:
- Upload points:

## Testing Notes
- 

## Interesting Findings
- 
`,

'infra/10.10.10.15.md': `# Host - <hostname/IP>

**IP:** 
**OS:** 
**Access Level:** 

## Open Ports
| Port | Service | Version |
|------|---------|---------|
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |

## Notes
- 

## Files/Loot
- 
`,

'infra/10.10.10.25.md': `# Host - <hostname/IP>

**IP:** 
**OS:** 
**Access Level:** 

## Open Ports
| Port | Service | Version |
|------|---------|---------|
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |

## Notes
- 

## Files/Loot
- 
`,

'infra/10.10.10.50.md': `# Host - <hostname/IP>

**IP:** 
**OS:** 
**Access Level:** 

## Open Ports
| Port | Service | Version |
|------|---------|---------|
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |

## Notes
- 

## Files/Loot
- 
`,

'AD/bloodhound.md': `# BloodHound Results

**Collection Date:**
**Method:**

## High-Value Targets
- 

## Attack Paths
- 

## Notes
- 
`,

'AD/enum.md': `# AD Enumeration

## Domain Info
- Domain:
- DC:
- Functional level:

## Users
- Total:
- Interesting:

## Groups
- 

## Computers
- 

## Notes
- 
`,

'AD/attacks.md': `# AD Attacks

## Kerberoasting
- 

## ASREPRoasting
- 

## Lateral Movement
- 

## Privilege Escalation
- 

## Notes
- 
`,

'credentials.md': `# Credentials

| Source | Username | Password/Hash | Type | Tested On | Works |
|--------|----------|---------------|------|-----------|-------|
|        |          |               |      |           |       |
|        |          |               |      |           |       |
|        |          |               |      |           |       |
|        |          |               |      |           |       |
|        |          |               |      |           |       |

## Notes
- 
`,

'screenshots/.gitkeep': ``,

'findings/finding-template.md': `# Finding Title

**Severity:** [ ] Critical [ ] High [ ] Medium [ ] Low [ ] Info
**Component:**
**Status:** [ ] Draft [ ] Ready [ ] Client-Reviewed

## Description
- 

## Impact
- 

## Steps to Reproduce
1. 

## Request
~~~http

~~~

## Response
~~~http

~~~

## Screenshots
- screenshots/example.png

## Remediation
- 

## References
- 
`,

'timeline.md': `# Testing Timeline

## Day X
**00:00** - Activity summary

## Key Findings Summary
- 

## Notes
- 
`
    };
}

async function loadMarkdownFiles() {
    const mdFiles = [
        '01 - Reconnaissance & Enumeration.md',
        '02 - Vulnerability Research & Exploitation.md',
        '03 - Post Exploitation & Privilege Escalation.md',
        '04 - Lateral Movement.md',
        '05 - Active Directory Exploitation.md',
    ];

    const phaseList = document.getElementById('phaseList');
    phaseList.innerHTML = '';

    let loadedCount = 0;

    for (let i = 0; i < mdFiles.length; i++) {
        const filename = "notes/"+mdFiles[i];
        
        try {
            const response = await fetch(filename);
            if (response.ok) {
                const content = await response.text();
                phases[filename] = content;
                loadedCount++;
                
                const btn = document.createElement('button');
                btn.className = 'phase-btn';
                if (i === 0) {
                    btn.classList.add('active');
                    currentPhase = filename;
                }
                btn.dataset.phase = filename;
                btn.textContent = filename.replace('notes/','').replace('.md', '');
                btn.setAttribute('aria-label', `Load phase: ${filename.replace('.md', '')}`);
                
                btn.addEventListener('click', (e) => {
                    document.querySelectorAll('.phase-btn').forEach(b => b.classList.remove('active'));
                    e.target.classList.add('active');
                    currentPhase = e.target.dataset.phase;
                    checkboxStates.clear();
                    loadPhase(currentPhase);
                });
                
                phaseList.appendChild(btn);
            }
        } catch (error) {
            console.error(`Error loading ${filename}:`, error);
        }
    }

    if (loadedCount === 0) {
        phaseList.innerHTML = '<div class="loading-text">⚠️ No markdown files found.</div>';
        return;
    }

    if (currentPhase && phases[currentPhase]) {
        loadPhase(currentPhase);
    } else if (Object.keys(phases).length > 0) {
        currentPhase = Object.keys(phases)[0];
        loadPhase(currentPhase);
    }
}

function loadPhase(phase) {
    const content = phases[phase] || '';
    currentContent = content;
    checkboxStates.clear();
    clearCodeBlockSelection(true);
    paramSearchTerm = '';

    const matches = content.matchAll(/\[([ xX])\]/g);
    let index = 0;
    for (const match of matches) {
        checkboxStates.set(index, match[1].toLowerCase() === 'x');
        index++;
    }

    const storedStates = loadCheckboxStatesFromStorage(phase);
    if (storedStates) {
        storedStates.forEach((state, idx) => {
            if (typeof state === 'boolean') {
                checkboxStates.set(idx, state);
            }
        });
    }

    extractParameters(content);
    renderContent();
    resetContentScroll();
}

function renderContent() {
    codeBlockParamMap = extractCodeBlockParameters(currentContent);
    const contentWithValues = applyParametersToContent(currentContent);
    const html = marked.parse(contentWithValues);
    document.getElementById('contentArea').innerHTML = html;
    
    enhanceCodeBlocks();
    highlightHashComments();
    // Run highlighting after DOM is built
    highlightParametersInText();
    highlightParametersInCodeBlocks();
    
    makeCheckboxesInteractive();
    setupCodeBlockSelection();
}

function applyParametersToContent(content) {
    let processedContent = content;

    Object.keys(parameters).forEach(param => {
        const value = wrapValueWithMarkers(param, getDisplayValueForParam(param));
        const safeParam = param.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex1 = new RegExp(`<${safeParam}>`, 'g');
        const regex2 = new RegExp(`{{${safeParam}}}`, 'g');
        processedContent = processedContent.replace(regex1, () => value);
        processedContent = processedContent.replace(regex2, () => value);
    });

    return processedContent;
}

function wrapValueWithMarkers(param, value) {
    // Keep separator free of table delimiters so inline code in tables stays intact
    return `${PARAM_MARKER_START}${param}${PARAM_SEPARATOR}${value}${PARAM_MARKER_END}`;
}

function extractCodeBlockParameters(content) {
    try {
        const tokens = marked.lexer(content);
        return tokens
            .filter(token => token.type === 'code')
            .map(token => extractParamsFromText(token.text));
    } catch (error) {
        console.warn('Failed to extract code block parameters', error);
        return [];
    }
}

function enhanceCodeBlocks() {
    const contentArea = document.getElementById('contentArea');
    const codeBlocks = contentArea.querySelectorAll('pre > code');
    let blockIndex = 0;
    codeBlockWrappers = [];

    codeBlocks.forEach(codeBlock => {
        const pre = codeBlock.parentElement;

        if (!pre || (pre.parentElement && pre.parentElement.classList.contains('code-block'))) {
            return;
        }

        const wrapper = document.createElement('div');
        wrapper.className = 'code-block';
        wrapper.dataset.blockIndex = blockIndex;
        wrapper.dataset.params = JSON.stringify(codeBlockParamMap[blockIndex] || []);
        blockIndex++;

        pre.parentNode.insertBefore(wrapper, pre);
        wrapper.appendChild(pre);

        addSelectionCopyBehavior(wrapper);
    });

    attachSelectionCopyHandler();
}

function addSelectionCopyBehavior(wrapper) {
    codeBlockWrappers.push(wrapper);
}

function attachSelectionCopyHandler() {
    if (selectionCopyHandlerAttached) {
        return;
    }

    const handleSelectionCopy = () => {
        const selection = window.getSelection();
        if (!selection || selection.isCollapsed) {
            return;
        }

        const wrapper = findIntersectingWrapper(selection);
        if (!wrapper) {
            return;
        }

        const selectedText = selection.toString();
        if (!selectedText.trim()) {
            return;
        }

        const now = Date.now();
        if (selectedText === lastCopiedSelection && wrapper === lastCopiedWrapper && (now - lastCopiedAt) < 200) {
            return;
        }

        lastCopiedSelection = selectedText;
        lastCopiedWrapper = wrapper;
        lastCopiedAt = now;

        navigator.clipboard.writeText(selectedText)
            .then(() => showCopyFeedback(wrapper, 'Copied'))
            .catch((error) => {
                console.warn('Copy failed', error);
                showCopyFeedback(wrapper, 'Copy failed');
            });
    };

    ['mouseup', 'keyup', 'touchend'].forEach(eventName => {
        document.addEventListener(eventName, handleSelectionCopy);
    });

    selectionCopyHandlerAttached = true;
}

function findIntersectingWrapper(selection) {
    if (!selection.rangeCount) {
        return null;
    }

    for (const wrapper of codeBlockWrappers) {
        if (selectionIntersectsWrapper(selection, wrapper)) {
            return wrapper;
        }
    }

    return null;
}

function selectionIntersectsWrapper(selection, wrapper) {
    for (let i = 0; i < selection.rangeCount; i++) {
        const range = selection.getRangeAt(i);
        if (typeof range.intersectsNode === 'function') {
            if (range.intersectsNode(wrapper)) {
                return true;
            }
        } else {
            const wrapperRange = document.createRange();
            wrapperRange.selectNodeContents(wrapper);
            const startsBeforeEnd = range.compareBoundaryPoints(Range.END_TO_START, wrapperRange) < 0;
            const endsAfterStart = range.compareBoundaryPoints(Range.START_TO_END, wrapperRange) > 0;
            if (startsBeforeEnd && endsAfterStart) {
                return true;
            }
        }
    }
    return false;
}

function showCopyFeedback(wrapper, message) {
    let badge = wrapper.querySelector('.copy-feedback');
    if (!badge) {
        badge = document.createElement('div');
        badge.className = 'copy-feedback';
        wrapper.appendChild(badge);
    }

    badge.textContent = message;
    badge.classList.add('visible');

    if (badge._timeoutId) {
        clearTimeout(badge._timeoutId);
    }

    badge._timeoutId = setTimeout(() => {
        badge.classList.remove('visible');
    }, 1600);
}

function highlightHashComments() {
    const codeBlocks = document.querySelectorAll('#contentArea pre > code');

    codeBlocks.forEach(codeBlock => {
        const className = (codeBlock.className || '').toLowerCase();
        const langMatch = className.match(/language-([a-z0-9_+-]+)/);
        const language = langMatch ? langMatch[1] : '';

        const skipHashHighlight = ['markdown', 'python', 'c'];
        if (skipHashHighlight.includes(language)) {
            return;
        }

        const escapeHtml = (value) => value
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        // IMPORTANT: We use textContent here to properly process plain text including markers
        const lines = codeBlock.textContent.split('\n');
        let hasHashComments = false;

        const highlightedHtml = lines
            .map(line => {
                const match = line.match(/(^|\s)#/);

                if (!match) {
                    return escapeHtml(line);
                }

                const hashIndex = (match.index || 0) + match[1].length;
                hasHashComments = true;

                const codePart = line.slice(0, hashIndex);
                const commentPart = line.slice(hashIndex);

                return `${escapeHtml(codePart)}<span class="hash-comment">${escapeHtml(commentPart)}</span>`;
            })
            .join('\n');

        if (hasHashComments) {
            codeBlock.innerHTML = highlightedHtml;
        }
    });
}

function highlightParametersInCodeBlocks() {
    const wrappers = document.querySelectorAll('.code-block');

    wrappers.forEach(wrapper => {
        const codeBlock = wrapper.querySelector('code');
        if (!codeBlock) {
            return;
        }
        highlightMarkedParameters(codeBlock, false);
    });
}

function highlightParametersInText() {
    const contentArea = document.getElementById('contentArea');
    if (!contentArea) {
        return;
    }
    // Preserve markers in code blocks so they can be processed separately
    highlightMarkedParameters(contentArea, true, true);
}

function highlightMarkedParameters(element, skipCodeBlocks, preserveCodeBlockMarkers = false) {
    mergeAdjacentTextNodes(element);

    const walker = document.createTreeWalker(
        element,
        NodeFilter.SHOW_TEXT,
        {
            acceptNode(node) {
                if (!node.nodeValue || node.nodeValue.indexOf(PARAM_MARKER_START) === -1) {
                    return NodeFilter.FILTER_REJECT;
                }

                const parent = node.parentElement;
                if (!parent) return NodeFilter.FILTER_ACCEPT;

                if (parent.closest('.param-token')) return NodeFilter.FILTER_REJECT;
                if (parent.closest('input, textarea, button, .params-panel')) return NodeFilter.FILTER_REJECT;
                if (skipCodeBlocks && parent.closest('.code-block')) return NodeFilter.FILTER_REJECT;

                return NodeFilter.FILTER_ACCEPT;
            }
        }
    );

    const textNodes = [];
    let textNode;
    while ((textNode = walker.nextNode())) {
        textNodes.push(textNode);
    }

    textNodes.forEach(node => {
        wrapMarkersInTextNode(node);
    });

    cleanupResidualMarkers(element, preserveCodeBlockMarkers);
}

function mergeAdjacentTextNodes(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;

    while ((node = walker.nextNode())) {
        while (node.nextSibling && node.nextSibling.nodeType === Node.TEXT_NODE) {
            node.nodeValue += node.nextSibling.nodeValue;
            node.parentNode.removeChild(node.nextSibling);
        }
    }
}

function wrapMarkersInTextNode(node) {
    const text = node.nodeValue;
    // Use escaped separator so inline code/backticks and tables parse safely
    const regex = new RegExp(`${PARAM_MARKER_START}([A-Z0-9_]+)${PARAM_SEPARATOR_REGEX}([\\s\\S]*?)${PARAM_MARKER_END}`, 'g');

    const matches = Array.from(text.matchAll(regex));
    if (!matches.length) {
        // Fallback: strip markers if regex failed (cleans up potential visible artifacts)
        if (text.includes(PARAM_MARKER_START) || text.includes(PARAM_MARKER_END)) {
            const cleaned = text
                .replace(new RegExp(`${PARAM_MARKER_START}[A-Z0-9_]+${PARAM_SEPARATOR_REGEX}`, 'g'), '')
                .replace(new RegExp(PARAM_MARKER_END, 'g'), '');
            node.nodeValue = cleaned;
        }
        return;
    }

    const fragment = document.createDocumentFragment();
    let lastIndex = 0;

    matches.forEach(match => {
        const start = match.index || 0;
        const value = match[2];

        if (start > lastIndex) {
            fragment.appendChild(document.createTextNode(text.slice(lastIndex, start)));
        }

        const span = document.createElement('span');
        span.className = 'param-token';
        span.dataset.param = match[1];
        span.textContent = value;
        // Force Inline Style as Backup
        span.style.color = 'rgb(0, 255, 30)';
        span.style.fontWeight = 'bold';
        
        fragment.appendChild(span);

        lastIndex = (match.index || 0) + match[0].length;
    });

    if (lastIndex < text.length) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    }

    node.parentNode.replaceChild(fragment, node);
}

function cleanupResidualMarkers(element, skipCodeBlocks = false) {
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    let node;

    while ((node = walker.nextNode())) {
        if (skipCodeBlocks && node.parentElement && node.parentElement.closest('.code-block')) {
            continue;
        }

        const value = node.nodeValue || '';
        if (!value.includes(PARAM_MARKER_START) && !value.includes(PARAM_MARKER_END)) {
            continue;
        }

        const cleaned = value
            .replace(new RegExp(`${PARAM_MARKER_START}[A-Z0-9_]+${PARAM_SEPARATOR_REGEX}`, 'g'), '')
            .replace(new RegExp(PARAM_MARKER_END, 'g'), '');

        if (cleaned !== value) {
            node.nodeValue = cleaned;
        }
    }
}

function getDisplayValueForParam(param) {
    const value = parameters[param];
    if (value === undefined || value === null || `${value}` === '') {
        return `<${param}>`;
    }
    return `${value}`;
}

function setupCodeBlockSelection() {
    const wrappers = document.querySelectorAll('.code-block');

    wrappers.forEach(wrapper => {
        wrapper.addEventListener('click', () => {
            selectCodeBlock(wrapper);
        });
    });

    if (!outsideClickListenerAttached) {
        document.addEventListener('click', (event) => {
            const clickedInsideCode = event.target.closest('.code-block');
            const clickedInsideParams = event.target.closest('#rightPanel');
            if (clickedInsideCode || clickedInsideParams) {
                return;
            }
            if (filteredParameters !== null || activeCodeBlock) {
                clearCodeBlockSelection();
            }
        });
        outsideClickListenerAttached = true;
    }

    if (activeCodeBlockIndex !== null) {
        const match = Array.from(wrappers).find(
            wrapper => Number(wrapper.dataset.blockIndex) === Number(activeCodeBlockIndex)
        );
        if (match) {
            if (suppressParamPanelRender) {
                activeCodeBlock = match;
                activeCodeBlock.classList.add('code-block-active');
                suppressParamPanelRender = false;
            } else {
                selectCodeBlock(match);
            }
        } else {
            suppressParamPanelRender = false;
        }
    }
}

function selectCodeBlock(wrapper) {
    if (!wrapper) {
        return;
    }

    if (activeCodeBlock && activeCodeBlock !== wrapper) {
        activeCodeBlock.classList.remove('code-block-active');
    }

    activeCodeBlock = wrapper;
    activeCodeBlockIndex = Number(wrapper.dataset.blockIndex);
    wrapper.classList.add('code-block-active');

    const params = parseParamsFromDataset(wrapper.dataset.params);
    filteredParameters = params;

    renderParametersPanel();
}

function parseParamsFromDataset(rawParams) {
    if (!rawParams) {
        return [];
    }
    try {
        const parsed = JSON.parse(rawParams);
        return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
        console.warn('Unable to parse code block parameters', error);
        return [];
    }
}

function clearCodeBlockSelection(skipRender = false) {
    if (activeCodeBlock) {
        activeCodeBlock.classList.remove('code-block-active');
    }
    activeCodeBlock = null;
    activeCodeBlockIndex = null;
    filteredParameters = null;

    if (!skipRender) {
        renderParametersPanel();
    }
}

function ensureParamSearchField() {
    const panel = document.querySelector('.params-panel');
    if (!panel) {
        return null;
    }

    let searchWrapper = panel.querySelector('.param-search');
    if (!searchWrapper) {
        searchWrapper = document.createElement('div');
        searchWrapper.className = 'param-search';

        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'param-search-input';
        input.placeholder = 'Search parameters';
        input.setAttribute('aria-label', 'Search parameters');

        searchWrapper.appendChild(input);

        const title = panel.querySelector('.panel-title');
        if (title) {
            title.insertAdjacentElement('afterend', searchWrapper);
        } else {
            panel.insertBefore(searchWrapper, panel.firstChild);
        }
    }

    if (filteredParameters !== null) {
        searchWrapper.classList.add('param-search-hidden');
    } else {
        searchWrapper.classList.remove('param-search-hidden');
    }

    const searchInput = searchWrapper.querySelector('.param-search-input');
    if (searchInput && !searchInput.dataset.bound) {
        searchInput.dataset.bound = 'true';
        searchInput.addEventListener('input', (e) => {
            paramSearchTerm = e.target.value;
            const caret = e.target.selectionStart || 0;
            renderParametersPanel();
            requestAnimationFrame(() => {
                const refreshedInput = document.querySelector('.param-search-input');
                if (refreshedInput) {
                    refreshedInput.focus();
                    refreshedInput.setSelectionRange(caret, caret);
                }
            });
        });
    }

    return searchInput || null;
}

function makeCheckboxesInteractive() {
    const contentArea = document.getElementById('contentArea');
    const listItems = contentArea.querySelectorAll('li');
    
    let checkboxIndex = 0;
    
    listItems.forEach(li => {
        const textContent = li.textContent || li.innerText;
        const existingCheckbox = li.querySelector('input[type="checkbox"]');
        const hasMarker = textContent.match(/^\s*\[([ xX])\]/) || Boolean(existingCheckbox);

        if (!hasMarker) {
            return;
        }

        if (existingCheckbox) {
            existingCheckbox.remove();
        }

        const isChecked = checkboxStates.get(checkboxIndex) || false;

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = isChecked;
        checkbox.dataset.index = checkboxIndex;
        checkbox.setAttribute('aria-label', `Task checkbox ${checkboxIndex + 1}`);
        
        checkbox.addEventListener('change', (e) => {
            const idx = parseInt(e.target.dataset.index);
            checkboxStates.set(idx, e.target.checked);
            persistCheckboxStates(currentPhase);
            
            e.target.style.transform = 'scale(1.2)';
            setTimeout(() => {
                e.target.style.transform = '';
            }, 200);
        });
        
        const originalHTML = li.innerHTML;
        const newHTML = originalHTML.replace(/^\s*\[([ xX])\]\s*/, '');
        li.innerHTML = newHTML;
        li.style.display = 'flex';
        li.style.alignItems = 'flex-start';
        li.insertBefore(checkbox, li.firstChild);
        
        checkboxIndex++;
    });
}

function extractParameters(content) {
    const oldParams = {...parameters};
    parameters = {};
    
    const matches = extractParamsFromText(content);
    
    if (matches.length) {
        matches.forEach(param => {
            const storedValue = getStoredParameters()[param];
            parameters[param] = storedValue !== undefined ? storedValue : (oldParams[param] || '');
        });
    }
    
    renderParametersPanel();
}

function extractParamsFromText(text) {
    const matches = text.match(PARAM_TOKEN_REGEX);
    return matches ? [...new Set(matches.map(token => token.replace(/[<>{}]/g, '')))] : [];
}

function renderParametersPanel() {
    const container = document.getElementById('paramsContainer');
    const allParams = Object.keys(parameters);
    const hasAnyParameters = allParams.length > 0;
    const baseParams = filteredParameters !== null ? filteredParameters : allParams;
    const searchTerm = paramSearchTerm.trim().toLowerCase();
    let displayParams = baseParams.slice().sort();

    if (searchTerm) {
        displayParams = displayParams.filter(param => param.toLowerCase().includes(searchTerm));
    }

    const hasDisplayParams = displayParams.length > 0;

    toggleLayoutForParameters(hasAnyParameters);

    const searchInput = ensureParamSearchField();
    if (searchInput) {
        searchInput.value = paramSearchTerm;
    }
    
    if (!hasDisplayParams) {
        const message = !hasAnyParameters
            ? 'No parameters found in this phase'
            : (searchTerm
                ? 'No parameters match your search'
                : (filteredParameters !== null
                    ? 'No parameters found for this code block'
                    : 'No parameters found in this phase'));
        container.innerHTML = `<p class="text-secondary" style="color: var(--text-secondary); font-size: 0.875rem; text-align: center; padding: 1rem;">${message}</p>`;
        return;
    }
    
    let html = '';
    displayParams.forEach(param => {
        html += `
            <div class="param-group">
                <label class="param-label">${param}</label>
                <input type="text" 
                       class="param-input" 
                       data-param="${param}" 
                       value="${parameters[param] || ''}" 
                       placeholder="Enter ${param.toLowerCase().replace(/_/g, ' ')}"
                       aria-label="Parameter input for ${param}">
            </div>
        `;
    });
    
    container.innerHTML = html;
    
    container.querySelectorAll('.param-input').forEach(input => {
        input.addEventListener('input', (e) => {
            const scrollPos = document.getElementById('contentArea').scrollTop;
            parameters[e.target.dataset.param] = e.target.value;
            persistParameters();
            suppressParamPanelRender = filteredParameters !== null;
            updateContent(scrollPos);
        });

        input.addEventListener('focus', (e) => {
            e.target.parentElement.style.transform = 'translateX(4px)';
        });

        input.addEventListener('blur', (e) => {
            e.target.parentElement.style.transform = '';
        });
    });
}

function updateContent(scrollPos = null) {
    renderContent();
    
    if (scrollPos !== null) {
        document.getElementById('contentArea').scrollTop = scrollPos;
    }
}

function toggleRightPanel() {
    const rightPanel = document.getElementById('rightPanel');
    rightPanel.classList.toggle('collapsed');
    localStorage.setItem('rightPanelCollapsed', rightPanel.classList.contains('collapsed'));
}

function toggleLayoutForParameters(hasParameters) {
    const centerPanel = document.getElementById('centerPanel');
    const rightPanel = document.getElementById('rightPanel');

    if (!centerPanel || !rightPanel) {
        return;
    }

    if (hasParameters) {
        centerPanel.classList.remove('col-lg-10', 'col-md-9');
        centerPanel.classList.add('col-lg-7', 'col-md-6');
        rightPanel.classList.remove('d-none');
        
        const wasCollapsed = localStorage.getItem('rightPanelCollapsed') === 'true';
        if (wasCollapsed) {
            rightPanel.classList.add('collapsed');
        }
    } else {
        centerPanel.classList.remove('col-lg-7', 'col-md-6');
        centerPanel.classList.add('col-lg-10', 'col-md-9');
        rightPanel.classList.add('d-none');
    }
}

function loadCheckboxStatesFromStorage(phase) {
    const stored = getStoredCheckboxState()[phase];
    return Array.isArray(stored) ? stored.map(value => Boolean(value)) : null;
}

function persistCheckboxStates(phase) {
    const allCheckboxStates = getStoredCheckboxState();
    const stateArray = [];

    checkboxStates.forEach((value, key) => {
        stateArray[key] = value;
    });

    allCheckboxStates[phase] = stateArray;
    localStorage.setItem(CHECKBOX_STORAGE_KEY, JSON.stringify(allCheckboxStates));
    updateResetButtonVisibility();
}

function getStoredCheckboxState() {
    try {
        const raw = localStorage.getItem(CHECKBOX_STORAGE_KEY);
        return raw ? JSON.parse(raw) : {};
    } catch (error) {
        console.warn('Could not read checkbox state from localStorage', error);
        return {};
    }
}

function getStoredParameters() {
    try {
        const raw = localStorage.getItem(PARAMS_STORAGE_KEY);
        return raw ? JSON.parse(raw) : {};
    } catch (error) {
        console.warn('Could not read parameters from localStorage', error);
        return {};
    }
}

function persistParameters() {
    localStorage.setItem(PARAMS_STORAGE_KEY, JSON.stringify(parameters));
    updateResetButtonVisibility();
}

function hasStoredCheckboxData() {
    const stored = getStoredCheckboxState();
    return Object.values(stored).some(value => Array.isArray(value) && value.length > 0);
}

function hasStoredParameterData() {
    const stored = getStoredParameters();
    return Object.keys(stored).length > 0;
}

function updateResetButtonVisibility() {
    const resetBtn = document.getElementById('newAssessmentBtn');
    if (!resetBtn) {
        return;
    }

    const shouldShow = hasStoredCheckboxData() || hasStoredParameterData();
    resetBtn.hidden = !shouldShow;
}

function resetAssessment() {
    if (!confirm('Are you sure you want to reset the playbook? This will clear all checkboxes and parameters.')) {
        return;
    }

    localStorage.removeItem(CHECKBOX_STORAGE_KEY);
    localStorage.removeItem(PARAMS_STORAGE_KEY);
    checkboxStates.clear();
    parameters = {};
    
    if (currentPhase) {
        loadPhase(currentPhase);
    }

    updateResetButtonVisibility();
    showResetToast();
}

function showResetToast() {
    const toast = document.getElementById('resetToast');
    if (!toast) return;

    toast.classList.add('show');

    if (resetToastTimeout) {
        clearTimeout(resetToastTimeout);
    }

    resetToastTimeout = setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function resetContentScroll() {
    const contentArea = document.getElementById('contentArea');
    if (contentArea) {
        contentArea.scrollTop = 0;
    }
}
