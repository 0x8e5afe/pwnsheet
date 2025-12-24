# JWT Tokens Without Expiration

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
