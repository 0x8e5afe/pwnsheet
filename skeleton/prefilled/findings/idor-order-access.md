# IDOR Allowing Access to Other Users' Orders

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
