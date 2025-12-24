# Web App - REST API

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
