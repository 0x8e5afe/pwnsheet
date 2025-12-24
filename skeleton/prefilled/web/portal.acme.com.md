# Web App - Customer Portal

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
