# Notes Skeleton (Prefilled)

Mirrors the `buildNotesSkeleton('prefilled')` branch in `script.js` and the "Prefilled" option in the Notes Skeleton menu. It ships with sample data for a fictional ACME engagement so you can see how to structure findings and timelines.

## Files created
```
pwnsheet-skeleton/
|- README.md
|- info.md
|- web/
|  |- portal.acme.com.md
|  |- api.acme.com.md
|- infra/
|  |- 10.10.10.15.md
|  |- 10.10.10.25.md
|  |- 10.10.10.50.md
|- AD/
|  |- bloodhound.md
|  |- enum.md
|  |- attacks.md
|- credentials.md
|- screenshots/.gitkeep
|- findings/
|  |- sqli-portal-search.md
|  |- idor-order-access.md
|  |- graphql-introspection.md
|  |- jwt-no-expiration.md
|- timeline.md
```

Each Markdown file is already populated with representative content, CVSS scoring, and reproduction steps you can adapt to real engagements.
