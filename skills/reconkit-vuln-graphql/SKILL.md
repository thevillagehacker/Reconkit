---
name: reconkit-vuln-graphql
description: >
  GraphQL recon and abuse checks when /graphql or introspection signals appear.
  Introspection alone is not a finding; pair with authz/IDOR/mutation impact.
---

# GraphQL

## When
- `/graphql`, `/api/graphql`, `application/graphql`  
- Introspection or `__schema` in crawl/JS  

## Efficient path
1. Confirm endpoint in scope.  
2. Introspection → map types/mutations (C0 alone if only schema).  
3. Prioritize: auth mutations, user objects, file uploads, admin fields.  
4. Batch/alias DoS only if RoE allows (often LOUD).  
5. IDOR via `node(id:)` or global IDs — need two sessions.

## Confidence
- C0: introspection only  
- C1: sensitive fields visible  
- C2: unauthorized field/mutation works with canary  
- C3: cross-user data or auth bypass  

## Pair with
`reconkit-vuln-idor`, `reconkit-fp-eval` (never-submit introspection alone).  
