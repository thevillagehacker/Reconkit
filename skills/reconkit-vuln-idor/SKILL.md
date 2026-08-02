---
name: reconkit-vuln-idor
description: >
  IDOR/BOLA methodology for reconkit when params, APIs, or user IDs appear.
  Use for content/vuln specialists and analyst triage of object-level auth bugs.
---

# IDOR / BOLA (authorized)

## When this skill applies
- Params with `id`, `user_id`, `uid`, `account`, `order`, `uuid`
- REST paths like `/api/v1/users/{id}`, `/orders/{id}`
- GraphQL `node(id:)` / object fields

## Efficiency tests (cheap → expensive)
1. Map object IDs from crawl/params (no brute).
2. Need **two identities** (user A / user B) before claiming IDOR.
3. Replay A's object ID under B's session — compare body fields, not only status.
4. Check both directions (B reading A, A reading B).
5. Anon access to the same object = missing auth (different class).

## Confidence
- C1: interesting ID pattern only  
- C2: different status/body length under wrong session  
- C3: other-user PII/action proven  
- C0: own-account only / intended multi-tenant admin  

## Never
- Mass ID brute on production without RoE  
- Report without cross-account proof  
