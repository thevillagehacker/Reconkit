---
name: reconkit-vuln-jwt
description: >
  JWT/token audit methodology when JWTs or auth tokens appear in JS, cookies, or APIs.
  Decode-first, no offline cracking loops unless lab/RoE allows.
---

# JWT / token audit

## When
- `eyJ` tokens in cookies, localStorage notes, JS secrets, Authorization headers  
- Auth modules / API gateways  

## Steps (efficient)
1. Decode header+payload (no verify) — note `alg`, `kid`, roles, exp, aud.  
2. Check `alg=none` / weird algs only with **safe** probe (read-only endpoint).  
3. Role claims: does low-priv token carry admin claims?  
4. Kid/jku/x5u: only note for human; do not fetch arbitrary URLs.  
5. Prefer prove session differences over cryptographic attacks.

## Confidence
- C1: token present + interesting claims  
- C2: accepted modified claim on safe endpoint (HITL)  
- C3: privilege escalation / ATO  

## Never
- Unlimited offline brute of signing keys in bounty mode  
- Dumping full tokens into agent logs/reports (redact middle)  
