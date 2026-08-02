---
name: reconkit-vuln-sqli
description: >
  SQLi candidate handling for reconkit sqli canaries and optional sqli_boolean prove.
  Error strings alone are weak; prefer controlled boolean canary under policy.
---

# SQLi

## When
- Module `sqli`, error-based/boolean canary files, SQL error strings  

## Efficient path
1. Re-read recon canary evidence — classify C1.  
2. If policy `allow_sqli_boolean` — single true/false pair only.  
3. No UNION dumps, no sqlmap in default path.  
4. Time-based only if RoE allows and rate-limited.  
5. WAF noise → don't loop payloads.

## Confidence
- C0: cosmetic error, no control  
- C1: canary candidate  
- C2: boolean divergence (prove)  
- C3: data access demonstrated (HITL, minimal)  

## Prove map
`sqli_boolean` (off by default in exploit_policy.json)  
