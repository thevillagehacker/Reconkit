---
name: reconkit-vuln-secrets
description: >
  Secrets/key handling when js secrets, AWS keys, tokens, or webhooks appear.
  Redact in logs; classify live vs dummy; no mass abuse of found keys.
---

# Secrets / keys

## When
- Module `js`, secrets JSON, high-score secret findings, webhooks  

## Efficient path
1. Categorize (AWS, GitHub, JWT, webhook, private key).  
2. Redact mid-token in agent output.  
3. Dummy/test patterns → C0/C1.  
4. Live key checks only under RoE (minimal, non-destructive).  
5. Prefer report as credential exposure with scope of access.

## Confidence
- C1: pattern match  
- C2: format-valid + likely live  
- C3: demonstrated privileged API access (HITL)  

## Never
- Paste full secrets into dashboards/reports unnecessarily  
- Mass API abuse with stolen keys  
