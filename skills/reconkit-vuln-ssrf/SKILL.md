---
name: reconkit-vuln-ssrf
description: >
  SSRF methodology for reconkit ssrf candidates and webhook/url params.
  Prefer hunter-owned OAST; never treat DNS-only as C3.
---

# SSRF

## When
- Modules `ssrf_ssti`, params `url`, `callback`, `webhook`, `redirect`, `next`  
- Features that fetch remote resources server-side  

## Efficient path
1. Confirm parameter influences server fetch.  
2. OAST with **your** collaborator (`oast_base_url` / interactsh) → HTTP hit preferred.  
3. DNS-only = C1/needs_manual, not report-critical.  
4. Internal targets only under RoE; reconkit prove does not hit 169.254 by default.  
5. Cloud metadata = human/HITL only.

## Prove map
- `ssrf_canary_review`  
- Optional OAST in exploit_policy.json  

## Confidence
- C1: param looks injectable  
- C2: OAST HTTP callback  
- C3: internal service data returned  
