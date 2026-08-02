---
name: reconkit-vuln-xss
description: >
  XSS candidate handling for reconkit xss/dalfox output and prove xss_reflect.
  Reflection is not executable XSS; use context classification and CSP awareness.
---

# XSS

## When
- Module `xss`, dalfox/kxss hits, reflected params  

## Efficient path
1. Run prove `xss_reflect` — note context (html/attr/js/url/encoded).  
2. CSP present → often C1/info unless bypass chain.  
3. Self-XSS only → C0 for most programs.  
4. Stored sinks need canary write + render proof (HITL cleanup).  
5. Do not claim session theft from `alert(domain)` alone.

## Confidence
- C1: reflection  
- C2: marker in sink with breakout path  
- C3: impact under RoE (session/sensitive action)  

## Never
- Mass browser weaponization in default agents  
