---
name: reconkit-vuln-takeover
description: >
  Subdomain takeover methodology for CNAME/dangling DNS candidates from reconkit dns module.
  Fingerprint only in automation; claiming is human.
---

# Subdomain takeover

## When
- `cname_takeover_candidates`, dangling CNAME, nuclei takeover templates  

## Efficient path
1. Confirm CNAME target + NXDOMAIN/fingerprint (prove `takeover_fingerprint`).  
2. Match provider fingerprint (S3, GitHub pages, Heroku, etc.).  
3. Do **not** auto-claim DNS in reconkit.  
4. Note OAuth/cookie scope impact for severity (chain).  
5. Report only if claimable under program rules.

## Confidence
- C1: candidate line in recon  
- C2: fingerprint confirms dangling  
- C3: human claimability / impact chain  

## Prove map
`takeover_fingerprint`  
