# Threat model

## Trust boundaries

| # | Boundary | Guarded by |
| --- | --- | --- |
| 1 | Internet to Gateway | TLS, nothing else |

## Findings

Carried into Phase 13 for verification.

| # | Boundary | Finding | Proposed response | Status |
| --- | --- | --- | --- | --- |
| 1 | 1 | No rate limiting on the public endpoint | Mitigate | Closed, proven under a flood |
| 10 | 8 | No provenance, SBOM, signature, or admission policy | Mitigate, after 7 | Accepted for now |
| 11 | 3 | DNS is the one egress channel out of the namespace | Accept | Accepted |

Findings 1, 3, 5, 6 and 9 are measured rather than reasoned.

## References

- [SLSA](https://slsa.dev/)
