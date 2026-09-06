# AstraNova ANVOS — node layer

> **Pre-release (private).** Publication pending final certification review.

Sovereign node governance layer: every service is signature-verified before every
execution (fail-closed). 82 stdlib-only Python services: fleet attestation, integrity
chains, deception, telemetry, AI governance.

## Licensing

Dual license:
- **AGPLv3** (see `LICENSE`) — includes an express patent grant (art. 11) for the
  pending applications **ES P202631174** and **ES P202631188** (see `NOTICE`).
- **Commercial license** — for use without AGPL copyleft obligations. Contact below.

Contributions require the CLA (see `CLA.md`).

## Configuration

No addresses, node names or trust anchors are hardcoded. Everything is declared via
environment (see `config.sample.env`); undeclared values fail closed (local-only).
