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

## Bootstrapping the supervised layer

The package ships **no `manifest.txt` and no signatures**: the supervisor
(`anvos-layerd`) verifies every service against a manifest signed by **your**
release key, generated at your own admission ceremony. Shipping our manifest
would tie your node's trust to our identity — the same reason no trust anchor
is embedded in the sources. Generate your manifest over the deployed tree, sign
it with your release key, and layerd enforces it fail-closed from then on.
