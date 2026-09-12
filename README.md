# AstraNova ANVOS — node layer

[![License: AGPL v3](https://img.shields.io/badge/license-AGPLv3-blue.svg)](LICENSE)
[![Patent pending](https://img.shields.io/badge/patent-pending%20(ES)-lightgrey.svg)](NOTICE)
[![Python stdlib only](https://img.shields.io/badge/python-3.11%2B%20stdlib%20only-green.svg)](services/)

**A node that verifies every service against a signed manifest before every execution, and refuses to run anything it cannot verify.**

ANVOS is the governance layer of an AstraNova node: 82 Python services, standard library only, supervised by a daemon that checks each one's signature at each run (fail-closed). The services attest the node's own integrity, cross-attest the fleet, keep hash-chained integrity records, run deception sensors, publish signed alert envelopes and escalate critical states to the operator.

## What you get, measurably

- **Fail-closed execution.** A service whose signature does not verify against *your* release key is never started. No warning mode.
- **Self-attestation with a verdict.** `self_integrity` walks the deployed tree and emits `SEALED` or `TAMPER`; `vigias_watch` turns a broken signature into a persistent critical state; `anv-crit-escalator` escalates persistent critical states to the operator queue; `alerts_channel` publishes a signed envelope that a master can verify against the node's genesis-bound authorship certificate.
- **Nothing hardcoded.** No addresses, node names or trust anchors in the sources. Everything comes from the environment; undeclared values fail closed (local-only).

## Try it in ten minutes

Every service is a standalone script that prints one JSON record and exits 0. With an empty data directory you see the fail-closed behaviour immediately:

```sh
git clone https://github.com/fractalastra/anvos.git && cd anvos
mkdir -p /tmp/anvos/data /tmp/anvos/staging
export ANVOS_DATA=/tmp/anvos/data ANVOS_STAGING=/tmp/anvos/staging
python3 services/vigias_watch.py      # {"svc": "vigias_watch", ... "verdict": "SUPERVISION_OK"}
python3 services/self_integrity.py    # verifier_ok: false — no embedded verifier: reports, does not pretend
python3 services/alerts_channel.py    # state: PUBLICADO_SIN_FIRMA — no authorship key: says so, never fakes a signature
```

To run the supervised layer for real, generate and sign your own manifest (see *Bootstrapping* below). The supervisor is `services/anvos-layerd.py`.

## Licensing

Dual license:
- **AGPLv3** (see `LICENSE`) — includes an express patent grant (art. 11) for the
  pending applications **ES P202631174** and **ES P202631188** (see `NOTICE`).
- **Commercial license** — for use without AGPL copyleft obligations. Contact below.

Contributions require the CLA (see `CLA.md`). **Interim rule:** the CLA is
under legal review — pull requests are welcome and will be read, but nothing
is merged until the CLA process is in place. Opening an issue first is the
fastest path.

Commercial licensing and general contact: **contact@fractalastra.com**.
Security reports: see `SECURITY.md`.

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

## Optional module: Sentinel deep scan

`sentinel_immune.py` can orchestrate **Sentinel**, a separate deep-analysis
module (secrets, permissions, duplicates, container and network analyzers)
distributed independently and not included in this repository. Without it the
service degrades cleanly: it reports the immune layer as incomplete
(fail-closed) and the rest of the node layer runs unaffected. To enable the
deep scan, obtain Sentinel separately and place the signed `sentinel.pyz`
next to the services — availability is announced through the project channels.
