# Contributing

Thank you for looking at ANVOS. Two rules while the project is young:

1. **Open an issue first.** Say what you observed, what you expected and how to reproduce it. Measured facts (command, output, versions) beat descriptions.
2. **Pull requests are read but not merged yet.** Contributions require the CLA (`CLA.md`), which is under legal review. Until it is in place nothing external is merged; we will tell you in the PR when that changes.

Design rules every change must respect:

- **Fail closed.** If a service cannot verify, it must refuse and say why. Never a warning mode.
- **Standard library only.** No third-party imports in `services/`.
- **Nothing hardcoded.** Addresses, node names and trust anchors come from the environment (`config.sample.env`).
- **One JSON record per run.** Each service prints exactly one JSON object to stdout and exits 0; the supervisor treats stdout as the service's ledger.

Security reports: see `SECURITY.md`. Licensing questions: `contact@fractalastra.com`.
