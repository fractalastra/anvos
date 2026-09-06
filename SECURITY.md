# Security Policy

## Reporting a vulnerability

Please report security issues **privately** to **security@fractalastra.com** —
do not open a public issue for anything exploitable. Include what you measured,
how to reproduce it, and the affected service(s).

You will receive an acknowledgement, and coordinated disclosure is honored:
we ask for a reasonable window to ship a fix before publication.

## Scope

This repository contains the ANVOS node layer only. The layer is designed
fail-closed: a finding that shows a fail-open path (a branch that proceeds
when it cannot verify or cannot measure) is exactly the class of report we
care most about.

## Verification

Every service is meant to run under `anvos-layerd` supervision, verified
against a manifest signed by the deploying realm's own release key (see
README). Reports about bypassing that verification chain are in scope.
