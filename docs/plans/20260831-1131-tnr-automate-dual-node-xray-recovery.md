# Trojan Node Recovery Automation

## Anchor Context

Implement the approved local `bin/trojan-node` orchestrator for two clean
Ubuntu 24.04 Aiyun nodes. Keep Cloudflare management credentials in the
`personal` creds profile, rotate independent node credentials, reuse the
user-confirmed local ED25519 alias trust, and deploy the existing transactional Xray
installer one node at a time.

## Authorized Scope

- Add the Trojan-scoped local CLI, non-secret manifest, offline tests, CI, and
  documentation in this repository.
- Do not change the remote installer unless an offline test proves a required
  compatibility defect.
- Do not modify normal Clash Verge configuration.
- Do not trust network-scanned SSH keys. Require exactly one existing ED25519
  `known_hosts` entry for each alias plus key-only SSH; add one root-only
  provenance marker after install and service/TLS verification.

## Slices

1. Command surface, manifest validation, and unconfirmed host-key refusal.
2. Masked creds status and fail-closed stdin writes.
3. Cloudflare zone/DNS/token lifecycle with compensation.
4. Strict known-host SSH preflight and exact-source archive staging.
5. One-node deploy, isolated verification, idempotence, and CI/docs.

## Stop Conditions

Stop at the first failed contract or live gate. Never log a secret, edit the
user's known_hosts, disable host-key checking, auto-delete conflicting DNS, or
operate both nodes in one apply command.
