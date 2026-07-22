# chg-20260722-0953-cgb — Reconstructed plan

[reconstructed plan]

Implement an operations-only layer without modifying the Go manager or original `install.sh`. Rewrite `install-with-certman.sh` as a self-contained CLI covering guided install, existing-host adoption, status, normal renewal, email test, DNS rollback, and automation-only uninstall. Pin and verify Jrohy v2.15.3 assets, use Cloudflare DNS-01 for new hosts, preserve standalone ACME behavior for adopted hosts, and cut DNS only after local validation. Add systemd renewal/alert units, SMTP 465 configuration, documentation, mocked Bats coverage, and GitHub Actions checks.

Files: `install-with-certman.sh`, `README.md`, `.github/workflows/certman-ci.yml`, `tests/certman.bats`.

Verification: `bash -n install-with-certman.sh`; `shellcheck -x install-with-certman.sh`; `bats tests/certman.bats`; `git diff --check`; compare downloaded release SHA-256 values.
