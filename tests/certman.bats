#!/usr/bin/env bats

setup() {
  export TEST_ROOT="$BATS_TEST_TMPDIR/root"
  mkdir -p "$TEST_ROOT/etc/trojan-certman/secrets" \
    "$TEST_ROOT/var/lib/trojan-certman" \
    "$TEST_ROOT/etc/systemd/system" \
    "$TEST_ROOT/etc/trojan/tls" \
    "$TEST_ROOT/root/.acme.sh/example.com_ecc" \
    "$TEST_ROOT/run/lock"
  export CERTMAN_CONFIG_DIR="$TEST_ROOT/etc/trojan-certman"
  export CERTMAN_CONFIG_FILE="$CERTMAN_CONFIG_DIR/config"
  export CERTMAN_SECRETS_DIR="$CERTMAN_CONFIG_DIR/secrets"
  export CERTMAN_CF_TOKEN_FILE="$CERTMAN_SECRETS_DIR/cloudflare-token"
  export CERTMAN_SMTP_PASSWORD_FILE="$CERTMAN_SECRETS_DIR/smtp-password"
  export CERTMAN_MSMTP_CONFIG="$CERTMAN_CONFIG_DIR/msmtprc"
  export CERTMAN_STATE_DIR="$TEST_ROOT/var/lib/trojan-certman"
  export CERTMAN_STATUS_FILE="$CERTMAN_STATE_DIR/status"
  export CERTMAN_DNS_BACKUP_FILE="$CERTMAN_STATE_DIR/dns-before.json"
  export CERTMAN_LOCK_FILE="$TEST_ROOT/run/lock/trojan-certman.lock"
  export CERTMAN_ACME_HOME="$TEST_ROOT/root/.acme.sh"
  export CERTMAN_ACME_BIN="$CERTMAN_ACME_HOME/acme.sh"
  export CERTMAN_TROJAN_CONFIG="$TEST_ROOT/usr/local/etc/trojan/config.json"
  export CERTMAN_TROJAN_TLS_DIR="$TEST_ROOT/etc/trojan/tls"
  export CERTMAN_SYSTEMD_DIR="$TEST_ROOT/etc/systemd/system"
  export CERTMAN_INSTALLED_BIN="$TEST_ROOT/usr/local/sbin/trojan-certman"
  export CERTMAN_DNS_WAIT_SECONDS=0
  export CERTMAN_DNS_POLL_SECONDS=0
  export CERTMAN_SKIP_ROOT_CHECK=1
  export CERTMAN_ASSUME_YES=1
  # shellcheck source=../install-with-certman.sh
  source "$BATS_TEST_DIRNAME/../install-with-certman.sh"
}

make_certificate() {
  local days=$1 domain=$2 key=$3 cert=$4
  openssl req -x509 -newkey rsa:2048 -nodes -days "$days" \
    -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain" \
    -keyout "$key" -out "$cert" >/dev/null 2>&1
}

@test "architecture normalization is pinned to supported release assets" {
  [ "$(normalize_arch x86_64)" = amd64 ]
  [ "$(normalize_arch aarch64)" = arm64 ]
  run normalize_arch riscv64
  [ "$status" -ne 0 ]
  [ "$UPSTREAM_AMD64_SHA256" = 3acd0b3fbe51aaf56ec482370c63d4832fd9deec534bcfea8922fffd7b03b98c ]
  [ "$UPSTREAM_ARM64_SHA256" = b8a8a4d8afc6307f4ee954ed52d5aecc8ee70932c0a16ab8d504be39ea164f59 ]
}

@test "IPv4 validation rejects malformed and out-of-range addresses" {
  valid_ipv4 23.95.133.118
  run valid_ipv4 256.1.1.1
  [ "$status" -ne 0 ]
  run valid_ipv4 not-an-ip
  [ "$status" -ne 0 ]
}

@test "public IPv4 validation rejects private and reserved ranges" {
  public_ipv4 23.95.133.118
  run public_ipv4 10.0.0.1
  [ "$status" -ne 0 ]
  run public_ipv4 100.64.0.1
  [ "$status" -ne 0 ]
  run public_ipv4 192.168.1.1
  [ "$status" -ne 0 ]
  run public_ipv4 203.0.113.10
  [ "$status" -ne 0 ]
}

@test "generated config is non-secret and msmtp uses a password file" {
  CERT_DOMAIN=example.com
  CF_ZONE_NAME=example.com
  CF_ZONE_ID=zone-id
  PUBLIC_IPV4=192.0.2.10
  CERT_FILE="$CERTMAN_TROJAN_TLS_DIR/fullchain.pem"
  KEY_FILE="$CERTMAN_TROJAN_TLS_DIR/private.key"
  TROJAN_PORT=443
  ACME_MODE=dns
  SMTP_HOST=smtp.qiye.aliyun.com
  SMTP_PORT=465
  SMTP_USER=operator@example.com
  SMTP_FROM=operator@example.com
  SMTP_RECIPIENT=operator@example.com
  printf 'smtp-secret' >"$CERTMAN_SMTP_PASSWORD_FILE"
  chmod 0600 "$CERTMAN_SMTP_PASSWORD_FILE"

  write_config
  write_msmtp_config

  run grep -R 'smtp-secret' "$CERTMAN_CONFIG_DIR"
  [ "$status" -eq 0 ]
  [ "$output" = "$CERTMAN_SMTP_PASSWORD_FILE:smtp-secret" ]
  ! grep -q 'smtp-secret' "$CERTMAN_CONFIG_FILE"
  ! grep -q 'smtp-secret' "$CERTMAN_MSMTP_CONFIG"
  grep -Fq 'tls_starttls off' "$CERTMAN_MSMTP_CONFIG"
  grep -Fq 'from operator@example.com' "$CERTMAN_MSMTP_CONFIG"
  grep -Fq "passwordeval \"cat $CERTMAN_SMTP_PASSWORD_FILE\"" "$CERTMAN_MSMTP_CONFIG"
  mode=$(stat -c %a "$CERTMAN_SMTP_PASSWORD_FILE" 2>/dev/null || stat -f %Lp "$CERTMAN_SMTP_PASSWORD_FILE")
  [ "$mode" = 600 ]
}

@test "systemd timer is persistent and failure-wired" {
  systemctl() { :; }
  INSTALLED_BIN=/usr/local/sbin/trojan-certman
  install_systemd_units
  grep -Fq 'Persistent=true' "$CERTMAN_SYSTEMD_DIR/trojan-certman-renew.timer"
  grep -Fq 'RandomizedDelaySec=1h' "$CERTMAN_SYSTEMD_DIR/trojan-certman-renew.timer"
  grep -Fq 'OnFailure=trojan-certman-alert@%n.service' "$CERTMAN_SYSTEMD_DIR/trojan-certman-renew.service"
  grep -Fq 'ExecStart=/usr/local/sbin/trojan-certman renew' "$CERTMAN_SYSTEMD_DIR/trojan-certman-renew.service"
}

@test "Cloudflare cutover refuses multiple same-name A records" {
  CERT_DOMAIN=example.com
  CF_ZONE_NAME=example.com
  CF_ZONE_ID=zone-id
  PUBLIC_IPV4=192.0.2.10
  cf_request() {
    printf '{"success":true,"result":[{"id":"one"},{"id":"two"}]}\n'
  }
  run cutover_dns
  [ "$status" -ne 0 ]
  [[ "$output" == *"refusing to modify multiple A records"* ]]
}

@test "Cloudflare cutover creates a missing DNS-only A record and saves rollback" {
  CERT_DOMAIN=example.com
  CF_ZONE_NAME=example.com
  CF_ZONE_ID=zone-id
  PUBLIC_IPV4=23.95.133.118
  cf_request() {
    printf '%s %s %s\n' "$1" "$2" "${3:-}" >>"$TEST_ROOT/cf.log"
    if [[ "$1" == GET ]]; then
      printf '{"success":true,"result":[]}\n'
    else
      printf '{"success":true,"result":{"id":"created-id"}}\n'
    fi
  }
  verify_authoritative_dns() { return 0; }

  cutover_dns
  grep -Fq 'POST /zones/zone-id/dns_records' "$TEST_ROOT/cf.log"
  grep -Fq '"proxied":false' "$TEST_ROOT/cf.log"
  [ "$(jq -r '.action' "$CERTMAN_DNS_BACKUP_FILE")" = create ]
  [ "$(jq -r '.created_record_id' "$CERTMAN_DNS_BACKUP_FILE")" = created-id ]
}

@test "idempotent Cloudflare cutover preserves the original rollback point" {
  CERT_DOMAIN=example.com
  CF_ZONE_NAME=example.com
  CF_ZONE_ID=zone-id
  PUBLIC_IPV4=23.95.133.118
  printf '{"action":"update","sentinel":"keep-me"}\n' >"$CERTMAN_DNS_BACKUP_FILE"
  cf_request() {
    printf '{"success":true,"result":[{"id":"same","content":"23.95.133.118","proxied":false}]}\n'
  }
  verify_authoritative_dns() { return 0; }

  cutover_dns
  [ "$(jq -r '.sentinel' "$CERTMAN_DNS_BACKUP_FILE")" = keep-me ]
}

@test "Cloudflare API failure and authoritative timeout both fail closed" {
  CERT_DOMAIN=example.com
  CF_ZONE_NAME=example.com
  CF_ZONE_ID=zone-id
  PUBLIC_IPV4=23.95.133.118
  cf_request() {
    [[ "$1" == GET ]] && printf '{"success":true,"result":[{"id":"old","content":"23.1.1.1","proxied":false}]}\n' && return 0
    return 1
  }
  run cutover_dns
  [ "$status" -ne 0 ]
  [[ "$output" == *"update failed"* ]]

  cf_request() {
    if [[ "$1" == GET ]]; then
      printf '{"success":true,"result":[]}\n'
    else
      printf '{"success":true,"result":{"id":"new"}}\n'
    fi
  }
  verify_authoritative_dns() { return 1; }
  run cutover_dns
  [ "$status" -ne 0 ]
  [[ "$output" == *"did not converge"* ]]
}

@test "DNS rollback restores an updated record and verifies authoritative DNS" {
  CERT_DOMAIN=example.com
  CF_ZONE_NAME=example.com
  CF_ZONE_ID=zone-id
  PUBLIC_IPV4=23.95.133.118
  SMTP_HOST=smtp.qiye.aliyun.com
  SMTP_PORT=465
  SMTP_USER=operator@example.com
  SMTP_FROM=operator@example.com
  SMTP_RECIPIENT=operator@example.com
  CERT_FILE="$CERTMAN_TROJAN_TLS_DIR/fullchain.pem"
  KEY_FILE="$CERTMAN_TROJAN_TLS_DIR/private.key"
  TROJAN_PORT=443
  ACME_MODE=dns
  write_config
  printf token >"$CERTMAN_CF_TOKEN_FILE"
  printf '%s\n' '{"action":"update","zone_id":"zone-id","record":{"id":"old-id","type":"A","name":"example.com","content":"23.1.1.1","ttl":1,"proxied":false}}' >"$CERTMAN_DNS_BACKUP_FILE"
  cf_request() { printf '%s %s %s\n' "$1" "$2" "${3:-}" >>"$TEST_ROOT/rollback.log"; printf '{"success":true,"result":{}}\n'; }
  verify_authoritative_dns_value() { printf '%s\n' "$1" >"$TEST_ROOT/verified-value"; }

  rollback_dns
  grep -Fq 'PUT /zones/zone-id/dns_records/old-id' "$TEST_ROOT/rollback.log"
  [ "$(<"$TEST_ROOT/verified-value")" = 23.1.1.1 ]
}

@test "certificate validation checks SAN lifetime and key match" {
  CERT_DOMAIN=example.com
  CERT_FILE="$CERTMAN_TROJAN_TLS_DIR/fullchain.pem"
  KEY_FILE="$CERTMAN_TROJAN_TLS_DIR/private.key"
  make_certificate 30 example.com "$KEY_FILE" "$CERT_FILE"
  verify_certificate_files

  make_certificate 1 example.com "$KEY_FILE" "$CERT_FILE"
  run verify_certificate_files
  [ "$status" -ne 0 ]

  make_certificate 30 wrong.example "$KEY_FILE" "$CERT_FILE"
  run verify_certificate_files
  [ "$status" -ne 0 ]

  make_certificate 30 example.com "$KEY_FILE" "$CERT_FILE"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY_FILE" >/dev/null 2>&1
  run verify_certificate_files
  [ "$status" -ne 0 ]
}

@test "live certificate fingerprint must match the managed disk certificate" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  CERT_FILE="$CERTMAN_TROJAN_TLS_DIR/fullchain.pem"
  KEY_FILE="$CERTMAN_TROJAN_TLS_DIR/private.key"
  make_certificate 30 example.com "$KEY_FILE" "$CERT_FILE"
  cp "$CERT_FILE" "$TEST_ROOT/live.pem"
  timeout() { cat "$TEST_ROOT/live.pem"; }
  verify_live_certificate

  make_certificate 30 other.example "$TEST_ROOT/other.key" "$TEST_ROOT/live.pem"
  run verify_live_certificate
  [ "$status" -ne 0 ]
}

@test "standalone renewal outside its window does not stop trojan-web" {
  CERT_DOMAIN=example.com
  CERT_FILE="$CERTMAN_TROJAN_TLS_DIR/fullchain.pem"
  KEY_FILE="$CERTMAN_TROJAN_TLS_DIR/private.key"
  TROJAN_PORT=443
  ACME_MODE=standalone
  CF_ZONE_NAME=example.com
  CF_ZONE_ID=
  PUBLIC_IPV4=
  SMTP_HOST=smtp.qiye.aliyun.com
  SMTP_PORT=465
  SMTP_USER=operator@example.com
  SMTP_FROM=operator@example.com
  SMTP_RECIPIENT=operator@example.com
  make_certificate 60 example.com "$KEY_FILE" "$CERT_FILE"
  write_config
  write_status failed health-verification
  flock() { return 0; }
  systemctl() { printf '%s ' "$@" >>"$TEST_ROOT/systemctl.log"; printf '\n' >>"$TEST_ROOT/systemctl.log"; return 0; }
  verify_live_certificate() { return 0; }
  send_email() { printf '%s\n' "$1" >"$TEST_ROOT/recovery-email"; }

  run run_renew
  [ "$status" -eq 0 ]
  ! grep -q 'stop trojan-web.service' "$TEST_ROOT/systemctl.log"
  grep -Fq 'LAST_STAGE=not-due' "$CERTMAN_STATUS_FILE"
  grep -Fq 'recovered: example.com' "$TEST_ROOT/recovery-email"
}

@test "standalone renewal failure restores trojan-web" {
  CERT_DOMAIN=example.com
  CERT_FILE="$CERTMAN_TROJAN_TLS_DIR/fullchain.pem"
  KEY_FILE="$CERTMAN_TROJAN_TLS_DIR/private.key"
  TROJAN_PORT=443
  ACME_MODE=standalone
  CF_ZONE_NAME=example.com
  CF_ZONE_ID=
  PUBLIC_IPV4=
  SMTP_HOST=smtp.qiye.aliyun.com
  SMTP_PORT=465
  SMTP_USER=operator@example.com
  SMTP_FROM=operator@example.com
  SMTP_RECIPIENT=operator@example.com
  make_certificate 1 example.com "$KEY_FILE" "$CERT_FILE"
  write_config
  cat >"$CERTMAN_ACME_BIN" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  chmod +x "$CERTMAN_ACME_BIN"
  flock() { return 0; }
  systemctl() { printf '%s ' "$@" >>"$TEST_ROOT/systemctl.log"; printf '\n' >>"$TEST_ROOT/systemctl.log"; return 0; }

  run run_renew
  [ "$status" -ne 0 ]
  grep -q 'stop trojan-web.service' "$TEST_ROOT/systemctl.log"
  grep -q 'start trojan-web.service' "$TEST_ROOT/systemctl.log"
  grep -Fq 'LAST_STATE=failed' "$CERTMAN_STATUS_FILE"
}

@test "successful DNS renewal never forces issuance and restarts Trojan on certificate change" {
  CERT_DOMAIN=example.com
  CERT_FILE="$CERTMAN_TROJAN_TLS_DIR/fullchain.pem"
  KEY_FILE="$CERTMAN_TROJAN_TLS_DIR/private.key"
  TROJAN_PORT=443
  ACME_MODE=dns
  CF_ZONE_NAME=example.com
  CF_ZONE_ID=zone-id
  PUBLIC_IPV4=23.95.133.118
  SMTP_HOST=smtp.qiye.aliyun.com
  SMTP_PORT=465
  SMTP_USER=operator@example.com
  SMTP_FROM=operator@example.com
  SMTP_RECIPIENT=operator@example.com
  make_certificate 30 example.com "$KEY_FILE" "$CERT_FILE"
  write_config
  printf token >"$CERTMAN_CF_TOKEN_FILE"
  cat >"$CERTMAN_ACME_BIN" <<EOF
#!/usr/bin/env bash
printf '%s ' "\$@" >"$TEST_ROOT/acme.args"
EOF
  chmod +x "$CERTMAN_ACME_BIN"
  flock() { return 0; }
  certificate_fingerprint() {
    if [[ -e "$TEST_ROOT/fingerprint-called" ]]; then printf 'after\n'; else touch "$TEST_ROOT/fingerprint-called"; printf 'before\n'; fi
  }
  verify_certificate_files() { return 0; }
  verify_services() { return 0; }
  verify_live_certificate() { return 0; }
  systemctl() { printf '%s ' "$@" >>"$TEST_ROOT/systemctl.log"; printf '\n' >>"$TEST_ROOT/systemctl.log"; }

  run_renew
  grep -Fq -- '--cron' "$TEST_ROOT/acme.args"
  ! grep -Fq -- '--force' "$TEST_ROOT/acme.args"
  grep -Fq 'restart trojan.service' "$TEST_ROOT/systemctl.log"
  grep -Fq 'LAST_STATE=success' "$CERTMAN_STATUS_FILE"
}

@test "failure alert is throttled to one email per 24 hours" {
  CERT_DOMAIN=example.com
  CERT_FILE="$CERTMAN_TROJAN_TLS_DIR/fullchain.pem"
  KEY_FILE="$CERTMAN_TROJAN_TLS_DIR/private.key"
  TROJAN_PORT=443
  ACME_MODE=dns
  CF_ZONE_NAME=example.com
  CF_ZONE_ID=zone-id
  PUBLIC_IPV4=23.95.133.118
  SMTP_HOST=smtp.qiye.aliyun.com
  SMTP_PORT=465
  SMTP_USER=operator@example.com
  SMTP_FROM=operator@example.com
  SMTP_RECIPIENT=operator@example.com
  make_certificate 30 example.com "$KEY_FILE" "$CERT_FILE"
  write_config
  write_status failed renewal
  send_email() { printf 'sent\n' >>"$TEST_ROOT/email.log"; }

  send_failure_alert trojan-certman-renew.service
  send_failure_alert trojan-certman-renew.service
  [ "$(grep -c '^sent$' "$TEST_ROOT/email.log")" -eq 1 ]
}

@test "adopt is repeatable and does not install Trojan issue a certificate or touch DNS" {
  SMTP_HOST=smtp.qiye.aliyun.com
  SMTP_PORT=465
  SMTP_USER=operator@example.com
  SMTP_FROM=operator@example.com
  SMTP_RECIPIENT=operator@example.com
  mkdir -p "$(dirname "$CERTMAN_TROJAN_CONFIG")"
  printf '%s\n' '{"local_port":443,"ssl":{"sni":"example.com","cert":"/managed/fullchain.pem","key":"/managed/private.key"}}' >"$CERTMAN_TROJAN_CONFIG"
  mkdir -p "$CERTMAN_ACME_HOME/example.com_ecc"
  printf "Le_Webroot='no'\n" >"$CERTMAN_ACME_HOME/example.com_ecc/example.com.conf"
  printf smtp-secret >"$TEST_ROOT/smtp-input"
  export CERTMAN_SMTP_PASSWORD_INPUT_FILE="$TEST_ROOT/smtp-input"
  msmtp() { :; }
  systemctl() { :; }
  verify_health() { :; }
  deliver_test_email() { printf 'email\n' >>"$TEST_ROOT/adopt.log"; }
  install_self() { printf 'self\n' >>"$TEST_ROOT/adopt.log"; }
  install_systemd_units() { printf 'units\n' >>"$TEST_ROOT/adopt.log"; }
  download_manager() { return 89; }
  issue_dns_certificate() { return 90; }
  cutover_dns() { return 91; }

  adopt_existing
  adopt_existing
  [ "$(grep -c '^self$' "$TEST_ROOT/adopt.log")" -eq 2 ]
  [ "$(grep -c '^units$' "$TEST_ROOT/adopt.log")" -eq 2 ]
  [ "$(grep -c '^email$' "$TEST_ROOT/adopt.log")" -eq 2 ]
  grep -Fq 'ACME_MODE=standalone' "$CERTMAN_CONFIG_FILE"
}

@test "guided install keeps DNS cutover last and is safely repeatable under mocks" {
  CERT_DOMAIN=example.com
  CF_ZONE_NAME=example.com
  PUBLIC_IPV4=23.95.133.118
  CERT_FILE="$CERTMAN_TROJAN_TLS_DIR/fullchain.pem"
  KEY_FILE="$CERTMAN_TROJAN_TLS_DIR/private.key"
  TROJAN_MANAGER_BIN="$TEST_ROOT/trojan-manager"
  cat >"$TROJAN_MANAGER_BIN" <<EOF
#!/usr/bin/env bash
printf 'manager\n' >>"$TEST_ROOT/install.log"
EOF
  chmod +x "$TROJAN_MANAGER_BIN"
  step() { printf '%s\n' "$1" >>"$TEST_ROOT/install.log"; }
  preflight_os() { printf 'amd64\n'; }
  install_dependencies() { step dependencies; }
  install_secret() { step secret; }
  resolve_zone_id() { CF_ZONE_ID=zone-id; step zone; }
  configure_smtp() {
    SMTP_HOST=smtp.qiye.aliyun.com
    SMTP_PORT=465
    SMTP_USER=operator@example.com
    SMTP_FROM=operator@example.com
    SMTP_RECIPIENT=operator@example.com
    step smtp
  }
  download_manager() { step "download-$1"; }
  install_trojan_web_unit() { step web-unit; }
  issue_dns_certificate() { step issue; }
  atomic_update_trojan_config() { step config; }
  systemctl() { step services; }
  install_self() { step self; }
  install_systemd_units() { step timer; }
  verify_health() { step verify; }
  run_test_email() { step email; }
  cutover_dns() { step cutover; }

  install_new
  install_new
  [ "$(grep -c '^cutover$' "$TEST_ROOT/install.log")" -eq 2 ]
  [ "$(grep -c '^manager$' "$TEST_ROOT/install.log")" -eq 2 ]
  first_verify=$(grep -n '^verify$' "$TEST_ROOT/install.log" | head -n1 | cut -d: -f1)
  first_email=$(grep -n '^email$' "$TEST_ROOT/install.log" | head -n1 | cut -d: -f1)
  first_cutover=$(grep -n '^cutover$' "$TEST_ROOT/install.log" | head -n1 | cut -d: -f1)
  ((first_verify < first_email && first_email < first_cutover))
}

@test "automation uninstall targets no Trojan, MariaDB, or certificate path" {
  body=$(declare -f uninstall_automation)
  [[ "$body" != *'/usr/local/etc/trojan'* ]]
  [[ "$body" != *'/home/mariadb'* ]]
  [[ "$body" != *'/etc/trojan/tls'* ]]
  [[ "$body" != *'docker rm'* ]]
}
