#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

PROGRAM="trojan-certman"
PROGRAM_VERSION="0.1.0"
UPSTREAM_VERSION="v2.15.3"
UPSTREAM_BASE_URL="https://github.com/Jrohy/trojan/releases/download/${UPSTREAM_VERSION}"
UPSTREAM_AMD64_SHA256="3acd0b3fbe51aaf56ec482370c63d4832fd9deec534bcfea8922fffd7b03b98c"
UPSTREAM_ARM64_SHA256="b8a8a4d8afc6307f4ee954ed52d5aecc8ee70932c0a16ab8d504be39ea164f59"

CONFIG_DIR="${CERTMAN_CONFIG_DIR:-/etc/trojan-certman}"
CONFIG_FILE="${CERTMAN_CONFIG_FILE:-${CONFIG_DIR}/config}"
SECRETS_DIR="${CERTMAN_SECRETS_DIR:-${CONFIG_DIR}/secrets}"
CF_TOKEN_FILE="${CERTMAN_CF_TOKEN_FILE:-${SECRETS_DIR}/cloudflare-token}"
SMTP_PASSWORD_FILE="${CERTMAN_SMTP_PASSWORD_FILE:-${SECRETS_DIR}/smtp-password}"
MSMTP_CONFIG="${CERTMAN_MSMTP_CONFIG:-${CONFIG_DIR}/msmtprc}"
STATE_DIR="${CERTMAN_STATE_DIR:-/var/lib/trojan-certman}"
STATUS_FILE="${CERTMAN_STATUS_FILE:-${STATE_DIR}/status}"
DNS_BACKUP_FILE="${CERTMAN_DNS_BACKUP_FILE:-${STATE_DIR}/dns-before.json}"
LOCK_FILE="${CERTMAN_LOCK_FILE:-/run/lock/trojan-certman.lock}"
ACME_HOME="${CERTMAN_ACME_HOME:-/root/.acme.sh}"
ACME_BIN="${CERTMAN_ACME_BIN:-${ACME_HOME}/acme.sh}"
TROJAN_MANAGER_BIN="${CERTMAN_TROJAN_MANAGER_BIN:-/usr/local/bin/trojan}"
TROJAN_CONFIG="${CERTMAN_TROJAN_CONFIG:-/usr/local/etc/trojan/config.json}"
TROJAN_TLS_DIR="${CERTMAN_TROJAN_TLS_DIR:-/etc/trojan/tls}"
SYSTEMD_DIR="${CERTMAN_SYSTEMD_DIR:-/etc/systemd/system}"
INSTALLED_BIN="${CERTMAN_INSTALLED_BIN:-/usr/local/sbin/trojan-certman}"
CF_API="https://api.cloudflare.com/client/v4"

DEFAULT_DOMAIN="introspect.czyhandsome.ink"
DEFAULT_ZONE="czyhandsome.ink"
DEFAULT_SMTP_HOST="smtp.qiye.aliyun.com"
DEFAULT_SMTP_PORT="465"
DEFAULT_SMTP_USER="caoziyu@hidream.ai"
RENEW_WINDOW_SECONDS=$((31 * 24 * 60 * 60))
MIN_VALID_SECONDS=$((14 * 24 * 60 * 60))
DNS_WAIT_SECONDS=${CERTMAN_DNS_WAIT_SECONDS:-180}
DNS_POLL_SECONDS=${CERTMAN_DNS_POLL_SECONDS:-5}

log() { printf '[%s] %s\n' "$PROGRAM" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$PROGRAM" "$*" >&2; }
die() { printf '[%s] ERROR: %s\n' "$PROGRAM" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  install-with-certman.sh install
  trojan-certman adopt
  trojan-certman status
  trojan-certman renew
  trojan-certman test-email
  trojan-certman dns-rollback
  trojan-certman uninstall-automation

Commands:
  install               Guided installation on a new Ubuntu host. DNS cutover is last.
  adopt                 Add renewal and email alerting to an existing installation.
  status                Show non-secret DNS, certificate, service and timer status.
  renew                 Run a normal renewal check. This command never adds --force.
  test-email            Send a confirmation email after an interactive prompt.
  dns-rollback          Restore the A record saved before the most recent cutover.
  uninstall-automation  Remove only certman automation and its settings.

Secret-file overrides for non-interactive provisioning:
  CERTMAN_CF_TOKEN_INPUT_FILE
  CERTMAN_SMTP_PASSWORD_INPUT_FILE
EOF
}

require_root() {
  [[ "${CERTMAN_SKIP_ROOT_CHECK:-0}" == "1" ]] && return
  [[ "$(id -u)" == "0" ]] || die "run as root"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

normalize_arch() {
  case "${1:-$(uname -m)}" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) return 1 ;;
  esac
}

valid_ipv4() {
  local ip=${1:-} octet
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<<"$ip"
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ ]] && ((10#$octet <= 255)) || return 1
  done
}

public_ipv4() {
  local ip=$1 first second third
  valid_ipv4 "$ip" || return 1
  IFS=. read -r first second third _ <<<"$ip"
  case "$first" in
    0|10|127) return 1 ;;
    100) ((second >= 64 && second <= 127)) && return 1 ;;
    169) [[ "$second" == 254 ]] && return 1 ;;
    172) ((second >= 16 && second <= 31)) && return 1 ;;
    192)
      [[ "$second" == 168 ]] && return 1
      [[ "$second" == 0 && ("$third" == 0 || "$third" == 2) ]] && return 1
      [[ "$second" == 88 && "$third" == 99 ]] && return 1
      ;;
    198)
      [[ "$second" == 18 || "$second" == 19 ]] && return 1
      [[ "$second" == 51 && "$third" == 100 ]] && return 1
      ;;
    203) [[ "$second" == 0 && "$third" == 113 ]] && return 1 ;;
  esac
  ((first < 224))
}

prompt_value() {
  local variable=$1 prompt=$2 default=${3:-} value
  if [[ -n "${!variable:-}" ]]; then return; fi
  [[ -r /dev/tty ]] || die "cannot prompt for $variable without a TTY"
  read -r -p "$prompt [$default]: " value </dev/tty
  printf -v "$variable" '%s' "${value:-$default}"
}

confirm() {
  local prompt=$1 answer
  [[ "${CERTMAN_ASSUME_YES:-0}" == "1" ]] && return 0
  [[ -r /dev/tty ]] || return 1
  read -r -p "$prompt [y/N]: " answer </dev/tty
  [[ "$answer" =~ ^[Yy]$ ]]
}

install_secret() {
  local label=$1 target=$2 input_file=${3:-} value temp
  install -d -m 0700 "$SECRETS_DIR"
  chown root:root "$SECRETS_DIR" 2>/dev/null || true
  temp=$(mktemp "${SECRETS_DIR}/.secret.XXXXXX")
  chmod 0600 "$temp"
  if [[ -n "$input_file" ]]; then
    [[ -f "$input_file" ]] || die "$label input file not found"
    tr -d '\r\n' <"$input_file" >"$temp"
  elif [[ -s "$target" ]]; then
    cp "$target" "$temp"
  else
    [[ -r /dev/tty ]] || die "cannot prompt for $label without a TTY"
    read -r -s -p "$label: " value </dev/tty
    printf '\n' >/dev/tty
    [[ -n "$value" ]] || die "$label cannot be empty"
    printf '%s' "$value" >"$temp"
    unset value
  fi
  [[ -s "$temp" ]] || { rm -f "$temp"; die "$label cannot be empty"; }
  mv -f "$temp" "$target"
  chown root:root "$target" 2>/dev/null || true
  chmod 0600 "$target"
}

write_config() {
  local temp
  install -d -m 0755 "$CONFIG_DIR"
  temp=$(mktemp "${CONFIG_DIR}/.config.XXXXXX")
  {
    printf 'CERT_DOMAIN=%q\n' "$CERT_DOMAIN"
    printf 'CF_ZONE_NAME=%q\n' "${CF_ZONE_NAME:-}"
    printf 'CF_ZONE_ID=%q\n' "${CF_ZONE_ID:-}"
    printf 'PUBLIC_IPV4=%q\n' "${PUBLIC_IPV4:-}"
    printf 'CERT_FILE=%q\n' "$CERT_FILE"
    printf 'KEY_FILE=%q\n' "$KEY_FILE"
    printf 'TROJAN_PORT=%q\n' "$TROJAN_PORT"
    printf 'ACME_MODE=%q\n' "$ACME_MODE"
    printf 'SMTP_HOST=%q\n' "$SMTP_HOST"
    printf 'SMTP_PORT=%q\n' "$SMTP_PORT"
    printf 'SMTP_USER=%q\n' "$SMTP_USER"
    printf 'SMTP_FROM=%q\n' "$SMTP_FROM"
    printf 'SMTP_RECIPIENT=%q\n' "$SMTP_RECIPIENT"
  } >"$temp"
  chmod 0644 "$temp"
  mv -f "$temp" "$CONFIG_FILE"
}

load_config() {
  [[ -r "$CONFIG_FILE" ]] || die "configuration not found: $CONFIG_FILE"
  # This file is generated by write_config and is root-owned in production.
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
}

write_status() {
  local state=$1 stage=$2 now temp previous_alert=0
  install -d -m 0755 "$STATE_DIR"
  [[ -r "$STATUS_FILE" ]] && previous_alert=$(awk -F= '$1=="LAST_ALERT_EPOCH" {print $2}' "$STATUS_FILE" 2>/dev/null || true)
  temp=$(mktemp "${STATE_DIR}/.status.XXXXXX")
  now=$(date +%s)
  {
    printf 'LAST_STATE=%q\n' "$state"
    printf 'LAST_STAGE=%q\n' "$stage"
    printf 'LAST_RUN_EPOCH=%q\n' "$now"
    printf 'LAST_ALERT_EPOCH=%q\n' "${previous_alert:-0}"
  } >"$temp"
  chmod 0644 "$temp"
  mv -f "$temp" "$STATUS_FILE"
}

update_alert_epoch() {
  local temp now
  [[ -r "$STATUS_FILE" ]] || return 0
  now=$(date +%s)
  temp=$(mktemp "${STATE_DIR}/.status.XXXXXX")
  awk -F= -v now="$now" '$1=="LAST_ALERT_EPOCH" {$0="LAST_ALERT_EPOCH=" now} {print}' "$STATUS_FILE" >"$temp"
  chmod 0644 "$temp"
  mv -f "$temp" "$STATUS_FILE"
}

config_value() {
  local key=$1 file=$2
  sed -n "s/^${key}='\\(.*\\)'$/\\1/p" "$file" | head -n1
}

preflight_os() {
  local version arch
  [[ -r /etc/os-release ]] || die "unsupported OS"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "v1 supports Ubuntu only"
  version=${VERSION_ID:-}
  [[ "$version" == "22.04" || "$version" == "24.04" ]] || die "v1 supports Ubuntu 22.04 or 24.04"
  command -v systemctl >/dev/null 2>&1 || die "systemd is required"
  arch=$(normalize_arch) || die "supported architectures: amd64, arm64"
  printf '%s\n' "$arch"
}

install_dependencies() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y bash-completion ca-certificates cron curl dnsutils jq msmtp openssl socat xz-utils
}

install_self() {
  local source_path
  source_path=$(readlink -f "${BASH_SOURCE[0]}")
  install -d -m 0755 "$(dirname "$INSTALLED_BIN")"
  install -m 0755 "$source_path" "$INSTALLED_BIN"
}

download_manager() {
  local arch=$1 asset expected temp_dir temp_file actual
  case "$arch" in
    amd64) asset=trojan-linux-amd64; expected=$UPSTREAM_AMD64_SHA256 ;;
    arm64) asset=trojan-linux-arm64; expected=$UPSTREAM_ARM64_SHA256 ;;
    *) die "unsupported architecture: $arch" ;;
  esac
  temp_dir=$(mktemp -d)
  temp_file="${temp_dir}/${asset}"
  trap 'rm -rf "$temp_dir"' RETURN
  curl -fsSL --proto '=https' --tlsv1.2 "${UPSTREAM_BASE_URL}/${asset}" -o "$temp_file"
  actual=$(sha256sum "$temp_file" | awk '{print $1}')
  [[ "$actual" == "$expected" ]] || die "upstream binary checksum mismatch"
  install -m 0755 "$temp_file" "$TROJAN_MANAGER_BIN"
  trap - RETURN
  rm -rf "$temp_dir"
}

install_trojan_web_unit() {
  cat >"${SYSTEMD_DIR}/trojan-web.service" <<'EOF'
[Unit]
Description=trojan-web
Documentation=https://github.com/Jrohy/trojan
After=network.target network-online.target nss-lookup.target mysql.service mariadb.service mysqld.service docker.service

[Service]
Type=simple
StandardError=journal
ExecStart=/usr/local/bin/trojan web
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable trojan-web.service
}

install_acme() {
  local temp
  [[ -x "$ACME_BIN" ]] && return
  temp=$(mktemp)
  curl -fsSL --proto '=https' --tlsv1.2 https://get.acme.sh -o "$temp"
  bash "$temp" --no-cron
  rm -f "$temp"
  [[ -x "$ACME_BIN" ]] || die "acme.sh installation failed"
}

cf_curl_config() {
  local temp token
  token=$(<"$CF_TOKEN_FILE")
  temp=$(mktemp)
  chmod 0600 "$temp"
  printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$token" >"$temp"
  unset token
  printf '%s\n' "$temp"
}

cf_request() {
  local method=$1 path=$2 data=${3:-} cfg response
  cfg=$(cf_curl_config)
  if [[ -n "$data" ]]; then
    response=$(curl -fsS --config "$cfg" -X "$method" --data "$data" "${CF_API}${path}") || { rm -f "$cfg"; return 1; }
  else
    response=$(curl -fsS --config "$cfg" -X "$method" "${CF_API}${path}") || { rm -f "$cfg"; return 1; }
  fi
  rm -f "$cfg"
  jq -e '.success == true' >/dev/null <<<"$response" || { jq -c '.errors // []' <<<"$response" >&2; return 1; }
  printf '%s\n' "$response"
}

resolve_zone_id() {
  local response count
  [[ -n "${CF_ZONE_ID:-}" ]] && return
  response=$(cf_request GET "/zones?name=${CF_ZONE_NAME}&status=active") || die "Cloudflare zone lookup failed"
  count=$(jq '.result | length' <<<"$response")
  [[ "$count" == "1" ]] || die "expected exactly one active Cloudflare zone named ${CF_ZONE_NAME}"
  CF_ZONE_ID=$(jq -r '.result[0].id' <<<"$response")
}

issue_dns_certificate() {
  local token
  install -d -m 0755 "$TROJAN_TLS_DIR"
  install_acme
  token=$(<"$CF_TOKEN_FILE")
  CF_Token="$token" "$ACME_BIN" --issue --dns dns_cf -d "$CERT_DOMAIN" --server letsencrypt --keylength ec-256
  unset token
  "$ACME_BIN" --install-cert -d "$CERT_DOMAIN" --ecc \
    --key-file "$KEY_FILE" \
    --fullchain-file "$CERT_FILE" \
    --reloadcmd "systemctl try-restart trojan.service"
  chmod 0600 "$KEY_FILE"
  chmod 0644 "$CERT_FILE"
}

atomic_update_trojan_config() {
  local temp
  [[ -r "$TROJAN_CONFIG" ]] || die "Trojan initialization did not create $TROJAN_CONFIG"
  temp=$(mktemp "$(dirname "$TROJAN_CONFIG")/.config.XXXXXX")
  jq --arg cert "$CERT_FILE" --arg key "$KEY_FILE" --arg sni "$CERT_DOMAIN" \
    '.ssl.cert=$cert | .ssl.key=$key | .ssl.sni=$sni' "$TROJAN_CONFIG" >"$temp"
  chmod --reference="$TROJAN_CONFIG" "$temp"
  chown --reference="$TROJAN_CONFIG" "$temp"
  mv -f "$temp" "$TROJAN_CONFIG"
}

write_msmtp_config() {
  local temp
  install -d -m 0755 "$CONFIG_DIR"
  temp=$(mktemp "${CONFIG_DIR}/.msmtprc.XXXXXX")
  cat >"$temp" <<EOF
defaults
auth on
tls on
tls_starttls off
tls_trust_file /etc/ssl/certs/ca-certificates.crt
timeout 20

account trojan-certman
host ${SMTP_HOST}
port ${SMTP_PORT}
from ${SMTP_FROM}
user ${SMTP_USER}
passwordeval "cat ${SMTP_PASSWORD_FILE}"

account default : trojan-certman
EOF
  chmod 0600 "$temp"
  mv -f "$temp" "$MSMTP_CONFIG"
}

send_email() {
  local subject=$1 body=$2
  [[ -s "$MSMTP_CONFIG" && -s "$SMTP_PASSWORD_FILE" ]] || return 1
  {
    printf 'From: %s\n' "$SMTP_FROM"
    printf 'To: %s\n' "$SMTP_RECIPIENT"
    printf 'Subject: %s\n' "$subject"
    printf 'Content-Type: text/plain; charset=UTF-8\n\n'
    printf '%b\n' "$body"
  } | msmtp --file="$MSMTP_CONFIG" --account=trojan-certman "$SMTP_RECIPIENT"
}

send_recovery_email() {
  send_email "[trojan-certman] recovered: ${CERT_DOMAIN}" \
    "Certificate automation recovered on $(hostname -f 2>/dev/null || hostname). Current expiry: $(certificate_enddate)." || warn "recovery email failed"
}

certificate_enddate() {
  openssl x509 -in "$CERT_FILE" -noout -enddate 2>/dev/null | cut -d= -f2-
}

certificate_fingerprint() {
  openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2-
}

verify_certificate_files() {
  [[ -r "$CERT_FILE" && -r "$KEY_FILE" ]] || return 1
  openssl x509 -in "$CERT_FILE" -noout -checkend "$MIN_VALID_SECONDS" >/dev/null 2>&1 || return 1
  openssl x509 -in "$CERT_FILE" -noout -ext subjectAltName 2>/dev/null | grep -Fq "DNS:${CERT_DOMAIN}" || return 1
  local cert_pub key_pub
  cert_pub=$(openssl x509 -in "$CERT_FILE" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  key_pub=$(openssl pkey -in "$KEY_FILE" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]]
}

verify_live_certificate() {
  local live temp
  temp=$(mktemp)
  if ! timeout 15 openssl s_client -connect "127.0.0.1:${TROJAN_PORT}" -servername "$CERT_DOMAIN" </dev/null 2>/dev/null \
      | openssl x509 -outform PEM >"$temp" 2>/dev/null; then
    rm -f "$temp"
    return 1
  fi
  live=$(openssl x509 -in "$temp" -noout -fingerprint -sha256 | cut -d= -f2-)
  rm -f "$temp"
  [[ "$live" == "$(certificate_fingerprint)" ]]
}

capture_live_certificate() {
  local target=$1
  timeout 15 openssl s_client -connect "127.0.0.1:${TROJAN_PORT}" -servername "$CERT_DOMAIN" </dev/null 2>/dev/null \
    | openssl x509 -outform PEM >"$target" 2>/dev/null
}

verify_services() {
  systemctl is-active --quiet trojan.service || return 1
  systemctl is-active --quiet trojan-web.service || return 1
}

verify_health() {
  verify_certificate_files || die "certificate files failed validation"
  verify_services || die "trojan services are not both active"
  verify_live_certificate || die "live TLS certificate does not match the managed certificate"
}

detect_acme_mode() {
  local domain_conf webroot
  domain_conf="${ACME_HOME}/${CERT_DOMAIN}_ecc/${CERT_DOMAIN}.conf"
  [[ -r "$domain_conf" ]] || { printf 'unknown\n'; return; }
  webroot=$(config_value Le_Webroot "$domain_conf")
  [[ "$webroot" == dns_* ]] && printf 'dns\n' || printf 'standalone\n'
}

install_systemd_units() {
  cat >"${SYSTEMD_DIR}/trojan-certman-renew.service" <<EOF
[Unit]
Description=Renew and verify the managed Trojan TLS certificate
After=network-online.target
Wants=network-online.target
OnFailure=trojan-certman-alert@%n.service

[Service]
Type=oneshot
UMask=0077
ExecStart=${INSTALLED_BIN} renew
EOF

  cat >"${SYSTEMD_DIR}/trojan-certman-renew.timer" <<'EOF'
[Unit]
Description=Daily Trojan certificate renewal check

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
Unit=trojan-certman-renew.service

[Install]
WantedBy=timers.target
EOF

  cat >"${SYSTEMD_DIR}/trojan-certman-alert@.service" <<EOF
[Unit]
Description=Send a Trojan certificate failure alert for %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
UMask=0077
ExecStart=${INSTALLED_BIN} alert %i
EOF
  systemctl daemon-reload
  systemctl enable --now trojan-certman-renew.timer
}

record_dns_before() {
  local response=$1 action=$2 temp
  install -d -m 0755 "$STATE_DIR"
  temp=$(mktemp "${STATE_DIR}/.dns-before.XXXXXX")
  jq --arg action "$action" --arg zone_id "$CF_ZONE_ID" \
    '{action:$action, zone_id:$zone_id, record:(.result[0] // null)}' <<<"$response" >"$temp"
  chmod 0600 "$temp"
  mv -f "$temp" "$DNS_BACKUP_FILE"
}

verify_authoritative_dns_value() {
  local expected=$1 deadline=$((SECONDS + DNS_WAIT_SECONDS)) ns all_match
  local -a answers nameservers
  mapfile -t nameservers < <(dig +short NS "$CF_ZONE_NAME" | sed 's/\.$//')
  ((${#nameservers[@]} > 0)) || return 1
  while :; do
    all_match=1
    for ns in "${nameservers[@]}"; do
      mapfile -t answers < <(dig +short A "$CERT_DOMAIN" "@$ns")
      if [[ "$expected" == absent ]]; then
        ((${#answers[@]} == 0)) || { all_match=0; break; }
      else
        ((${#answers[@]} == 1)) && [[ "${answers[0]}" == "$expected" ]] || { all_match=0; break; }
      fi
    done
    ((all_match == 1)) && return 0
    ((SECONDS >= deadline)) && return 1
    sleep "$DNS_POLL_SECONDS"
  done
}

verify_authoritative_dns() {
  verify_authoritative_dns_value "$PUBLIC_IPV4"
}

cutover_dns() {
  local lookup count record_id payload response
  resolve_zone_id
  lookup=$(cf_request GET "/zones/${CF_ZONE_ID}/dns_records?type=A&name=${CERT_DOMAIN}") || die "Cloudflare A-record lookup failed"
  count=$(jq '.result | length' <<<"$lookup")
  ((count <= 1)) || die "refusing to modify multiple A records named ${CERT_DOMAIN}"
  payload=$(jq -nc --arg name "$CERT_DOMAIN" --arg content "$PUBLIC_IPV4" \
    '{type:"A",name:$name,content:$content,ttl:1,proxied:false}')
  if [[ "$count" == "1" ]]; then
    if [[ "$(jq -r '.result[0].content' <<<"$lookup")" == "$PUBLIC_IPV4" ]] &&
       [[ "$(jq -r '.result[0].proxied' <<<"$lookup")" == false ]]; then
      verify_authoritative_dns || die "Cloudflare record is already correct, but authoritative DNS does not agree"
      log "Cloudflare A record already points to ${PUBLIC_IPV4}; saved rollback state was preserved"
      return 0
    fi
    record_id=$(jq -r '.result[0].id' <<<"$lookup")
    record_dns_before "$lookup" update
    response=$(cf_request PUT "/zones/${CF_ZONE_ID}/dns_records/${record_id}" "$payload") || die "Cloudflare A-record update failed"
  else
    record_dns_before "$lookup" create
    response=$(cf_request POST "/zones/${CF_ZONE_ID}/dns_records" "$payload") || die "Cloudflare A-record creation failed"
    record_id=$(jq -r '.result.id' <<<"$response")
    jq --arg id "$record_id" '.created_record_id=$id' "$DNS_BACKUP_FILE" >"${DNS_BACKUP_FILE}.tmp"
    mv -f "${DNS_BACKUP_FILE}.tmp" "$DNS_BACKUP_FILE"
    chmod 0600 "$DNS_BACKUP_FILE"
  fi
  verify_authoritative_dns || die "Cloudflare accepted the change, but authoritative DNS did not converge within ${DNS_WAIT_SECONDS} seconds"
  log "authoritative DNS now returns ${PUBLIC_IPV4} for ${CERT_DOMAIN}"
}

rollback_dns() {
  local action zone_id record record_id payload expected
  load_config
  [[ -s "$CF_TOKEN_FILE" ]] || die "Cloudflare token is not configured"
  [[ -s "$DNS_BACKUP_FILE" ]] || die "no DNS rollback record found"
  confirm "Restore the saved A record for ${CERT_DOMAIN}?" || die "rollback cancelled"
  action=$(jq -r '.action' "$DNS_BACKUP_FILE")
  zone_id=$(jq -r '.zone_id' "$DNS_BACKUP_FILE")
  if [[ "$action" == "update" ]]; then
    record=$(jq '.record' "$DNS_BACKUP_FILE")
    record_id=$(jq -r '.id' <<<"$record")
    expected=$(jq -r '.content' <<<"$record")
    payload=$(jq '{type,name,content,ttl,proxied}' <<<"$record")
    cf_request PUT "/zones/${zone_id}/dns_records/${record_id}" "$payload" >/dev/null || die "DNS rollback failed"
  elif [[ "$action" == "create" ]]; then
    record_id=$(jq -r '.created_record_id' "$DNS_BACKUP_FILE")
    [[ -n "$record_id" && "$record_id" != null ]] || die "created record ID missing"
    cf_request DELETE "/zones/${zone_id}/dns_records/${record_id}" >/dev/null || die "DNS rollback failed"
    expected=absent
  else
    die "invalid rollback action"
  fi
  verify_authoritative_dns_value "$expected" || die "Cloudflare accepted the rollback, but authoritative DNS did not converge within ${DNS_WAIT_SECONDS} seconds"
  log "DNS rollback completed and authoritative DNS was verified"
}

configure_smtp() {
  prompt_value SMTP_HOST "SMTP host" "$DEFAULT_SMTP_HOST"
  prompt_value SMTP_PORT "SMTP port" "$DEFAULT_SMTP_PORT"
  prompt_value SMTP_USER "SMTP username" "$DEFAULT_SMTP_USER"
  SMTP_FROM=${SMTP_FROM:-$SMTP_USER}
  SMTP_RECIPIENT=${SMTP_RECIPIENT:-$SMTP_USER}
  [[ "$SMTP_FROM" == "$SMTP_USER" ]] || die "Alibaba Mail requires From to match the authenticated username"
  install_secret "SMTP third-party client password" "$SMTP_PASSWORD_FILE" "${CERTMAN_SMTP_PASSWORD_INPUT_FILE:-}"
  write_msmtp_config
}

run_test_email() {
  load_config
  confirm "Send a test email to ${SMTP_RECIPIENT}?" || die "test email cancelled"
  send_email "[trojan-certman] test from $(hostname -f 2>/dev/null || hostname)" \
    "Trojan certificate email alerting is configured for ${CERT_DOMAIN}." || die "test email failed"
  log "test email accepted by SMTP server"
}

adopt_existing() {
  require_root
  require_command jq
  require_command openssl
  require_command systemctl
  [[ -r "$TROJAN_CONFIG" ]] || die "existing Trojan config not found"
  CERT_DOMAIN=$(jq -r '.ssl.sni // empty' "$TROJAN_CONFIG")
  CERT_FILE=$(jq -r '.ssl.cert // empty' "$TROJAN_CONFIG")
  KEY_FILE=$(jq -r '.ssl.key // empty' "$TROJAN_CONFIG")
  TROJAN_PORT=$(jq -r '.local_port // 443' "$TROJAN_CONFIG")
  [[ -n "$CERT_DOMAIN" && -n "$CERT_FILE" && -n "$KEY_FILE" ]] || die "cannot derive TLS settings from existing config"
  ACME_MODE=$(detect_acme_mode)
  CF_ZONE_NAME=${CF_ZONE_NAME:-$DEFAULT_ZONE}
  CF_ZONE_ID=${CF_ZONE_ID:-}
  PUBLIC_IPV4=${PUBLIC_IPV4:-}
  if ! command -v msmtp >/dev/null 2>&1; then
    apt-get update
    apt-get install -y ca-certificates msmtp
  fi
  configure_smtp
  write_config
  install_self
  install_systemd_units
  verify_health
  write_status success adopted
  log "existing installation adopted without DNS changes or certificate re-issuance"
  confirm "Send the installation test email now?" && run_test_email || true
}

install_new() {
  local arch
  require_root
  arch=$(preflight_os)
  install_dependencies
  prompt_value CERT_DOMAIN "Trojan domain" "$DEFAULT_DOMAIN"
  prompt_value CF_ZONE_NAME "Cloudflare zone" "$DEFAULT_ZONE"
  PUBLIC_IPV4=${PUBLIC_IPV4:-$(curl -4fsS --proto '=https' --tlsv1.2 https://api.ipify.org)}
  public_ipv4 "$PUBLIC_IPV4" || die "not a supported public IPv4 address: $PUBLIC_IPV4"
  CERT_FILE="${TROJAN_TLS_DIR}/fullchain.pem"
  KEY_FILE="${TROJAN_TLS_DIR}/private.key"
  TROJAN_PORT=443
  ACME_MODE=dns
  install_secret "Cloudflare zone-scoped API token" "$CF_TOKEN_FILE" "${CERTMAN_CF_TOKEN_INPUT_FILE:-}"
  resolve_zone_id
  configure_smtp
  write_config
  download_manager "$arch"
  install_trojan_web_unit
  issue_dns_certificate
  cat <<EOF

The upstream Trojan initializer will now run interactively.
When asked for the certificate method, choose "custom certificate path" and enter:
  cert: ${CERT_FILE}
  key:  ${KEY_FILE}
  domain: ${CERT_DOMAIN}
Then finish MariaDB and first-user initialization.
EOF
  "$TROJAN_MANAGER_BIN"
  atomic_update_trojan_config
  systemctl restart trojan.service trojan-web.service
  install_self
  install_systemd_units
  verify_health
  write_status success installed
  run_test_email
  log "local service checks passed; DNS has not changed yet"
  confirm "Cut over ${CERT_DOMAIN} to ${PUBLIC_IPV4} now?" || die "installation is healthy, but DNS cutover was cancelled"
  cutover_dns
  log "installation and DNS cutover completed"
}

run_renew() {
  local before after web_was_active=0 token previous_state=unknown rc=0 stage=renewal
  require_root
  load_config
  require_command flock
  install -d -m 0755 "$(dirname "$LOCK_FILE")"
  exec 9>"$LOCK_FILE"
  flock -n 9 || die "another renewal is running"
  [[ -r "$CERT_FILE" ]] || { write_status failed missing-certificate; return 1; }
  [[ -r "$STATUS_FILE" ]] && previous_state=$(awk -F= '$1=="LAST_STATE" {print $2}' "$STATUS_FILE" | tr -d "'")
  before=$(certificate_fingerprint || true)

  cleanup_standalone_web() {
    if ((web_was_active == 1)); then
      systemctl start trojan-web.service >/dev/null 2>&1 || true
      web_was_active=0
    fi
  }

  if [[ "$ACME_MODE" == "standalone" ]]; then
    if openssl x509 -in "$CERT_FILE" -noout -checkend "$RENEW_WINDOW_SECONDS" >/dev/null 2>&1; then
      if ! verify_certificate_files || ! verify_services || ! verify_live_certificate; then
        write_status failed health-verification
        return 1
      fi
      write_status success not-due
      if [[ "$previous_state" == "failed" ]]; then
        send_recovery_email
      fi
      log "certificate is outside the standalone renewal window"
      return 0
    fi
    systemctl is-active --quiet trojan-web.service && web_was_active=1
    if ((web_was_active == 1)); then
      trap cleanup_standalone_web EXIT
      systemctl stop trojan-web.service
    fi
  elif [[ "$ACME_MODE" == "dns" ]]; then
    [[ -s "$CF_TOKEN_FILE" ]] || { write_status failed missing-cloudflare-token; return 1; }
    token=$(<"$CF_TOKEN_FILE")
    export CF_Token="$token"
    unset token
  else
    write_status failed unknown-acme-mode
    return 1
  fi

  set +e
  "$ACME_BIN" --cron --home "$ACME_HOME"
  rc=$?
  set -e
  cleanup_standalone_web
  trap - EXIT
  unset CF_Token 2>/dev/null || true
  if ((rc != 0)); then
    write_status failed "$stage"
    return "$rc"
  fi
  after=$(certificate_fingerprint || true)
  if [[ -n "$before" && -n "$after" && "$before" != "$after" ]]; then
    systemctl restart trojan.service
  fi
  if ! verify_certificate_files || ! verify_services || ! verify_live_certificate; then
    write_status failed health-verification
    return 1
  fi
  write_status success verified
  if [[ "$previous_state" == "failed" ]]; then
    send_recovery_email
  fi
  log "renewal check and health verification succeeded"
}

send_failure_alert() {
  local unit=${1:-trojan-certman-renew.service} last_alert=0 now stage=unknown enddate=unknown
  load_config
  [[ -r "$STATUS_FILE" ]] && {
    last_alert=$(awk -F= '$1=="LAST_ALERT_EPOCH" {print $2}' "$STATUS_FILE" 2>/dev/null || printf 0)
    stage=$(awk -F= '$1=="LAST_STAGE" {print $2}' "$STATUS_FILE" 2>/dev/null | tr -d "'" || printf unknown)
  }
  now=$(date +%s)
  ((now - ${last_alert:-0} >= 86400)) || { log "failure email suppressed by 24-hour throttle"; return 0; }
  [[ -r "$CERT_FILE" ]] && enddate=$(certificate_enddate || printf unknown)
  send_email "[trojan-certman] FAILED: ${CERT_DOMAIN}" \
    "Host: $(hostname -f 2>/dev/null || hostname)\nDomain: ${CERT_DOMAIN}\nUnit: ${unit}\nStage: ${stage}\nCertificate expiry: ${enddate}\nInspect with: journalctl -u trojan-certman-renew.service" || return 1
  update_alert_epoch
}

show_status() {
  local live_cert live_expiry=unavailable live_fingerprint=unavailable
  load_config
  live_cert=$(mktemp)
  if capture_live_certificate "$live_cert"; then
    live_expiry=$(openssl x509 -in "$live_cert" -noout -enddate 2>/dev/null | cut -d= -f2-)
    live_fingerprint=$(openssl x509 -in "$live_cert" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2-)
  fi
  rm -f "$live_cert"
  printf 'domain: %s\n' "$CERT_DOMAIN"
  printf 'dns A: %s\n' "$(dig +short A "$CERT_DOMAIN" | paste -sd, -)"
  printf 'acme mode: %s\n' "$ACME_MODE"
  printf 'certificate file: %s\n' "$CERT_FILE"
  printf 'disk certificate expiry: %s\n' "$(certificate_enddate || printf unavailable)"
  printf 'disk certificate fingerprint: %s\n' "$(certificate_fingerprint || printf unavailable)"
  printf 'live certificate expiry: %s\n' "$live_expiry"
  printf 'live certificate fingerprint: %s\n' "$live_fingerprint"
  printf 'trojan.service: %s\n' "$(systemctl is-active trojan.service 2>/dev/null || true)"
  printf 'trojan-web.service: %s\n' "$(systemctl is-active trojan-web.service 2>/dev/null || true)"
  printf 'renew timer: %s\n' "$(systemctl is-enabled trojan-certman-renew.timer 2>/dev/null || true)"
  systemctl list-timers trojan-certman-renew.timer --no-pager 2>/dev/null || true
  [[ -r "$STATUS_FILE" ]] && sed -n '1,4p' "$STATUS_FILE"
}

uninstall_automation() {
  require_root
  confirm "Remove certman automation and its saved credentials (Trojan and certificates stay untouched)?" || die "uninstall cancelled"
  systemctl disable --now trojan-certman-renew.timer 2>/dev/null || true
  rm -f "${SYSTEMD_DIR}/trojan-certman-renew.service" \
    "${SYSTEMD_DIR}/trojan-certman-renew.timer" \
    "${SYSTEMD_DIR}/trojan-certman-alert@.service"
  systemctl daemon-reload
  rm -f "$INSTALLED_BIN"
  rm -rf -- "$CONFIG_DIR" "$STATE_DIR"
  log "certman automation removed; Trojan, MariaDB and certificate files were not changed"
}

main() {
  case "${1:-help}" in
    install) install_new ;;
    adopt) adopt_existing ;;
    status) show_status ;;
    renew) run_renew ;;
    test-email) run_test_email ;;
    alert) send_failure_alert "${2:-trojan-certman-renew.service}" ;;
    dns-rollback) require_root; rollback_dns ;;
    uninstall-automation) uninstall_automation ;;
    help|-h|--help) usage ;;
    version|--version) printf '%s %s\n' "$PROGRAM" "$PROGRAM_VERSION" ;;
    *) usage >&2; exit 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
