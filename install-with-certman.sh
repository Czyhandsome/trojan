#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

PROGRAM="trojan-certman"
PROGRAM_VERSION="3.0.0"

XRAY_VERSION="v26.3.27"
XRAY_AMD64_SHA256="23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
XRAY_ARM64_SHA256="4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c"
XRAY_RELEASE_BASE="https://github.com/XTLS/Xray-core/releases/download"
ACME_VERSION="3.1.4"
ACME_COMMIT="3661fd86b6304115e42f43910e6dd452ab9866d6"
ACME_TARBALL_SHA256="9af3ad3d775a5782246df4cdd4b4e7b9b3179deb63c509b10e3ba0433093a884"
ACME_SCRIPT_SHA256="8a32aeb017c71929e3f5b9ad804ced2b629e2b28ea50797fb2f8e7678e681997"
ACME_TARBALL_URL="https://codeload.github.com/acmesh-official/acme.sh/tar.gz/3661fd86b6304115e42f43910e6dd452ab9866d6"

CONFIG_DIR=${CERTMAN_CONFIG_DIR:-/etc/trojan-certman-v3}
CONFIG_FILE=${CERTMAN_CONFIG_FILE:-${CONFIG_DIR}/config}
SECRETS_DIR=${CERTMAN_SECRETS_DIR:-${CONFIG_DIR}/secrets}
PASSWORD_FILE=${CERTMAN_PASSWORD_FILE:-${SECRETS_DIR}/trojan-password}
CF_TOKEN_FILE=${CERTMAN_CF_TOKEN_FILE:-${SECRETS_DIR}/cloudflare-token}
STATE_DIR=${CERTMAN_STATE_DIR:-/var/lib/trojan-certman-v3}
STATUS_FILE=${CERTMAN_STATUS_FILE:-${STATE_DIR}/status}
ROLLBACK_ROOT=${CERTMAN_ROLLBACK_ROOT:-${STATE_DIR}/rollback}
LEGACY_MIGRATION_DIR=${CERTMAN_LEGACY_MIGRATION_DIR:-${STATE_DIR}/legacy-migration}
LOCK_FILE=${CERTMAN_LOCK_FILE:-/run/lock/trojan-certman-v3.lock}

XRAY_CONFIG_DIR=${CERTMAN_XRAY_CONFIG_DIR:-/etc/xray}
XRAY_CONFIG=${CERTMAN_XRAY_CONFIG:-${XRAY_CONFIG_DIR}/config.json}
XRAY_TLS_ROOT=${CERTMAN_XRAY_TLS_ROOT:-${XRAY_CONFIG_DIR}/tls}
XRAY_TLS_VERSIONS=${CERTMAN_XRAY_TLS_VERSIONS:-${XRAY_TLS_ROOT}/versions}
XRAY_TLS_CURRENT=${CERTMAN_XRAY_TLS_CURRENT:-${XRAY_TLS_ROOT}/current}
XRAY_TLS_PREVIOUS=${CERTMAN_XRAY_TLS_PREVIOUS:-${XRAY_TLS_ROOT}/previous}
XRAY_INSTALL_ROOT=${CERTMAN_XRAY_INSTALL_ROOT:-/usr/local/lib/xray}
XRAY_VERSIONS_DIR=${CERTMAN_XRAY_VERSIONS_DIR:-${XRAY_INSTALL_ROOT}/versions}
XRAY_CURRENT=${CERTMAN_XRAY_CURRENT:-${XRAY_INSTALL_ROOT}/current}
XRAY_PREVIOUS=${CERTMAN_XRAY_PREVIOUS:-${XRAY_INSTALL_ROOT}/previous}
XRAY_BIN=${CERTMAN_XRAY_BIN:-/usr/local/bin/xray}
SYSTEMD_DIR=${CERTMAN_SYSTEMD_DIR:-/etc/systemd/system}
SYSCTL_FILE=${CERTMAN_SYSCTL_FILE:-/etc/sysctl.d/90-trojan-xray-capacity.conf}
INSTALLED_BIN=${CERTMAN_INSTALLED_BIN:-/usr/local/sbin/trojan-certman}
STAGED_BIN=${CERTMAN_STAGED_BIN:-/usr/local/sbin/trojan-certman-v3}
ASSET_DIR=${CERTMAN_ASSET_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/asset}

ACME_HOME=${CERTMAN_ACME_HOME:-/root/.acme.sh}
ACME_BIN=${CERTMAN_ACME_BIN:-${ACME_HOME}/acme.sh}
LEGACY_CONFIG=${CERTMAN_LEGACY_CONFIG:-/usr/local/etc/trojan/config.json}
MIN_VALID_SECONDS=$((14 * 24 * 60 * 60))

log() { printf '[%s] %s\n' "$PROGRAM" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$PROGRAM" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  install-with-certman.sh install
  trojan-certman adopt
  trojan-certman renew
  trojan-certman status
  trojan-certman deploy-cert CERT_FILE KEY_FILE
  trojan-certman snapshot
  trojan-certman upgrade VERSION SHA256
  trojan-certman cutover
  trojan-certman rollback

Provisioning inputs are passed as readable files, never as secret command
arguments. install requires CERTMAN_PASSWORD_INPUT_FILE and
CERTMAN_CF_TOKEN_INPUT_FILE. adopt requires only the password input file and
does not read the password from the legacy configuration.
EOF
}

require_root() {
  [[ ${CERTMAN_SKIP_ROOT_CHECK:-0} == 1 ]] && return
  [[ $(id -u) == 0 ]] || die 'run as root'
}

normalize_arch() {
  case $1 in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) return 1 ;;
  esac
}

xray_asset_for_arch() {
  case $1 in
    amd64) printf 'Xray-linux-64.zip\n' ;;
    arm64) printf 'Xray-linux-arm64-v8a.zip\n' ;;
    *) return 1 ;;
  esac
}

xray_sha_for_arch() {
  case $1 in
    amd64) printf '%s\n' "$XRAY_AMD64_SHA256" ;;
    arm64) printf '%s\n' "$XRAY_ARM64_SHA256" ;;
    *) return 1 ;;
  esac
}

safe_chown() {
  [[ ${CERTMAN_SKIP_CHOWN:-0} == 1 ]] && return 0
  chown "$@"
}

atomic_symlink() {
  local target=$1 link=$2 temp
  install -d -m 0755 "$(dirname "$link")"
  temp="${link}.new.$$"
  rm -f -- "$temp"
  ln -s "$target" "$temp"
  if mv --help >/dev/null 2>&1; then mv -Tf "$temp" "$link"; else mv -fh "$temp" "$link"; fi
}

read_link_or_empty() {
  if [[ -L $1 ]]; then readlink "$1"; fi
}

install_secret_file() {
  local target=$1 input=$2 temp
  [[ -f $input ]] || die 'password input file not found'
  install -d -m 0700 "$SECRETS_DIR"
  temp=$(mktemp "${SECRETS_DIR}/.secret.XXXXXX")
  chmod 0600 "$temp"
  tr -d '\r\n' <"$input" >"$temp"
  [[ -s $temp ]] || { rm -f -- "$temp"; die 'password input file is empty'; }
  mv -f "$temp" "$target"
  chmod 0600 "$target"
  safe_chown root:root "$target" 2>/dev/null || true
}

write_config() {
  local temp
  install -d -m 0755 "$CONFIG_DIR"
  temp=$(mktemp "${CONFIG_DIR}/.config.XXXXXX")
  {
    printf 'CERT_DOMAIN=%q\n' "$CERT_DOMAIN"
    printf 'TROJAN_PORT=%q\n' "$TROJAN_PORT"
    printf 'ACME_CERT_FILE=%q\n' "${ACME_CERT_FILE:-${ACME_HOME}/${CERT_DOMAIN}_ecc/fullchain.cer}"
    printf 'ACME_KEY_FILE=%q\n' "${ACME_KEY_FILE:-${ACME_HOME}/${CERT_DOMAIN}_ecc/${CERT_DOMAIN}.key}"
  } >"$temp"
  chmod 0644 "$temp"
  mv -f "$temp" "$CONFIG_FILE"
}

load_config() {
  [[ -r $CONFIG_FILE ]] || die "configuration not found: $CONFIG_FILE"
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
}

write_status() {
  local state=$1 stage=$2 temp
  install -d -m 0755 "$STATE_DIR"
  temp=$(mktemp "${STATE_DIR}/.status.XXXXXX")
  printf 'LAST_STATE=%q\nLAST_STAGE=%q\nLAST_RUN_EPOCH=%q\n' "$state" "$stage" "$(date +%s)" >"$temp"
  chmod 0644 "$temp"
  mv -f "$temp" "$STATUS_FILE"
}

write_xray_config() {
  local temp
  [[ -s $PASSWORD_FILE ]] || die 'Trojan password file is missing'
  install -d -m 0750 "$XRAY_CONFIG_DIR"
  safe_chown root:xray "$XRAY_CONFIG_DIR" 2>/dev/null || true
  temp=$(mktemp "${XRAY_CONFIG_DIR}/.config.XXXXXX")
  jq -n --rawfile password "$PASSWORD_FILE" --arg domain "$CERT_DOMAIN" --argjson port "$TROJAN_PORT" \
    --arg cert "${XRAY_TLS_CURRENT}/fullchain.pem" --arg key "${XRAY_TLS_CURRENT}/private.key" '
    {log:{loglevel:"warning"},inbounds:[{
      listen:(if $port == 18443 then "127.0.0.1" else "0.0.0.0" end),port:$port,protocol:"trojan",
      settings:{clients:[{password:($password | rtrimstr("\n"))}]},
      streamSettings:{network:"tcp",security:"tls",tlsSettings:{serverName:$domain,minVersion:"1.2",
        certificates:[{certificateFile:$cert,keyFile:$key}]}}
    }],
    routing:{domainStrategy:"IPIfNonMatch",rules:[{
      type:"field",outboundTag:"blocked",
      ip:["0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16",
          "172.16.0.0/12","192.0.0.0/24","192.168.0.0/16","198.18.0.0/15","224.0.0.0/4","240.0.0.0/4",
          "::/128","::1/128","fc00::/7","fe80::/10","ff00::/8"]
    }]},
    outbounds:[{protocol:"freedom",tag:"direct"},{protocol:"blackhole",tag:"blocked"}]}' >"$temp"
  [[ $(jq '.inbounds[0].settings.clients | length' "$temp") == 1 ]] || die 'Xray config must contain exactly one client'
  [[ $(jq -r '.inbounds[0].settings.fallbacks // empty' "$temp") == '' ]] || die 'Trojan fallbacks are forbidden'
  [[ $(jq '[.routing.rules[] | select(.outboundTag == "blocked") | .ip[] | select(. == "100.64.0.0/10")] | length' "$temp") == 1 ]] \
    || die 'cloud metadata and private destinations must be blocked'
  chmod 0640 "$temp"
  safe_chown root:xray "$temp" 2>/dev/null || true
  mv -f "$temp" "$XRAY_CONFIG"
}

certificate_fingerprint_file() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2-
}

certificate_enddate_file() { openssl x509 -in "$1" -noout -enddate 2>/dev/null | cut -d= -f2-; }

verify_certificate_pair() {
  local cert=$1 key=$2 domain=$3 cert_pub key_pub
  [[ -r $cert && -r $key ]] || return 1
  openssl x509 -in "$cert" -noout -checkend "$MIN_VALID_SECONDS" >/dev/null 2>&1 || return 1
  openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null \
    | tr ',' '\n' \
    | sed -E 's/^[[:space:]]+//' \
    | grep -Fxq "DNS:$domain" || return 1
  cert_pub=$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  key_pub=$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  [[ -n $cert_pub && $cert_pub == "$key_pub" ]]
}

current_cert_file() { printf '%s/fullchain.pem\n' "$XRAY_TLS_CURRENT"; }
current_key_file() { printf '%s/private.key\n' "$XRAY_TLS_CURRENT"; }

verify_live_certificate() {
  local expected live temp
  expected=$(current_cert_file)
  temp=$(mktemp)
  if ! timeout 15 openssl s_client -connect "127.0.0.1:${TROJAN_PORT}" -servername "$CERT_DOMAIN" </dev/null 2>/dev/null \
      | openssl x509 -outform PEM >"$temp" 2>/dev/null; then
    rm -f -- "$temp"
    return 1
  fi
  live=$(certificate_fingerprint_file "$temp")
  rm -f -- "$temp"
  [[ $live == "$(certificate_fingerprint_file "$expected")" ]]
}

xray_config_test() {
  local binary=${1:-$XRAY_BIN} config=${2:-$XRAY_CONFIG}
  "$binary" run -test -config "$config" >/dev/null
}

candidate_config_test() {
  local cert=$1 key=$2 temp temp_base
  temp_base=$(mktemp "${XRAY_CONFIG_DIR}/.candidate.XXXXXX")
  temp="${temp_base}.json"
  mv "$temp_base" "$temp"
  jq --arg cert "$cert" --arg key "$key" \
    '.inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile=$cert |
     .inbounds[0].streamSettings.tlsSettings.certificates[0].keyFile=$key' "$XRAY_CONFIG" >"$temp"
  chmod 0600 "$temp"
  if ! xray_config_test "$XRAY_BIN" "$temp"; then rm -f -- "$temp"; return 1; fi
  rm -f -- "$temp"
}

prepare_rollback() {
  local slot temp core_target cert_target previous_target
  install -d -m 0700 "$ROLLBACK_ROOT"
  temp=$(mktemp -d "${ROLLBACK_ROOT}/.snapshot.XXXXXX")
  core_target=$(read_link_or_empty "$XRAY_CURRENT")
  cert_target=$(read_link_or_empty "$XRAY_TLS_CURRENT")
  [[ -r $XRAY_CONFIG ]] && { cp "$XRAY_CONFIG" "$temp/config.json"; chmod 0600 "$temp/config.json"; }
  {
    printf 'CORE_TARGET=%q\n' "$core_target"
    printf 'CERT_TARGET=%q\n' "$cert_target"
    printf 'CONFIG_PRESENT=%q\n' "$([[ -r $XRAY_CONFIG ]] && printf 1 || printf 0)"
  } >"$temp/manifest"
  chmod 0600 "$temp/manifest"
  slot="${ROLLBACK_ROOT}/current"
  previous_target=$(read_link_or_empty "$slot")
  [[ -n $previous_target ]] && atomic_symlink "$previous_target" "${ROLLBACK_ROOT}/previous"
  atomic_symlink "$temp" "$slot"
}

restore_rollback_state() {
  local slot manifest
  slot=$(read_link_or_empty "${ROLLBACK_ROOT}/current")
  [[ -n $slot && -r $slot/manifest ]] || return 1
  manifest=$slot/manifest
  # shellcheck disable=SC1090
  source "$manifest"
  if [[ -n ${CORE_TARGET:-} ]]; then atomic_symlink "$CORE_TARGET" "$XRAY_CURRENT"; else rm -f -- "$XRAY_CURRENT"; fi
  if [[ -n ${CERT_TARGET:-} ]]; then atomic_symlink "$CERT_TARGET" "$XRAY_TLS_CURRENT"; else rm -f -- "$XRAY_TLS_CURRENT"; fi
  if [[ ${CONFIG_PRESENT:-0} == 1 ]]; then
    install -m 0640 "$slot/config.json" "$XRAY_CONFIG"
    safe_chown root:xray "$XRAY_CONFIG" 2>/dev/null || true
  else
    rm -f -- "$XRAY_CONFIG"
  fi
}

restart_and_verify_xray() {
  systemctl restart xray.service || return 1
  systemctl is-active --quiet xray.service || return 1
  verify_live_certificate
}

deploy_certificate_locked() {
  local source_cert=$1 source_key=$2 version_dir old_target fingerprint current_fingerprint stamp stage
  verify_certificate_pair "$source_cert" "$source_key" "$CERT_DOMAIN" || return 1
  fingerprint=$(certificate_fingerprint_file "$source_cert")
  if [[ -r $(current_cert_file) && -r $(current_key_file) ]]; then
    current_fingerprint=$(certificate_fingerprint_file "$(current_cert_file)" 2>/dev/null || true)
    if [[ -n $current_fingerprint && $current_fingerprint == "$fingerprint" ]] \
        && verify_certificate_pair "$(current_cert_file)" "$(current_key_file)" "$CERT_DOMAIN" \
        && xray_config_test && verify_live_certificate; then
      write_status success certificate-unchanged
      log 'certificate already deployed; no restart required'
      return 0
    fi
  fi
  install -d -m 0750 "$XRAY_TLS_ROOT" "$XRAY_TLS_VERSIONS"
  safe_chown root:xray "$XRAY_TLS_ROOT" "$XRAY_TLS_VERSIONS" 2>/dev/null || true
  fingerprint=$(printf '%s' "$fingerprint" | tr -d ':' | cut -c1-16)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  version_dir="${XRAY_TLS_VERSIONS}/${stamp}-${fingerprint}"
  [[ ! -e $version_dir ]] || version_dir="${version_dir}-$$"
  stage=$(mktemp -d "${XRAY_TLS_VERSIONS}/.stage.XXXXXX")
  install -m 0644 "$source_cert" "$stage/fullchain.pem"
  install -m 0640 "$source_key" "$stage/private.key"
  safe_chown -R root:xray "$stage" 2>/dev/null || true
  verify_certificate_pair "$stage/fullchain.pem" "$stage/private.key" "$CERT_DOMAIN" || { rm -rf -- "$stage"; return 1; }
  candidate_config_test "$stage/fullchain.pem" "$stage/private.key" || { rm -rf -- "$stage"; return 1; }
  prepare_rollback
  old_target=$(read_link_or_empty "$XRAY_TLS_CURRENT")
  mv "$stage" "$version_dir"
  [[ -n $old_target ]] && atomic_symlink "$old_target" "$XRAY_TLS_PREVIOUS"
  atomic_symlink "$version_dir" "$XRAY_TLS_CURRENT"
  if ! restart_and_verify_xray; then
    restore_rollback_state || true
    systemctl restart xray.service >/dev/null 2>&1 || true
    write_status failed certificate-rollback
    return 1
  fi
  write_status success certificate-deployed
  log 'certificate deployed and live fingerprint verified'
}

with_lock() {
  install -d -m 0755 "$(dirname "$LOCK_FILE")"
  exec 9>"$LOCK_FILE"
  flock -n 9 || die 'another certman operation is running'
  "$@"
}

deploy_certificate() {
  require_root
  [[ $# == 2 ]] || die 'usage: trojan-certman deploy-cert CERT_FILE KEY_FILE'
  load_config
  with_lock deploy_certificate_locked "$1" "$2"
}

download_xray_archive() {
  local version=$1 asset=$2 target=$3
  curl -fL --proto '=https' --tlsv1.2 "${XRAY_RELEASE_BASE}/${version}/${asset}" -o "$target"
}

xray_binary_matches_version() {
  local binary=$1 version=$2 output
  output=$("$binary" version 2>&1) || return 1
  [[ $output == *"${version#v}"* ]]
}

install_xray_release() {
  local version=$1 supplied_sha=$2 activate=${3:-1} arch asset expected stage archive extracted final old_target actual
  [[ $version == "$XRAY_VERSION" ]] || die "unsupported Xray version: $version"
  arch=$(normalize_arch "$(uname -m)") || die 'supported architectures: amd64, arm64'
  asset=$(xray_asset_for_arch "$arch")
  expected=$(xray_sha_for_arch "$arch")
  [[ $supplied_sha == "$expected" ]] || die 'Xray SHA-256 does not match the pinned release manifest'
  install -d -m 0755 "$XRAY_VERSIONS_DIR"
  final="${XRAY_VERSIONS_DIR}/${version}-${arch}"
  if [[ -e $final ]]; then
    [[ -x $final/xray && -r $final/.archive.sha256 ]] || die 'existing Xray version directory is incomplete'
    [[ $(<"$final/.archive.sha256") == "$expected" ]] || die 'existing Xray version directory has an untrusted checksum marker'
    xray_binary_matches_version "$final/xray" "$version" || die 'existing Xray binary version does not match'
  else
    stage=$(mktemp -d "${XRAY_VERSIONS_DIR}/.stage.XXXXXX")
    archive="$stage/$asset"
    extracted="$stage/root"
    download_xray_archive "$version" "$asset" "$archive"
    actual=$(sha256sum "$archive" | awk '{print $1}')
    [[ $actual == "$expected" ]] || { rm -rf -- "$stage"; die 'downloaded Xray archive checksum mismatch'; }
    install -d -m 0755 "$extracted"
    unzip -q "$archive" -d "$extracted"
    [[ -x $extracted/xray ]] || { rm -rf -- "$stage"; die 'Xray archive does not contain an executable xray'; }
    xray_binary_matches_version "$extracted/xray" "$version" \
      || { rm -rf -- "$stage"; die 'Xray binary version does not match requested version'; }
    rm -f -- "$archive"
    printf '%s\n' "$expected" >"$extracted/.archive.sha256"
    chmod 0644 "$extracted/.archive.sha256"
    mv "$extracted" "$final"
    rm -rf -- "$stage"
    safe_chown -R root:root "$final" 2>/dev/null || true
  fi
  ((activate == 1)) || return 0
  prepare_rollback
  old_target=$(read_link_or_empty "$XRAY_CURRENT")
  [[ -n $old_target ]] && atomic_symlink "$old_target" "$XRAY_PREVIOUS"
  atomic_symlink "$final" "$XRAY_CURRENT"
  install -d -m 0755 "$(dirname "$XRAY_BIN")"
  if [[ ! -L $XRAY_BIN || $(readlink "$XRAY_BIN") != "$XRAY_CURRENT/xray" ]]; then atomic_symlink "$XRAY_CURRENT/xray" "$XRAY_BIN"; fi
}

upgrade_xray() {
  local version=${1:-} supplied_sha=${2:-}
  require_root
  [[ -n $version && -n $supplied_sha && $# == 2 ]] || die 'usage: trojan-certman upgrade VERSION SHA256'
  load_config
  with_lock upgrade_xray_locked "$version" "$supplied_sha"
}

upgrade_xray_locked() {
  local version=$1 supplied_sha=$2
  install_xray_release "$version" "$supplied_sha" 1
  if ! xray_config_test || ! restart_and_verify_xray; then
    restore_rollback_state || true
    systemctl restart xray.service >/dev/null 2>&1 || true
    write_status failed upgrade-rollback
    return 1
  fi
  write_status success upgraded
  log "Xray upgraded to $version"
}

rollback() {
  require_root
  load_config
  if [[ -r $LEGACY_MIGRATION_DIR/manifest ]] && grep -Fxq 'CUTOVER_ACTIVE=1' "$LEGACY_MIGRATION_DIR/manifest"; then
    with_lock rollback_legacy_locked
  else
    with_lock rollback_locked
  fi
}

rollback_locked() {
  restore_rollback_state || die 'no rollback snapshot is available'
  xray_config_test || die 'restored Xray configuration is invalid'
  restart_and_verify_xray || die 'restored Xray state failed health verification'
  write_status success rolled-back
  log 'previous core, configuration and certificate restored'
}

install_pinned_acme() {
  local stage archive actual source installed_sha
  if [[ -x $ACME_BIN ]]; then
    installed_sha=$(sha256sum "$ACME_BIN" | awk '{print $1}')
    if [[ $installed_sha == "$ACME_SCRIPT_SHA256" ]] \
        && "$ACME_BIN" --version 2>/dev/null | grep -Fq "$ACME_VERSION"; then
      return 0
    fi
  fi
  stage=$(mktemp -d)
  archive="$stage/acme.tar.gz"
  curl -fL --proto '=https' --tlsv1.2 "$ACME_TARBALL_URL" -o "$archive"
  actual=$(sha256sum "$archive" | awk '{print $1}')
  [[ $actual == "$ACME_TARBALL_SHA256" ]] || { rm -rf -- "$stage"; die 'acme.sh tarball checksum mismatch'; }
  tar -xzf "$archive" -C "$stage"
  source="$stage/acme.sh-${ACME_COMMIT}"
  [[ -x $source/acme.sh ]] || { rm -rf -- "$stage"; die 'acme.sh archive layout mismatch'; }
  (cd "$source" && ./acme.sh --install --home "$ACME_HOME" --no-cron --no-profile)
  rm -rf -- "$stage"
  [[ -x $ACME_BIN ]] || die 'pinned acme.sh installation failed'
  installed_sha=$(sha256sum "$ACME_BIN" | awk '{print $1}')
  [[ $installed_sha == "$ACME_SCRIPT_SHA256" ]] || die 'installed acme.sh script checksum mismatch'
}

issue_certificate_dns() {
  [[ -s $CF_TOKEN_FILE ]] || die 'Cloudflare token file is missing'
  CF_Token=$(tr -d '\r\n' <"$CF_TOKEN_FILE") "$ACME_BIN" --issue --dns dns_cf \
    -d "$CERT_DOMAIN" --server letsencrypt --keylength ec-256
  ACME_CERT_FILE="${ACME_HOME}/${CERT_DOMAIN}_ecc/fullchain.cer"
  ACME_KEY_FILE="${ACME_HOME}/${CERT_DOMAIN}_ecc/${CERT_DOMAIN}.key"
  verify_certificate_pair "$ACME_CERT_FILE" "$ACME_KEY_FILE" "$CERT_DOMAIN" \
    || die 'issued certificate failed local validation'
}

clear_acme_legacy_deploy_state() {
  "$ACME_BIN" --install-cert --home "$ACME_HOME" -d "$CERT_DOMAIN" --ecc --reloadcmd ''
}

run_renew() { require_root; load_config; with_lock run_renew_locked; }

run_renew_locked() {
  local before after rc
  [[ -x $ACME_BIN ]] || { write_status failed missing-acme; return 1; }
  before=$(certificate_fingerprint_file "$(current_cert_file)" 2>/dev/null || true)
  set +e
  "$ACME_BIN" --cron --home "$ACME_HOME"
  rc=$?
  set -e
  ((rc == 0)) || { write_status failed renewal; return "$rc"; }
  [[ -r $ACME_CERT_FILE && -r $ACME_KEY_FILE ]] || { write_status success not-due; return 0; }
  after=$(certificate_fingerprint_file "$ACME_CERT_FILE" 2>/dev/null || true)
  if [[ -n $after && $after != "$before" ]]; then
    deploy_certificate_locked "$ACME_CERT_FILE" "$ACME_KEY_FILE" || return 1
  else
    verify_certificate_pair "$(current_cert_file)" "$(current_key_file)" "$CERT_DOMAIN" || { write_status failed certificate-health; return 1; }
    verify_live_certificate || { write_status failed live-health; return 1; }
    write_status success not-due
  fi
  log 'renewal check completed without forced issuance'
}

netstat_counter() {
  local key=$1
  awk -v wanted="$key" '/^TcpExt:/ {if (header == "") {header=$0; next} n=split(header,h); split($0,v); for (i=2; i<=n; i++) if (h[i] == wanted) {print v[i]; exit}}' /proc/net/netstat 2>/dev/null || true
}

tls_probe() {
  local started ended elapsed temp expiry fingerprint
  temp=$(mktemp)
  started=$(date +%s%3N 2>/dev/null || date +%s000)
  if timeout 15 openssl s_client -connect "127.0.0.1:${TROJAN_PORT}" -servername "$CERT_DOMAIN" </dev/null 2>/dev/null \
      | openssl x509 -outform PEM >"$temp" 2>/dev/null; then
    ended=$(date +%s%3N 2>/dev/null || date +%s000)
    elapsed=$((ended - started))
    expiry=$(certificate_enddate_file "$temp")
    fingerprint=$(certificate_fingerprint_file "$temp")
    printf '%s|%s|%s\n' "$elapsed" "$expiry" "$fingerprint"
  else
    printf 'unavailable|unavailable|unavailable\n'
  fi
  rm -f -- "$temp"
}

snapshot() {
  local active restarts pid fd_used=0 fd_limit=0 queue=unavailable conntrack=unavailable conntrack_max=unavailable
  local drops overflows syncookies tls_ms expiry fingerprint probe somaxconn backlog_note=ok
  load_config
  active=$(systemctl is-active xray.service 2>/dev/null || true)
  restarts=$(systemctl show xray.service -p NRestarts --value 2>/dev/null || printf unavailable)
  pid=$(systemctl show xray.service -p MainPID --value 2>/dev/null || printf 0)
  if [[ $pid =~ ^[0-9]+$ && $pid -gt 0 && -d /proc/$pid/fd ]]; then
    fd_used=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')
    fd_limit=$(awk '$1=="Max" && $2=="open" && $3=="files" {print $4}' "/proc/$pid/limits" 2>/dev/null || printf 0)
  fi
  command -v ss >/dev/null 2>&1 && queue=$(ss -lntH "sport = :${TROJAN_PORT}" 2>/dev/null | awk 'NR==1 {print $2 "/" $3}' || true)
  [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]] && conntrack=$(</proc/sys/net/netfilter/nf_conntrack_count)
  [[ -r /proc/sys/net/netfilter/nf_conntrack_max ]] && conntrack_max=$(</proc/sys/net/netfilter/nf_conntrack_max)
  drops=$(netstat_counter ListenDrops); drops=${drops:-unavailable}
  overflows=$(netstat_counter ListenOverflows); overflows=${overflows:-unavailable}
  syncookies=$(netstat_counter SyncookiesSent); syncookies=${syncookies:-unavailable}
  somaxconn=$(sysctl -n net.core.somaxconn 2>/dev/null || printf unavailable)
  [[ $queue == */128 ]] && backlog_note=core-fixed-128
  probe=$(tls_probe)
  IFS='|' read -r tls_ms expiry fingerprint <<<"$probe"
  printf 'service=%s restarts=%s fd=%s/%s listen_queue=%s somaxconn=%s backlog_note=%s conntrack=%s/%s listen_drops=%s listen_overflows=%s syncookies=%s tls_ms=%s cert_expiry=%q cert_sha256=%s\n' \
    "${active:-unknown}" "${restarts:-unknown}" "$fd_used" "$fd_limit" "${queue:-unavailable}" "$somaxconn" "$backlog_note" \
    "$conntrack" "$conntrack_max" "$drops" "$overflows" "$syncookies" "$tls_ms" "$expiry" "$fingerprint"
}

show_status() {
  snapshot
  [[ -r $STATUS_FILE ]] && sed -n '1,3p' "$STATUS_FILE"
  systemctl is-enabled trojan-certman-renew.timer 2>/dev/null || true
  systemctl is-enabled trojan-certman-snapshot.timer 2>/dev/null || true
}

install_systemd_units() {
  local unit
  for unit in xray.service trojan-certman-renew.service trojan-certman-renew.timer trojan-certman-snapshot.service trojan-certman-snapshot.timer; do
    [[ -r $ASSET_DIR/$unit ]] || die "missing systemd asset: $ASSET_DIR/$unit"
    install -m 0644 "$ASSET_DIR/$unit" "$SYSTEMD_DIR/$unit"
  done
  systemctl daemon-reload
  systemctl enable trojan-certman-renew.timer trojan-certman-snapshot.timer
}

install_xray_unit() {
  [[ -r $ASSET_DIR/xray.service ]] || die "missing systemd asset: $ASSET_DIR/xray.service"
  install -m 0644 "$ASSET_DIR/xray.service" "$SYSTEMD_DIR/xray.service"
  systemctl daemon-reload
}

configure_capacity() {
  local temp
  install -d -m 0755 "$(dirname "$SYSCTL_FILE")" "$STATE_DIR"
  if [[ ! -r $STATE_DIR/sysctl-before ]]; then
    {
      printf 'net.core.somaxconn=%s\n' "$(sysctl -n net.core.somaxconn)"
      printf 'net.ipv4.tcp_max_syn_backlog=%s\n' "$(sysctl -n net.ipv4.tcp_max_syn_backlog)"
    } >"$STATE_DIR/sysctl-before"
    chmod 0600 "$STATE_DIR/sysctl-before"
  fi
  temp=$(mktemp "$(dirname "$SYSCTL_FILE")/.trojan-xray.XXXXXX")
  {
    printf '# Managed by trojan-certman; restore sysctl-before to roll back.\n'
    printf 'net.core.somaxconn = 4096\n'
    printf 'net.ipv4.tcp_max_syn_backlog = 4096\n'
  } >"$temp"
  chmod 0644 "$temp"
  mv -f "$temp" "$SYSCTL_FILE"
  sysctl -p "$SYSCTL_FILE" >/dev/null
}

install_self() {
  local source target=${1:-$INSTALLED_BIN}
  source=$(readlink -f "${BASH_SOURCE[0]}")
  install -d -m 0755 "$(dirname "$target")"
  install -m 0755 "$source" "$target"
}

create_xray_user() {
  getent group xray >/dev/null 2>&1 || groupadd --system xray
  id xray >/dev/null 2>&1 || useradd --system --gid xray --home-dir /nonexistent --shell /usr/sbin/nologin xray
}

install_dependencies() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl iproute2 jq openssl procps unzip util-linux
}

preflight_os() {
  local version
  [[ -r /etc/os-release ]] || die 'unsupported OS'
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ ${ID:-} == ubuntu ]] || die 'Ubuntu is required'
  version=${VERSION_ID:-}
  [[ $version == 22.04 || $version == 24.04 ]] || die 'Ubuntu 22.04 or 24.04 is required'
  normalize_arch "$(uname -m)" >/dev/null || die 'supported architectures: amd64, arm64'
}

install_new() {
  local arch sha
  require_root
  preflight_os
  install_dependencies
  create_xray_user
  [[ -n ${CERT_DOMAIN:-} ]] || die 'CERT_DOMAIN is required'
  TROJAN_PORT=${TROJAN_PORT:-443}
  [[ $TROJAN_PORT == 443 ]] || die 'personal-node install listens on port 443'
  [[ -n ${CERTMAN_PASSWORD_INPUT_FILE:-} && -n ${CERTMAN_CF_TOKEN_INPUT_FILE:-} ]] \
    || die 'password and Cloudflare token input files are required'
  if ss -lntH 'sport = :443' 2>/dev/null | grep -q .; then die 'port 443 is already in use'; fi
  install_secret_file "$PASSWORD_FILE" "$CERTMAN_PASSWORD_INPUT_FILE"
  install_secret_file "$CF_TOKEN_FILE" "$CERTMAN_CF_TOKEN_INPUT_FILE"
  arch=$(normalize_arch "$(uname -m)")
  sha=$(xray_sha_for_arch "$arch")
  install_xray_release "$XRAY_VERSION" "$sha" 1
  install_pinned_acme
  issue_certificate_dns
  clear_acme_legacy_deploy_state
  write_config
  write_xray_config
  install_self
  install_systemd_units
  configure_capacity
  deploy_certificate "$ACME_CERT_FILE" "$ACME_KEY_FILE"
  systemctl enable xray.service
  systemctl start trojan-certman-renew.timer trojan-certman-snapshot.timer
  log 'personal Xray Trojan node installed'
}

derive_legacy_tls() {
  [[ -r $LEGACY_CONFIG ]] || die "legacy Trojan config not found: $LEGACY_CONFIG"
  CERT_DOMAIN=$(jq -r '.ssl.sni // empty' "$LEGACY_CONFIG")
  LEGACY_CERT_FILE=$(jq -r '.ssl.cert // empty' "$LEGACY_CONFIG")
  LEGACY_KEY_FILE=$(jq -r '.ssl.key // empty' "$LEGACY_CONFIG")
  [[ -n $CERT_DOMAIN && -r $LEGACY_CERT_FILE && -r $LEGACY_KEY_FILE ]] || die 'cannot derive legacy TLS settings'
}

adopt_existing() {
  local arch sha
  require_root
  [[ -n ${CERTMAN_PASSWORD_INPUT_FILE:-} ]] || die 'adopt requires CERTMAN_PASSWORD_INPUT_FILE; legacy password is not read automatically'
  preflight_os
  install_dependencies
  create_xray_user
  derive_legacy_tls
  TROJAN_PORT=18443
  install_secret_file "$PASSWORD_FILE" "$CERTMAN_PASSWORD_INPUT_FILE"
  write_config
  write_xray_config
  arch=$(normalize_arch "$(uname -m)") || die 'supported architectures: amd64, arm64'
  sha=$(xray_sha_for_arch "$arch")
  install_xray_release "$XRAY_VERSION" "$sha" 1
  install_self "$STAGED_BIN"
  install_xray_unit
  deploy_certificate "$LEGACY_CERT_FILE" "$LEGACY_KEY_FILE"
  systemctl enable xray.service
  log "legacy TLS adopted; Xray canary listens only on 127.0.0.1:18443; staged CLI: $STAGED_BIN"
}

service_is_active() { systemctl is-active --quiet "$1" && printf 1 || printf 0; }
service_is_enabled() { systemctl is-enabled --quiet "$1" && printf 1 || printf 0; }

copy_if_present() {
  local source=$1 target_dir=$2
  [[ -e $source || -L $source ]] || return 0
  install -d -m 0700 "$target_dir"
  cp -a "$source" "$target_dir/"
}

prepare_legacy_migration() {
  local temp unit
  if [[ -r $LEGACY_MIGRATION_DIR/manifest ]] && grep -Fxq 'CUTOVER_ACTIVE=0' "$LEGACY_MIGRATION_DIR/manifest"; then return 0; fi
  [[ ! -e $LEGACY_MIGRATION_DIR ]] || die "active legacy migration snapshot already exists: $LEGACY_MIGRATION_DIR"
  temp=$(mktemp -d "${STATE_DIR}/.legacy-migration.XXXXXX")
  chmod 0700 "$temp"
  install -d -m 0700 "$temp/files/bin" "$temp/files/systemd" "$temp/files/sysctl"
  cp -a "$XRAY_CONFIG" "$temp/xray-canary.json"
  cp -a "$CONFIG_FILE" "$temp/certman-canary.config"
  copy_if_present "$INSTALLED_BIN" "$temp/files/bin"
  copy_if_present "$SYSCTL_FILE" "$temp/files/sysctl"
  [[ -d $ACME_HOME ]] && cp -a "$ACME_HOME" "$temp/files/acme-home"
  for unit in trojan-certman-renew.service trojan-certman-renew.timer trojan-certman-alert@.service \
      trojan-certman-snapshot.service trojan-certman-snapshot.timer; do
    copy_if_present "$SYSTEMD_DIR/$unit" "$temp/files/systemd"
  done
  {
    printf 'CUTOVER_ACTIVE=0\n'
    printf 'TROJAN_ACTIVE=%q\n' "$(service_is_active trojan.service)"
    printf 'TROJAN_ENABLED=%q\n' "$(service_is_enabled trojan.service)"
    printf 'WEB_ACTIVE=%q\n' "$(service_is_active trojan-web.service)"
    printf 'WEB_ENABLED=%q\n' "$(service_is_enabled trojan-web.service)"
    printf 'RENEW_ACTIVE=%q\n' "$(service_is_active trojan-certman-renew.timer)"
    printf 'RENEW_ENABLED=%q\n' "$(service_is_enabled trojan-certman-renew.timer)"
    printf 'SOMAXCONN=%q\n' "$(sysctl -n net.core.somaxconn)"
    printf 'SYN_BACKLOG=%q\n' "$(sysctl -n net.ipv4.tcp_max_syn_backlog)"
    printf 'HAD_SYSCTL_FILE=%q\n' "$([[ -e $SYSCTL_FILE ]] && printf 1 || printf 0)"
    printf 'HAD_ACME_HOME=%q\n' "$([[ -d $ACME_HOME ]] && printf 1 || printf 0)"
    printf 'LEGACY_CONFIG_MODE=%q\n' "$(stat -c %a "$LEGACY_CONFIG" 2>/dev/null || printf unknown)"
  } >"$temp/manifest"
  chmod 0600 "$temp/manifest"
  mv "$temp" "$LEGACY_MIGRATION_DIR"
}

set_cutover_marker() {
  local value=$1 temp
  temp=$(mktemp "${LEGACY_MIGRATION_DIR}/.manifest.XXXXXX")
  awk -F= -v value="$value" '$1=="CUTOVER_ACTIVE" {$0="CUTOVER_ACTIVE=" value} {print}' \
    "$LEGACY_MIGRATION_DIR/manifest" >"$temp"
  chmod 0600 "$temp"
  mv -f "$temp" "$LEGACY_MIGRATION_DIR/manifest"
}

restore_legacy_units() {
  local unit saved_dir=$LEGACY_MIGRATION_DIR/files/systemd
  for unit in trojan-certman-renew.service trojan-certman-renew.timer trojan-certman-alert@.service \
      trojan-certman-snapshot.service trojan-certman-snapshot.timer; do
    if [[ -e $saved_dir/$unit ]]; then
      cp -a "$saved_dir/$unit" "$SYSTEMD_DIR/$unit"
    else
      rm -f -- "$SYSTEMD_DIR/$unit"
    fi
  done
  if [[ -e $LEGACY_MIGRATION_DIR/files/bin/$(basename "$INSTALLED_BIN") ]]; then
    cp -a "$LEGACY_MIGRATION_DIR/files/bin/$(basename "$INSTALLED_BIN")" "$INSTALLED_BIN"
  else
    rm -f -- "$INSTALLED_BIN"
  fi
  systemctl daemon-reload
}

rollback_legacy_locked() {
  local manifest=$LEGACY_MIGRATION_DIR/manifest failed_acme rc=0
  local TROJAN_ACTIVE=0 TROJAN_ENABLED=0 WEB_ACTIVE=0 WEB_ENABLED=0
  local RENEW_ACTIVE=0 RENEW_ENABLED=0 SOMAXCONN=128 SYN_BACKLOG=128 HAD_SYSCTL_FILE=0 HAD_ACME_HOME=0 LEGACY_CONFIG_MODE=unknown
  [[ -r $manifest ]] || return 1
  # shellcheck disable=SC1090
  source "$manifest"
  systemctl disable --now trojan-certman-renew.timer trojan-certman-snapshot.timer >/dev/null 2>&1 || true
  systemctl stop xray.service >/dev/null 2>&1 || true
  cp -a "$LEGACY_MIGRATION_DIR/xray-canary.json" "$XRAY_CONFIG" || rc=1
  cp -a "$LEGACY_MIGRATION_DIR/certman-canary.config" "$CONFIG_FILE" || rc=1
  TROJAN_PORT=18443
  restore_legacy_units || rc=1
  if [[ ${HAD_SYSCTL_FILE:-0} == 1 ]]; then
    cp -a "$LEGACY_MIGRATION_DIR/files/sysctl/$(basename "$SYSCTL_FILE")" "$SYSCTL_FILE" || rc=1
  else
    rm -f -- "$SYSCTL_FILE" || rc=1
  fi
  sysctl -w "net.core.somaxconn=${SOMAXCONN}" "net.ipv4.tcp_max_syn_backlog=${SYN_BACKLOG}" >/dev/null || rc=1
  if [[ -e $ACME_HOME ]]; then
    failed_acme="${ACME_HOME}.failed-cutover.$(date -u +%Y%m%dT%H%M%SZ)"
    mv "$ACME_HOME" "$failed_acme" || rc=1
  fi
  if [[ ${HAD_ACME_HOME:-0} == 1 ]]; then
    cp -a "$LEGACY_MIGRATION_DIR/files/acme-home" "$ACME_HOME" || rc=1
  fi
  if [[ ${LEGACY_CONFIG_MODE:-unknown} =~ ^[0-7]{3,4}$ ]]; then
    chmod "$LEGACY_CONFIG_MODE" "$LEGACY_CONFIG" 2>/dev/null || true
  fi
  if [[ ${TROJAN_ENABLED:-0} == 1 ]]; then systemctl enable trojan.service >/dev/null 2>&1 || rc=1; fi
  if [[ ${WEB_ENABLED:-0} == 1 ]]; then systemctl enable trojan-web.service >/dev/null 2>&1 || rc=1; fi
  if [[ ${TROJAN_ACTIVE:-0} == 1 ]]; then systemctl start trojan.service || rc=1; fi
  if [[ ${WEB_ACTIVE:-0} == 1 ]]; then systemctl start trojan-web.service || rc=1; fi
  if [[ ${RENEW_ENABLED:-0} == 1 ]]; then systemctl enable trojan-certman-renew.timer >/dev/null 2>&1 || rc=1; fi
  if [[ ${RENEW_ACTIVE:-0} == 1 ]]; then systemctl start trojan-certman-renew.timer || rc=1; fi
  systemctl start xray.service >/dev/null 2>&1 || rc=1
  if [[ ${TROJAN_ACTIVE:-0} == 1 ]]; then
    systemctl is-active --quiet trojan.service || rc=1
    ss -lntH 'sport = :443' 2>/dev/null | grep -q . || rc=1
  fi
  if [[ ${WEB_ACTIVE:-0} == 1 ]]; then systemctl is-active --quiet trojan-web.service || rc=1; fi
  if [[ ${RENEW_ACTIVE:-0} == 1 ]]; then systemctl is-active --quiet trojan-certman-renew.timer || rc=1; fi
  systemctl is-active --quiet xray.service || rc=1
  verify_live_certificate || rc=1
  ((rc == 0)) || { log 'legacy rollback was incomplete; CUTOVER_ACTIVE remains set for a retry'; return 1; }
  set_cutover_marker 0 || return 1
  log 'legacy Trojan services and the loopback Xray canary were restored'
}

cutover() { require_root; load_config; with_lock cutover_locked; }

perform_cutover() {
  systemctl stop xray.service || return 1
  systemctl stop trojan.service trojan-web.service || return 1
  TROJAN_PORT=443
  write_config || return 1
  write_xray_config || return 1
  xray_config_test || return 1
  systemctl start xray.service || return 1
  systemctl is-active --quiet xray.service || return 1
  verify_live_certificate || return 1
}

finalize_cutover() {
  install_self || return 1
  install_systemd_units || return 1
  configure_capacity || return 1
  chmod 0600 "$LEGACY_CONFIG" 2>/dev/null || true
  systemctl disable trojan.service trojan-web.service >/dev/null 2>&1 || true
  systemctl enable xray.service trojan-certman-renew.timer trojan-certman-snapshot.timer || return 1
  systemctl start trojan-certman-renew.timer trojan-certman-snapshot.timer || return 1
}

cutover_locked() {
  [[ $TROJAN_PORT == 18443 ]] || die 'cutover requires a verified loopback canary on port 18443'
  systemctl is-active --quiet xray.service || die 'Xray canary is not active'
  verify_live_certificate || die 'Xray canary TLS verification failed'
  prepare_legacy_migration
  if ! (install_pinned_acme && clear_acme_legacy_deploy_state); then
    rollback_legacy_locked || log 'legacy rollback after acme.sh failure was incomplete'
    return 1
  fi
  if ! (perform_cutover); then
    rollback_legacy_locked || log 'legacy rollback after cutover failure was incomplete'
    return 1
  fi
  TROJAN_PORT=443
  load_config
  if ! (finalize_cutover); then
    rollback_legacy_locked || log 'legacy rollback after finalization failure was incomplete'
    return 1
  fi
  set_cutover_marker 1
  write_status success cutover-complete
  log 'Xray now owns 443; legacy services are stopped and preserved for rollback'
}

main() {
  case ${1:-help} in
    install) shift; install_new "$@" ;;
    adopt) shift; adopt_existing "$@" ;;
    renew) shift; run_renew "$@" ;;
    status) shift; show_status "$@" ;;
    deploy-cert) shift; deploy_certificate "$@" ;;
    snapshot) shift; snapshot "$@" ;;
    upgrade) shift; upgrade_xray "$@" ;;
    cutover) shift; cutover "$@" ;;
    rollback) shift; rollback "$@" ;;
    help|-h|--help) usage ;;
    version|--version) printf '%s %s\n' "$PROGRAM" "$PROGRAM_VERSION" ;;
    *) usage >&2; exit 2 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
