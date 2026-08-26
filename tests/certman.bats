#!/usr/bin/env bats

setup() {
  local bats_tmp_base
  bats_tmp_base=${BATS_TEST_TMPDIR:-${BATS_TMPDIR:-${TMPDIR:-/tmp}}}
  export TEST_ROOT="$bats_tmp_base/trojan-certman-${BATS_TEST_NUMBER:-$$}"
  mkdir -p "$TEST_ROOT/etc/trojan-certman/secrets" "$TEST_ROOT/var/lib/trojan-certman" \
    "$TEST_ROOT/etc/xray/tls/versions" "$TEST_ROOT/usr/local/lib/xray/versions" \
    "$TEST_ROOT/usr/local/bin" "$TEST_ROOT/etc/systemd/system" "$TEST_ROOT/run/lock" \
    "$TEST_ROOT/root"
  export CERTMAN_CONFIG_DIR="$TEST_ROOT/etc/trojan-certman"
  export CERTMAN_CONFIG_FILE="$CERTMAN_CONFIG_DIR/config"
  export CERTMAN_SECRETS_DIR="$CERTMAN_CONFIG_DIR/secrets"
  export CERTMAN_PASSWORD_FILE="$CERTMAN_SECRETS_DIR/trojan-password"
  export CERTMAN_CF_TOKEN_FILE="$CERTMAN_SECRETS_DIR/cloudflare-token"
  export CERTMAN_STATE_DIR="$TEST_ROOT/var/lib/trojan-certman"
  export CERTMAN_STATUS_FILE="$CERTMAN_STATE_DIR/status"
  export CERTMAN_INSTALL_TRANSACTION_FILE="$CERTMAN_STATE_DIR/install-transaction"
  export CERTMAN_ROLLBACK_ROOT="$CERTMAN_STATE_DIR/rollback"
  export CERTMAN_LEGACY_MIGRATION_DIR="$CERTMAN_STATE_DIR/legacy-migration"
  export CERTMAN_LOCK_FILE="$TEST_ROOT/run/lock/trojan-certman.lock"
  export CERTMAN_XRAY_CONFIG_DIR="$TEST_ROOT/etc/xray"
  export CERTMAN_XRAY_CONFIG="$CERTMAN_XRAY_CONFIG_DIR/config.json"
  export CERTMAN_XRAY_TLS_ROOT="$CERTMAN_XRAY_CONFIG_DIR/tls"
  export CERTMAN_XRAY_TLS_VERSIONS="$CERTMAN_XRAY_TLS_ROOT/versions"
  export CERTMAN_XRAY_TLS_CURRENT="$CERTMAN_XRAY_TLS_ROOT/current"
  export CERTMAN_XRAY_TLS_PREVIOUS="$CERTMAN_XRAY_TLS_ROOT/previous"
  export CERTMAN_XRAY_INSTALL_ROOT="$TEST_ROOT/usr/local/lib/xray"
  export CERTMAN_XRAY_VERSIONS_DIR="$CERTMAN_XRAY_INSTALL_ROOT/versions"
  export CERTMAN_XRAY_CURRENT="$CERTMAN_XRAY_INSTALL_ROOT/current"
  export CERTMAN_XRAY_PREVIOUS="$CERTMAN_XRAY_INSTALL_ROOT/previous"
  export CERTMAN_XRAY_BIN="$TEST_ROOT/usr/local/bin/xray"
  export CERTMAN_SYSTEMD_DIR="$TEST_ROOT/etc/systemd/system"
  export CERTMAN_SYSCTL_FILE="$TEST_ROOT/etc/sysctl.d/90-trojan-xray-capacity.conf"
  export CERTMAN_INSTALLED_BIN="$TEST_ROOT/usr/local/sbin/trojan-certman"
  export CERTMAN_STAGED_BIN="$TEST_ROOT/usr/local/sbin/trojan-certman-v3"
  export CERTMAN_MANAGED_ASSET_DIR="$TEST_ROOT/usr/local/lib/trojan-certman-v3/asset"
  export CERTMAN_ASSET_DIR="$BATS_TEST_DIRNAME/../asset"
  export CERTMAN_ACME_HOME="$TEST_ROOT/root/.acme.sh"
  export CERTMAN_ACME_BIN="$CERTMAN_ACME_HOME/acme.sh"
  export CERTMAN_LEGACY_CONFIG="$TEST_ROOT/legacy.json"
  export CERTMAN_SKIP_ROOT_CHECK=1
  export CERTMAN_SKIP_CHOWN=1
  export CERTMAN_SKIP_LOCK=1
  # shellcheck source=../install-with-certman.sh
  source "$BATS_TEST_DIRNAME/../install-with-certman.sh"
}

make_certificate() {
  local days=$1 domain=$2 key=$3 cert=$4
  openssl req -x509 -newkey rsa:2048 -nodes -days "$days" \
    -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain" \
    -keyout "$key" -out "$cert" >/dev/null 2>&1
}

file_mode() {
  stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"
}

write_base_config() {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  printf '%s' 'fixture-personal-credential' >"$PASSWORD_FILE"
  chmod 0600 "$PASSWORD_FILE"
  write_config
  write_xray_config
}

seed_certificate_version() {
  local name=$1 cert=$2 key=$3 target
  target="$XRAY_TLS_VERSIONS/$name"
  mkdir -p "$target"
  cp "$cert" "$target/fullchain.pem"
  cp "$key" "$target/private.key"
  atomic_symlink "$target" "$XRAY_TLS_CURRENT"
}

@test "release manifest pins Xray for amd64 and arm64 plus acme.sh" {
  [ "$(normalize_arch x86_64)" = amd64 ]
  [ "$(normalize_arch aarch64)" = arm64 ]
  run normalize_arch riscv64
  [ "$status" -ne 0 ]
  [ "$XRAY_VERSION" = v26.3.27 ]
  [ "$XRAY_AMD64_SHA256" = 23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae ]
  [ "$XRAY_ARM64_SHA256" = 4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c ]
  [ "$ACME_VERSION" = 3.1.4 ]
  [ "$ACME_TARBALL_SHA256" = 9af3ad3d775a5782246df4cdd4b4e7b9b3179deb63c509b10e3ba0433093a884 ]
  [ "$ACME_SCRIPT_SHA256" = fcabf274d4f96966ec933879ae0257266e8ef2f7d16161f14b84dd896c0cac32 ]
  [ "$ACME_DNS_CF_SHA256" = 9628ee8238cb3f9cfa1b1a985c0e9593436a3e4f8a9d65a6f775b981be9e76c8 ]
  grep -Fq -- '--no-cron --no-profile' "$BATS_TEST_DIRNAME/../install-with-certman.sh"
  grep -Fq -- 'NO_DETECT_SH=1' "$BATS_TEST_DIRNAME/../install-with-certman.sh"
}

@test "installed CLI resolves packaged systemd assets without the repository" {
  install_self "$CERTMAN_STAGED_BIN"

  [ -r "$CERTMAN_MANAGED_ASSET_DIR/xray.service" ]
  run env -u CERTMAN_ASSET_DIR \
    CERTMAN_MANAGED_ASSET_DIR="$CERTMAN_MANAGED_ASSET_DIR" \
    CERTMAN_SYSTEMD_DIR="$CERTMAN_SYSTEMD_DIR" \
    bash -c '
      source "$1"
      systemctl() { :; }
      [[ $ASSET_DIR == "$CERTMAN_MANAGED_ASSET_DIR" ]]
      install_systemd_units
    ' _ "$CERTMAN_STAGED_BIN"

  [ "$status" -eq 0 ]
  [ -r "$CERTMAN_SYSTEMD_DIR/xray.service" ]
  [ -r "$CERTMAN_SYSTEMD_DIR/trojan-certman-renew.timer" ]
}

@test "Xray version check consumes full output without pipefail SIGPIPE" {
  local fake_xray="$TEST_ROOT/fake-xray"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf "Xray 26.3.27 (Xray, Penetrates Everything.)\\n"' \
    'for _ in {1..10000}; do printf "version-detail-padding\\n"; done' >"$fake_xray"
  chmod 0755 "$fake_xray"

  xray_binary_matches_version "$fake_xray" v26.3.27
  run xray_binary_matches_version "$fake_xray" v99.0.0
  [ "$status" -ne 0 ]
}

@test "generated Xray config has one Trojan client and no fallback" {
  write_base_config
  [ "$(jq -r '.inbounds[0].protocol' "$XRAY_CONFIG")" = trojan ]
  [ "$(jq '.inbounds[0].settings.clients | length' "$XRAY_CONFIG")" -eq 1 ]
  [ "$(jq -r '.inbounds[0].settings.clients[0].password' "$XRAY_CONFIG")" = fixture-personal-credential ]
  [ "$(jq -r '.inbounds[0].settings.fallbacks // empty' "$XRAY_CONFIG")" = '' ]
  [ "$(jq -r '.routing.domainStrategy' "$XRAY_CONFIG")" = IPIfNonMatch ]
  [ "$(jq '[.routing.rules[] | select(.outboundTag == "blocked") | .ip[] | select(. == "100.64.0.0/10")] | length' "$XRAY_CONFIG")" -eq 1 ]
  [ "$(jq '[.routing.rules[] | select(.outboundTag == "blocked") | .ip[] | select(. == "169.254.0.0/16")] | length' "$XRAY_CONFIG")" -eq 1 ]
  [ "$(file_mode "$XRAY_CONFIG")" = 640 ]
  ! grep -Fq fixture-personal-credential "$CONFIG_FILE"
}

@test "rewriting config with the same input is idempotent" {
  write_base_config
  before=$(sha256sum "$XRAY_CONFIG" | awk '{print $1}')
  write_xray_config
  after=$(sha256sum "$XRAY_CONFIG" | awk '{print $1}')
  [ "$before" = "$after" ]
}

@test "install is a no-op for an already healthy managed node" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  printf '%s' fixture-personal-credential >"$CERTMAN_PASSWORD_FILE"
  printf '%s' fixture-cloudflare-token >"$CERTMAN_CF_TOKEN_FILE"
  chmod 0600 "$CERTMAN_PASSWORD_FILE" "$CERTMAN_CF_TOKEN_FILE"
  printf '%s' fixture-personal-credential >"$TEST_ROOT/password-input"
  printf '%s' fixture-cloudflare-token >"$TEST_ROOT/cloudflare-input"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password-input"
  export CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  write_config
  write_xray_config
  install_self
  install -m 0644 "$CERTMAN_ASSET_DIR/xray.service" "$CERTMAN_SYSTEMD_DIR/xray.service"
  install -d "$XRAY_VERSIONS_DIR/healthy"
  printf '#!/usr/bin/env bash\nprintf "Xray 26.3.27\\n"\n' >"$XRAY_VERSIONS_DIR/healthy/xray"
  chmod 0755 "$XRAY_VERSIONS_DIR/healthy/xray"
  printf '%s\n' "$(xray_sha_for_arch "$(normalize_arch "$(uname -m)")")" \
    >"$XRAY_VERSIONS_DIR/healthy/.archive.sha256"
  atomic_symlink "$XRAY_VERSIONS_DIR/healthy" "$XRAY_CURRENT"
  atomic_symlink "$XRAY_CURRENT/xray" "$XRAY_BIN"
  for unit in "${SYSTEMD_UNITS[@]}"; do
    install -m 0644 "$CERTMAN_ASSET_DIR/$unit" "$CERTMAN_SYSTEMD_DIR/$unit"
  done
  make_certificate 30 example.com "$TEST_ROOT/healthy.key" "$TEST_ROOT/healthy.pem"
  seed_certificate_version healthy "$TEST_ROOT/healthy.pem" "$TEST_ROOT/healthy.key"
  unset TROJAN_PORT

  preflight_os() { :; }
  acme_home_is_trusted() { printf checked >"$TEST_ROOT/acme-trust-checked"; return 0; }
  xray_config_test() { return 0; }
  verify_live_certificate() { return 0; }
  systemctl() {
    case "$1:$2:$3" in
      'is-active:--quiet:xray.service') return 0 ;;
      'is-enabled:--quiet:xray.service') printf checked >"$TEST_ROOT/xray-enabled"; return 0 ;;
      'is-enabled:--quiet:trojan-certman-renew.timer'|'is-enabled:--quiet:trojan-certman-snapshot.timer') return 0 ;;
      'is-active:--quiet:trojan-certman-renew.timer') printf checked >"$TEST_ROOT/renew-active"; return 0 ;;
      'is-active:--quiet:trojan-certman-snapshot.timer') printf checked >"$TEST_ROOT/snapshot-active"; return 0 ;;
      'show:xray.service:-p') printf checked >"$TEST_ROOT/mainpid-checked"; printf '1\n'; return 0 ;;
      *) printf '%s\n' "$*" >>"$TEST_ROOT/mutation.log" ;;
    esac
  }
  install_dependencies() { printf dependencies >>"$TEST_ROOT/mutation.log"; }
  create_xray_user() { printf user >>"$TEST_ROOT/mutation.log"; }
  install_xray_release() { printf xray >>"$TEST_ROOT/mutation.log"; }
  install_pinned_acme() { printf acme >>"$TEST_ROOT/mutation.log"; }
  issue_certificate_dns() { printf certificate >>"$TEST_ROOT/mutation.log"; }
  ss() { printf 'LISTEN 0 4096 *:443 *:* users:(("xray",pid=1,fd=3))\n'; }

  run install_new

  [ "$status" -eq 0 ]
  [[ "$output" == *'already installed and healthy'* ]]
  [ -e "$TEST_ROOT/renew-active" ]
  [ -e "$TEST_ROOT/snapshot-active" ]
  [ -e "$TEST_ROOT/acme-trust-checked" ]
  [ -e "$TEST_ROOT/xray-enabled" ]
  [ -e "$TEST_ROOT/mainpid-checked" ]
  [ ! -e "$TEST_ROOT/mutation.log" ]
}

@test "clean install succeeds and the identical second run preserves runtime state" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  printf '%s' fixture-personal-credential >"$TEST_ROOT/password-input"
  printf '%s' fixture-cloudflare-token >"$TEST_ROOT/cloudflare-input"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password-input"
  export CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  mkdir -p "$TEST_ROOT/service-active" "$TEST_ROOT/service-enabled"

  preflight_os() { :; }
  ss() {
    [[ -e "$TEST_ROOT/service-active/xray.service" ]] \
      && printf 'LISTEN 0 4096 *:443 *:* users:(("xray",pid=4242,fd=3))\n'
    return 0
  }
  install_dependencies() { printf 'dependencies\n' >>"$TEST_ROOT/install-calls"; }
  create_xray_user() { printf 'user\n' >>"$TEST_ROOT/install-calls"; }
  install_xray_release() {
    local target="$XRAY_VERSIONS_DIR/fresh"
    install -d "$target"
    printf '#!/usr/bin/env bash\nprintf "Xray 26.3.27\\n"\n' >"$target/xray"
    chmod 0755 "$target/xray"
    printf '%s\n' "$(xray_sha_for_arch "$(normalize_arch "$(uname -m)")")" >"$target/.archive.sha256"
    atomic_symlink "$target" "$XRAY_CURRENT"
    atomic_symlink "$XRAY_CURRENT/xray" "$XRAY_BIN"
    printf 'xray\n' >>"$TEST_ROOT/install-calls"
  }
  install_pinned_acme() {
    install -d "$ACME_HOME/dnsapi"
    printf '#!/usr/bin/env bash\nexit 0\n' >"$ACME_BIN"
    printf plugin >"$ACME_HOME/dnsapi/dns_cf.sh"
    chmod 0755 "$ACME_BIN"
    write_acme_pin_marker
    printf 'acme\n' >>"$TEST_ROOT/install-calls"
  }
  acme_home_is_trusted() { [[ -r $ACME_PIN_FILE ]]; }
  issue_certificate_dns() {
    ACME_CERT_FILE="${ACME_HOME}/${CERT_DOMAIN}_ecc/fullchain.cer"
    ACME_KEY_FILE="${ACME_HOME}/${CERT_DOMAIN}_ecc/${CERT_DOMAIN}.key"
    install -d "$(dirname "$ACME_CERT_FILE")"
    make_certificate 30 "$CERT_DOMAIN" "$ACME_KEY_FILE" "$ACME_CERT_FILE"
    printf 'certificate\n' >>"$TEST_ROOT/install-calls"
  }
  clear_acme_legacy_deploy_state() { :; }
  configure_capacity() {
    install -d "$(dirname "$SYSCTL_FILE")" "$STATE_DIR"
    printf 'net.core.somaxconn=128\n' >"$STATE_DIR/sysctl-before"
    printf 'net.core.somaxconn = 4096\n' >"$SYSCTL_FILE"
  }
  deploy_certificate_locked() {
    install -d "$XRAY_TLS_CURRENT"
    install -m 0644 "$1" "$XRAY_TLS_CURRENT/fullchain.pem"
    install -m 0640 "$2" "$XRAY_TLS_CURRENT/private.key"
    printf 4242 >"$TEST_ROOT/main-pid"
    printf 0 >"$TEST_ROOT/restarts"
    touch "$TEST_ROOT/service-active/xray.service"
  }
  xray_config_test() { return 0; }
  verify_live_certificate() { return 0; }
  systemctl() {
    local action=$1 name
    shift
    case $action in
      daemon-reload) return 0 ;;
      enable)
        for name in "$@"; do touch "$TEST_ROOT/service-enabled/$name"; done
        ;;
      start)
        for name in "$@"; do touch "$TEST_ROOT/service-active/$name"; done
        ;;
      is-active)
        [[ ${1:-} == --quiet ]] && shift
        [[ -e "$TEST_ROOT/service-active/$1" ]]
        ;;
      is-enabled)
        [[ ${1:-} == --quiet ]] && shift
        [[ -e "$TEST_ROOT/service-enabled/$1" ]]
        ;;
      show)
        [[ $1 == xray.service ]]
        cat "$TEST_ROOT/main-pid"
        ;;
      *) return 0 ;;
    esac
  }

  install_new
  first_pid=$(<"$TEST_ROOT/main-pid")
  first_restarts=$(<"$TEST_ROOT/restarts")
  first_config_sha=$(sha256sum "$XRAY_CONFIG" | awk '{print $1}')
  first_cert_sha=$(certificate_fingerprint_file "$XRAY_TLS_CURRENT/fullchain.pem")
  first_calls=$(wc -l <"$TEST_ROOT/install-calls")

  install_new

  [ "$(<"$TEST_ROOT/main-pid")" = "$first_pid" ]
  [ "$(<"$TEST_ROOT/restarts")" = "$first_restarts" ]
  [ "$(sha256sum "$XRAY_CONFIG" | awk '{print $1}')" = "$first_config_sha" ]
  [ "$(certificate_fingerprint_file "$XRAY_TLS_CURRENT/fullchain.pem")" = "$first_cert_sha" ]
  [ "$(wc -l <"$TEST_ROOT/install-calls")" = "$first_calls" ]
  [ ! -e "$INSTALL_TRANSACTION_FILE" ]
}

@test "install rejects partial managed state before installing dependencies" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  printf '%s\n' 'CERT_DOMAIN=example.com' >"$CERTMAN_CONFIG_FILE"
  printf '%s' fixture-personal-credential >"$TEST_ROOT/password-input"
  printf '%s' fixture-cloudflare-token >"$TEST_ROOT/cloudflare-input"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password-input"
  export CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  preflight_os() { :; }
  install_dependencies() { printf called >"$TEST_ROOT/dependencies-called"; }
  ss() { return 0; }

  run install_new

  [ "$status" -ne 0 ]
  [[ "$output" == *'partial or conflicting managed state'* ]]
  [ ! -e "$TEST_ROOT/dependencies-called" ]
}

@test "fresh-install health probing never sources an untrusted residual config" {
  printf '%s\n' \
    'CERT_DOMAIN=$(touch "'"$TEST_ROOT"'/config-executed")' \
    'TROJAN_PORT=443' >"$CERTMAN_CONFIG_FILE"
  printf secret >"$CERTMAN_PASSWORD_FILE"
  printf token >"$CERTMAN_CF_TOKEN_FILE"
  printf '{}' >"$CERTMAN_XRAY_CONFIG"
  mkdir -p "$(dirname "$CERTMAN_INSTALLED_BIN")"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$CERTMAN_XRAY_BIN"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$CERTMAN_INSTALLED_BIN"
  chmod 0755 "$CERTMAN_XRAY_BIN" "$CERTMAN_INSTALLED_BIN"
  install -m 0644 "$CERTMAN_ASSET_DIR/xray.service" "$CERTMAN_SYSTEMD_DIR/xray.service"
  mkdir -p "$CERTMAN_XRAY_TLS_CURRENT"
  printf cert >"$CERTMAN_XRAY_TLS_CURRENT/fullchain.pem"
  printf key >"$CERTMAN_XRAY_TLS_CURRENT/private.key"

  run managed_install_is_healthy example.com 443

  [ "$status" -ne 0 ]
  [ ! -e "$TEST_ROOT/config-executed" ]
}

@test "install rejects missing secret inputs before installing dependencies" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  unset CERTMAN_PASSWORD_INPUT_FILE CERTMAN_CF_TOKEN_INPUT_FILE
  preflight_os() { :; }
  install_dependencies() { printf called >"$TEST_ROOT/dependencies-called"; }

  run install_new

  [ "$status" -ne 0 ]
  [[ "$output" == *'password and Cloudflare token input files are required'* ]]
  [ ! -e "$TEST_ROOT/dependencies-called" ]
}

@test "install rejects an occupied 443 before installing dependencies" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  printf '%s' fixture-personal-credential >"$TEST_ROOT/password-input"
  printf '%s' fixture-cloudflare-token >"$TEST_ROOT/cloudflare-input"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password-input"
  export CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  preflight_os() { :; }
  install_dependencies() { printf called >"$TEST_ROOT/dependencies-called"; }
  ss() { printf 'LISTEN 0 128 *:443 *:*\n'; }

  run install_new

  [ "$status" -ne 0 ]
  [[ "$output" == *'port 443 is already in use'* ]]
  [ ! -e "$TEST_ROOT/dependencies-called" ]
}

@test "install rejects an invalid domain before installing dependencies" {
  CERT_DOMAIN=not_a_dns_name
  TROJAN_PORT=443
  printf '%s' fixture-personal-credential >"$TEST_ROOT/password-input"
  printf '%s' fixture-cloudflare-token >"$TEST_ROOT/cloudflare-input"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password-input"
  export CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  preflight_os() { :; }
  install_dependencies() { printf called >"$TEST_ROOT/dependencies-called"; }
  ss() { return 0; }

  run install_new

  [ "$status" -ne 0 ]
  [[ "$output" == *'valid DNS name'* ]]
  [ ! -e "$TEST_ROOT/dependencies-called" ]
}

@test "install rejects an unowned acme home before installing dependencies" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  printf '%s' fixture-personal-credential >"$TEST_ROOT/password-input"
  printf '%s' fixture-cloudflare-token >"$TEST_ROOT/cloudflare-input"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password-input"
  export CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  mkdir -p "$CERTMAN_ACME_HOME"
  preflight_os() { :; }
  ss() { return 0; }
  install_dependencies() { printf called >"$TEST_ROOT/dependencies-called"; }

  run install_new

  [ "$status" -ne 0 ]
  [[ "$output" == *'not owned and pinned by certman'* ]]
  [ ! -e "$TEST_ROOT/dependencies-called" ]
}

@test "install rejects a multiline secret before installing dependencies" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  printf 'first-line\nsecond-line\n' >"$TEST_ROOT/password-input"
  printf '%s' fixture-cloudflare-token >"$TEST_ROOT/cloudflare-input"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password-input"
  export CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  preflight_os() { :; }
  ss() { return 0; }
  install_dependencies() { printf called >"$TEST_ROOT/dependencies-called"; return 1; }

  run install_new

  [ "$status" -ne 0 ]
  [ ! -e "$TEST_ROOT/dependencies-called" ]
}

@test "failed fresh install cleans managed state but preserves dependencies and xray user" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  printf '%s' fixture-personal-credential >"$TEST_ROOT/password-input"
  printf '%s' fixture-cloudflare-token >"$TEST_ROOT/cloudflare-input"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password-input"
  export CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  preflight_os() { :; }
  ss() { return 0; }
  install_dependencies() { printf retained >"$TEST_ROOT/dependencies-retained"; }
  create_xray_user() { printf retained >"$TEST_ROOT/xray-user-retained"; }
  install_xray_release() {
    install -d "$XRAY_VERSIONS_DIR/fresh"
    printf '#!/usr/bin/env bash\nexit 0\n' >"$XRAY_VERSIONS_DIR/fresh/xray"
    chmod 0755 "$XRAY_VERSIONS_DIR/fresh/xray"
    atomic_symlink "$XRAY_VERSIONS_DIR/fresh" "$XRAY_CURRENT"
    atomic_symlink "$XRAY_CURRENT/xray" "$XRAY_BIN"
  }
  install_pinned_acme() { :; }
  issue_certificate_dns() {
    ACME_CERT_FILE="$TEST_ROOT/issued.pem"
    ACME_KEY_FILE="$TEST_ROOT/issued.key"
    make_certificate 30 example.com "$ACME_KEY_FILE" "$ACME_CERT_FILE"
  }
  clear_acme_legacy_deploy_state() { :; }
  install_systemd_units() {
    local unit
    for unit in "${SYSTEMD_UNITS[@]}"; do
      install -m 0644 "$CERTMAN_ASSET_DIR/$unit" "$CERTMAN_SYSTEMD_DIR/$unit"
    done
    return 1
  }
  systemctl() { return 0; }

  run install_new

  [ "$status" -ne 0 ]
  [ -e "$TEST_ROOT/dependencies-retained" ]
  [ -e "$TEST_ROOT/xray-user-retained" ]
  [ ! -e "$CERTMAN_CONFIG_FILE" ]
  [ ! -e "$CERTMAN_PASSWORD_FILE" ]
  [ ! -e "$CERTMAN_CF_TOKEN_FILE" ]
  [ ! -e "$CERTMAN_XRAY_CONFIG" ]
  [ ! -e "$CERTMAN_XRAY_BIN" ]
  [ ! -e "$CERTMAN_INSTALLED_BIN" ]
  [ ! -e "$CERTMAN_SYSTEMD_DIR/xray.service" ]
  [ ! -e "$CERTMAN_INSTALL_TRANSACTION_FILE" ]
}

@test "fresh cleanup treats absent systemd units as already clean" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  printf '%s' fixture-personal-credential >"$TEST_ROOT/password-input"
  printf '%s' fixture-cloudflare-token >"$TEST_ROOT/cloudflare-input"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password-input"
  export CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  preflight_os() { :; }
  ss() { return 0; }
  install_dependencies() { :; }
  create_xray_user() { :; }
  install_xray_release() { return 1; }
  systemctl() { return 5; }

  run install_new

  [ "$status" -ne 0 ]
  [ ! -e "$CERTMAN_INSTALL_TRANSACTION_FILE" ]
  [ ! -e "$CERTMAN_PASSWORD_FILE" ]
  [ ! -e "$CERTMAN_CF_TOKEN_FILE" ]
}

@test "failed fresh install removes an acme home created by the transaction" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  printf '%s' fixture-personal-credential >"$TEST_ROOT/password-input"
  printf '%s' fixture-cloudflare-token >"$TEST_ROOT/cloudflare-input"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password-input"
  export CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  preflight_os() { :; }
  ss() { return 0; }
  install_dependencies() { :; }
  create_xray_user() { :; }
  install_xray_release() { :; }
  install_pinned_acme() {
    mkdir -p "$CERTMAN_ACME_HOME/dnsapi"
    printf partial >"$CERTMAN_ACME_BIN"
    return 1
  }
  systemctl() { return 0; }

  run install_new

  [ "$status" -ne 0 ]
  [ ! -e "$CERTMAN_ACME_HOME" ]
  [ ! -e "$CERTMAN_INSTALL_TRANSACTION_FILE" ]
}

@test "next install recovers an owned stale transaction before retrying" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=443
  printf '%s' fixture-personal-credential >"$TEST_ROOT/password-input"
  printf '%s' fixture-cloudflare-token >"$TEST_ROOT/cloudflare-input"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password-input"
  export CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  printf 'OWNER=trojan-certman-v3\nSTATE=in-progress\n' >"$CERTMAN_INSTALL_TRANSACTION_FILE"
  printf partial >"$CERTMAN_PASSWORD_FILE"
  printf partial >"$CERTMAN_CF_TOKEN_FILE"
  printf partial >"$CERTMAN_XRAY_CONFIG"
  preflight_os() { :; }
  ss() { return 0; }
  systemctl() { return 0; }
  install_dependencies() { return 1; }

  run install_new

  [ "$status" -ne 0 ]
  [[ "$output" == *'dependency installation failed'* ]]
  [ ! -e "$CERTMAN_INSTALL_TRANSACTION_FILE" ]
  [ ! -e "$CERTMAN_PASSWORD_FILE" ]
  [ ! -e "$CERTMAN_CF_TOKEN_FILE" ]
  [ ! -e "$CERTMAN_XRAY_CONFIG" ]
}

@test "cleanup keeps the transaction marker when a managed unit was replaced" {
  printf 'OWNER=trojan-certman-v3\nSTATE=in-progress\n' >"$CERTMAN_INSTALL_TRANSACTION_FILE"
  printf '%s\n' '[Unit]' 'Description=foreign replacement' >"$CERTMAN_SYSTEMD_DIR/xray.service"
  systemctl() { printf called >"$TEST_ROOT/systemctl-called"; }

  run cleanup_fresh_install_transaction

  [ "$status" -ne 0 ]
  [ -e "$CERTMAN_INSTALL_TRANSACTION_FILE" ]
  [ -e "$CERTMAN_SYSTEMD_DIR/xray.service" ]
  [ ! -e "$TEST_ROOT/systemctl-called" ]
}

@test "candidate Xray config keeps a json suffix for format detection" {
  write_base_config
  xray_config_test() {
    printf '%s' "$2" >"$TEST_ROOT/candidate-path"
    return 0
  }

  candidate_config_test "$TEST_ROOT/candidate.pem" "$TEST_ROOT/candidate.key"

  [[ $(<"$TEST_ROOT/candidate-path") == *.json ]]
  [ ! -e "$(<"$TEST_ROOT/candidate-path")" ]
}

@test "certificate validation enforces lifetime SAN and key match" {
  make_certificate 30 example.com "$TEST_ROOT/good.key" "$TEST_ROOT/good.pem"
  verify_certificate_pair "$TEST_ROOT/good.pem" "$TEST_ROOT/good.key" example.com
  make_certificate 1 example.com "$TEST_ROOT/short.key" "$TEST_ROOT/short.pem"
  run verify_certificate_pair "$TEST_ROOT/short.pem" "$TEST_ROOT/short.key" example.com
  [ "$status" -ne 0 ]
  make_certificate 30 wrong.example "$TEST_ROOT/wrong.key" "$TEST_ROOT/wrong.pem"
  run verify_certificate_pair "$TEST_ROOT/wrong.pem" "$TEST_ROOT/wrong.key" example.com
  [ "$status" -ne 0 ]
  make_certificate 30 example.com.attacker "$TEST_ROOT/prefix.key" "$TEST_ROOT/prefix.pem"
  run verify_certificate_pair "$TEST_ROOT/prefix.pem" "$TEST_ROOT/prefix.key" example.com
  [ "$status" -ne 0 ]
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj '/CN=example.com' \
    -keyout "$TEST_ROOT/cn-only.key" -out "$TEST_ROOT/cn-only.pem" >/dev/null 2>&1
  run verify_certificate_pair "$TEST_ROOT/cn-only.pem" "$TEST_ROOT/cn-only.key" example.com
  [ "$status" -ne 0 ]
  make_certificate 30 example.com "$TEST_ROOT/mismatch.key" "$TEST_ROOT/mismatch.pem"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TEST_ROOT/mismatch.key" >/dev/null 2>&1
  run verify_certificate_pair "$TEST_ROOT/mismatch.pem" "$TEST_ROOT/mismatch.key" example.com
  [ "$status" -ne 0 ]
}

@test "deploy-cert atomically advances current and previous" {
  write_base_config
  make_certificate 30 example.com "$TEST_ROOT/old.key" "$TEST_ROOT/old.pem"
  make_certificate 60 example.com "$TEST_ROOT/new.key" "$TEST_ROOT/new.pem"
  seed_certificate_version old "$TEST_ROOT/old.pem" "$TEST_ROOT/old.key"
  candidate_config_test() { return 0; }
  restart_and_verify_xray() { return 0; }

  deploy_certificate_locked "$TEST_ROOT/new.pem" "$TEST_ROOT/new.key"

  [ "$(readlink "$XRAY_TLS_PREVIOUS")" = "$XRAY_TLS_VERSIONS/old" ]
  [ "$(certificate_fingerprint_file "$XRAY_TLS_CURRENT/fullchain.pem")" = "$(certificate_fingerprint_file "$TEST_ROOT/new.pem")" ]
  [ "$(file_mode "$(readlink "$XRAY_TLS_CURRENT")")" = 750 ]
  [ "$(file_mode "$XRAY_TLS_CURRENT/private.key")" = 640 ]
  grep -Fq 'LAST_STAGE=certificate-deployed' "$STATUS_FILE"
}

@test "deploy-cert is a no-op when the same valid certificate is already live" {
  write_base_config
  make_certificate 30 example.com "$TEST_ROOT/current.key" "$TEST_ROOT/current.pem"
  seed_certificate_version current "$TEST_ROOT/current.pem" "$TEST_ROOT/current.key"
  xray_config_test() { return 0; }
  verify_live_certificate() { return 0; }
  restart_and_verify_xray() { printf restarted >"$TEST_ROOT/restarted"; return 0; }

  deploy_certificate_locked "$TEST_ROOT/current.pem" "$TEST_ROOT/current.key"

  [ "$(readlink "$XRAY_TLS_CURRENT")" = "$XRAY_TLS_VERSIONS/current" ]
  [ ! -e "$XRAY_TLS_PREVIOUS" ]
  [ ! -e "$TEST_ROOT/restarted" ]
  grep -Fq 'LAST_STAGE=certificate-unchanged' "$STATUS_FILE"
}

@test "deploy-cert restores old certificate when runtime verification fails" {
  write_base_config
  make_certificate 30 example.com "$TEST_ROOT/old.key" "$TEST_ROOT/old.pem"
  make_certificate 60 example.com "$TEST_ROOT/new.key" "$TEST_ROOT/new.pem"
  seed_certificate_version old "$TEST_ROOT/old.pem" "$TEST_ROOT/old.key"
  candidate_config_test() { return 0; }
  restart_and_verify_xray() { return 1; }
  systemctl() { return 0; }

  run deploy_certificate_locked "$TEST_ROOT/new.pem" "$TEST_ROOT/new.key"

  [ "$status" -ne 0 ]
  [ "$(readlink "$XRAY_TLS_CURRENT")" = "$XRAY_TLS_VERSIONS/old" ]
  grep -Fq 'LAST_STAGE=certificate-rollback' "$STATUS_FILE"
}

@test "first certificate failure stops Xray when no prior certificate exists" {
  write_base_config
  make_certificate 60 example.com "$TEST_ROOT/new.key" "$TEST_ROOT/new.pem"
  candidate_config_test() { return 0; }
  restart_and_verify_xray() { return 1; }
  systemctl() { printf '%s %s\n' "$1" "${2:-}" >>"$TEST_ROOT/systemctl.log"; return 0; }

  run deploy_certificate_locked "$TEST_ROOT/new.pem" "$TEST_ROOT/new.key"

  [ "$status" -ne 0 ]
  [ ! -e "$XRAY_TLS_CURRENT" ]
  grep -Fxq 'stop xray.service' "$TEST_ROOT/systemctl.log"
  ! grep -Fxq 'restart xray.service' "$TEST_ROOT/systemctl.log"
}

@test "live certificate verification retries until the listener is ready" {
  write_base_config
  make_certificate 60 example.com "$TEST_ROOT/current.key" "$TEST_ROOT/current.pem"
  seed_certificate_version current "$TEST_ROOT/current.pem" "$TEST_ROOT/current.key"
  fetch_live_certificate() {
    local count=0
    [[ -r $TEST_ROOT/fetch-count ]] && count=$(<"$TEST_ROOT/fetch-count")
    count=$((count + 1))
    printf '%s' "$count" >"$TEST_ROOT/fetch-count"
    ((count >= 3)) || return 1
    cp "$XRAY_TLS_CURRENT/fullchain.pem" "$1"
  }
  sleep() { :; }

  verify_live_certificate

  [ "$(<"$TEST_ROOT/fetch-count")" -eq 3 ]
}

@test "upgrade rejects a non-matching requested hash before download or switch" {
  write_base_config
  mkdir -p "$XRAY_VERSIONS_DIR/old"
  atomic_symlink "$XRAY_VERSIONS_DIR/old" "$XRAY_CURRENT"
  uname() { printf 'x86_64\n'; }
  download_xray_archive() { return 99; }

  run install_xray_release "$XRAY_VERSION" deadbeef 1

  [ "$status" -ne 0 ]
  [[ "$output" == *'does not match the pinned release manifest'* ]]
  [ "$(readlink "$XRAY_CURRENT")" = "$XRAY_VERSIONS_DIR/old" ]
}

@test "interrupted or corrupt upgrade never changes current" {
  write_base_config
  mkdir -p "$XRAY_VERSIONS_DIR/old"
  atomic_symlink "$XRAY_VERSIONS_DIR/old" "$XRAY_CURRENT"
  uname() { printf 'x86_64\n'; }
  download_xray_archive() { printf 'corrupt' >"$3"; }

  run install_xray_release "$XRAY_VERSION" "$XRAY_AMD64_SHA256" 1

  [ "$status" -ne 0 ]
  [[ "$output" == *'checksum mismatch'* ]]
  [ "$(readlink "$XRAY_CURRENT")" = "$XRAY_VERSIONS_DIR/old" ]
}

@test "rollback restores captured core config and certificate targets" {
  write_base_config
  mkdir -p "$XRAY_VERSIONS_DIR/old-core" "$XRAY_VERSIONS_DIR/new-core" "$XRAY_TLS_VERSIONS/old-cert" "$XRAY_TLS_VERSIONS/new-cert"
  atomic_symlink "$XRAY_VERSIONS_DIR/old-core" "$XRAY_CURRENT"
  atomic_symlink "$XRAY_TLS_VERSIONS/old-cert" "$XRAY_TLS_CURRENT"
  cp "$XRAY_CONFIG" "$TEST_ROOT/original-config"
  prepare_rollback
  atomic_symlink "$XRAY_VERSIONS_DIR/new-core" "$XRAY_CURRENT"
  atomic_symlink "$XRAY_TLS_VERSIONS/new-cert" "$XRAY_TLS_CURRENT"
  printf '{}\n' >"$XRAY_CONFIG"

  restore_rollback_state

  [ "$(readlink "$XRAY_CURRENT")" = "$XRAY_VERSIONS_DIR/old-core" ]
  [ "$(readlink "$XRAY_TLS_CURRENT")" = "$XRAY_TLS_VERSIONS/old-cert" ]
  cmp "$TEST_ROOT/original-config" "$XRAY_CONFIG"
}

@test "renew uses file-sourced Cloudflare DNS-01 without force or duplicate restart" {
  write_base_config
  make_certificate 60 example.com "$TEST_ROOT/current.key" "$TEST_ROOT/current.pem"
  seed_certificate_version current "$TEST_ROOT/current.pem" "$TEST_ROOT/current.key"
  ACME_CERT_FILE="$XRAY_TLS_CURRENT/fullchain.pem"
  ACME_KEY_FILE="$XRAY_TLS_CURRENT/private.key"
  printf '%s' 'fixture-cloudflare-token' >"$CERTMAN_CF_TOKEN_FILE"
  chmod 0600 "$CERTMAN_CF_TOKEN_FILE"
  mkdir -p "$CERTMAN_ACME_HOME"
  cat >"$ACME_BIN" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" >"$TEST_ROOT/acme-args"
[[ -n \${CF_Token:-} ]] || exit 9
printf present >"$TEST_ROOT/acme-renew-token-present"
exit 2
EOF
  chmod +x "$ACME_BIN"
  verify_live_certificate() { return 0; }
  deploy_certificate_locked() { printf 'unexpected-deploy\n' >"$TEST_ROOT/deploy"; return 1; }

  run_renew_locked

  grep -Fxq -- '--issue' "$TEST_ROOT/acme-args"
  grep -Fxq -- '--dns' "$TEST_ROOT/acme-args"
  grep -Fxq -- 'dns_cf' "$TEST_ROOT/acme-args"
  ! grep -Fxq -- '--force' "$TEST_ROOT/acme-args"
  [ "$(<"$TEST_ROOT/acme-renew-token-present")" = present ]
  ! grep -R -Fq fixture-cloudflare-token "$TEST_ROOT/acme-args" "$STATUS_FILE" 2>/dev/null
  [ ! -e "$TEST_ROOT/deploy" ]
  grep -Fq 'LAST_STAGE=not-due' "$STATUS_FILE"
}

@test "cutover imports a root-only Cloudflare token before taking the lock" {
  write_base_config
  printf '%s' 'fixture-cloudflare-token' >"$TEST_ROOT/cloudflare-input"
  chmod 0600 "$TEST_ROOT/cloudflare-input"
  CERTMAN_CF_TOKEN_INPUT_FILE="$TEST_ROOT/cloudflare-input"
  with_lock() { printf '%s' "$1" >"$TEST_ROOT/locked-command"; }

  cutover

  [ "$(file_mode "$CERTMAN_CF_TOKEN_FILE")" = 600 ]
  [ "$(<"$CERTMAN_CF_TOKEN_FILE")" = fixture-cloudflare-token ]
  [ "$(<"$TEST_ROOT/locked-command")" = cutover_locked ]
}

@test "cutover refuses a missing Cloudflare token before touching migration state" {
  write_base_config

  run cutover

  [ "$status" -ne 0 ]
  [[ "$output" == *'Cloudflare token'* ]]
  [ ! -e "$CERTMAN_LEGACY_MIGRATION_DIR" ]
}

@test "DNS-01 issuance passes a file-sourced token only through the acme environment" {
  CERT_DOMAIN=example.com
  make_certificate 60 example.com "$TEST_ROOT/issued.key" "$TEST_ROOT/issued.pem"
  printf '%s' 'fixture-cloudflare-token' >"$CERTMAN_CF_TOKEN_FILE"
  chmod 0600 "$CERTMAN_CF_TOKEN_FILE"
  mkdir -p "$CERTMAN_ACME_HOME"
  cat >"$ACME_BIN" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" >"$TEST_ROOT/acme-issue-args"
[[ -n \${CF_Token:-} ]] || exit 9
printf present >"$TEST_ROOT/acme-token-present"
mkdir -p "$CERTMAN_ACME_HOME/example.com_ecc"
cp "$TEST_ROOT/issued.pem" "$CERTMAN_ACME_HOME/example.com_ecc/fullchain.cer"
cp "$TEST_ROOT/issued.key" "$CERTMAN_ACME_HOME/example.com_ecc/example.com.key"
EOF
  chmod +x "$ACME_BIN"

  issue_certificate_dns

  grep -Fxq -- '--issue' "$TEST_ROOT/acme-issue-args"
  grep -Fxq -- 'dns_cf' "$TEST_ROOT/acme-issue-args"
  ! grep -Fxq -- '--force' "$TEST_ROOT/acme-issue-args"
  [ "$(<"$TEST_ROOT/acme-token-present")" = present ]
  ! grep -R -Fq fixture-cloudflare-token "$TEST_ROOT/acme-issue-args" "$STATUS_FILE" 2>/dev/null
}

@test "DNS-01 issuance accepts rc 2 with a valid pair and scrubs persisted Cloudflare token" {
  CERT_DOMAIN=example.com
  mkdir -p "$CERTMAN_ACME_HOME/example.com_ecc"
  make_certificate 60 example.com \
    "$CERTMAN_ACME_HOME/example.com_ecc/example.com.key" \
    "$CERTMAN_ACME_HOME/example.com_ecc/fullchain.cer"
  printf '%s' fixture-cloudflare-token >"$CERTMAN_CF_TOKEN_FILE"
  chmod 0600 "$CERTMAN_CF_TOKEN_FILE"
  cat >"$ACME_BIN" <<EOF
#!/usr/bin/env bash
printf '%s\n' "SAVED_CF_Token='fixture-cloudflare-token'" >"$CERTMAN_ACME_HOME/account.conf"
printf '%s\n' "CF_Token='fixture-cloudflare-token'" >"$CERTMAN_ACME_HOME/example.com_ecc/example.com.conf"
exit 2
EOF
  chmod +x "$ACME_BIN"

  run issue_certificate_dns

  [ "$status" -eq 0 ]
  ! grep -Fq fixture-cloudflare-token "$CERTMAN_ACME_HOME/account.conf"
  ! grep -Fq fixture-cloudflare-token "$CERTMAN_ACME_HOME/example.com_ecc/example.com.conf"
}

@test "pinned acme refuses an unowned existing home without downloading" {
  mkdir -p "$CERTMAN_ACME_HOME"
  cat >"$ACME_BIN" <<'EOF'
#!/usr/bin/env bash
printf 'acme.sh 3.1.4\n'
EOF
  chmod +x "$ACME_BIN"
  ACME_SCRIPT_SHA256=$(sha256sum "$ACME_BIN" | awk '{print $1}')
  curl() { printf called >"$TEST_ROOT/curl-called"; return 1; }

  run install_pinned_acme

  [ "$status" -ne 0 ]
  [[ "$output" == *'not owned and pinned by certman'* ]]
  [ ! -e "$TEST_ROOT/curl-called" ]
}

@test "pinned acme refuses a modified Cloudflare DNS plugin" {
  mkdir -p "$CERTMAN_ACME_HOME/dnsapi"
  cat >"$ACME_BIN" <<'EOF'
#!/usr/bin/env bash
printf 'acme.sh 3.1.4\n'
EOF
  printf '%s\n' '#!/usr/bin/env sh' 'printf modified' >"$CERTMAN_ACME_HOME/dnsapi/dns_cf.sh"
  chmod +x "$ACME_BIN" "$CERTMAN_ACME_HOME/dnsapi/dns_cf.sh"
  ACME_SCRIPT_SHA256=$(sha256sum "$ACME_BIN" | awk '{print $1}')
  ACME_DNS_CF_SHA256=$(printf expected-plugin | sha256sum | awk '{print $1}')
  cat >"$CERTMAN_ACME_HOME/.trojan-certman-pin" <<EOF
VERSION=$ACME_VERSION
COMMIT=$ACME_COMMIT
SCRIPT_SHA256=$ACME_SCRIPT_SHA256
DNS_CF_SHA256=$ACME_DNS_CF_SHA256
EOF

  run install_pinned_acme

  [ "$status" -ne 0 ]
  [[ "$output" == *'not owned and pinned by certman'* ]]
}

@test "legacy acme deploy paths and reload command are cleared without a second restart" {
  CERT_DOMAIN=example.com
  mkdir -p "$CERTMAN_ACME_HOME"
  cat >"$ACME_BIN" <<EOF
#!/usr/bin/env bash
printf '%q\n' "\$@" >"$TEST_ROOT/acme-install-cert-args"
EOF
  chmod +x "$ACME_BIN"

  clear_acme_legacy_deploy_state

  grep -Fxq -- '--install-cert' "$TEST_ROOT/acme-install-cert-args"
  grep -Fxq -- '--reloadcmd' "$TEST_ROOT/acme-install-cert-args"
  [ "$(tail -n 1 "$TEST_ROOT/acme-install-cert-args")" = "''" ]
}

@test "snapshot is one non-secret line with required signals" {
  write_base_config
  systemctl() {
    if [[ $1 == is-active ]]; then
      printf 'active\n'
    elif [[ $* == *NRestarts* ]]; then
      printf '2\n'
    elif [[ $* == *MainPID* ]]; then
      printf '0\n'
    fi
  }
  netstat_counter() { printf '3\n'; }
  tls_probe() { printf '12|Dec 1 00:00:00 2026 GMT|AA:BB\n'; }
  sysctl() { printf '4096\n'; }

  run snapshot

  [ "$status" -eq 0 ]
  [ "$(printf '%s\n' "$output" | wc -l | tr -d ' ')" -eq 1 ]
  [[ "$output" == *'service=active'* ]]
  [[ "$output" == *'listen_queue='* ]]
  [[ "$output" == *'conntrack='* ]]
  [[ "$output" == *'tls_ms=12'* ]]
  [[ "$output" != *'fixture-personal-credential'* ]]
}

@test "adopt refuses implicit legacy password extraction" {
  printf '%s\n' '{"password":["must-not-be-read"],"ssl":{"sni":"example.com","cert":"/missing","key":"/missing"}}' >"$CERTMAN_LEGACY_CONFIG"
  unset CERTMAN_PASSWORD_INPUT_FILE

  run adopt_existing

  [ "$status" -ne 0 ]
  [[ "$output" == *'requires CERTMAN_PASSWORD_INPUT_FILE'* ]]
  [ ! -e "$PASSWORD_FILE" ]
}

@test "adopt prepares only the loopback canary and preserves production certman timers" {
  printf '%s' fixture-personal-credential >"$TEST_ROOT/password"
  make_certificate 30 example.com "$TEST_ROOT/legacy.key" "$TEST_ROOT/legacy.pem"
  jq -n --arg cert "$TEST_ROOT/legacy.pem" --arg key "$TEST_ROOT/legacy.key" \
    '{ssl:{sni:"example.com",cert:$cert,key:$key}}' >"$CERTMAN_LEGACY_CONFIG"
  export CERTMAN_PASSWORD_INPUT_FILE="$TEST_ROOT/password"
  preflight_os() { :; }
  install_dependencies() { :; }
  create_xray_user() { :; }
  install_xray_release() { :; }
  install_self() { printf '%s\n' "$1" >"$TEST_ROOT/installed-self"; }
  install_xray_unit() { printf xray >"$TEST_ROOT/installed-unit"; }
  deploy_certificate() { printf deployed >"$TEST_ROOT/deployed"; }
  systemctl() { printf '%s\n' "$*" >>"$TEST_ROOT/systemctl.log"; }

  adopt_existing

  [ "$(<"$TEST_ROOT/installed-self")" = "$CERTMAN_STAGED_BIN" ]
  [ -e "$TEST_ROOT/installed-unit" ]
  ! grep -q 'trojan-certman-renew' "$TEST_ROOT/systemctl.log"
  [ "$(jq -r '.inbounds[0].listen' "$XRAY_CONFIG")" = 127.0.0.1 ]
  [ "$(jq -r '.inbounds[0].port' "$XRAY_CONFIG")" -eq 18443 ]
}

@test "cutover promotes the verified canary to 443 only after stopping legacy listeners" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=18443
  printf '%s' fixture-personal-credential >"$PASSWORD_FILE"
  chmod 0600 "$PASSWORD_FILE"
  write_config
  write_xray_config
  verify_live_certificate() { :; }
  prepare_legacy_migration() { :; }
  install_pinned_acme() { :; }
  clear_acme_legacy_deploy_state() { :; }
  xray_config_test() { :; }
  install_self() { printf self >>"$TEST_ROOT/cutover-actions"; }
  install_systemd_units() { printf units >>"$TEST_ROOT/cutover-actions"; }
  configure_capacity() { printf capacity >>"$TEST_ROOT/cutover-actions"; }
  set_cutover_marker() { printf 'marker=%s\n' "$1" >>"$TEST_ROOT/cutover-actions"; }
  systemctl() { printf '%s|' "$@" >>"$TEST_ROOT/systemctl.log"; printf '\n' >>"$TEST_ROOT/systemctl.log"; return 0; }

  cutover_locked

  [ "$(jq -r '.inbounds[0].port' "$XRAY_CONFIG")" -eq 443 ]
  [ "$(jq -r '.inbounds[0].listen' "$XRAY_CONFIG")" = 0.0.0.0 ]
  grep -Fxq 'stop|trojan.service|trojan-web.service|' "$TEST_ROOT/systemctl.log"
  grep -Fq 'marker=1' "$TEST_ROOT/cutover-actions"
  grep -Fq 'LAST_STAGE=cutover-complete' "$STATUS_FILE"
}

@test "cutover failure invokes legacy rollback instead of leaving 443 down" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=18443
  printf '%s' fixture-personal-credential >"$PASSWORD_FILE"
  chmod 0600 "$PASSWORD_FILE"
  write_config
  write_xray_config
  verify_live_certificate() { :; }
  prepare_legacy_migration() { :; }
  install_pinned_acme() { :; }
  clear_acme_legacy_deploy_state() { :; }
  xray_config_test() { return 1; }
  rollback_legacy_locked() { printf rolled-back >"$TEST_ROOT/legacy-rollback"; }
  systemctl() { return 0; }

  run cutover_locked

  [ "$status" -ne 0 ]
  [ "$(<"$TEST_ROOT/legacy-rollback")" = rolled-back ]
}

@test "acme installation failure invokes legacy rollback before touching 443" {
  CERT_DOMAIN=example.com
  TROJAN_PORT=18443
  printf '%s' fixture-personal-credential >"$PASSWORD_FILE"
  chmod 0600 "$PASSWORD_FILE"
  write_config
  write_xray_config
  verify_live_certificate() { :; }
  prepare_legacy_migration() { :; }
  install_pinned_acme() { return 7; }
  clear_acme_legacy_deploy_state() { printf cleared >"$TEST_ROOT/acme-cleared"; }
  rollback_legacy_locked() { printf rolled-back >"$TEST_ROOT/legacy-rollback"; }
  perform_cutover() { printf touched-443 >"$TEST_ROOT/touched-443"; }
  systemctl() { return 0; }

  run cutover_locked

  [ "$status" -ne 0 ]
  [ "$(<"$TEST_ROOT/legacy-rollback")" = rolled-back ]
  [ ! -e "$TEST_ROOT/touched-443" ]
}

@test "incomplete legacy rollback keeps the active marker for a safe retry" {
  mkdir -p "$CERTMAN_LEGACY_MIGRATION_DIR/files/systemd"
  printf '%s\n' '{"canary":true}' >"$CERTMAN_LEGACY_MIGRATION_DIR/xray-canary.json"
  printf '%s\n' 'CERT_DOMAIN=example.com' 'TROJAN_PORT=18443' \
    'ACME_CERT_FILE=/missing/cert' 'ACME_KEY_FILE=/missing/key' \
    >"$CERTMAN_LEGACY_MIGRATION_DIR/certman-canary.config"
  cat >"$CERTMAN_LEGACY_MIGRATION_DIR/manifest" <<'EOF'
CUTOVER_ACTIVE=1
TROJAN_ACTIVE=1
TROJAN_ENABLED=1
WEB_ACTIVE=0
WEB_ENABLED=0
RENEW_ACTIVE=0
RENEW_ENABLED=0
SOMAXCONN=128
SYN_BACKLOG=128
HAD_SYSCTL_FILE=0
HAD_ACME_HOME=0
LEGACY_CONFIG_MODE=600
EOF
  restore_legacy_units() { :; }
  sysctl() { return 0; }
  verify_live_certificate() { return 0; }
  systemctl() {
    if [[ $1 == start && $2 == trojan.service ]]; then return 1; fi
    return 0
  }

  run rollback_legacy_locked

  [ "$status" -ne 0 ]
  grep -Fxq 'CUTOVER_ACTIVE=1' "$CERTMAN_LEGACY_MIGRATION_DIR/manifest"
}

@test "systemd assets enforce non-root Xray hardening and scheduled snapshots" {
  grep -Fxq 'User=xray' "$CERTMAN_ASSET_DIR/xray.service"
  grep -Fxq 'Group=xray' "$CERTMAN_ASSET_DIR/xray.service"
  grep -Fxq 'LimitNOFILE=65536' "$CERTMAN_ASSET_DIR/xray.service"
  grep -Fxq 'NoNewPrivileges=true' "$CERTMAN_ASSET_DIR/xray.service"
  grep -Fxq 'ProtectSystem=strict' "$CERTMAN_ASSET_DIR/xray.service"
  grep -Fxq 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' "$CERTMAN_ASSET_DIR/xray.service"
  grep -Fxq 'OnUnitActiveSec=1min' "$CERTMAN_ASSET_DIR/trojan-certman-snapshot.timer"
  grep -Fxq 'Persistent=true' "$CERTMAN_ASSET_DIR/trojan-certman-renew.timer"
  grep -Fxq 'TimeoutStartSec=15min' "$CERTMAN_ASSET_DIR/trojan-certman-renew.service"
}

@test "v3 script contains no MySQL mutable latest or curl pipe installer" {
  ! grep -Eq 'MariaDB|mysql|download/latest|curl[^\n]*\|[^\n]*bash' "$BATS_TEST_DIRNAME/../install-with-certman.sh"
}
