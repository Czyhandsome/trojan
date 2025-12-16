#!/bin/bash
# Author: Jrohy (modified by Czyhandsome)
# GitHub: https://github.com/Czyhandsome/trojan
# One-click Trojan + Cloudflare DNS-01 auto TLS (IP-ban friendly)

set -e

############ CONFIG ############
download_url="https://github.com/Jrohy/trojan/releases/download/"
version_check="https://api.github.com/repos/Jrohy/trojan/releases/latest"
service_url="https://raw.githubusercontent.com/Jrohy/trojan/master/asset/trojan-web.service"

############ COLOR #############
red="31m"; green="32m"; yellow="33m"; blue="36m"
colorEcho(){ echo -e "\033[${1}${@:2}\033[0m"; }

############ FLAGS #############
remove=0
help=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove) remove=1 ;;
    -h|--help) help=1 ;;
  esac
  shift
done

############ HELP ##############
show_help() {
  echo "Usage:"
  echo "  bash install.sh [--remove]"
  echo
  echo "Environment variables for auto TLS (Cloudflare DNS-01):"
  echo "  CF_Token        Cloudflare API Token"
  echo "  CF_Account_ID   Cloudflare Account ID"
  echo "  CERT_DOMAIN     Domain (e.g. introspect.czyhandsome.ink)"
}

############ REMOVE ############
removeTrojan() {
  systemctl stop trojan-web 2>/dev/null || true
  rm -rf /usr/bin/trojan /usr/local/bin/trojan
  rm -rf /usr/local/etc/trojan /var/lib/trojan-manager
  rm -f /etc/systemd/system/trojan-web.service
  systemctl daemon-reload
  docker rm -f trojan-mysql trojan-mariadb 2>/dev/null || true
  colorEcho $green "Trojan removed successfully."
}

############ SYSTEM CHECK ######
checkSys() {
  [[ $(id -u) != 0 ]] && { colorEcho $red "Must run as root"; exit 1; }

  arch=$(uname -m)
  [[ "$arch" != "x86_64" && "$arch" != "aarch64" ]] && {
    colorEcho $red "Unsupported architecture: $arch"; exit 1;
  }

  if command -v apt-get >/dev/null; then
    package_manager=apt-get
  elif command -v yum >/dev/null; then
    package_manager=yum
  elif command -v dnf >/dev/null; then
    package_manager=dnf
  else
    colorEcho $red "Unsupported OS"
    exit 1
  fi
}

############ DEPENDENCIES ######
installDependent() {
  if [[ "$package_manager" == "apt-get" ]]; then
    apt-get update
    apt-get install -y curl socat cron bash-completion xz-utils
  else
    $package_manager install -y curl socat crontabs bash-completion
  fi
}

############ CERT (Cloudflare) #
install_cert_cloudflare() {
  [[ -z "$CERT_DOMAIN" ]] && return 0

  if [[ -z "$CF_Token" || -z "$CF_Account_ID" ]]; then
    colorEcho $red "Cloudflare env vars missing!"
    colorEcho $yellow "Please export CF_Token, CF_Account_ID, CERT_DOMAIN"
    exit 1
  fi

  export CF_Token CF_Account_ID

  if [[ ! -f "$HOME/.acme.sh/acme.sh" ]]; then
    curl -fsSL https://get.acme.sh | sh
  fi

  colorEcho $blue "Issuing TLS cert for $CERT_DOMAIN (Cloudflare DNS-01, ECDSA)..."

  "$HOME/.acme.sh/acme.sh" \
    --issue \
    --dns dns_cf \
    -d "$CERT_DOMAIN" \
    --keylength ec-256

  "$HOME/.acme.sh/acme.sh" \
    --install-cert -d "$CERT_DOMAIN" --ecc \
    --key-file       /usr/local/etc/trojan/private.key \
    --fullchain-file /usr/local/etc/trojan/fullchain.pem \
    --reloadcmd     "systemctl reload trojan-web || systemctl restart trojan-web"

  colorEcho $green "TLS installed and auto-renew enabled."
}

############ INSTALL TROJAN ####
installTrojan() {
  latest_version=$(curl -fsSL "$version_check" | grep tag_name | cut -d\" -f4)
  [[ "$arch" == "x86_64" ]] && bin="trojan-linux-amd64" || bin="trojan-linux-arm64"

  colorEcho $blue "Downloading Trojan $latest_version..."
  curl -fsSL "$download_url/$latest_version/$bin" -o /usr/local/bin/trojan
  chmod +x /usr/local/bin/trojan

  if [[ ! -f /etc/systemd/system/trojan-web.service ]]; then
    curl -fsSL "$service_url" -o /etc/systemd/system/trojan-web.service
    systemctl daemon-reload
    systemctl enable trojan-web
  fi

  install_cert_cloudflare

  systemctl restart trojan-web

  colorEcho $green "Trojan installed successfully."
  colorEcho $blue "Launching trojan manager..."
  trojan
}

############ MAIN #############
main() {
  [[ $help == 1 ]] && show_help && exit 0
  [[ $remove == 1 ]] && removeTrojan && exit 0

  checkSys

  # Only install deps if trojan not present
  [[ ! -x /usr/local/bin/trojan ]] && installDependent

  installTrojan
}

main
