#!/usr/bin/env bash
# Safer non-exiting defaults: we handle errors explicitly and keep the menu alive.
set -uo pipefail

#############################################
# Config you might want to tweak
#############################################
TELEPORT_VERSION="${TELEPORT_VERSION:-18.2.4}"
TELEPORT_PROXY="${TELEPORT_PROXY:-teleport.auth.freeletics.com:443}"
TELEPORT_AUTH="${TELEPORT_AUTH:-Engineering}"
TELEPORT_EDITION="${TELEPORT_EDITION:-oss}"   # linux installer edition (oss/ent/etc.)

DB_NAME_INTEGRATION="bodyweight"
DB_TUNNEL_INTEGRATION="fl-integration-cluster"

DB_NAME_PRODUCTION="bodyweight"
DB_TUNNEL_PRODUCTION="fl-prod-aurora"

KUBE_CLUSTER_INTEGRATION="fl-integration-12012024"
KUBE_CLUSTER_PRODUCTION="fl-production-13022024"

# Namespaces to browse for logs/exec
KUBE_NAMESPACES=(
  audit bodyweight coach coach-plus messaging nutrition
  payment social tracking user web-blog web-service-main web-ssr
)

#############################################
# UI helpers
#############################################
bold() { printf "\033[1m%s\033[0m\n" "$*"; }
warn() { printf "\033[33m%s\033[0m\n" "$*"; }
err()  { printf "\033[31m%s\033[0m\n" "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

open_url() {
  local url="$1"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    open "$url" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 || true
  elif command -v gio >/dev/null 2>&1; then
    gio open "$url" >/dev/null 2>&1 || true
  else
    echo "Open this URL in your browser:"
    echo "  $url"
  fi
}

# --- Ctrl-C handling: always bounce to menu ---
WAS_INTERRUPTED=0
on_sigint() {
  WAS_INTERRUPTED=1
  echo
  warn "Interrupted. Returning to menu..."
}
trap 'on_sigint' INT

pause() {
  if [[ "${WAS_INTERRUPTED:-0}" -eq 1 ]]; then
    WAS_INTERRUPTED=0
    return
  fi
  read -r -p "Press ENTER to continue..."
}

# Wrap long-running commands so Ctrl-C is "expected"
run_blocking() {
  set +e
  "$@"
  local status=$?
  set -e
  [[ $status -eq 130 ]] && WAS_INTERRUPTED=1
  return $status
}

#############################################
# OS / privilege
#############################################
OS="" ARCH="" SUDO=""
detect_os() {
  local uname_s uname_m
  uname_s="$(uname -s)"
  uname_m="$(uname -m)"
  case "$uname_s" in
    Darwin) OS="macos" ;;
    Linux)  OS="linux" ;;
    *) err "Unsupported OS: $uname_s"; exit 1 ;;
  esac
  case "$uname_m" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) ARCH="$uname_m" ;;
  esac
}
require_sudo() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    SUDO="sudo"
  else
    SUDO=""
  fi
}

#############################################
# Installers
#############################################
install_fzf() {
  if have fzf; then return 0; fi
  warn "fzf is required for the menu."
  read -r -p "Install fzf now? [y/N]: " yn || true
  case "${yn:-N}" in
    y|Y)
      if [[ "$OS" == "macos" ]]; then
        if have brew; then
          brew install fzf || { err "brew install fzf failed"; exit 1; }
        else
          err "Homebrew not found. Install Homebrew or install fzf manually: https://github.com/junegunn/fzf"
          exit 1
        fi
      else
        if have apt; then
          $SUDO apt-get update -y && $SUDO apt-get install -y fzf
        elif have dnf; then
          $SUDO dnf install -y fzf
        elif have yum; then
          $SUDO yum install -y fzf
        elif have pacman; then
          $SUDO pacman -Sy --noconfirm fzf
        else
          err "No known package manager found. Please install fzf manually: https://github.com/junegunn/fzf"
          exit 1
        fi
      fi
      ;;
    *) err "fzf is required. Aborting."; exit 1 ;;
  esac
}

install_teleport_macos() {
  local pkg_url="https://cdn.teleport.dev/teleport-${TELEPORT_VERSION}.pkg"
  local pkg_file="/tmp/teleport-${TELEPORT_VERSION}.pkg"
  bold "Downloading Teleport macOS package ${TELEPORT_VERSION}..."
  curl -fsSL -o "$pkg_file" "$pkg_url"
  bold "Installing Teleport (you may be prompted for sudo password)..."
  sudo installer -pkg "$pkg_file" -target /
}

install_teleport_linux() {
  bold "Installing Teleport ${TELEPORT_VERSION} (${TELEPORT_EDITION}) via official installer..."
  curl -fsSL "https://cdn.teleport.dev/install.sh" | bash -s "${TELEPORT_VERSION}" "${TELEPORT_EDITION}"
}

ensure_teleport_installed() {
  if have tsh; then return 0; fi
  bold "Teleport (tsh) not found. Installing..."
  if [[ "$OS" == "macos" ]]; then
    install_teleport_macos
  else
    install_teleport_linux
  fi
  if ! have tsh; then
    err "tsh not found after installation. Please check your PATH or installation logs."
    exit 1
  fi
}

#############################################
# Proxy reachability (VPN pre-check)
#############################################
PROXY_HOST="" PROXY_PORT=""
parse_proxy() {
  local p="$TELEPORT_PROXY"
  p="${p#http://}"; p="${p#https://}"
  PROXY_HOST="${p%:*}"
  PROXY_PORT="${p##*:}"
  [[ "$PROXY_HOST" == "$PROXY_PORT" ]] && PROXY_PORT="443"
}

proxy_reachable() {
  # Try nc, then curl, then openssl, then /dev/tcp
  if have nc; then
    nc -z -w 3 "$PROXY_HOST" "$PROXY_PORT" >/dev/null 2>&1 && return 0
  fi
  if have curl; then
    curl -sk --connect-timeout 5 "https://${PROXY_HOST}:${PROXY_PORT}/" -o /dev/null && return 0
  fi
  if have openssl; then
    (echo | openssl s_client -connect "${PROXY_HOST}:${PROXY_PORT}" -servername "${PROXY_HOST}" -brief >/dev/null 2>&1) && return 0
  fi
  # Bash /dev/tcp test
  ( exec 3<>/dev/tcp/"$PROXY_HOST"/"$PROXY_PORT" ) >/dev/null 2>&1 && { exec 3>&- 2>/dev/null || true; return 0; }
  return 1
}

#############################################
# MFA helpers (stateless checks using tsh mfa ls)
#############################################
mfa_ls_json() {
  tsh mfa ls --format=json 2>/dev/null || tsh mfa ls 2>/dev/null || true
}

has_totp_device() {
  local out; out="$(mfa_ls_json)"
  [[ -z "$out" ]] && return 1
  grep -qiE '"type"\s*:\s*"totp"|(^|[^a-zA-Z])TOTP([^a-zA-Z]|$)' <<<"$out"
}

has_touchid_or_webauthn_device() {
  local out; out="$(mfa_ls_json)"
  [[ -z "$out" ]] && return 1
  grep -qiE '"type"\s*:\s*"touchid"|"type"\s*:\s*"webauthn"|(^|[^a-zA-Z])(TOUCHID|WEBAUTHN)([^a-zA-Z]|$)' <<<"$out"
}

ensure_totp_present_flow() {
  if has_totp_device; then return 0; fi

  parse_proxy
  local base="https://${PROXY_HOST}"
  [[ "${PROXY_PORT}" != "443" ]] && base="${base}:${PROXY_PORT}"
  local dash="${base}/web/"

  err "No TOTP device is registered for your Teleport account."
  echo "You must add a TOTP device (Authenticator app) before continuing."
  echo
  echo "I'll open the Teleport dashboard. In the UI, go to:"
  echo "  Account → Security / Multi-factor Authentication → Add TOTP"
  echo
  open_url "$dash"
  read -r -p "When you've added a TOTP device, press ENTER to re-check..." _

  if ! has_totp_device; then
    err "Still no TOTP detected. Please finish adding TOTP in the dashboard."
    read -r -p "Press ENTER to check again (or Ctrl-C to abort)..." _
    has_totp_device || { err "No TOTP device found. Aborting."; return 1; }
  fi

  bold "TOTP detected. Proceeding…"
}

add_touchid_or_webauthn_flow() {
  # Skip if already present
  if has_touchid_or_webauthn_device; then
    return 0
  fi

  # Require TOTP first (as proof for registering passkey)
  ensure_totp_present_flow || return 1

  local type_flag
  if [[ "$OS" == "macos" ]]; then
    type_flag="--type TOUCHID"
  else
    type_flag="--type WEBAUTHN"
  fi

  bold "Adding a ${type_flag#--type } device (you'll be asked for a TOTP code, then Touch ID / security key)…"
  run_blocking tsh mfa add --proxy="${TELEPORT_PROXY}" ${type_flag} --mfa-mode=otp || true

  if ! has_touchid_or_webauthn_device; then
    err "Could not confirm a Touch ID/WebAuthn device was added."
    echo "If the flow failed or timed out, please try again:"
    echo "  tsh mfa add --proxy='${TELEPORT_PROXY}' ${type_flag} --mfa-mode=otp"
    return 1
  fi

  bold "Touch ID / WebAuthn device detected."
}

ensure_db_mfa_requirements() {
  ensure_logged_in || return 1
  ensure_totp_present_flow || return 1
  add_touchid_or_webauthn_flow || return 1
  return 0
}

#############################################
# Teleport session helpers
#############################################
ensure_logged_in() {
  parse_proxy
  local st
  st="$(tsh status 2>/dev/null || true)"
  if ! grep -q "Proxy: .*${PROXY_HOST}:${PROXY_PORT}" <<<"$st"; then
    warn "Not logged in to ${PROXY_HOST}:${PROXY_PORT}. Launching login…"
    tsh_login || return 1
  fi
  return 0
}

#############################################
# Teleport actions
#############################################
tsh_login() {
  parse_proxy
  bold "Checking reachability of Teleport proxy: ${PROXY_HOST}:${PROXY_PORT} ..."
  if ! proxy_reachable; then
    err "Proxy ${PROXY_HOST}:${PROXY_PORT} is not reachable."
    warn "If this proxy is reachable only via VPN, please enable your VPN and try again."
    read -r -p "Press ENTER to return to menu, or type 'force' to try login anyway: " ans || true
    if [[ "${ans:-}" != "force" ]]; then
      return 0
    fi
  fi

  bold "Logging into Teleport..."
  run_blocking tsh login --proxy="${TELEPORT_PROXY}" --auth="${TELEPORT_AUTH}" || true

  # === MFA bootstrap ===
  ensure_totp_present_flow || return 0
  add_touchid_or_webauthn_flow || true

  pause
}

tsh_logout() {
  bold "Teleport logout..."
  run_blocking tsh logout || true
  pause
}

#############################################
# DB Proxy helpers (interactive; no output capture)
#############################################
prompt_port() {
  local default_port="${1:-5432}"
  local port
  read -r -p "Port to listen on [${default_port}] (press ENTER for default PostgreSQL port): " port || true
  port="${port:-$default_port}"
  echo "$port"
}
prompt_db_user() {
  local default_user="${1:-root}"
  local user
  read -r -p "Database user [${default_user}]: " user || true
  user="${user:-$default_user}"
  echo "$user"
}

proxy_db() {
  local tunnel="$1"      # Teleport DB resource name
  local dbname="$2"      # SQL database name
  local default_port="${3:-5432}"

  # Enforce MFA prerequisites before DB
  ensure_db_mfa_requirements || return 0

  local dbuser port
  dbuser="$(prompt_db_user "root")"
  port="$(prompt_port "$default_port")"

  bold "Preparing DB session (MFA may prompt)…"
  if ! run_blocking tsh db login --db-user "${dbuser}" --db-name "${dbname}" "${tunnel}"; then
    err "tsh db login failed. You can try inline connect:"
    echo "  tsh db connect --db-user \"${dbuser}\" --db-name \"${dbname}\" \"${tunnel}\""
    pause
    return 0
  fi

  bold "Starting DB proxy for ${dbname} via tunnel ${tunnel} on localhost:${port}"
  warn "Press CTRL-C to stop and return to the menu."
  echo
  run_blocking tsh proxy db --tunnel "${tunnel}" --port "${port}" || true

  if [[ "${WAS_INTERRUPTED:-0}" -eq 1 ]]; then
    WAS_INTERRUPTED=0
    return
  fi

  echo
  echo "Sample connection strings (adjust user as needed):"
  echo "  postgresql://${dbuser}@127.0.0.1:${port}/${dbname}"
  echo "  postgresql://${dbuser}@127.0.0.1:${port}/${dbname}?sslmode=verify-full"
  pause
}

#############################################
# Kubernetes helpers
#############################################
need_kubectl() {
  if ! have kubectl; then
    err "kubectl not found. Please install kubectl before using Kubernetes options."
    if [[ "$OS" == "macos" ]]; then
      echo "  macOS (Homebrew): brew install kubectl"
    else
      echo "  Ubuntu/Debian: sudo apt-get install -y kubectl (see Kubernetes docs for repo setup)"
      echo "  Fedora/RHEL/CentOS: use dnf/yum per Kubernetes docs"
    fi
    pause
    return 1
  fi
  return 0
}

kube_login() {
  local cluster="$1"
  bold "tsh kube login ${cluster}"
  run_blocking tsh kube login "${cluster}" || true
}

choose_env() {
  printf "integration\nproduction\n" | fzf --prompt="Environment > " --height=10 --border || true
}

context_for_cluster() {
  local cluster="$1"
  kubectl config get-contexts -o name 2>/dev/null | grep -i "$cluster" | head -n1 || true
}

choose_namespace() {
  printf "%s\n" "${KUBE_NAMESPACES[@]}" | fzf --prompt="Namespace > " --height=20 --border || true
}

list_pods_in_namespace() {
  local ctx="$1" ns="$2"
  kubectl ${ctx:+--context "$ctx"} -n "$ns" get pods --no-headers 2>/dev/null | awk '{print $1}'
}

# Return only pods suitable for exec: Running + has 'rails' container
list_exec_pods_in_namespace() {
  local ctx="$1" ns="$2"
  local pods pod phase containers
  pods="$(list_pods_in_namespace "$ctx" "$ns" || true)"
  [[ -z "${pods:-}" ]] && return 0
  while IFS= read -r pod; do
    phase="$(kubectl ${ctx:+--context "$ctx"} -n "$ns" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    containers="$(kubectl ${ctx:+--context "$ctx"} -n "$ns" get pod "$pod" -o jsonpath='{..containers[*].name}' 2>/dev/null || true)"
    if [[ "$phase" == "Running" ]] && grep -qE '(^| )rails( |$)' <<<"$containers"; then
      printf "%s\n" "$pod"
    fi
  done <<< "$pods"
}

#############################################
# Kubernetes flows (env → ns → pod)
#############################################
kube_logs_flow() {
  need_kubectl || return 0

  local env cluster ctx ns pod
  env="$(choose_env)"
  [[ -z "${env:-}" ]] && return 0

  if [[ "$env" == "integration" ]]; then
    cluster="$KUBE_CLUSTER_INTEGRATION"
  else
    cluster="$KUBE_CLUSTER_PRODUCTION"
  fi

  kube_login "$cluster"
  ctx="$(context_for_cluster "$cluster")"
  [[ -z "$ctx" ]] && warn "Could not detect a matching kubectl context. Using current context."

  ns="$(choose_namespace)"
  [[ -z "${ns:-}" ]] && return 0

  pod="$(list_pods_in_namespace "${ctx:-}" "$ns" | while read -r p; do
          names="$(kubectl ${ctx:+--context "$ctx"} -n "$ns" get pod "$p" -o jsonpath='{..containers[*].name}' 2>/dev/null || true)"
          grep -qE '(^| )rails( |$)' <<<"$names" && echo "$p"
        done | fzf --prompt="Pod in $ns > " --height=25 --border)"
  [[ -z "${pod:-}" ]] && return 0

  if ! kubectl ${ctx:+--context "$ctx"} -n "$ns" get pod "$pod" -o jsonpath='{..containers[*].name}' 2>/dev/null \
      | tr ' ' '\n' | grep -qx 'rails'; then
    err "Container 'rails' not found in $pod. Aborting logs."
    pause
    return 0
  fi

  bold "Streaming logs for container 'rails' from ${pod} (ns=${ns})..."
  warn "Press CTRL-C to stop and return to the menu."
  run_blocking kubectl ${ctx:+--context "$ctx"} -n "$ns" logs -f "$pod" -c rails || true

  if [[ "${WAS_INTERRUPTED:-0}" -eq 1 ]]; then
    WAS_INTERRUPTED=0
    return
  fi
  pause
}

kube_exec_flow() {
  need_kubectl || return 0

  local env cluster ctx ns pod
  env="$(choose_env)"
  [[ -z "${env:-}" ]] && return 0

  if [[ "$env" == "integration" ]]; then
    cluster="$KUBE_CLUSTER_INTEGRATION"
  else
    cluster="$KUBE_CLUSTER_PRODUCTION"
  fi

  kube_login "$cluster"
  ctx="$(context_for_cluster "$cluster")"
  [[ -z "$ctx" ]] && warn "Could not detect a matching kubectl context. Using current context."

  ns="$(choose_namespace)"
  [[ -z "${ns:-}" ]] && return 0

  pod="$(list_exec_pods_in_namespace "${ctx:-}" "$ns" | fzf --prompt="Pod in $ns (exec) > " --height=25 --border || true)"
  [[ -z "${pod:-}" ]] && return 0

  bold "Exec into $pod (ns=$ns) container 'rails' using /bin/bash"
  warn "Inside the remote shell, use 'exit' or Ctrl-D to return to the menu."

  run_blocking kubectl ${ctx:+--context "$ctx"} exec -it "$pod" -n "$ns" -c rails -- /bin/bash || true

  if [[ "${WAS_INTERRUPTED:-0}" -eq 1 ]]; then
    WAS_INTERRUPTED=0
    return
  fi
  pause
}

#############################################
# Main menu
#############################################
main_menu() {
  while :; do
    local choice
    choice="$(
      printf "%s\n" \
        "Login to Teleport (tsh login)" \
        "DB: Proxy Integration (${DB_TUNNEL_INTEGRATION} → ${DB_NAME_INTEGRATION})" \
        "DB: Proxy Production (${DB_TUNNEL_PRODUCTION} → ${DB_NAME_PRODUCTION})" \
        "K8s: Login Integration (${KUBE_CLUSTER_INTEGRATION})" \
        "K8s: Login Production (${KUBE_CLUSTER_PRODUCTION})" \
        "K8s: Logs (env → ns → pod 'rails')" \
        "K8s: Exec (env → ns → pod 'rails')" \
        "Teleport Logout" \
        "Quit" \
      | fzf --prompt="Teleport Helper > " --height=20 --border
    )" || true

    case "${choice:-}" in
      "Login to Teleport (tsh login)") tsh_login ;;
      "DB: Proxy Integration"*) proxy_db "$DB_TUNNEL_INTEGRATION" "$DB_NAME_INTEGRATION" "5432" ;;
      "DB: Proxy Production"*)  proxy_db "$DB_TUNNEL_PRODUCTION"   "$DB_NAME_PRODUCTION"   "5432" ;;
      "K8s: Login Integration"*) kube_login "$KUBE_CLUSTER_INTEGRATION"; pause ;;
      "K8s: Login Production"*)  kube_login "$KUBE_CLUSTER_PRODUCTION"; pause ;;
      "K8s: Logs"*)              kube_logs_flow ;;
      "K8s: Exec"*)              kube_exec_flow ;;
      "Teleport Logout")         tsh_logout ;;
      "Quit")                    break ;;
      "" )                       ;;   # cancelled -> redisplay menu
      * )                        ;;   # unknown -> redisplay menu
    esac
  done
}

#############################################
# Bootstrap
#############################################
detect_os
require_sudo
install_fzf
ensure_teleport_installed

bold "tsh version:"
tsh version || true
main_menu