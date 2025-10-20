#!/usr/bin/env bash
# Safer non-exiting defaults: we handle errors explicitly and keep the menu alive.
set -uo pipefail

# Store original arguments for potential restart after update
ORIGINAL_ARGS=("$@")

#############################################
# Logging setup
#############################################
# Define log file path in user's home directory
LOG_FILE="${HOME}/.teleport_helper.log"

# Create a new log file (clear any existing one)
: > "$LOG_FILE"

# Start logging session with timestamp and system info
{
    echo "=== Teleport Helper Log $(date) ==="
    echo "System: $(uname -a)"
    echo "User: $(whoami)"
    echo "Script: $0"
    echo "Args: $*"
    echo "========================================"
    echo ""
} >> "$LOG_FILE"

# Create a filter function to strip ANSI escape sequences and control characters
strip_ansi() {
    # Remove ANSI escape sequences, cursor movement commands, and other control sequences
    sed -E 's/\x1B\[[0-9;]*[a-zA-Z]//g' | 
    sed -E 's/\x1B\][0-9;]*[a-zA-Z]//g' | 
    sed -E 's/\x1B\[[0-9]+n//g' |
    sed -E 's/\x1B\[[0-9]+;[0-9]+[HfR]//g' |
    sed -E 's/\x1B\[[0-9]+[ABCDEFGJKST]//g' |
    sed -E 's/\x1B\[[\?=][0-9;]*[hlm]//g' |
    sed 's/\r//' |
    grep -v '^\s*$' # Remove empty lines
}

# Redirect stderr to both console and log file (with ANSI filtering)
exec 3>&2 # Save original stderr
exec 2> >(tee >(strip_ansi >> "$LOG_FILE") >&3)

# Function to log messages
log_msg() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $msg" >> "$LOG_FILE"
}

# Set up error trap to log any errors
trap_err() {
    local lineno=$1
    local command=$2
    local code=${3:-1}
    log_msg "ERROR" "Command '$command' failed with exit code $code at line $lineno"
}
trap 'trap_err ${LINENO} "$BASH_COMMAND" $?' ERR

# Log start of script execution
log_msg "INFO" "Script started"

#############################################
# Config you might want to tweak
#############################################
TELEPORT_VERSION="${TELEPORT_VERSION:-18.2.2}"
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
bold() { 
    printf "\033[1m%s\033[0m\n" "$*"
    log_msg "INFO" "[BOLD] $*"
}
warn() { 
    printf "\033[33m%s\033[0m\n" "$*"
    log_msg "WARN" "$*"
}
err()  { 
    printf "\033[31m%s\033[0m\n" "$*" >&2
    log_msg "ERROR" "$*"
}
debug() {
    # Only log to file, don't display on screen
    log_msg "DEBUG" "$*"
}
have() { 
    command -v "$1" >/dev/null 2>&1
    local ret=$?
    if [ $ret -eq 0 ]; then
        log_msg "DEBUG" "Command '$1' is available"
    else
        log_msg "DEBUG" "Command '$1' is not available"
    fi
    return $ret
}

open_url() {
  local url="$1"
  log_msg "INFO" "Attempting to open URL: $url"
  
  if [[ "$(uname -s)" == "Darwin" ]]; then
    log_msg "DEBUG" "Using macOS 'open' command"
    open "$url" >/dev/null 2>&1 || { 
        log_msg "ERROR" "Failed to open URL with 'open' command"
        true
    }
  elif command -v xdg-open >/dev/null 2>&1; then
    log_msg "DEBUG" "Using 'xdg-open' command"
    xdg-open "$url" >/dev/null 2>&1 || {
        log_msg "ERROR" "Failed to open URL with 'xdg-open' command"
        true
    }
  elif command -v gio >/dev/null 2>&1; then
    log_msg "DEBUG" "Using 'gio open' command"
    gio open "$url" >/dev/null 2>&1 || {
        log_msg "ERROR" "Failed to open URL with 'gio open' command"
        true
    }
  else
    log_msg "WARN" "No suitable command found to open URLs"
    echo "Open this URL in your browser:"
    echo "  $url"
  fi
}

# --- Ctrl-C handling: always bounce to menu ---
WAS_INTERRUPTED=0
on_sigint() {
  WAS_INTERRUPTED=1
  echo
  log_msg "INFO" "User interrupted execution (Ctrl-C)"
  warn "Interrupted. Returning to menu..."
}
trap 'on_sigint' INT

pause() {
  if [[ "${WAS_INTERRUPTED:-0}" -eq 1 ]]; then
    WAS_INTERRUPTED=0
    log_msg "DEBUG" "Pause skipped due to previous interruption"
    return
  fi
  log_msg "DEBUG" "Pausing for user input"
  read -r -p "Press ENTER to continue..."
  log_msg "DEBUG" "User continued after pause"
}

# Wrap long-running commands so Ctrl-C is "expected"
run_blocking() {
  log_msg "INFO" "Running command: $*"
  set +e
  "$@" 2> >(tee -a "$LOG_FILE" >&2)
  local status=$?
  set -e
  log_msg "INFO" "Command completed with status: $status"
  [[ $status -eq 130 ]] && {
    WAS_INTERRUPTED=1
    log_msg "INFO" "Command was interrupted by user"
  }
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

need_jq() {
  if ! have jq; then
    err "jq not found. Please install jq before using Kubernetes options."
    if [[ "$OS" == "macos" ]]; then
      echo "  macOS (Homebrew): brew install jq"
    else
      echo "  Ubuntu/Debian: sudo apt-get install -y jq"
      echo "  Fedora/RHEL/CentOS: sudo dnf install jq / sudo yum install jq"
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
  # Get pods with status and container info in one command for better performance
  kubectl ${ctx:+--context "$ctx"} -n "$ns" get pods -o custom-columns="NAME:.metadata.name,STATUS:.status.phase,CONTAINERS:.spec.containers[*].name" --no-headers 2>/dev/null | 
    awk '{print $1}'
}

# Return only pods suitable for exec: Running + has 'rails' container
list_exec_pods_in_namespace() {
  local ctx="$1" ns="$2"
  need_jq || return 1
  
  # Get pods with status and container info in one command for better performance
  kubectl ${ctx:+--context "$ctx"} -n "$ns" get pods -o json 2>/dev/null | 
    jq -r '.items[] | 
           select(.status.phase=="Running") | 
           select(.spec.containers[].name=="rails") | 
           .metadata.name'
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

  bold "Fetching pods with rails container..."
  # Get pods with rails container in one call for better performance
  pod="$(kubectl ${ctx:+--context "$ctx"} -n "$ns" get pods -o custom-columns="NAME:.metadata.name,STATUS:.status.phase,CONTAINERS:.spec.containers[*].name" --no-headers 2>/dev/null |
         grep -i "rails" | awk '{print $1}' | fzf --prompt="Pod in $ns > " --height=25 --border)"
  [[ -z "${pod:-}" ]] && return 0

  # Check container with direct access to avoid additional kubectl calls
  container_list=$(kubectl ${ctx:+--context "$ctx"} -n "$ns" get pod "$pod" -o jsonpath="{.spec.containers[*].name}" 2>/dev/null)
  debug "Available containers in pod: $container_list"
  
  if ! echo "$container_list" | grep -qE '(^|,| )rails($|,| )'; then
    err "Container 'rails' not found in $pod. Aborting logs."
    debug "Containers in pod are: $container_list"
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

  # Double-check the container exists (better safe than sorry)
  container_list=$(kubectl ${ctx:+--context "$ctx"} -n "$ns" get pod "$pod" -o jsonpath="{.spec.containers[*].name}" 2>/dev/null)
  debug "Available containers in pod: $container_list"
  
  if ! echo "$container_list" | grep -qE '(^|,| )rails($|,| )'; then
    err "Container 'rails' not found in $pod. Aborting exec."
    debug "Containers in pod are: $container_list"
    pause
    return 0
  fi

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
# System check functions
#############################################
# Emoji indicators for system checks
EMOJI_SUCCESS="✅"
EMOJI_WARNING="⚠️"
EMOJI_ERROR="❌"
EMOJI_INFO="ℹ️"
EMOJI_PENDING="🔄"

# Check if the Teleport proxy is reachable (NETWORK CONNECTIVITY ONLY)
check_teleport_proxy() {
  echo -n "Teleport proxy ($TELEPORT_PROXY) reachable: "
  
  # Use existing global variables and proxy_reachable function
  # Ensure proxy host and port are set correctly
  parse_proxy
  
  # Try simple TCP connection test without checking login status
  if proxy_reachable; then
    echo "$EMOJI_SUCCESS Network connectivity confirmed"
    return 0
  else
    echo "$EMOJI_ERROR No network connectivity - check VPN or network connection"
    log_msg "DEBUG" "Failed to connect to proxy ${PROXY_HOST}:${PROXY_PORT}"
    return 1
  fi
}

# Check DNS settings
check_dns_settings() {
  echo -n "DNS settings: "
  local dns_servers=$(cat /etc/resolv.conf | grep -E '^nameserver' | awk '{print $2}')
  
  if echo "$dns_servers" | grep -q "10.130.0.2"; then
    echo "$EMOJI_SUCCESS Using expected nameserver (10.130.0.2)"
    return 0
  else
    echo "$EMOJI_WARNING Not using expected nameserver 10.130.0.2"
    echo "  Current nameservers: $dns_servers"
    return 1
  fi
}

# Check if user is logged in to Teleport
check_teleport_login() {
  echo -n "Teleport login status: "
  
  if ! have tsh; then
    echo "$EMOJI_ERROR tsh command not found"
    return 1
  fi
  
  local login_status=$(tsh status 2>&1)
  if echo "$login_status" | grep -q "You are not logged in"; then
    echo "$EMOJI_WARNING Not logged in"
    return 1
  else
    # Try multiple methods to extract username
    local username=""
    # Method 1: Try getting from status directly
    username=$(tsh status | grep -E '^>|^Profile' | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -1)
    
    # Method 2: If empty, try getting from tsh status Username field
    if [[ -z "$username" ]]; then
      username=$(tsh status | grep -i "username" | awk '{print $2}')
    fi
    
    # Method 3: If still empty, try from whoami command
    if [[ -z "$username" ]]; then
      username=$(tsh whoami 2>/dev/null || echo "")
    fi
    
    # Fallback
    if [[ -z "$username" ]]; then
      username="$(whoami)@$(tsh status | grep -i "proxy" | awk '{print $2}')"
    fi
    
    echo "$EMOJI_SUCCESS Logged in as $username"
    return 0
  fi
}

# Check for important tools
check_required_tools() {
  local missing=0
  local all_tools="tsh kubectl jq nc curl grep awk sed"
  local missing_tools=""
  local present_tools=""
  
  # First check all tools
  for tool in $all_tools; do
    if have "$tool"; then
      present_tools="$present_tools $tool"
    else
      missing_tools="$missing_tools $tool"
      missing=$((missing + 1))
    fi
  done
  
  # Report on present tools
  if [[ -n "$present_tools" ]]; then
    echo "$EMOJI_SUCCESS Present:$(echo $present_tools | sed 's/ /, /g')"
  fi
  
  # Report on missing tools
  if [[ -n "$missing_tools" ]]; then
    echo "$EMOJI_ERROR Missing:$(echo $missing_tools | sed 's/ /, /g')"
    echo "  Please install missing tools for full functionality"
  fi
  
  return $missing
}

# Check if user can access DBs
check_database_access() {
  echo -n "Database access: "
  
  # Try to list databases to verify access
  local result
  result=$(tsh db ls 2>&1)
  local status_code=$?
  
  if [[ $status_code -ne 0 ]]; then
    echo "$EMOJI_ERROR Cannot access databases (command failed)"
    echo "  Error: $result"
    return 1
  elif echo "$result" | grep -qE "error|denied|not found"; then
    echo "$EMOJI_ERROR Cannot access databases"
    echo "  Error: $result"
    return 1
  elif echo "$result" | grep -q "$DB_TUNNEL_INTEGRATION\|$DB_TUNNEL_PRODUCTION"; then
    echo "$EMOJI_SUCCESS Can access required databases"
    # List the databases found
    echo "  Databases: $(echo "$result" | grep -E "$DB_TUNNEL_INTEGRATION|$DB_TUNNEL_PRODUCTION" | awk '{print $1}' | paste -sd "," -)"
    return 0
  else
    echo "$EMOJI_WARNING Can access databases but expected tunnels not found"
    echo "  Available databases: $(echo "$result" | grep -v "^NAME" | awk '{print $1}' | paste -sd "," -)"
    return 1
  fi
}

# Check if user can access Kubernetes
check_kubernetes_access() {
  echo -n "Kubernetes access: "
  
  # Try to list clusters to verify access
  local result
  result=$(tsh kube ls 2>&1)
  local status_code=$?
  
  if [[ $status_code -ne 0 ]]; then
    echo "$EMOJI_ERROR Cannot access Kubernetes clusters (command failed)"
    echo "  Error: $result"
    return 1
  elif echo "$result" | grep -qE "error|denied|not found"; then
    echo "$EMOJI_ERROR Cannot access Kubernetes clusters"
    echo "  Error: $result"
    return 1
  elif echo "$result" | grep -q "$KUBE_CLUSTER_INTEGRATION\|$KUBE_CLUSTER_PRODUCTION"; then
    echo "$EMOJI_SUCCESS Can access required Kubernetes clusters"
    # List the clusters found
    echo "  Clusters: $(echo "$result" | grep -E "$KUBE_CLUSTER_INTEGRATION|$KUBE_CLUSTER_PRODUCTION" | awk '{print $1}' | paste -sd "," -)"
    return 0
  else
    echo "$EMOJI_WARNING Can access Kubernetes but expected clusters not found"
    echo "  Available clusters: $(echo "$result" | grep -v "^NAME" | awk '{print $1}' | paste -sd "," -)"
    return 1
  fi
}

# Check MFA TOTP status
check_mfa_totp() {
  echo -n "MFA TOTP: "
  
  local result
  result=$(tsh mfa ls 2>&1)
  
  if [[ $? -ne 0 ]]; then
    echo "$EMOJI_ERROR Failed to check MFA status"
    return 1
  elif echo "$result" | grep -q "TOTP"; then
    local device=$(echo "$result" | grep "TOTP" | awk '{print $1}')
    echo "$EMOJI_SUCCESS Configured ($device)"
    return 0
  else
    echo "$EMOJI_ERROR Not configured (required)"
    return 1
  fi
}

# Check Touch ID MFA status
check_touch_id() {
  echo -n "Touch ID MFA: "
  
  # Check if platform supports Touch ID
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "$EMOJI_INFO Not available on this platform"
    return 0
  fi
  
  local result
  result=$(tsh mfa ls 2>&1)
  
  if [[ $? -ne 0 ]]; then
    echo "$EMOJI_ERROR Failed to check MFA status"
    return 1
  elif echo "$result" | grep -qiE "WebAuthn|TouchID|Passkey"; then
    local device=$(echo "$result" | grep -iE "WebAuthn|TouchID|Passkey" | awk '{print $1}')
    echo "$EMOJI_SUCCESS Configured ($device)"
    return 0
  else
    echo "$EMOJI_WARNING Not configured (recommended for macOS users)"
    return 1
  fi
}

# Run all basic system checks and return overall status
run_basic_system_checks() {
  local status=0
  
  bold "Running basic system checks..."
  echo
  
  bold "Network Connectivity:"
  check_teleport_proxy || status=1
  check_dns_settings || status=1
  echo
  
  bold "Teleport Status:"
  check_teleport_login || status=1
  echo
  
  bold "Required Tools:"
  check_required_tools || status=1
  
  return $status
}

# Run advanced system checks (only if logged in)
run_advanced_system_checks() {
  local status=0
  
  bold "Running advanced system checks (requires active Teleport login)..."
  echo
  
  # Only run these checks if the user is logged in
  if ! check_teleport_login > /dev/null; then
    echo "$EMOJI_WARNING Skipping advanced checks - not logged in to Teleport"
    return 1
  fi
  
  bold "Resource Access:"
  check_database_access || status=1
  check_kubernetes_access || status=1
  echo
  
  bold "Security Configuration:"
  check_mfa_totp || status=1
  check_touch_id || status=1
  
  return $status
}

# Main system check function
system_check() {
  clear
  bold "System Check Results"
  echo "======================="
  echo "Date: $(date)"
  echo "User: $(whoami)"
  echo "Host: $(hostname)"
  echo "OS: $(uname -s) $(uname -r)"
  echo "======================="
  echo
  
  local basic_status=0
  local advanced_status=0
  
  run_basic_system_checks || basic_status=1
  echo
  run_advanced_system_checks || advanced_status=1
  
  echo
  echo "======================="
  bold "Summary:"
  
  if [[ $basic_status -eq 0 && $advanced_status -eq 0 ]]; then
    bold "$EMOJI_SUCCESS All system checks passed!"
  elif [[ $basic_status -eq 0 && $advanced_status -ne 0 ]]; then
    bold "$EMOJI_WARNING Basic checks passed but some advanced checks failed"
    echo "    - Check MFA configuration settings"
    echo "    - Verify access to required resources"
  else
    bold "$EMOJI_ERROR System check found issues that need attention"
    echo "    - Basic connectivity or tool issues detected"
    echo "    - Please resolve these before attempting to use Teleport"
  fi
  echo
  
  # Log the check results
  log_msg "INFO" "System check completed. Basic checks: $([[ $basic_status -eq 0 ]] && echo "PASS" || echo "FAIL"), Advanced checks: $([[ $advanced_status -eq 0 ]] && echo "PASS" || echo "FAIL")"
  echo
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
        "System Check (connectivity, access, MFA status)" \
        "Install Shell Shortcuts (k alias, tp login/logout, kns)" \
        "Check for Updates" \
        "Report a Bug" \
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
      "System Check"*)          system_check; pause ;;
      "Install Shell Shortcuts"*) install_shell_shortcuts ;;
      "Check for Updates")       check_and_update_script ;;
      "Report a Bug")            create_bug_report ;;
      "Teleport Logout")         tsh_logout ;;
      "Quit")                    break ;;
      "" )                       ;;   # cancelled -> redisplay menu
      * )                        ;;   # unknown -> redisplay menu
    esac
  done
}

#############################################
# Shell shortcuts installation
#############################################
install_shell_shortcuts() {
  local shell_rc=""
  local install_k_alias="y"
  local install_tp_login="y"
  local install_tp_logout="y"
  local install_kns_function="y"
  local install_tp_script_command="y"
  local tp_function=""
  local kns_function=""
  local script_path="$(realpath "$0" 2>/dev/null || echo "$0")"
  
  # Determine which shell config file to use
  if [[ "$SHELL" == */zsh ]]; then
    shell_rc="${HOME}/.zshrc"
  elif [[ "$SHELL" == */bash ]]; then
    if [[ -f "${HOME}/.bashrc" ]]; then
      shell_rc="${HOME}/.bashrc"
    elif [[ -f "${HOME}/.bash_profile" ]]; then
      shell_rc="${HOME}/.bash_profile"
    fi
  else
    warn "Unsupported shell: $SHELL"
    echo "Only bash and zsh are currently supported for shortcuts."
    return 1
  fi
  
  if [[ ! -f "$shell_rc" ]]; then
    err "Shell configuration file not found: $shell_rc"
    return 1
  fi
  
  # Check for existing shortcuts section
  local has_existing_shortcuts=0
  if grep -q "# Teleport shortcuts added on" "$shell_rc"; then
    has_existing_shortcuts=1
    bold "Found existing Teleport shortcuts in $shell_rc"
    echo "Existing shortcuts will be updated"
  fi
  
  bold "Shell shortcuts installation"
  echo "This will add helpful aliases to: $shell_rc"
  echo "AND make them available in your current session immediately"
  echo
  
  read -r -p "Install 'k' alias for 'tsh kubectl --'? [Y/n]: " response
  case "${response:-y}" in
    [yY]|[yY][eE][sS]|"") install_k_alias="y" ;;
    *) install_k_alias="n" ;;
  esac
  
  read -r -p "Install 'tp login' shortcut for Teleport login? [Y/n]: " response
  case "${response:-y}" in
    [yY]|[yY][eE][sS]|"") install_tp_login="y" ;;
    *) install_tp_login="n" ;;
  esac
  
  read -r -p "Install 'tp logout' shortcut for Teleport logout? [Y/n]: " response
  case "${response:-y}" in
    [yY]|[yY][eE][sS]|"") install_tp_logout="y" ;;
    *) install_tp_logout="n" ;;
  esac
  
  read -r -p "Install 'kns' function for changing Kubernetes namespaces? [Y/n]: " response
  case "${response:-y}" in
    [yY]|[yY][eE][sS]|"") install_kns_function="y" ;;
    *) install_kns_function="n" ;;
  esac
  
  read -r -p "Install 'tp' command to run this script directly? [Y/n]: " response
  case "${response:-y}" in
    [yY]|[yY][eE][sS]|"") install_tp_script_command="y" ;;
    *) install_tp_script_command="n" ;;
  esac
  
  # Remove existing shortcuts if present
  if [[ "$has_existing_shortcuts" -eq 1 ]]; then
    local temp_file
    temp_file=$(mktemp)
    grep -v -F -f <(sed -n '/# Teleport shortcuts added on/,/# End of Teleport shortcuts/p' "$shell_rc") "$shell_rc" > "$temp_file"
    cat "$temp_file" > "$shell_rc"
    rm "$temp_file"
  fi

  # Create the shortcuts section if any shortcuts are requested
  if [[ "$install_k_alias" == "y" || "$install_tp_login" == "y" || "$install_tp_logout" == "y" || "$install_kns_function" == "y" || "$install_tp_script_command" == "y" ]]; then
    echo >> "$shell_rc"
    echo "# Teleport shortcuts added on $(date)" >> "$shell_rc"
    
    if [[ "$install_k_alias" == "y" ]]; then
      echo "alias k='tsh kubectl'" >> "$shell_rc"
      echo "Added: alias k='tsh kubectl'"
      
      # Apply to current session
      alias k='tsh kubectl'
    fi
    
    # Add tp script command if requested
    if [[ "$install_tp_script_command" == "y" ]]; then
      # Decide whether to use a symbolic link or a function
      if [[ -w "/usr/local/bin" ]]; then
        # Create a symbolic link in /usr/local/bin
        sudo ln -sf "$script_path" /usr/local/bin/tp
        echo "Added: tp command (symlink to $script_path)"
      else
        # Add a function to source the script
        echo "tp() { bash \"$script_path\" \"\$@\"; }" >> "$shell_rc"
        eval "tp() { bash \"$script_path\" \"\$@\"; }"
        echo "Added: tp command (function wrapper)"
      fi
    fi
    
    # Only add tp function if we're not installing the script command
    if [[ "$install_tp_script_command" != "y" && ("$install_tp_login" == "y" || "$install_tp_logout" == "y") ]]; then
      # Build tp function for both file and current session
      tp_function="
# tp - Teleport helper function
tp() {
  local script_path=\"$script_path\"
  case \"\$1\" in"
      
      if [[ "$install_tp_login" == "y" ]]; then
        tp_function+="
    login)
      shift
      tsh login --proxy=\"${TELEPORT_PROXY:-teleport.auth.freeletics.com:443}\" --auth=\"${TELEPORT_AUTH:-Engineering}\" \$@
      ;;"
        echo "Added: tp login - for quick Teleport login"
      fi
      
      if [[ "$install_tp_logout" == "y" ]]; then
        tp_function+="
    logout)
      tsh logout
      ;;
    check)
      bash \"\$script_path\" --system-check
      ;;"
        echo "Added: tp logout - for quick Teleport logout"
      fi
      
      # Close function block
      tp_function+="
    *)
      echo \"Usage: tp <command>\"
      echo \"Available commands:\""
      
      [[ "$install_tp_login" == "y" ]] && tp_function+="
      echo \"  login   - Login to Teleport\""
      [[ "$install_tp_logout" == "y" ]] && tp_function+="
      echo \"  logout  - Logout from Teleport\""
      tp_function+="
      echo \"  check   - Run system checks (connectivity, access, MFA)\""
      
      tp_function+="
      return 1
      ;;
  esac
}"
      
      # Write to config file
      echo "$tp_function" >> "$shell_rc"
      
      # Apply to current session
      eval "$tp_function"
    elif [[ "$install_tp_login" == "y" || "$install_tp_logout" == "y" ]]; then
      # If we're installing the script command but also want login/logout
      echo "Note: 'tp login' and 'tp logout' will be available through the tp script"
    fi
    
    bold "Shortcuts installed successfully!"
    bold "✓ Shortcuts are now active in your current session!"
    echo "They will also be available in new shell sessions automatically."
    
    # Add kns function if requested
    if [[ "$install_kns_function" == "y" ]]; then
      kns_function="
# kns - Change Kubernetes namespace with teleport
kns() {
  local namespaces namespace
  
  # Define inline formatting functions for standalone use
  local _bold='\\033[1m' _reset='\\033[0m' _yellow='\\033[33m' _red='\\033[31m'
  
  if [ -z \"\$1\" ]; then
    # Without argument, list namespaces and let user select one
    echo -e \"\${_bold}Fetching available namespaces...\${_reset}\"
    
    # Use a more direct approach to fetch namespaces quickly
    namespaces=\$(tsh kubectl get namespaces --no-headers -o custom-columns=\":metadata.name\" 2>/dev/null)
    if [ -z \"\$namespaces\" ]; then
      echo -e \"\${_red}Failed to get namespaces. Are you logged in to Teleport?\${_reset}\" >&2
      return 1
    fi

    # Use full terminal height and consistent styling with other menus
    namespace=\$(printf \"%s\\n\" \$namespaces | fzf --prompt=\"Namespace > \" --height=20 --border)
    if [ -z \"\$namespace\" ]; then
      echo -e \"\${_yellow}No namespace selected\${_reset}\"
      return 1
    fi
  else
    namespace=\"\$1\"
  fi

  # Change the namespace
  kubectl config set-context --current --namespace=\"\$namespace\"
  echo -e \"\${_bold}Switched to namespace: \$namespace\${_reset}\"
}
"
      # Write to config file
      echo "$kns_function" >> "$shell_rc"
      
      # Apply to current session
      eval "$kns_function"
      
      echo "Added: kns - Change Kubernetes namespace with teleport"
    fi
    
    # Add end marker for the shortcuts section to make updating easier
    echo "# End of Teleport shortcuts" >> "$shell_rc"
    
    # Verify the shortcuts work
    echo
    echo "Available shortcuts:"
    [[ "$install_k_alias" == "y" ]] && echo "  k           - Shortcut for 'tsh kubectl'"
    [[ "$install_tp_login" == "y" ]] && echo "  tp login    - Login to Teleport"
    [[ "$install_tp_logout" == "y" ]] && echo "  tp logout   - Logout from Teleport"
    [[ "$install_kns_function" == "y" ]] && echo "  kns         - Change Kubernetes namespace (interactive when used without arguments)"
    if [[ "$install_tp_script_command" == "y" ]]; then
        echo "  tp          - Run this teleport helper script directly"
        echo "  tp update   - Check for and install script updates"
        echo "  tp report   - Create and send a bug report"
    fi
  else
    echo "No shortcuts selected for installation."
  fi
  
  pause
}

#############################################
# Bootstrap
#############################################
detect_os
require_sudo
#############################################
# Bug reporting functionality 
#############################################
create_bug_report() {
  log_msg "INFO" "Creating bug report"
  
  # Gather additional system information
  local report_file="${HOME}/.teleport_helper_report.txt"
  
  # Check if we have any errors in the log
  local error_count=0
  if [[ -f "$LOG_FILE" ]]; then
    # Use wc -l to count lines, safer than grep -c which can return non-numeric strings
    error_count=$(grep -E '\[ERROR\]' "$LOG_FILE" | wc -l | tr -d ' ')
    # Ensure error_count is a number
    if ! [[ "$error_count" =~ ^[0-9]+$ ]]; then
      error_count=0
    fi
  fi
  
  # Create the detailed report file
  {
    echo "=== TELEPORT HELPER BUG REPORT ==="
    echo "Generated: $(date)"
    echo "Script Version: $(grep -m 1 'TELEPORT_VERSION=' "$0" | cut -d '"' -f 2 || echo "Unknown")"
    echo ""
    
    echo "=== SYSTEM INFORMATION ==="
    echo "OS: $OS"
    echo "Arch: $ARCH"
    echo "Kernel: $(uname -r)"
    echo "User: $(whoami)"
    echo "Shell: $SHELL"
    echo ""
    
    echo "=== TELEPORT INFORMATION ==="
    # Get version in a safer way
    TSH_VERSION=$(tsh version 2>/dev/null | head -1 | strip_ansi || echo "Not installed or not found")
    echo "Teleport Client Version: $TSH_VERSION"
    echo "Teleport Proxy: ${TELEPORT_PROXY}"
    echo "Teleport Auth: ${TELEPORT_AUTH}"
    echo ""
    
    echo "=== INSTALLED DEPENDENCIES ==="
    # Get versions with proper error handling
    KUBECTL_VERSION=$(kubectl version --client 2>/dev/null | grep -o 'Client.*' | strip_ansi || echo "Not installed")
    FZF_VERSION=$(fzf --version 2>/dev/null | strip_ansi || echo "Not installed")
    CURL_VERSION=$(curl --version 2>/dev/null | head -1 | strip_ansi || echo "Not installed")
    
    echo "kubectl: $KUBECTL_VERSION"
    echo "fzf: $FZF_VERSION"
    echo "curl: $CURL_VERSION"
    echo ""
    
    if [[ $error_count -gt 0 ]]; then
      echo "=== ERRORS FOUND ($error_count total) ==="
      grep -E '\[ERROR\]' "$LOG_FILE" | strip_ansi || echo "No errors in log (unexpected condition)"
      echo ""
    fi
    
    echo "=== COMPLETE LOG (ANSI Escape Codes Removed) ==="
    echo "Log file: $LOG_FILE"
    echo "----------------------------------------"
    if [[ -f "$LOG_FILE" ]]; then
      # Make sure we clean up the log to be plaintext
      cat "$LOG_FILE" | strip_ansi
    else
      echo "Log file not found"
    fi
  } > "$report_file"
  
  # Make the report file readable
  chmod 644 "$report_file"
  
  # Show the report creation summary
  clear
  bold "=== BUG REPORT CREATED ==="
  echo
  echo "Report file: $report_file"
  echo "File size: $(du -h "$report_file" | awk '{print $1}' 2>/dev/null || echo "Unknown")"
  
  # Show error summary if any
  if [[ $error_count -gt 0 ]]; then
    echo
    bold "Found $error_count errors in the log:"
    grep -E '\[ERROR\]' "$LOG_FILE" | head -5
    [[ $error_count -gt 5 ]] && echo "... and $(($error_count - 5)) more errors (see full report) ..."
  fi
  
  echo
  bold "What would you like to do with this report?"
  echo "1. Email it to operations@freeletics.com (recommended)"
  echo "2. View the report contents"
  echo "3. Return to the main menu"
  echo
  
  read -r -p "Enter your choice (1-3): " choice
  
  case "$choice" in
    1)
      send_bug_report "$report_file"
      ;;
    2)
      # View the report
      if command -v less >/dev/null 2>&1; then
        less "$report_file"
      else
        # Fall back to more or just cat
        if command -v more >/dev/null 2>&1; then
          more "$report_file"
        else
          cat "$report_file"
        fi
      fi
      
      # After viewing, ask if user wants to send
      echo
      read -r -p "Would you like to email this report now? [Y/n]: " send_choice
      case "${send_choice:-y}" in
        [yY]|[yY][eE][sS]|"")
          send_bug_report "$report_file"
          ;;
        *)
          echo "Report not sent. You can manually email the report file to operations@freeletics.com"
          echo "Report location: $report_file"
          ;;
      esac
      ;;
    *)
      echo "Report not sent. You can manually email the report file to operations@freeletics.com"
      echo "Report location: $report_file"
      ;;
  esac
  
  pause
}

send_bug_report() {
  local report_file="$1"
  local subject="Teleport Helper Bug Report - $(date +%Y-%m-%d)"
  local recipient="operations@freeletics.com"
  
  log_msg "INFO" "Attempting to send bug report to $recipient"
  
  # Since mailto: encoding is problematic, we'll display the contents
  # and give clearer instructions for all platforms
  
  # Check if we have any log entries that indicate errors
  local error_count=0
  if [[ -f "$LOG_FILE" ]]; then
    error_count=$(grep -c -E '\[ERROR\]' "$LOG_FILE" || echo "0")
  fi
  
  clear
  bold "=== BUG REPORT READY ==="
  echo
  echo "To: $recipient"
  echo "Subject: $subject"
  echo
  if [[ $error_count -gt 0 ]]; then
    bold "Found $error_count errors in the log file:"
    echo
    grep -E '\[ERROR\]' "$LOG_FILE" | tail -10
    [[ $error_count -gt 10 ]] && echo "... and $(($error_count - 10)) more errors ..."
    echo
  fi
  
  bold "What happens next:"
  echo "1. When you press ENTER, your default email client will open."
  echo "2. The email subject is already set, but you'll need to:"
  echo "   - Describe the issue you encountered"
  echo "   - List the steps to reproduce"
  echo "   - Attach the full bug report file: $report_file"
  echo
  bold "Important: Please attach the bug report file!"
  echo "Report file location: $report_file"
  echo
  
  read -r -p "Press ENTER to open your email client..." || true
  
  # Try platform-specific email clients first
  if [[ "$OS" == "macos" ]]; then
    # For macOS, try to use native Mail.app with a minimal body
    open "mailto:${recipient}?subject=${subject}&body=Please see attached bug report file." || open_email_fallback "$recipient" "$subject" "$report_file"
  elif command -v xdg-email >/dev/null 2>&1; then
    # For Linux with xdg-email
    xdg-email --subject "$subject" --body "Please see attached bug report file." "$recipient" || open_email_fallback "$recipient" "$subject" "$report_file"
  else
    # Fall back to web-based email
    open_email_fallback "$recipient" "$subject" "$report_file"
  fi
}

open_email_fallback() {
  local recipient="$1"
  local subject="$2"
  local report_file="$3"
  
  # As fallback, display instructions and open a webmail service
  bold "Could not open native email client. Using web email instead."
  echo
  echo "Please remember to:"
  echo "1. Set the recipient to: $recipient"
  echo "2. Set the subject to: $subject"
  echo "3. Attach the bug report file: $report_file"
  echo
  
  # Try to open a webmail service
  read -r -p "Press ENTER to open Gmail (or Ctrl+C to cancel)..." || true
  open_url "https://mail.google.com/mail/?view=cm&fs=1&to=${recipient}&su=${subject}"
}

#############################################
# Self-update functionality
#############################################
check_and_update_script() {
  local script_path current_hash remote_hash temp_file
  
  script_path="$(realpath "$0" 2>/dev/null || echo "$0")"
  bold "Checking for updates..."
  
  # Verify we have required tools
  if ! have curl; then
    err "curl is required for self-update. Please install curl first."
    pause
    return 1
  fi
  
  # Calculate hash of current script
  if have md5sum; then
    current_hash=$(md5sum "$script_path" | awk '{print $1}')
  elif have md5; then
    current_hash=$(md5 -q "$script_path")
  else
    err "Neither md5sum nor md5 command found. Cannot verify update."
    pause
    return 1
  fi
  
  # Create a temporary file for downloading the remote script
  temp_file=$(mktemp)
  
  # Download the latest version
  echo "Downloading latest version..."
  if ! curl -s "https://raw.githubusercontent.com/freeletics/public-scripts/refs/heads/master/teleport.sh" -o "$temp_file"; then
    err "Failed to download the latest version."
    rm -f "$temp_file"
    pause
    return 1
  fi
  
  # Calculate hash of downloaded script
  if have md5sum; then
    remote_hash=$(md5sum "$temp_file" | awk '{print $1}')
  elif have md5; then
    remote_hash=$(md5 -q "$temp_file")
  fi
  
  # Compare hashes
  if [[ "$current_hash" == "$remote_hash" ]]; then
    bold "✓ You already have the latest version."
    rm -f "$temp_file"
    pause
    return 0
  fi
  
  # Update needed
  bold "New version found!"
  echo "Current version: $current_hash"
  echo "Latest version:  $remote_hash"
  
  # Ask for confirmation
  read -r -p "Would you like to update to the latest version? [Y/n]: " response
  case "${response:-y}" in
    [yY]|[yY][eE][sS]|"")
      # Check if we have write permission
      if [[ -w "$script_path" ]]; then
        # Replace the current script with the downloaded one
        mv "$temp_file" "$script_path"
        chmod +x "$script_path"
        bold "✓ Script updated successfully!"
        echo "The script will restart to apply changes."
        
        # Restart the script
        exec "$script_path" "${ORIGINAL_ARGS[@]}"
      else
        err "You don't have permission to update $script_path"
        echo "Try running with sudo or copying manually:"
        echo "  sudo cp $temp_file $script_path"
        rm -f "$temp_file"
      fi
      ;;
    *)
      echo "Update cancelled."
      rm -f "$temp_file"
      ;;
  esac
  
  pause
  return 0
}

# Support for command-line arguments when script is run directly as `tp`
process_args() {
  case "$1" in
    login)
      shift
      tsh_login "$@"
      exit 0
      ;;
    logout)
      tsh_logout
      exit 0
      ;;
    update)
      check_and_update_script
      exit 0
      ;;
    check)
      system_check
      pause
      exit 0
      ;;
    report)
      create_bug_report
      exit 0
      ;;
    *)
      # No arguments or unknown argument, continue to interactive menu
      ;;
  esac
}

# Initialization
install_fzf
ensure_teleport_installed

bold "tsh version:"
tsh version || true

# Check if we were called with arguments (useful for tp command)
if [[ $# -gt 0 ]]; then
  # Handle special case for help
  if [[ "$1" == "help" || "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Teleport Helper Script"
    echo "Usage: $(basename "$0") [command]"
    echo ""
    echo "Available commands:"
    echo "  login            - Login to Teleport"
    echo "  logout           - Logout from Teleport"
    echo "  update           - Check for and install updates"
    echo "  report           - Create and send a bug report"
    echo "  --system-check   - Run system checks"
    echo "  help             - Show this help message"
    echo ""
    echo "Without arguments, shows interactive menu."
    exit 0
  elif [[ "$1" == "--system-check" ]]; then
    system_check
    pause
    exit 0
  fi
  
  # Process other arguments
  process_args "$@"
fi

# Set up exit logging
log_exit() {
  log_msg "INFO" "Script exiting with status code $?"
  log_msg "INFO" "Total execution time: $SECONDS seconds"
  log_msg "INFO" "==== End of session ===="
}
trap log_exit EXIT

# Start the interactive menu
main_menu