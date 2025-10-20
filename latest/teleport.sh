#!/usr/bin/env bash
# Safer non-exiting defaults: we handle errors explicitly and keep the menu alive.
set -uo pipefail

# Store original arguments for potential restart after update
ORIGINAL_ARGS=("$@")

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
  # Get pods with status and container info in one command for better performance
  kubectl ${ctx:+--context "$ctx"} -n "$ns" get pods -o custom-columns="NAME:.metadata.name,STATUS:.status.phase,CONTAINERS:.spec.containers[*].name" --no-headers 2>/dev/null | 
    awk '{print $1}'
}

# Return only pods suitable for exec: Running + has 'rails' container
list_exec_pods_in_namespace() {
  local ctx="$1" ns="$2"
  # Get pods with status and container info in one command for better performance
  kubectl ${ctx:+--context "$ctx"} -n "$ns" get pods -o custom-columns="NAME:.metadata.name,STATUS:.status.phase,CONTAINERS:.spec.containers[*].name" --no-headers 2>/dev/null | 
    grep "Running" | grep -i "rails" | awk '{print $1}'
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
  if ! kubectl ${ctx:+--context "$ctx"} -n "$ns" get pod "$pod" -o custom-columns=":spec.containers[*].name" --no-headers 2>/dev/null |
       grep -qE '(^| )rails( |$)'; then
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
        "Install Shell Shortcuts (k alias, tp login/logout, kns)" \
        "Check for Updates" \
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
      "Install Shell Shortcuts"*) install_shell_shortcuts ;;
      "Check for Updates")       check_and_update_script ;;
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
    echo "  login    - Login to Teleport"
    echo "  logout   - Logout from Teleport"
    echo "  update   - Check for and install updates"
    echo "  help     - Show this help message"
    echo ""
    echo "Without arguments, shows interactive menu."
    exit 0
  fi
  
  # Process other arguments
  process_args "$@"
fi

# Start the interactive menu
main_menu