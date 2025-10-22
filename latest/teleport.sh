#!/usr/bin/env bash
# Safer non-exiting defaults: we handle errors explicitly and keep the menu alive.
set -uo pipefail

# Store original arguments for potential restart after update
ORIGINAL_ARGS=("$@")
MAIN_PID=${BASHPID:-$$}

#############################################
# CONFIGURABLE ENVIRONMENT VARIABLES GUIDE
#############################################
# This script can be customized by setting environment variables before running.
# Example: 
#   DEFAULT_CONTAINER=app DB_PORT=5433 bash teleport.sh
#
# Available configuration options:
#
# Teleport configuration:
# - TELEPORT_VERSION: Version of teleport to use (default: 18.2.2)
# - TELEPORT_PROXY: Teleport proxy address (default: teleport.auth.freeletics.com:443)
# - TELEPORT_AUTH: Auth role to use (default: Engineering)
#
# Database configuration:
# - DB_NAME_INTEGRATION: Integration database name (default: bodyweight)
# - DB_NAME_PRODUCTION: Production database name (default: bodyweight)
# - DB_TUNNEL_INTEGRATION: Integration tunnel name (default: fl-integration-cluster)
# - DB_TUNNEL_PRODUCTION: Production tunnel name (default: fl-prod-aurora)
# - DB_PORT: Database port (default: 5432)
# - DB_USER_INTEGRATION: Default integration DB user (default: root-teleport)
# - DB_USER_PRODUCTION: Default production DB user (default: root)
#
# Kubernetes configuration:
# - KUBE_CLUSTER_INTEGRATION: Integration cluster name (default: fl-integration-12012024)
# - KUBE_CLUSTER_PRODUCTION: Production cluster name (default: fl-production-13022024)
# - DEFAULT_CONTAINER: Container name to use for logs/exec operations (default: rails)
# - KUBE_NAMESPACES_LIST: Space-separated list of namespaces to show (default: see below)

#############################################
# Logging setup
#############################################
# Define log file path in user's home directory
LOG_FILE="${HOME}/.teleport_helper.log"
LOG_LEVEL="${LOG_LEVEL:-INFO}"  # Can be DEBUG, INFO, WARN, ERROR

# Control whether to log fzf UI related output (should be kept off to avoid clutter)
FILTER_FZF="${FILTER_FZF:-1}"   # Set to 0 only for debugging fzf issues

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
    # First filter out fzf-specific UI elements and lines before parsing the rest
    grep -v -E '^(\[|\s*\[|\s*>)' |                    # fzf selection indicators and prompts
    grep -v -E '^[│└─┌┐┘┤┬┴┼┼─┴┬│┐┌┘└][└─┌┐┘┤┬┴┼]*$' | # Box drawing characters
    grep -v -E '^> ' |                                  # fzf prompts
    grep -v -E '^\s*[0-9]+/[0-9]+' |                    # fzf counters
    grep -v -E '^  ([▶⣿▉⣾⣽⣻⢿⡿⣟⣯⡷⣿])' |               # fzf loading indicators
    grep -v -E '^(\(|.*\)|\[|\])$' |                    # Single brackets/parentheses lines
    
    # Filter out interactive keyboard inputs that might have leaked into the log
    grep -v -E '^\^\[\[' |                              # Arrow key sequences
    grep -v -E '^\^H|^\^C|^\^D|^\^E|^\^R' |            # Control character sequences
    
    # Remove ANSI escape sequences, cursor movement commands, and other control sequences
    sed -E 's/\x1B\[[0-9;]*[a-zA-Z]//g' |              # Standard ANSI color/formatting
    sed -E 's/\x1B\][0-9;]*[a-zA-Z]//g' |              # Terminal title and other OSC sequences
    sed -E 's/\x1B\[[0-9]+n//g' |                      # Device status report
    sed -E 's/\x1B\[[0-9]+;[0-9]+[HfR]//g' |           # Cursor positioning
    sed -E 's/\x1B\[[0-9]+[ABCDEFGJKST]//g' |          # Cursor movement
    sed -E 's/\x1B\[[\?=][0-9;]*[hlm]//g' |            # Terminal mode settings
    sed -E 's/\x1B[=>]//g' |                           # Application keypad/cursor keys
    sed -E 's/\x1B[()][AB012]//g' |                    # Character set selection
    sed -E 's/\r$//g' |                                # Trailing carriage returns
    sed -E 's/\x7F//g' |                               # Delete characters
    sed -E 's/\x08//g' |                               # Backspace characters
    
    # Final cleanup
    grep -v -E '^\s*([│└─┌┐┘┤┬┴┼]|\||-)' |             # Any remaining UI elements
    grep -v '^\s*$'                                    # Remove empty lines
}

# Redirect stderr to both console and log file (with ANSI filtering)
exec 3>&2 # Save original stderr
exec 2> >(tee >(strip_ansi >> "$LOG_FILE") >&3)

# Add a log category specifically for fzf operations to help with debugging
log_fzf() {
    # Only log fzf operations at debug level, not in normal logs
    if [[ "${DEBUG_FZF:-0}" -eq 1 ]]; then
        log_msg "FZF" "$*"
    fi
}

# Function to log messages based on configured log level
log_msg() {
    local level="$1"
    shift
    local msg="$*"
    
    # Skip logging based on log level
    case "$LOG_LEVEL" in
        INFO)  [[ "$level" == "DEBUG" ]] && return ;;
        WARN)  [[ "$level" == "DEBUG" || "$level" == "INFO" ]] && return ;;
        ERROR) [[ "$level" != "ERROR" ]] && return ;;
    esac
    
    # Check for fzf-related messages
    if [[ "$FILTER_FZF" -eq 1 && "$msg" == *"fzf"* && "$level" != "ERROR" ]]; then
        # Only log fzf-related messages at DEBUG level
        [[ "$LOG_LEVEL" != "DEBUG" ]] && return
    fi
    
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
# =============================================
# CONFIGURABLE ENVIRONMENT VARIABLES
# Override these by setting them before running the script
# =============================================

# Teleport configuration
TELEPORT_VERSION="${TELEPORT_VERSION:-18.2.2}"
TELEPORT_PROXY="${TELEPORT_PROXY:-teleport.auth.freeletics.com:443}"
TELEPORT_AUTH="${TELEPORT_AUTH:-Engineering}"
TELEPORT_EDITION="${TELEPORT_EDITION:-oss}"   # linux installer edition (oss/ent/etc.)

# Database configuration
DB_NAME_INTEGRATION="${DB_NAME_INTEGRATION:-bodyweight}"
DB_TUNNEL_INTEGRATION="${DB_TUNNEL_INTEGRATION:-fl-integration-cluster}"
DB_NAME_PRODUCTION="${DB_NAME_PRODUCTION:-bodyweight}"
DB_TUNNEL_PRODUCTION="${DB_TUNNEL_PRODUCTION:-fl-prod-aurora}"
DB_PORT="${DB_PORT:-5432}"  # Default PostgreSQL port
DB_USER_INTEGRATION="${DB_USER_INTEGRATION:-root-teleport}"  # Default user for integration DB
DB_USER_PRODUCTION="${DB_USER_PRODUCTION:-root}"  # Default user for production DB

# Kubernetes cluster configuration
KUBE_CLUSTER_INTEGRATION="${KUBE_CLUSTER_INTEGRATION:-fl-integration-12012024}"
KUBE_CLUSTER_PRODUCTION="${KUBE_CLUSTER_PRODUCTION:-fl-production-13022024}"

# Default container name for operations
DEFAULT_CONTAINER="${DEFAULT_CONTAINER:-rails}"

# Default namespaces to browse for logs/exec
# Can be overridden by setting KUBE_NAMESPACES_LIST as a space-separated string
# Example: KUBE_NAMESPACES_LIST="namespace1 namespace2 namespace3"
if [[ -n "${KUBE_NAMESPACES_LIST:-}" ]]; then
  read -r -a KUBE_NAMESPACES <<< "$KUBE_NAMESPACES_LIST"
else
  KUBE_NAMESPACES=(
    audit bodyweight coach coach-plus messaging nutrition
    payment social tracking user web-blog web-service-main web-ssr
  )
fi

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

create_shell_backup() {
  local shell_rc="${1:-}"

  if [[ -z "$shell_rc" ]]; then
    err "No shell configuration file provided for backup"
    return 1
  fi

  if [[ ! -e "$shell_rc" ]]; then
    warn "Shell configuration file $shell_rc not found. Creating it before backup."
    if ! touch "$shell_rc"; then
      err "Failed to create shell configuration file: $shell_rc"
      return 1
    fi
  fi

  local epoch
  epoch="$(date +%s)"
  local backup_file="${shell_rc}.backup.${epoch}"

  if ! cp "$shell_rc" "$backup_file"; then
    err "Failed to create backup of $shell_rc"
    return 1
  fi

  log_msg "INFO" "Shell configuration backup created: $backup_file"
  echo "$backup_file"
  return 0
}

# List of background PIDs to clean up on exit
CHILD_PIDS=()
INTERRUPT_TIMESTAMP=0
SCRIPT_EXITING=0
cleanup_child_pids() {
  if [[ "${#CHILD_PIDS[@]}" -gt 0 ]]; then
    log_msg "INFO" "Cleaning up ${#CHILD_PIDS[@]} child processes..."
    for pid in "${CHILD_PIDS[@]}"; do
      if [[ "$pid" != "$MAIN_PID" ]] && kill -0 "$pid" 2>/dev/null; then
        log_msg "DEBUG" "Terminating child process $pid"
        if ! kill -15 "$pid" 2>/dev/null; then
          kill -9 "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
      fi
    done
    CHILD_PIDS=()
  fi
}
trap 'cleanup_child_pids' EXIT


# Handle interrupt (Ctrl+C) more robustly
on_sigint() {
  cleanup_child_pids
  local current_time=$(date +%s)
  
  # Check if this is a rapid double-press (within 2 seconds)
  if [[ $((current_time - INTERRUPT_TIMESTAMP)) -lt 2 ]]; then
    INTERRUPT_COUNT=$((INTERRUPT_COUNT + 1))
  else
    INTERRUPT_COUNT=1
  fi
  
  INTERRUPT_TIMESTAMP=$current_time
  WAS_INTERRUPTED=1
  FORCE_RETURN_TO_MENU=1  # Add this flag to force exit loops
  echo
  
  # Different behavior based on how many times Ctrl+C was pressed
  if [[ $INTERRUPT_COUNT -ge 3 ]]; then
    log_msg "WARN" "User pressed Ctrl+C multiple times in rapid succession. Force exiting."
    echo -e "\033[31mForce exiting script due to multiple interrupts\033[0m"
    kill -9 $$ 2>/dev/null || exit 130  # Ensure we really exit
  elif [[ $INTERRUPT_COUNT -ge 2 ]]; then
    log_msg "INFO" "User pressed Ctrl+C twice. Offering exit option."
    echo -e "\033[33mPress Ctrl+C again within 2 seconds to force exit the script\033[0m"
    warn "Interrupted. Returning to menu..."
  else
    log_msg "INFO" "User interrupted execution (Ctrl+C)"
    warn "Interrupted. Returning to menu..."
  fi
}

# Emergency escape hatch - triggered if script appears hung
on_usr1() {
  log_msg "ERROR" "Emergency timeout triggered after inactivity"
  echo -e "\n\033[31mEmergency timeout reached!\033[0m"
  echo "The script appears to be unresponsive. Forcing return to main menu."
  FORCE_RETURN_TO_MENU=1
  WAS_INTERRUPTED=1
  INTERRUPT_COUNT=0
}

# Set up signal handlers
trap 'on_sigint' INT
trap 'on_usr1' USR1

# Setup safety timeout to handle potential hangs
setup_safety_timeout() {
  if [[ "$SCRIPT_EXITING" -eq 1 ]]; then return; fi
  # Clean up any previous timeout
  if [[ -n "${TIMEOUT_PID:-}" ]] && kill -0 $TIMEOUT_PID 2>/dev/null; then
    kill $TIMEOUT_PID 2>/dev/null || true
    wait $TIMEOUT_PID 2>/dev/null || true
  fi
  
  # Start a new timeout monitor (sends USR1 after 5 minutes)
  (
    sleep 300  # 5 minutes
    if [[ -n "${MAIN_PID:-}" ]]; then
      kill -USR1 "$MAIN_PID" 2>/dev/null || true
    fi
  ) &
  TIMEOUT_PID=$!
  CHILD_PIDS+=("$TIMEOUT_PID")
  log_msg "DEBUG" "Safety timeout set for 5 minutes (PID: $TIMEOUT_PID)"
}

cleanup_safety_timeout() {
  if [[ "${BASHPID:-$$}" != "${MAIN_PID:-$$}" ]]; then
    return
  fi

  if [[ -n "${TIMEOUT_PID:-}" ]]; then
    if kill -0 "$TIMEOUT_PID" 2>/dev/null; then
      kill "$TIMEOUT_PID" 2>/dev/null || true
      wait "$TIMEOUT_PID" 2>/dev/null || true
    fi
    unset TIMEOUT_PID
  fi
}

pause() {
  # Reset interrupt counter during normal operation
  INTERRUPT_COUNT=0
  
  if [[ "${WAS_INTERRUPTED:-0}" -eq 1 || "${FORCE_RETURN_TO_MENU:-0}" -eq 1 ]]; then
    WAS_INTERRUPTED=0
    FORCE_RETURN_TO_MENU=0
    log_msg "DEBUG" "Pause skipped due to previous interruption or force return"
    return
  fi
  log_msg "DEBUG" "Pausing for user input"
  read -r -p "Press ENTER to continue..."
  log_msg "DEBUG" "User continued after pause"
}

# Wrap long-running commands so Ctrl-C is "expected"
  run_blocking() {
    log_msg "INFO" "Running command: $*"
    
    # Reset interrupt counter before command execution
    INTERRUPT_COUNT=0
    FORCE_RETURN_TO_MENU=0
    
    # Setup safety timeout that will send USR1 signal if command hangs
    setup_safety_timeout
    
    # Run the command in the background
    "$@" &
    local cmd_pid=$!
    CHILD_PIDS+=("$cmd_pid")

    # Wait for the command to finish, but allow Ctrl+C to interrupt
    wait "$cmd_pid"
    local status=$?
    
    # Remove the PID from the cleanup list
    for i in "${!CHILD_PIDS[@]}"; do
      if [[ "${CHILD_PIDS[$i]}" == "$cmd_pid" ]]; then
        unset 'CHILD_PIDS[$i]'
        break
      fi
    done

    # Clean up the safety timeout
    cleanup_safety_timeout
    
    # Handle special cases
    if [[ $status -eq 130 ]]; then
      WAS_INTERRUPTED=1
      FORCE_RETURN_TO_MENU=1
      log_msg "INFO" "Command was interrupted by user (SIGINT)"
    elif [[ $status -ne 0 ]]; then
      log_msg "WARN" "Command completed with non-zero status: $status"
    else
      log_msg "INFO" "Command completed successfully"
    fi
    return $status
}

# Wrap interactive commands that need a TTY
run_interactive() {
  log_msg "INFO" "Running interactive command: $*"
  
  # Reset interrupt counter before command execution
  INTERRUPT_COUNT=0
  FORCE_RETURN_TO_MENU=0
  
  # Setup safety timeout that will send USR1 signal if command hangs
  setup_safety_timeout
  
  # Just run the command directly. The TTY is inherited.
  # The main script's INT trap will handle Ctrl+C and return to the menu.
  "$@"
  local status=$?

  # Clean up the safety timeout
  cleanup_safety_timeout

  if [[ $status -eq 130 ]]; then
    WAS_INTERRUPTED=1
    FORCE_RETURN_TO_MENU=1
    log_msg "INFO" "Command was interrupted by user (SIGINT)"
  elif [[ $status -ne 0 ]]; then
    # Don't log an error for common exit codes from shells
    if [[ $status -ne 1 && $status -ne 127 ]]; then
        log_msg "WARN" "Command completed with non-zero status: $status"
    fi
  else
    log_msg "INFO" "Command completed successfully"
  fi
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
  
  # Setup timeout for this operation
  setup_safety_timeout
  
  # Clear any previous interrupts
  WAS_INTERRUPTED=0
  FORCE_RETURN_TO_MENU=0
  
  read -r -p "When you've added a TOTP device, press ENTER to re-check (or Ctrl+C to return to menu)..." _

  # Check if user interrupted before continuing
  if [[ "$FORCE_RETURN_TO_MENU" -eq 1 || "$WAS_INTERRUPTED" -eq 1 ]]; then
    warn "Operation cancelled. Returning to menu."
    return 1
  fi

  if ! has_totp_device; then
    err "Still no TOTP detected. Please finish adding TOTP in the dashboard."
    
    # Allow limited retries before forcing return
    local retries=0
    while [[ $retries -lt 3 && "$FORCE_RETURN_TO_MENU" -eq 0 ]]; do
      read -r -p "Press ENTER to check again (or Ctrl-C to abort)..." _
      
      # Check for interruption
      if [[ "$FORCE_RETURN_TO_MENU" -eq 1 || "$WAS_INTERRUPTED" -eq 1 ]]; then
        warn "Operation cancelled. Returning to menu."
        return 1
      fi
      
      if has_totp_device; then
        break
      fi
      
      retries=$((retries + 1))
      if [[ $retries -eq 3 ]]; then
        err "Maximum retries reached. Returning to menu."
        return 1
      fi
      
      err "Still no TOTP detected. Please complete the setup in the dashboard."
    done
    
    # Final check
    if ! has_totp_device; then
      err "No TOTP device found. Aborting."
      return 1
    fi
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
  # Check if logged in
  if ! ensure_logged_in; then
    echo "You need to log in to Teleport first. Please select 'Login to Teleport' from the main menu."
    return 1
  fi
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
    warn "Not logged in to ${PROXY_HOST}:${PROXY_PORT}."
    # Don't auto-login, let user choose from menu instead
    # tsh_login || return 1
    return 1
  fi
  return 0
}

#############################################
# Teleport actions
#############################################
tsh_login() {
  # Check if we're already logged in
  if tsh status >/dev/null 2>&1; then
    local already_logged_in=1
    log_msg "INFO" "Already logged in to Teleport"
    if [[ "${1:-}" != "--force" ]]; then
      echo "You are already logged into Teleport."
      read -r -p "Log in again? [y/N]: " ans || true
      if [[ "${ans:-}" != "y" && "${ans:-}" != "Y" ]]; then
        return 0
      fi
    fi
  fi

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
  local default_user="${4:-root}"  # Default user (root-teleport for integration, root for production)

  # Enforce MFA prerequisites before DB
  ensure_db_mfa_requirements || return 0

  local dbuser port
  dbuser="$(prompt_db_user "$default_user")"
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

  if [[ "${WAS_INTERRUPTED:-0}" -eq 1 || "${FORCE_RETURN_TO_MENU:-0}" -eq 1 ]]; then
    WAS_INTERRUPTED=0
    FORCE_RETURN_TO_MENU=0
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
  
  # Check if we're already logged into this cluster
  local existing_ctx="$(context_for_cluster "$cluster")"
  if [[ -n "$existing_ctx" ]]; then
    log_msg "INFO" "Context for $cluster already exists: $existing_ctx"
    
    # Check if the context is still listed in tsh kube ls
    if tsh kube ls 2>/dev/null | grep -q "$cluster"; then
      log_msg "INFO" "Cluster $cluster is already accessible via Teleport"
      return 0
    else
      log_msg "INFO" "Context exists but cluster not in tsh kube ls, re-logging into $cluster"
    fi
  fi
  
  bold "tsh kube login ${cluster}"
  run_blocking tsh kube login "${cluster}" || true
}

choose_env() {
  log_msg "DEBUG" "Prompting user to choose environment"
  
  # Use a temporary file to capture fzf selection without UI noise
  local tmp_file=$(mktemp)
  # Using process substitution to avoid fzf UI noise in logs
  printf "integration\nproduction\n" | fzf --prompt="Environment > " --height=10 --border > "$tmp_file"
  local fzf_status=$?
  local env=""
  if [[ -s "$tmp_file" ]]; then
    env=$(cat "$tmp_file")
  fi
  rm -f "$tmp_file"
  
  log_msg "DEBUG" "Environment picker exit status: $fzf_status, result: '${env}'"

  if [[ $fzf_status -ne 0 || -z "$env" ]]; then
    log_msg "INFO" "Environment selection canceled"
    env=""
  else
    log_msg "INFO" "User selected environment: $env"
  fi
  
  echo "$env"
}

context_for_cluster() {
  local cluster="$1"
  kubectl config get-contexts -o name 2>/dev/null | grep -i "$cluster" | head -n1 || true
}

choose_namespace() {
  local ctx="${1:-}"
  local cluster="${2:-unknown}"
  local env="${3:-unknown}"

  log_msg "DEBUG" "Prompting user to choose namespace (env=$env, cluster=$cluster, ctx=${ctx:-current})"

  # Build candidate list from configured namespaces first
  local candidates=()
  if [[ "${#KUBE_NAMESPACES[@]}" -gt 0 ]]; then
    for ns in "${KUBE_NAMESPACES[@]}"; do
      if [[ -n "${ns// }" ]]; then
        candidates+=("$ns")
      fi
    done
  fi

  # Augment with namespaces discovered via kubectl (if available)
  local discovered=""
  discovered=$(kubectl ${ctx:+--context "$ctx"} get namespaces --no-headers -o custom-columns=":metadata.name" 2>/dev/null || true)
  if [[ -n "$discovered" ]]; then
    while IFS= read -r ns; do
      [[ -z "${ns// }" ]] && continue
      local exists=0
      for existing in "${candidates[@]}"; do
        if [[ "$existing" == "$ns" ]]; then
          exists=1
          break
        fi
      done
      if [[ $exists -eq 0 ]]; then
        candidates+=("$ns")
      fi
    done <<< "$discovered"
  fi

  log_msg "DEBUG" "Namespace candidate count: ${#candidates[@]}"

  if [[ ${#candidates[@]} -eq 0 ]]; then
    err "No namespaces available. Please verify your Kubernetes access."
    pause
    echo ""
    return
  fi

  # Use a temporary file to capture fzf selection without UI noise
  local tmp_file=$(mktemp)
  printf "%s\n" "${candidates[@]}" | fzf --prompt="Namespace > " --height=20 --border > "$tmp_file"
  local fzf_status=$?
  local ns=""
  if [[ -s "$tmp_file" ]]; then
    ns=$(cat "$tmp_file")
  fi
  rm -f "$tmp_file"
  
  log_msg "DEBUG" "Namespace picker exit status: $fzf_status, result: '${ns}'"

  if [[ $fzf_status -ne 0 || -z "$ns" ]]; then
    log_msg "INFO" "Namespace selection canceled"
    ns=""
  else
    log_msg "INFO" "User selected namespace: $ns"
  fi
  
  echo "$ns"
}

list_pods_in_namespace() {
  local ctx="$1" ns="$2"
  # Get pods with status and container info in one command for better performance
  kubectl ${ctx:+--context "$ctx"} -n "$ns" get pods -o custom-columns="NAME:.metadata.name,STATUS:.status.phase,CONTAINERS:.spec.containers[*].name" --no-headers 2>/dev/null | 
    awk '{print $1}'
}

# Return only pods suitable for exec: Running + has container matching DEFAULT_CONTAINER
list_exec_pods_in_namespace() {
  local ctx="$1" ns="$2"
  need_jq || return 1
  
  log_msg "DEBUG" "Listing executable pods in namespace $ns with container '$DEFAULT_CONTAINER'"
  
  # Get pods with status and container info in one command for better performance
  local pod_list
  pod_list=$(kubectl ${ctx:+--context "$ctx"} -n "$ns" get pods -o json 2>/dev/null | 
    jq -r --arg container "$DEFAULT_CONTAINER" '.items[] | 
           select(.status.phase=="Running") | 
           select(.spec.containers[].name==$container) | 
           .metadata.name')
           
  # Log the available pods to make debugging easier
  local pod_count=$(echo "$pod_list" | wc -l | tr -d ' ')
  if [[ "$pod_count" -gt 0 && -n "$pod_list" ]]; then
    log_msg "DEBUG" "Found $pod_count pods with container '$DEFAULT_CONTAINER' in namespace $ns"
  else
    log_msg "WARN" "No pods with container '$DEFAULT_CONTAINER' found in namespace $ns"
  fi
  
  echo "$pod_list"
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

  log_msg "INFO" "Preparing logs flow for env=$env (cluster=$cluster)"
  bold "Preparing access to cluster $cluster ($env)..."

  # Check if already logged into the cluster, if not, log in
  ctx="$(context_for_cluster "$cluster")"
  if [[ -z "$ctx" ]]; then
    log_msg "INFO" "Not logged into $cluster, attempting login..."
    bold "Logging into Teleport Kubernetes cluster $cluster..."
    kube_login "$cluster"
    ctx="$(context_for_cluster "$cluster")"
    [[ -z "$ctx" ]] && warn "Could not detect a matching kubectl context. Using current context."
  else
    log_msg "INFO" "Using existing kubectl context for $cluster: $ctx"
  fi

  log_msg "INFO" "Prompting for namespace selection"
  bold "Select a namespace to tail logs from:"
  ns="$(choose_namespace "${ctx:-}" "$cluster" "$env")"
  log_msg "INFO" "Namespace selection result: '${ns}'"
  [[ -z "${ns:-}" ]] && return 0

  bold "Fetching pods with ${DEFAULT_CONTAINER} container..."
  log_msg "DEBUG" "Listing pods with ${DEFAULT_CONTAINER} container in namespace $ns"
  
  # Get pods with container in one call for better performance
  local pod_list
  pod_list=$(timeout 15 kubectl ${ctx:+--context "$ctx"} -n "$ns" get pods -o custom-columns="NAME:.metadata.name,STATUS:.status.phase,CONTAINERS:.spec.containers[*].name" --no-headers |
         grep -i "${DEFAULT_CONTAINER}" | awk '{print $1}')  # Log the number of pods found
  local pod_count=$(echo "$pod_list" | wc -l | tr -d ' ')
  log_msg "DEBUG" "Found $pod_count pods with ${DEFAULT_CONTAINER} container in namespace $ns"
  
  # Use temporary file to avoid fzf UI in logs
  local tmp_file=$(mktemp)
  echo "$pod_list" | fzf --prompt="Pod in $ns > " --height=25 --border > "$tmp_file"
  
  pod=$(cat "$tmp_file")
  rm -f "$tmp_file"
  
  if [[ -n "$pod" ]]; then
    log_msg "INFO" "Selected pod: $pod"
  else
    log_msg "INFO" "Pod selection canceled"
    return 0
  fi

  # Check container with direct access to avoid additional kubectl calls
  container_list=$(kubectl ${ctx:+--context "$ctx"} -n "$ns" get pod "$pod" -o jsonpath="{.spec.containers[*].name}" 2>/dev/null)
  debug "Available containers in pod: $container_list"
  
  if ! echo "$container_list" | grep -qE "(^|,| )${DEFAULT_CONTAINER}($|,| )"; then
    err "Container '${DEFAULT_CONTAINER}' not found in $pod. Aborting logs."
    debug "Containers in pod are: $container_list"
    pause
    return 0
  fi

  bold "Streaming logs for container '${DEFAULT_CONTAINER}' from ${pod} (ns=${ns})..."
  warn "Press CTRL-C to stop and return to the menu."
  run_blocking kubectl ${ctx:+--context "$ctx"} -n "$ns" logs -f "$pod" -c "$DEFAULT_CONTAINER"

  if [[ "${WAS_INTERRUPTED:-0}" -eq 1 || "${FORCE_RETURN_TO_MENU:-0}" -eq 1 ]]; then
    WAS_INTERRUPTED=0
    FORCE_RETURN_TO_MENU=0
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

  # Check if already logged into the cluster, if not, log in
  ctx="$(context_for_cluster "$cluster")"
  if [[ -z "$ctx" ]]; then
    log_msg "INFO" "Not logged into $cluster, attempting login..."
    kube_login "$cluster"
    ctx="$(context_for_cluster "$cluster")"
    [[ -z "$ctx" ]] && warn "Could not detect a matching kubectl context. Using current context."
  else
    log_msg "DEBUG" "Already have context for $cluster: $ctx"
  fi

  ns="$(choose_namespace "${ctx:-}" "$cluster" "$env")"
  [[ -z "${ns:-}" ]] && return 0

  # Get list of exec-ready pods and filter through fzf, avoiding UI noise in logs
  local pod_list=$(list_exec_pods_in_namespace "${ctx:-}" "$ns")
  
  # Use temporary file to avoid fzf UI in logs
  local tmp_file=$(mktemp)
  echo "$pod_list" | fzf --prompt="Pod in $ns (exec) > " --height=25 --border > "$tmp_file"
  
  pod=$(cat "$tmp_file")
  rm -f "$tmp_file"
  
  if [[ -n "$pod" ]]; then
    log_msg "INFO" "Selected pod for exec: $pod"
  else
    log_msg "INFO" "Pod exec selection canceled"
    return 0
  fi

  # Double-check the container exists (better safe than sorry)
  container_list=$(kubectl ${ctx:+--context "$ctx"} -n "$ns" get pod "$pod" -o jsonpath="{.spec.containers[*].name}" 2>/dev/null)
  debug "Available containers in pod: $container_list"
  
  if ! echo "$container_list" | grep -qE "(^|,| )${DEFAULT_CONTAINER}($|,| )"; then
    err "Container '${DEFAULT_CONTAINER}' not found in $pod. Aborting exec."
    debug "Containers in pod are: $container_list"
    pause
    return 0
  fi

  bold "Exec into $pod (ns=$ns) container '${DEFAULT_CONTAINER}' using /bin/bash"
  warn "Inside the remote shell, use 'exit' or Ctrl-D to return to the menu."

  run_interactive kubectl ${ctx:+--context "$ctx"} exec -it "$pod" -n "$ns" -c "$DEFAULT_CONTAINER" -- /bin/bash || true

  if [[ "${WAS_INTERRUPTED:-0}" -eq 1 || "${FORCE_RETURN_TO_MENU:-0}" -eq 1 ]]; then
    WAS_INTERRUPTED=0
    FORCE_RETURN_TO_MENU=0
    return
  fi
  pause
}

#############################################
# Kubernetes context switching
#############################################
install_kcx() {
  need_kubectl || return 1
  
  local rc_file=""
  if [[ "$SHELL" == */zsh ]]; then
    rc_file="${HOME}/.zshrc"
  elif [[ "$SHELL" == */bash ]]; then
    if [[ -f "${HOME}/.bashrc" ]]; then
      rc_file="${HOME}/.bashrc"
    elif [[ -f "${HOME}/.bash_profile" ]]; then
      rc_file="${HOME}/.bash_profile"
    else
      rc_file="${HOME}/.bashrc"
    fi
  else
    warn "Unsupported shell: $SHELL"
    echo "Only bash and zsh are currently supported for shortcuts."
    return 1
  fi
  
  if [[ -f "$rc_file" ]] && grep -q "function kcx()" "$rc_file" 2>/dev/null; then
    info "kcx function is already installed in $rc_file"
    return 0
  fi

  local backup_file
  if ! backup_file=$(create_shell_backup "$rc_file"); then
    err "Failed to create backup of $rc_file. Aborting installation."
    return 1
  fi
  bold "Created backup: $backup_file"
  
  bold "Installing kcx function for easy context switching between clusters..."
  
  # Create the kcx function tailored for our environment using the current cluster variables
  cat >> "$rc_file" << EOF

# kcx - Fast kubernetes context switcher for Freeletics clusters
function kcx() {
  local INTEGRATION_CLUSTER="${KUBE_CLUSTER_INTEGRATION}"
  local PRODUCTION_CLUSTER="${KUBE_CLUSTER_PRODUCTION}"
  
  case "\$1" in
    i|int|integration)
      echo "Switching to integration cluster context..."
      kubectl config use-context "\$(kubectl config get-contexts -o name | grep -i "\$INTEGRATION_CLUSTER" | head -n1)"
      ;;
    p|prod|production)
      echo "Switching to production cluster context..."
      kubectl config use-context "\$(kubectl config get-contexts -o name | grep -i "\$PRODUCTION_CLUSTER" | head -n1)"
      ;;
    *)
      echo "Usage: kcx [i|int|integration|p|prod|production]"
      echo ""
      echo "Current contexts:"
      kubectl config get-contexts
      ;;
  esac
}
EOF

  success "kcx function installed! Please restart your terminal or run 'source $rc_file' to use it."
  info "Usage examples:"
  echo "  kcx i          # Switch to integration cluster"
  echo "  kcx p          # Switch to production cluster"
  echo "  kcx            # Show available contexts and usage info"
  
  return 0
}

switch_kube_context() {
  need_kubectl || return 0
  
  local env
  env="$(choose_env)"
  [[ -z "${env:-}" ]] && return 0
  
  if [[ "$env" == "integration" ]]; then
    cluster="$KUBE_CLUSTER_INTEGRATION"
  else
    cluster="$KUBE_CLUSTER_PRODUCTION"
  fi
  
  kube_login "$cluster"
  ctx="$(context_for_cluster "$cluster")"
  
  if [[ -n "$ctx" ]]; then
    bold "Switching kubectl context to: $ctx"
    kubectl config use-context "$ctx"
    success "Context switched to $ctx"
  else
    err "Could not find a context matching cluster $cluster"
    info "Available contexts:"
    kubectl config get-contexts
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

setup_vpn_resources() {
  local vpn_endpoint_url="https://self-service.clientvpn.amazonaws.com/endpoints/cvpn-endpoint-0047b5d8713877b13"
  local vpn_docs_url="https://freeletics.atlassian.net/wiki/spaces/IT/pages/4272685065/AWS+VPNs"

  bold "AWS Client VPN setup"
  echo "Opening the AWS Client VPN self-service portal in your browser..."
  open_url "$vpn_endpoint_url"
  echo
  echo "From the portal:" 
  echo "  • Download your VPN configuration profile (OVPN file)."
  echo "  • Download and install the AWS VPN Client application if it's not already installed."
  echo
  echo "For step-by-step guidance, see the internal documentation:"
  echo "  $vpn_docs_url"
  echo
  pause
}

#############################################
# Main menu
#############################################
main_menu() {
  while [[ "$FORCE_RETURN_TO_MENU" -eq 0 ]]; do
    # Reset interrupt flags before processing each menu choice
    WAS_INTERRUPTED=0
    log_msg "DEBUG" "Showing main menu"
    
    # Check if fzf is installed and available in PATH
    if ! command -v fzf >/dev/null 2>&1; then
      log_msg "ERROR" "fzf is not installed or not found in PATH"
      echo -e "\033[31mError: fzf is not installed or not found in PATH\033[0m"
      echo "Installing fzf..."
      install_fzf || { 
        echo "Could not install fzf. Menu cannot be displayed.";
        echo "Please install fzf manually and restart the script.";
        exit 1;
      }
    fi
    
    # Construct menu options
    local options=(
      "Login to Teleport (tsh login)"
      "DB: Proxy Integration (${DB_TUNNEL_INTEGRATION} → ${DB_NAME_INTEGRATION})"
      "DB: Proxy Production (${DB_TUNNEL_PRODUCTION} → ${DB_NAME_PRODUCTION})"
      "K8s: Login Integration (${KUBE_CLUSTER_INTEGRATION})"
      "K8s: Login Production (${KUBE_CLUSTER_PRODUCTION})"
      "K8s: Switch Context (quickly change between clusters)"
      "K8s: Install 'kcx' Command (for fast context switching)"
      "K8s: Logs (env → ns → pod '${DEFAULT_CONTAINER}')"
      "K8s: Exec (env → ns → pod '${DEFAULT_CONTAINER}')"
      "System Check (connectivity, access, MFA status)"
  "Setup AWS VPN (download config & client)"
      "Install Shell Shortcuts (k alias, tp login/logout, kns)"
      "Check for Updates"
      "Report a Bug"
      "Teleport Logout"
      "Quit"
    )
    
    # Use a pipe and `read` to get the choice from fzf robustly.
    local choice
    choice=$(printf "%s\n" "${options[@]}" | fzf --prompt="Teleport Helper > " --height=20 --border)
    local fzf_exit_code=$?

    if [[ $fzf_exit_code -ne 0 ]]; then
        log_msg "INFO" "Menu selection canceled or fzf failed (exit code: $fzf_exit_code)"
        # If fzf was cancelled (e.g. Ctrl-C, Esc), treat it like a Quit.
        if [[ $fzf_exit_code -eq 130 || $fzf_exit_code -eq 1 ]]; then
            choice="Quit"
        else
            choice="" # Other error, redisplay menu
        fi
    elif [[ -n "$choice" ]]; then
        log_msg "INFO" "User selected menu option: $choice"
    else
        log_msg "INFO" "Menu selection was empty"
    fi

    case "${choice:-}" in
      "Login to Teleport (tsh login)") tsh_login ;;
      "DB: Proxy Integration"*) proxy_db "$DB_TUNNEL_INTEGRATION" "$DB_NAME_INTEGRATION" "$DB_PORT" "$DB_USER_INTEGRATION" ;;
      "DB: Proxy Production"*)  proxy_db "$DB_TUNNEL_PRODUCTION"   "$DB_NAME_PRODUCTION"   "$DB_PORT" "$DB_USER_PRODUCTION" ;;
      "K8s: Login Integration"*) kube_login "$KUBE_CLUSTER_INTEGRATION"; pause ;;
      "K8s: Login Production"*)  kube_login "$KUBE_CLUSTER_PRODUCTION"; pause ;;
      "K8s: Switch Context"*)    switch_kube_context ;;
      "K8s: Install 'kcx'"*)     install_kcx; pause ;;
      "K8s: Logs"*)              kube_logs_flow ;;
      "K8s: Exec"*)              kube_exec_flow ;;
      "System Check"*)          system_check; pause ;;
  "Setup AWS VPN"*)         setup_vpn_resources ;;
      "Install Shell Shortcuts"*) install_shell_shortcuts ;;
      "Check for Updates")       check_and_update_script ;;
      "Report a Bug")            create_bug_report ;;
      "Teleport Logout")         tsh_logout ;;
      "Quit")
        break
        ;;
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
  
  local backup_file
  if ! backup_file=$(create_shell_backup "$shell_rc"); then
    err "Failed to create backup of $shell_rc. Aborting for safety."
    return 1
  fi
  bold "Created backup: $backup_file"
  
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
    # Use sed to safely remove only the Teleport shortcuts section
    sed '/# Teleport shortcuts added on/,/# End of Teleport shortcuts/d' "$shell_rc" > "$temp_file"
    mv "$temp_file" "$shell_rc"
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
      
      # Write to config file      echo "$tp_function" >> "$shell_rc"
      
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
    echo ""
    echo "Environment variables for customization:"
    echo "  DEFAULT_CONTAINER=app         - Use 'app' container instead of 'rails'"
    echo "  DB_PORT=5433                  - Use port 5433 for database connections" 
    echo "  DB_USER_INTEGRATION=myuser    - Set integration database user (default: root-teleport)"
    echo "  DB_USER_PRODUCTION=myuser     - Set production database user (default: root)"
    echo "  KUBE_NAMESPACES_LIST=\"ns1 ns2\" - Custom list of namespaces to display"
    echo ""
    echo "Example: DEFAULT_CONTAINER=app DB_USER_INTEGRATION=admin bash $(basename "$0")"
    exit 0
  elif [[ "$1" == "--system-check" ]]; then
    system_check
    pause
    exit 0
  fi
  
  # Process other arguments
  process_args "$@"
fi

# Initialize global variables for interrupt handling
FORCE_RETURN_TO_MENU=0
TIMEOUT_PID=""

# Set up exit logging
log_exit() {
  local exit_status=${1:-$?}
  SCRIPT_EXITING=1

  cleanup_safety_timeout
  cleanup_child_pids

  log_msg "INFO" "Script exiting with status code $exit_status"
  log_msg "INFO" "Total execution time: $SECONDS seconds"
  log_msg "INFO" "==== End of session ===="
}
trap 'log_exit "$?"' EXIT

# Setup the initial safety timeout
setup_safety_timeout

# Show current configuration on first run
if [[ -z "${CONFIG_SHOWN:-}" ]]; then
  echo -e "\033[1;36mCurrent configuration:\033[0m"
  echo -e "  \033[33mDefault container:\033[0m ${DEFAULT_CONTAINER}"
  echo -e "  \033[33mClusters:\033[0m ${KUBE_CLUSTER_INTEGRATION} (int), ${KUBE_CLUSTER_PRODUCTION} (prod)"
  echo -e "  \033[33mDB Connections:\033[0m ${DB_TUNNEL_INTEGRATION}:${DB_PORT} → ${DB_NAME_INTEGRATION} (user: ${DB_USER_INTEGRATION}), ${DB_TUNNEL_PRODUCTION}:${DB_PORT} → ${DB_NAME_PRODUCTION} (user: ${DB_USER_PRODUCTION})"
  echo -e "  \033[33mTeleport:\033[0m ${TELEPORT_PROXY} (auth: ${TELEPORT_AUTH})"
  echo -e "  \033[90m(Override these using environment variables before running the script)\033[0m"
  echo ""
  export CONFIG_SHOWN=1
fi

# Make sure fzf is installed before proceeding
if ! command -v fzf >/dev/null 2>&1; then
  echo "Installing fzf (required for menu)..."
  install_fzf
fi

# Start the interactive menu
main_menu

# The script will exit here after main_menu finishes.
echo "Goodbye!"
exit 0