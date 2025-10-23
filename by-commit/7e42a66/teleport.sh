#!/usr/bin/env bash
set -euo pipefail

export TELEPORT_PROXY="${TELEPORT_PROXY:-teleport.auth.freeletics.com:443}"
export TELEPORT_AUTH="${TELEPORT_AUTH:-Engineering}"

brew_formula_for() {
  case "$1" in
    tsh|teleport)   printf '%s' teleport ;;
    kubectl)        printf '%s' kubernetes-cli ;;
    k9s)            printf '%s' k9s ;;
    *)              return 1 ;;
  esac
}

ensure_brew_formula() {
  local formula="$1" binary="${2:-$1}"

  if command -v "$binary" >/dev/null 2>&1; then
    return 0
  fi

  if ! command -v brew >/dev/null 2>&1; then
    echo "Error: Homebrew not found; install '$formula' manually to continue." >&2
    return 127
  fi

  if brew list --versions "$formula" >/dev/null 2>&1; then
    # Formula installed but binary still missing – probably PATH issue.
    echo "Warning: Homebrew reports '$formula' installed, but '$binary' isn't on PATH." >&2
  else
    echo "Installing Homebrew formula '$formula' for '$binary'..." >&2
    if ! brew install "$formula"; then
      echo "Error: failed to install '$formula' via Homebrew." >&2
      return 1
    fi
  fi

  if command -v "$binary" >/dev/null 2>&1; then
    return 0
  fi

  echo "Error: '$binary' still not available after installing '$formula'." >&2
  echo "Check your PATH or reinstall the tool manually." >&2
  return 1
}


require_cmds() {
  local missing=0 c
  for c in "$@"; do
    if command -v "$c" >/dev/null 2>&1; then
      continue
    fi

    local formula
    if formula="$(brew_formula_for "$c" 2>/dev/null)"; then
      ensure_brew_formula "$formula" "$c" || true
    fi

    if ! command -v "$c" >/dev/null 2>&1; then
      echo "Error: required tool '$c' not found in PATH." >&2
      missing=1
    fi
  done
  return $missing
}

ensure_touchid_ready() {
  # Runs a quick diagnostic; succeeds only if "Touch ID enabled? true"
  # (Common gotcha on MacBooks: lid must be open for Touch ID to be usable.)
  if ! command -v tsh >/dev/null 2>&1; then
    echo "Error: 'tsh' is required for Touch ID diagnostics." >&2
    return 127
  fi
  local diag
  diag="$(tsh touchid diag 2>/dev/null || true)"

  if printf '%s\n' "$diag" | grep -qiE '^Touch ID enabled\?\s*true\s*$'; then
    return 0
  fi

  echo "Touch ID is not available/enabled for MFA right now." >&2
  echo "Make sure:" >&2
  echo "  • You're on a Mac with Touch ID" >&2
  echo "  • The laptop lid is open and Touch ID is usable" >&2
  echo "  • Touch ID is enabled in System Settings" >&2
  echo "" >&2
  echo "Diagnostics (tsh touchid diag):" >&2
  echo "$diag" >&2
  return 1
}


alias k='tsh kubectl'
alias kubectl='tsh kubectl'

tp() {
  local cmd; cmd="${1:-}"; if [ $# -gt 0 ]; then shift; fi

  case "$cmd" in
    login)
      require_cmds tsh || return 127
      tsh login --proxy="${TELEPORT_PROXY}" --auth="${TELEPORT_AUTH}" "$@"
      ;;

    logout)
      require_cmds tsh || return 127
      tsh logout "$@"
      ;;

    # MFA
    setup-mfa)
      require_cmds tsh || return 127
      tsh mfa add --proxy="${TELEPORT_PROXY}" --type=TOTP "$@"
      ;;
    setup-touchid)
      require_cmds tsh || return 127
      ensure_touchid_ready || return $?
      tsh mfa add --proxy="${TELEPORT_PROXY}" --type=TOUCHID "$@"
      ;;

    kube)
      local sub; sub="${1:-}"; if [ $# -gt 0 ]; then shift; fi
      case "$sub" in
        login)
          require_cmds tsh kubectl || return 127
          local target; target="${1:-}"; if [ $# -gt 0 ]; then shift; fi
          local cluster=""
          case "$target" in
            prod|PROD|production|PRODUCTION) cluster="fl-production-13022024" ;;
            int|INT|integration|INTEGRATION) cluster="fl-integration-12012024" ;;
            "") echo "Usage: tp kube login {prod|int|<cluster-name>}"; return 2 ;;
            *)  cluster="$target" ;;
          esac
          tsh kube login "$cluster" "$@"
          ;;

        shell)
          require_cmds tsh kubectl || return 127
          # Spawn proxied subshell via tsh; inside it, run: tp kube <namespace>
          local target; target="${1:-}"; if [ $# -gt 0 ]; then shift; fi
          local cluster=""
          case "$target" in
            prod|PROD|production|PRODUCTION) cluster="fl-production-13022024" ;;
            int|INT|integration|INTEGRATION) cluster="fl-integration-12012024" ;;
            "") echo "Usage: tp kube shell {prod|int|<cluster-name>}"; return 2 ;;
            *)  cluster="$target" ;;
          esac
          tsh proxy kube "$cluster" --exec
          ;;

        ""|help|HELP)
          echo "Usage:"
          echo "  tp kube login {prod|int|<cluster-name>}"
          echo "  tp kube shell {prod|int|<cluster-name>}  # open proxied subshell"
          echo "  tp kube <namespace>                      # run k9s in namespace (uses current KUBECONFIG)"
          return 2
          ;;

        *)
          # Shorthand: tp kube <namespace> → k9s using current KUBECONFIG
          require_cmds k9s || return 127
          local ns="$sub"
          if [ -z "${KUBECONFIG:-}" ] || [ ! -f "$KUBECONFIG" ]; then
            echo "No proxied KUBECONFIG detected."
            echo "Run: tp kube shell {prod|int|<cluster>}  # then: tp kube ${ns}"
            return 2
          fi
          KUBECONFIG="$KUBECONFIG" k9s --namespace "$ns" "$@"
          ;;
      esac
      ;;

    db)
      local sub; sub="${1:-}"; if [ $# -gt 0 ]; then shift; fi
      case "$sub" in
        login)
          require_cmds tsh || return 127
          # Hardcoded users: prod=root, int=root_teleport
          local target dbname
          target="${1:-}"; if [ $# -gt 0 ]; then shift; fi
          dbname="${1:-}"; if [ $# -gt 0 ]; then shift; fi

          local dbsvc dbuser
          case "$target" in
            prod|PROD|production|PRODUCTION) dbsvc="fl-prod-aurora";         dbuser="root" ;;
            int|INT|integration|INTEGRATION) dbsvc="fl-integration-cluster"; dbuser="root_teleport" ;;
            "") echo "Usage: tp db login {prod|int|<service>} <database>"; return 2 ;;
            *)  dbsvc="$target"; dbuser="root" ;;
          esac

          if [ -z "$dbname" ]; then
            if [ -n "${ZSH_VERSION-}" ]; then
              printf "Database name: "
              read -r dbname
            else
              read -r -p "Database name: " dbname
            fi
          fi

          # Drop accidental --db-user flags silently
          local passthrough=() skip_next=0 a
          for a in "$@"; do
            if [ "$skip_next" -eq 1 ]; then skip_next=0; continue; fi
            case "$a" in
              --db-user)   skip_next=1 ;;   # drop this and its value
              --db-user=*) ;;               # drop
              *)           passthrough+=("$a") ;;
            esac
          done

          tsh db login "$dbsvc" --db-user="$dbuser" --db-name="$dbname" "${passthrough[@]}"
          ;;

        ""|help|HELP)
          echo "Usage: tp db login {prod|int|<service>} <database>"
          return 2
          ;;

        *)
          echo "Usage: tp db login {prod|int|<service>} <database>"
          return 2
          ;;
      esac
      ;;

    help|--help|-h|"")
      cat <<'USAGE'
Usage:
  tp login [flags]
  tp logout

  tp setup-mfa
  tp setup-touchid   # requires: Touch ID enabled (lid open), see diagnostics

  tp kube login {prod|int|<cluster>}
  tp kube shell {prod|int|<cluster>}   # spawns proxied subshell (tsh proxy kube --exec)
  tp kube <namespace>                  # runs k9s (uses current KUBECONFIG)

  tp db login {prod|int|<service>} <database>

Prereqs (auto-checked where relevant): tsh, kubectl, k9s
If missing, Homebrew will be used to install the required tool automatically.
USAGE
      ;;

    *)
      echo "Unknown command: $cmd"
      tp help
      return 2
      ;;
  esac
}

if [[ ${BASH_SOURCE[0]:-} == "$0" ]]; then
  tp "$@"
fi
