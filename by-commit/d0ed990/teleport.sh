#!/usr/bin/env bash
#
# tp — a small, predictable wrapper around `tsh` for everyday Teleport access.
#
#   tp help     # everything this can do
#
# Run it as a command, or `source` it to get the `tp` function (and the k /
# kubectl aliases) in an interactive shell.  Kept compatible with bash 3.2 —
# the system bash on macOS — and with zsh.
#
# Piping it into a shell (`curl ... | bash`) is deliberately unsupported: from
# in here that is indistinguishable from `eval "$(cat tp)"`, and guessing wrong
# would hand somebody's interactive shell a `set -e` and a command they never
# typed.  Save it to a file first.
#
# The rule throughout: shorthands expand, and everything else is handed to tsh
# untouched.  This script does not re-decide anything tsh already decides.

# Answered here, at file scope, and only read back later: inside a function
# bash rewrites BASH_SOURCE to the function's definition site, which makes a
# copy loaded with `eval "$(cat tp)"` look like it was executed.  ZSH_SCRIPT is
# set only for a file zsh was asked to run — sourcing, eval and `cat tp | zsh`
# all leave it unset, and none of those should let this file take over the
# caller's shell.
if [ -n "${BASH_VERSION-}" ] && [ "${BASH_SOURCE[0]-}" = "${0-}" ]; then
  tp_main=1
elif [ -n "${ZSH_VERSION-}" ] && [ -n "${ZSH_SCRIPT-}" ]; then
  tp_main=1
else
  tp_main=0
fi

tp_is_main() { [ "${tp_main:-0}" = 1 ]; }

# Strict mode only when executed: sourcing this must never hand the caller's
# interactive shell a `set -e` it never asked for.
if tp_is_main; then
  set -euo pipefail
fi

# Where this file lives, for `tp version`; absolute, so it still finds itself
# after the caller has cd'd somewhere else.
tp_self="${BASH_SOURCE[0]:-${ZSH_SCRIPT:-$0}}"
case "$tp_self" in
  /*) ;;
  *)
    if tp_self_dir="$(cd "$(dirname "$tp_self")" 2>/dev/null && pwd -P)"; then
      tp_self="$tp_self_dir/$(basename "$tp_self")"
    fi
    unset tp_self_dir
    ;;
esac

: "${TELEPORT_PROXY:=teleport.auth.freeletics.com:443}"
: "${TELEPORT_AUTH:=Engineering}"
export TELEPORT_PROXY TELEPORT_AUTH

# ------------------------------------------------------------------ output --

tp_color() { [ -t 2 ] && [ -z "${NO_COLOR-}" ]; }
tp_err()   { if tp_color; then printf '\033[31m%s\033[0m\n' "$*" >&2; else printf '%s\n' "$*" >&2; fi; }
tp_warn()  { if tp_color; then printf '\033[33m%s\033[0m\n' "$*" >&2; else printf '%s\n' "$*" >&2; fi; }
tp_hint()  { if tp_color; then printf '\033[2m%s\033[0m\n'  "$*" >&2; else printf '%s\n' "$*" >&2; fi; }

tp_lc() { printf '%s' "${1-}" | tr '[:upper:]' '[:lower:]'; }

# macOS ships shasum, most Linuxes ship sha256sum, and the publish job uses the
# latter to generate the .sha256 next to the published copy.
tp_checksum() {
  if tp_have shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif tp_have sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  else
    return 1
  fi
}

# Is there a real executable by this name?  `command -v` alone would answer yes
# for the kubectl alias defined at the bottom of this file, and an alias is not
# something Homebrew can install.
tp_have() {
  case "$(command -v "$1" 2>/dev/null)" in
    /*) return 0 ;;
    *)  return 1 ;;
  esac
}

# Ask for a value on the terminal.  Never reads a non-terminal stdin: this may
# be running inside somebody's `while read` loop, and quietly eating one of
# their lines would be far worse than refusing to guess.
tp_ask() {
  local prompt="$1" answer="" what="${1%%:*}"

  if [ ! -t 0 ]; then
    tp_err "Error: $what is required."
    tp_hint "Pass it as an argument — there is no terminal here to ask on."
    return 2
  fi

  printf '%s' "$prompt" >&2
  # `read` reports failure at EOF even when it did read a final unterminated
  # line, so judge by what came back rather than by its exit status.
  IFS= read -r answer || true

  if [ -z "$answer" ]; then
    tp_err "Error: $what is required."
    return 2
  fi

  printf '%s' "$answer"
}

# --------------------------------------------------------------- toolchain --

tp_brew_formula_for() {
  case "$1" in
    tsh|teleport) printf '%s' teleport ;;
    kubectl)      printf '%s' kubernetes-cli ;;
    k9s)          printf '%s' k9s ;;
    *)            return 1 ;;
  esac
}

tp_ensure_brew_formula() {
  local formula="$1" binary="${2:-$1}"

  tp_have "$binary" && return 0

  if ! tp_have brew; then
    tp_err "Error: Homebrew not found; install '$formula' manually to continue."
    return 127
  fi

  if brew list --versions "$formula" >/dev/null 2>&1; then
    # Formula installed but binary still missing – probably a PATH problem.
    tp_warn "Warning: Homebrew reports '$formula' installed, but '$binary' isn't on PATH."
  else
    tp_hint "Installing Homebrew formula '$formula' for '$binary'..."
    # Homebrew's progress belongs on stderr: callers may capture our stdout.
    if ! brew install "$formula" >&2; then
      tp_err "Error: failed to install '$formula' via Homebrew."
      return 1
    fi
  fi

  tp_have "$binary" && return 0

  tp_err "Error: '$binary' still not available after installing '$formula'."
  tp_hint "Check your PATH or reinstall the tool manually."
  return 1
}

tp_require() {
  local missing=0 cmd formula
  for cmd in "$@"; do
    tp_have "$cmd" && continue

    if formula="$(tp_brew_formula_for "$cmd" 2>/dev/null)"; then
      tp_ensure_brew_formula "$formula" "$cmd" || true
    fi

    if ! tp_have "$cmd"; then
      tp_err "Error: required tool '$cmd' not found in PATH."
      missing=1
    fi
  done
  return "$missing"
}

tp_touchid_ready() {
  # Succeeds only when `tsh touchid diag` reports "Touch ID enabled? true".
  # (Common gotcha on MacBooks: the lid must be open for Touch ID to be usable.)
  tp_require tsh || return 127

  local diag
  diag="$(tsh touchid diag 2>/dev/null || true)"
  printf '%s\n' "$diag" | grep -qiE '^Touch ID enabled\?[[:space:]]*true[[:space:]]*$' && return 0

  tp_err "Touch ID is not available/enabled for MFA right now."
  tp_hint "Make sure:"
  tp_hint "  • You're on a Mac with Touch ID"
  tp_hint "  • The laptop lid is open and Touch ID is usable"
  tp_hint "  • Touch ID is enabled in System Settings"
  tp_hint ""
  tp_hint "Diagnostics (tsh touchid diag):"
  tp_hint "$diag"
  return 1
}

# --------------------------------------------------------------- resolvers --

# prod/int are shorthands, not facts: override them per shell when the names
# behind them change, instead of waiting for this script to catch up.
tp_kube_cluster() {
  case "$(tp_lc "${1-}")" in
    prod|production) printf '%s' "${TP_KUBE_PROD:-fl-production-13022024}" ;;
    int|integration) printf '%s' "${TP_KUBE_INT:-fl-integration-12012024}" ;;
    "")              return 1 ;;
    *)               printf '%s' "$1" ;;
  esac
}

tp_db_service() {
  case "$(tp_lc "${1-}")" in
    prod|production) printf '%s' "${TP_DB_PROD:-fl-prod-aurora}" ;;
    int|integration) printf '%s' "${TP_DB_INT:-fl-integration-cluster}" ;;
    "")              return 1 ;;
    *)               printf '%s' "$1" ;;
  esac
}

# True when the caller already named the database with a flag.  tsh's short
# flags take an attached value, so -nmydb names it just as -n mydb does.
tp_names_database() {
  local arg
  for arg in "$@"; do
    case "$arg" in
      --db-name|--db-name=*|-n|-n?*) return 0 ;;
    esac
  done
  return 1
}

# ------------------------------------------------------------------- usage --

tp_kube_usage() {
  cat <<'USAGE'
  tp kube login {prod|int|<cluster>}   # point kubectl at a cluster
  tp kube shell {prod|int|<cluster>}   # proxied subshell (tsh proxy kube --exec)
  tp kube <namespace>                  # k9s in that namespace (uses $KUBECONFIG)
USAGE
}

tp_db_usage() {
  cat <<'USAGE'
  tp db ls                                      # databases you can reach, and as whom
  tp db login   {prod|int|<service>} <database> [--db-user=<user>]
  tp db connect {prod|int|<service>} [database] [--db-user=<user>]
  tp db proxy   {prod|int|<service>} [database] # local tunnel for GUI clients
USAGE
}

# One source of truth for each family, so `tp help` and `tp db help` cannot
# drift apart.
tp_usage() {
  cat <<'USAGE'
Usage:
  tp login [flags]                     # SSO login in the browser
  tp logout
  tp status                            # profile, roles, expiry

  tp setup-mfa                         # register a TOTP authenticator
  tp setup-touchid                     # register Touch ID (lid must be open)

USAGE
  tp_kube_usage
  printf '\n'
  tp_db_usage
  cat <<'USAGE'

  tp version                           # where this script is, and its checksum

The database user comes from your Teleport roles: tsh picks it when exactly one
is granted and lists the options when there are several. Name one explicitly
with --db-user=<user>; every other flag is passed to tsh untouched, so tsh's own
--labels/--query selectors work here too.

Environment:
  TELEPORT_PROXY, TELEPORT_AUTH        # proxy address and SSO connector
  TP_KUBE_PROD, TP_KUBE_INT            # clusters behind the prod/int shorthands
  TP_DB_PROD, TP_DB_INT                # databases behind the prod/int shorthands
  NO_COLOR                             # plain, uncoloured output

Prereqs are installed with Homebrew on demand: tsh, kubectl, k9s.
USAGE
}

# --------------------------------------------------------------------- cli --

tp() {
  local cmd="${1-}"; [ $# -eq 0 ] || shift

  case "$cmd" in
    login)
      tp_require tsh || return 127
      tsh login --proxy="$TELEPORT_PROXY" --auth="$TELEPORT_AUTH" "$@"
      ;;

    logout)
      tp_require tsh || return 127
      tsh logout "$@"
      ;;

    status)
      tp_require tsh || return 127
      tsh status "$@"
      ;;

    setup-mfa)
      tp_require tsh || return 127
      tsh mfa add --proxy="$TELEPORT_PROXY" --type=TOTP "$@"
      ;;

    setup-touchid)
      tp_touchid_ready || return $?
      tsh mfa add --proxy="$TELEPORT_PROXY" --type=TOUCHID "$@"
      ;;

    kube)
      local sub="${1-}"; [ $# -eq 0 ] || shift
      case "$sub" in
        login|shell)
          tp_require tsh kubectl || return 127

          # A positional is only taken when it is not a flag, so a flag can
          # never be mistaken for the thing it was meant to describe.
          local target=""
          case "${1-}" in ""|-*) : ;; *) target="$1"; shift ;; esac

          local cluster=""
          if [ -n "$target" ]; then
            cluster="$(tp_kube_cluster "$target")"
          elif [ $# -eq 0 ]; then
            tp_err "Error: which cluster? Pass prod, int, or a cluster name."
            tp_kube_usage >&2
            return 2
          fi
          # Flags but no cluster is legitimate — `tsh kube login --all`.

          local -a tsh_args=()
          if [ "$sub" = "login" ]; then
            tsh_args=(kube login)
            [ -z "$cluster" ] || tsh_args+=("$cluster")
          else
            # Proxied subshell; inside it, run: tp kube <namespace>
            tsh_args=(proxy kube)
            [ -z "$cluster" ] || tsh_args+=("$cluster")
            tsh_args+=(--exec)
          fi
          [ $# -eq 0 ] || tsh_args+=("$@")

          tsh "${tsh_args[@]}"
          ;;

        help|--help|-h)
          printf 'Usage:\n'
          tp_kube_usage
          ;;

        "")
          printf 'Usage:\n' >&2
          tp_kube_usage >&2
          return 2
          ;;

        *)
          # Shorthand: tp kube <namespace> → k9s using the current KUBECONFIG.
          # Anything that cannot be a namespace is a typo, not a namespace.
          case "$sub" in
            *[!a-z0-9-]* | -* | *-)
              tp_err "Unknown command: tp kube $sub"
              tp_kube_usage >&2
              return 2
              ;;
          esac

          local arg
          for arg in "$@"; do
            case "$arg" in
              -*) ;;
              *)  tp_err "Unknown command: tp kube $sub $arg"
                  tp_kube_usage >&2
                  return 2
                  ;;
            esac
          done

          tp_require k9s || return 127

          # KUBECONFIG is a ':'-separated list; kubectl and k9s merge it.
          local kubeconfig="${KUBECONFIG-}"
          if [ -z "$kubeconfig" ] || [ ! -f "${kubeconfig%%:*}" ]; then
            tp_err "No proxied KUBECONFIG detected."
            tp_hint "Run: tp kube shell {prod|int|<cluster>}   # then: tp kube $sub"
            return 2
          fi
          # Passed explicitly: when sourced, KUBECONFIG may be set without being
          # exported, and k9s must not quietly fall back to the default cluster.
          KUBECONFIG="$kubeconfig" k9s --namespace "$sub" "$@"
          ;;
      esac
      ;;

    db)
      local sub="${1-}"; [ $# -eq 0 ] || shift
      case "$sub" in
        ls)
          tp_require tsh || return 127
          tsh db ls "$@"
          ;;

        login|connect|proxy)
          tp_require tsh || return 127

          local target=""
          case "${1-}" in ""|-*) : ;; *) target="$1"; shift ;; esac

          local service=""
          if [ -n "$target" ]; then
            service="$(tp_db_service "$target")"
          elif [ $# -eq 0 ]; then
            tp_err "Error: which database? Pass prod, int, or a service name."
            tp_db_usage >&2
            return 2
          fi
          # Flags but no service is legitimate — `tsh db login --labels=env=prod`.

          local dbname=""
          case "${1-}" in ""|-*) : ;; *) dbname="$1"; shift ;; esac

          if [ -n "$dbname" ] && tp_names_database "$@"; then
            tp_err "Error: database named twice — '$dbname' and a --db-name flag."
            tp_hint "tsh would silently keep the last one; say it once."
            return 2
          fi

          # Only `login` needs a name up front, and only when nothing else was
          # given: with flags in play, tsh parses them better than this can.
          if [ -z "$dbname" ] && [ "$sub" = "login" ] && [ $# -eq 0 ]; then
            dbname="$(tp_ask 'Database name: ')" || return $?
          fi

          # No --db-user here, deliberately.  tsh resolves it from your roles:
          # it auto-selects when exactly one is granted, lists the options when
          # several are, and honours denied users, wildcards and leaf clusters.
          # Guessing that client-side is what handed out certificates for a user
          # production does not accept.
          local -a tsh_args=()
          if [ "$sub" = "proxy" ]; then
            tsh_args=(proxy db --tunnel)
          else
            tsh_args=(db "$sub")
          fi
          [ -z "$service" ] || tsh_args+=("$service")
          [ -z "$dbname" ]  || tsh_args+=("--db-name=$dbname")
          [ $# -eq 0 ]      || tsh_args+=("$@")

          tsh "${tsh_args[@]}"
          ;;

        help|--help|-h)
          printf 'Usage:\n'
          tp_db_usage
          ;;

        *)
          [ -z "$sub" ] || tp_err "Unknown command: tp db $sub"
          printf 'Usage:\n' >&2
          tp_db_usage >&2
          return 2
          ;;
      esac
      ;;

    version)
      # Answers "am I running a stale copy?", and nothing else: `tsh version`
      # is a proxy round trip (~0.7s here) for a fact this command is not about.
      printf 'tp        %s\n' "${tp_self:-(unknown)}"
      local sum
      if [ ! -f "${tp_self-}" ]; then
        tp_warn "Cannot find this script on disk, so no checksum."
      elif sum="$(tp_checksum "$tp_self")"; then
        printf 'checksum  %s\n' "$sum"
        tp_hint "Compare with the .sha256 published next to it."
      else
        tp_warn "Neither shasum nor sha256sum is available, so no checksum."
      fi
      ;;

    help|--help|-h)
      tp_usage
      ;;

    "")
      tp_usage >&2
      return 2
      ;;

    *)
      tp_err "Unknown command: tp $cmd"
      tp_usage >&2
      return 2
      ;;
  esac
}

# Interactive shells only: aliases are not expanded in bash scripts anyway, and
# silently shadowing kubectl inside a zsh script would be unkind.
case "$-" in
  *i*) alias k='tsh kubectl'; alias kubectl='tsh kubectl' ;;
esac

if tp_is_main; then
  tp "$@"
fi
