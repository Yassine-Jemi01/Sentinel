#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

APP="Sentinel"
VERSION="0.1.0"
VENV="$ROOT/.venv"
LOCAL_BIN="${HOME}/.local/bin"
LOG="$(mktemp)"

trap 'rm -f "$LOG"' EXIT

# ── Terminal styling ──────────────────────────────────

if [[ -t 1 ]]; then
    BOLD='\033[1m'
    DIM='\033[2m'
    GREEN='\033[32m'
    RED='\033[31m'
    CYAN='\033[36m'
    RESET='\033[0m'
else
    BOLD='' DIM='' GREEN='' RED='' CYAN='' RESET=''
fi

header() {
    printf '\n%b\n' "${BOLD}${CYAN}  SENTINEL  /  SETUP${RESET}"
    printf '%b\n\n' "${DIM}  Local-first Linux Security & System Monitor${RESET}"
    printf '%b\n' "${DIM}  -------------------------------------------${RESET}"
}

step() {
    printf '  %b  %s...' "${CYAN}[*]${RESET}" "$1"
}

success() {
    printf '\r  %b  %s\n' "${GREEN}[OK]${RESET}" "$1"
}

fail() {
    printf '\r  %b  %s\n' "${RED}[FAIL]${RESET}" "$1" >&2

    if [[ -s "$LOG" ]]; then
        printf '\n%b\n' "${BOLD}Details:${RESET}" >&2
        cat "$LOG" >&2
    fi

    exit 1
}

run_logged() {
    if "$@" >"$LOG" 2>&1; then
        return 0
    else
        return 1
    fi
}

# ── System checks ─────────────────────────────────────

header

step "Checking operating system"

if [[ "$(uname -s)" != "Linux" ]]; then
    fail "Sentinel requires Linux."
fi

success "Linux detected"

step "Checking Python"

if ! command -v python3 >/dev/null 2>&1; then
    fail "Python 3 was not found. Install Python 3.12 or newer."
fi

if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 12))' 2>/dev/null; then
    fail "Python 3.12 or newer is required."
fi

PYTHON_VERSION="$(python3 --version 2>&1)"
success "$PYTHON_VERSION"

if [[ ! -f pyproject.toml || ! -f main.py ]]; then
    fail "Project files are missing. Run this script from a complete Sentinel source directory."
fi

# ── Virtual environment ───────────────────────────────

step "Preparing isolated Python environment"

if [[ ! -x "$VENV/bin/python" ]]; then
    if ! run_logged python3 -m venv "$VENV"; then
        fail "Could not create the virtual environment. Your distribution may require a separate venv package."
    fi
fi

success "Python environment ready"

# ── Installation ──────────────────────────────────────

step "Installing Sentinel and dependencies"

if ! run_logged "$VENV/bin/python" -m pip install \
    --disable-pip-version-check \
    --no-warn-script-location \
    --quiet \
    .; then
    fail "Installation failed."
fi

if [[ ! -x "$VENV/bin/sentinel" ]]; then
    fail "Sentinel command was not created by the package installer."
fi

success "Sentinel installed"

# ── Validation ────────────────────────────────────────

step "Checking Python source files"

if ! run_logged "$VENV/bin/python" -m compileall -q main.py sentinel; then
    fail "Python compilation failed."
fi

success "Source validation passed"

step "Running test suite"

if ! run_logged "$VENV/bin/python" -W error::ResourceWarning \
    -m unittest discover -s tests -q; then
    fail "One or more tests failed."
fi

TEST_SUMMARY="$(tail -n 2 "$LOG" | tr '\n' ' ')"
success "All tests passed — $TEST_SUMMARY"

# ── User command ──────────────────────────────────────

step "Setting up the sentinel command"

mkdir -p "$LOCAL_BIN"

if ! ln -sfn "$VENV/bin/sentinel" "$LOCAL_BIN/sentinel"; then
    fail "Could not create the sentinel command."
fi

success "Command installed in $LOCAL_BIN"

# ── Finished ──────────────────────────────────────────

printf '\n%b\n' "${BOLD}${GREEN}  Sentinel is ready.${RESET}"
printf '\n'
printf '  Launch:       %bsentinel%b\n' "$BOLD" "$RESET"
printf '  System check: %bsentinel check%b\n' "$BOLD" "$RESET"
printf '  Events:       %bsentinel events%b\n' "$BOLD" "$RESET"
printf '  Version:      %bsentinel version%b\n' "$BOLD" "$RESET"
printf '\n'

case ":${PATH}:" in
    *":${LOCAL_BIN}:"*)
        ;;
    *)
        printf '  %bNote:%b Add ~/.local/bin to your PATH:\n' "$DIM" "$RESET"
        printf '  %bexport PATH="$HOME/.local/bin:$PATH"%b\n\n' "$CYAN" "$RESET"
        ;;
esac

printf '  %bNo root access. No automatic system changes.%b\n\n' "$DIM" "$RESET"
