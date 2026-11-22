#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV="$ROOT/.venv"
LOCAL_BIN="$HOME/.local/bin"
LOG="$(mktemp)"
STEP=0
TOTAL_STEPS=8

trap 'rm -f "$LOG"' EXIT

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
    printf '\n%b\n' "${BOLD}${CYAN}  SENTINEL / BUILD${RESET}"
    printf '%b\n\n' "${DIM}  Local-first Linux Security & System Monitor${RESET}"
    printf '  -------------------------------------------\n\n'
}

step() {
    STEP=$((STEP + 1))
    printf '  %b  %s\n' "${CYAN}[${STEP}/${TOTAL_STEPS}]${RESET}" "$1"
}

success() {
    printf '       %b  %s\n' "${GREEN}[OK]${RESET}" "$1"
}

fail() {
    printf '\n  %b  %s\n' "${RED}[FAIL]${RESET}" "$1" >&2
    if [[ -s "$LOG" ]]; then
        printf '\n%b\n' "${BOLD}  Error details:${RESET}" >&2
        cat "$LOG" >&2
    fi
    exit 1
}

run_logged() {
    "$@" >"$LOG" 2>&1
}

header

step "Checking operating system"
[[ "$(uname -s)" == "Linux" ]] || fail "Sentinel requires Linux."
success "Linux detected"

step "Checking Python"
command -v python3 >/dev/null 2>&1 || fail "Python 3 was not found."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
    || fail "Python 3.12 or newer is required."
success "$(python3 --version 2>&1)"

step "Validating project structure"
[[ -f pyproject.toml && -f main.py && -d sentinel && -d tests ]] \
    || fail "Required project files are missing."
success "Project structure valid"

step "Preparing isolated Python environment"
if [[ ! -x "$VENV/bin/python" ]]; then
    run_logged python3 -m venv "$VENV" \
        || fail "Could not create the virtual environment. Install Python venv support."
fi
success "Virtual environment ready"

step "Installing Sentinel"
run_logged "$VENV/bin/python" -m pip install \
    --disable-pip-version-check \
    --no-warn-script-location \
    --quiet \
    . || fail "Package installation failed."
[[ -x "$VENV/bin/sentinel" ]] || fail "Sentinel executable was not created."
success "$("$VENV/bin/sentinel" version)"

step "Compiling Python sources"
run_logged "$VENV/bin/python" -m compileall -q main.py sentinel \
    || fail "Python compilation failed."
success "Source validation passed"

step "Running test suite"
run_logged "$VENV/bin/python" -W error::ResourceWarning \
    -m unittest discover -s tests -q \
    || fail "One or more tests failed."
success "All tests passed"

step "Configuring user command"
mkdir -p "$LOCAL_BIN"
if [[ -e "$LOCAL_BIN/sentinel" && ! -L "$LOCAL_BIN/sentinel" ]]; then
    fail "$LOCAL_BIN/sentinel exists and is not a symlink."
fi
ln -sfn "$VENV/bin/sentinel" "$LOCAL_BIN/sentinel"
success "Command configured at $LOCAL_BIN/sentinel"

printf '\n  -------------------------------------------\n'
printf '\n%b\n' "${BOLD}${GREEN}  BUILD SUCCESSFUL${RESET}"
printf '\n'
printf '  Launch:       %bsentinel%b\n' "$BOLD" "$RESET"
printf '  System check: %bsentinel check%b\n' "$BOLD" "$RESET"
printf '  Events:       %bsentinel events%b\n' "$BOLD" "$RESET"
printf '  Update:       %bsentinel update%b\n' "$BOLD" "$RESET"
printf '  Version:      %bsentinel version%b\n' "$BOLD" "$RESET"
printf '\n'

case ":$PATH:" in
    *":$LOCAL_BIN:"*) ;;
    *)
        printf '  Add ~/.local/bin to your PATH:\n'
        printf '  %sfish_add_path ~/.local/bin%s  (Fish)\n' "$CYAN" "$RESET"
        printf '  %sexport PATH="$HOME/.local/bin:$PATH"%s  (Bash)\n\n' "$CYAN" "$RESET"
        ;;
esac

printf '  %bNo root access. No automatic system changes.%b\n\n' "$DIM" "$RESET"
