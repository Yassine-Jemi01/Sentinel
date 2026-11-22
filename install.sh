#!/usr/bin/env bash
set -Eeuo pipefail

REPO="Yassine-Jemi01/Sentinel"
BRANCH="main"
ARCHIVE_URL="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}"

APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/sentinel"
VENV_DIR="$APP_DIR/venv"
BIN_DIR="$HOME/.local/bin"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

say() {
    printf '  %s\n' "$1"
}

fail() {
    printf '\n[ERROR] %s\n' "$1" >&2
    exit 1
}

case "${1:-}" in
    ""|--update) ;;
    --help|-h)
        echo "Usage: install.sh [--update]"
        exit 0
        ;;
    *) fail "Unknown option: $1" ;;
esac

if [[ "$(uname -s)" != "Linux" ]]; then
    fail "Sentinel requires Linux."
fi

# Avoid installing a user-level command that shadows an RPM-managed command.
# A confirmed unowned path is safe; any other RPM query failure is ambiguous.
if command -v rpm >/dev/null 2>&1 && [[ -e /usr/bin/sentinel ]]; then
    RPM_RESULT=""
    RPM_STATUS=0
    RPM_RESULT="$(LC_ALL=C rpm -qf --qf '%{NAME}' /usr/bin/sentinel 2>&1)" || RPM_STATUS=$?
    if [[ "$RPM_STATUS" -eq 0 ]]; then
        fail "/usr/bin/sentinel is managed by RPM package '$RPM_RESULT'. Update or remove it with your system package manager."
    elif [[ "$RPM_STATUS" -ne 1 ]] || [[ "$RPM_RESULT" != *"is not owned by any package"* ]]; then
        fail "Could not safely determine ownership of /usr/bin/sentinel. No installation was attempted."
    fi
fi

command -v python3 >/dev/null 2>&1 || fail "Python 3 is required."
command -v tar >/dev/null 2>&1 || fail "tar is required."

PYTHON_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
    || fail "Python 3.12 or newer is required. Found: $PYTHON_VERSION"

printf '\n  SENTINEL / %s\n\n' "${1:---install}"

say "[1/4] Downloading Sentinel"
ARCHIVE="$TMP_DIR/sentinel.tar.gz"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 "$ARCHIVE_URL" -o "$ARCHIVE"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$ARCHIVE_URL" -O "$ARCHIVE"
else
    fail "Install curl or wget first."
fi

tar -xzf "$ARCHIVE" -C "$TMP_DIR"

SOURCE_DIR="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d \
    -name 'Sentinel-*' -print -quit)"

[[ -n "$SOURCE_DIR" && -f "$SOURCE_DIR/pyproject.toml" ]] \
    || fail "Downloaded source is invalid."

say "[2/4] Preparing Python environment"
mkdir -p "$APP_DIR"

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    python3 -m venv "$VENV_DIR"
fi

say "[3/4] Installing Sentinel"
PIP_LOG="$TMP_DIR/pip.log"

if ! "$VENV_DIR/bin/python" -m pip install \
    --disable-pip-version-check \
    --quiet \
    --upgrade \
    --force-reinstall \
    "$SOURCE_DIR" >"$PIP_LOG" 2>&1; then
    cat "$PIP_LOG" >&2
    fail "Installation failed."
fi

[[ -x "$VENV_DIR/bin/sentinel" ]] || fail "Sentinel executable was not created."

say "[4/4] Configuring command"
mkdir -p "$BIN_DIR"

if [[ -e "$BIN_DIR/sentinel" && ! -L "$BIN_DIR/sentinel" ]]; then
    fail "$BIN_DIR/sentinel already exists and is not a symlink. Move it manually first."
fi

ln -sfn "$VENV_DIR/bin/sentinel" "$BIN_DIR/sentinel"

VERSION="$("$VENV_DIR/bin/sentinel" version 2>/dev/null || true)"

printf '\n'
printf '  [OK] Sentinel installed successfully\n'
printf '  [OK] %s\n' "$VERSION"
printf '  [OK] Command: %s/sentinel\n' "$BIN_DIR"
printf '\n'

case ":$PATH:" in
    *":$BIN_DIR:"*)
        say "Run: sentinel"
        ;;
    *)
        say "Add ~/.local/bin to your PATH."
        say "Fish: fish_add_path ~/.local/bin"
        say "Bash: export PATH=\"\$HOME/.local/bin:\$PATH\""
        ;;
esac

printf '\n'
