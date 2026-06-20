#!/usr/bin/env bash
#
# One-click installer for 5gpn — downloads the repo and runs install.sh.
#
#   sudo bash <(curl -fsSL https://raw.githubusercontent.com/lingchenfs1/5gpn/main/quick-install.sh)
#
# Any extra args are passed straight through to install.sh, e.g.:
#   sudo bash <(curl -fsSL .../quick-install.sh) --status
#
set -euo pipefail

REPO="lingchenfs1/5gpn"
BRANCH="${PGW_BRANCH:-main}"
DIR="${PGW_SRC_DIR:-/opt/5gpn}"

RED='\033[0;31m'; BLUE='\033[0;34m'; GREEN='\033[0;32m'; NC='\033[0m'
info() { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}   $*"; }
err()  { echo -e "${RED}[ERR]${NC}  $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    err "Run as root:  sudo bash <(curl -fsSL https://raw.githubusercontent.com/${REPO}/${BRANCH}/quick-install.sh)"
    exit 1
fi

pkg_install() {
    if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -qq && apt-get install -y -qq "$@"
    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q "$@"
    elif command -v yum >/dev/null 2>&1; then yum install -y -q "$@"
    else return 1; fi
}

command -v tar >/dev/null 2>&1 || pkg_install tar || { err "tar is required"; exit 1; }

DL=""
if command -v curl >/dev/null 2>&1; then DL="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then DL="wget -qO-"
else pkg_install curl && DL="curl -fsSL" || { err "curl or wget is required"; exit 1; }
fi

info "Downloading ${REPO}@${BRANCH} into ${DIR} ..."
mkdir -p "${DIR}"
if ! $DL "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" | tar -xz --strip-components=1 -C "${DIR}"; then
    err "Download/extract failed. Check network access to github.com."
    exit 1
fi
ok "Source ready at ${DIR}"

cd "${DIR}"
chmod +x install.sh exit-server-setup.sh quick-install.sh 2>/dev/null || true
info "Launching installer..."
exec bash ./install.sh "$@"
