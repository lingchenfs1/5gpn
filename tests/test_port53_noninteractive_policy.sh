#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")/.." && pwd)"; body="$(cat "$here/install.sh")"
fail(){ echo "FAIL: $*"; exit 1; }
# non-interactive installs must NOT abort at the port-53 prompt
[[ "$body" == *'if [[ -t 0 ]]; then'* ]] || fail "port-53 prompt must be gated on a TTY"
[[ "$body" == *'read -r -p "Stop and disable'*'|| confirm=""'* ]] || fail "port-53 read must be EOF-safe (|| confirm=)"
[[ "$body" == *'Non-interactive: automatically freeing port 53'* ]] || fail "must auto-free port 53 when non-interactive"
# stopping systemd-resolved must repair resolv.conf
[[ "$body" == *'127.0.0.53'* && "$body" == *'nameserver 1.1.1.1\nnameserver 8.8.8.8'* ]] || fail "must rewrite resolv.conf after disabling systemd-resolved"
echo "port-53 non-interactive policy OK"
