#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rules="$(cat "${root}/update-rules.sh")"

if [[ "${rules}" != *'dnsdist --check-config -C "${DNSDIST_CONF}"'* ]]; then
    echo "update-rules.sh must validate generated dnsdist.conf before reloading dnsdist." >&2
    exit 1
fi

if [[ "${rules}" != *'Generated dnsdist configuration failed validation'* ]]; then
    echo "update-rules.sh must stop with a clear error when dnsdist config validation fails." >&2
    exit 1
fi

echo "update-rules dnsdist config validation policy OK"
