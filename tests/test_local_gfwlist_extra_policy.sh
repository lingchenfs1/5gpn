#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rules="$(cat "${root}/update-rules.sh")"

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local description="$3"

    if [[ "${haystack}" != *"${needle}"* ]]; then
        echo "Missing local GFWList extra marker: ${description} (${needle})" >&2
        exit 1
    fi
}

assert_contains "${rules}" 'GFWLIST_EXTRA_FILE="${BASE_DIR}/gfwlist-extra-local.txt"' 'local extra list path'
assert_contains "${rules}" 'append_local_gfwlist_extras()' 'local extra append function'
assert_contains "${rules}" 'grep -Fxq "${domain}" "${gfw_domain_index}"' 'dedupe against downloaded GFWList'
assert_contains "${rules}" 'gfwList:add(newDNSName(\"${domain}\"))' 'append extra domains to dnsdist rules'

echo "local GFWList extra policy markers OK"
