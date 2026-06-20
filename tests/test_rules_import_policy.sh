#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
conv="${root}/rules-import.py"
gen="${root}/singbox-router-config.py"
install_body="$(cat "${root}/install.sh")"

fail() { echo "$1" >&2; exit 1; }

[[ -f "${conv}" ]] || fail "rules-import.py must exist"
python3 -m py_compile "${conv}" || fail "rules-import.py must compile"

tmp="$(mktemp -d)"; trap 'rm -rf "${tmp}"' EXIT
cat > "${tmp}/rules.conf" <<'S'
[Rule]
DOMAIN-SUFFIX,google.com,AI
PROCESS-NAME,/Applications/Foo.app,AI
IP-CIDR,1.2.3.0/24,"📕 小红书",no-resolve
OR,((DOMAIN,a.com), (SRC-IP,192.168.1.1), (DOMAIN-SUFFIX,b.com)),Proxy
RULE-SET,https://example.com/x.list,Netflix,"update-interval=86400"
FINAL,Proxy
S
out="$(python3 "${conv}" "${tmp}/rules.conf" 2>"${tmp}/err")"

# client-only matchers must be dropped
grep -q 'PROCESS-NAME' <<<"$out" && fail "PROCESS-NAME must be dropped"
grep -q 'SRC-IP' <<<"$out" && fail "SRC-IP must be dropped"
# OR flattened to its domain members (SRC-IP member dropped)
grep -qx 'DOMAIN,a.com,Proxy' <<<"$out" || fail "OR domain member must be kept"
grep -qx 'DOMAIN-SUFFIX,b.com,Proxy' <<<"$out" || fail "OR suffix member must be kept"
# modifiers stripped, quotes stripped, emoji-leading category normalized
grep -qx 'IP-CIDR,1.2.3.0/24,小红书' <<<"$out" || fail "modifiers/quotes/emoji must be normalized"
grep -qx 'RULE-SET,https://example.com/x.list,Netflix' <<<"$out" || fail "RULE-SET url+category must survive"
grep -qx 'FINAL,Proxy' <<<"$out" || fail "FINAL must survive"
grep -q 'CATEGORIES=' "${tmp}/err" || fail "converter must report categories on stderr"

# policy-map resolution: category -> exit/direct/block
mkdir -p "${tmp}/exits"
printf '{"outbounds":[{"type":"socks","tag":"out","server":"1.1.1.1","server_port":1080,"version":"5"}]}' > "${tmp}/exits/att.json"
printf 'DOMAIN-SUFFIX,openai.com,AI\nDOMAIN-SUFFIX,ad.net,Advertising\nFINAL,AI\n' > "${tmp}/rules.conf"
printf 'AI=att\nAdvertising=block\n' > "${tmp}/pm.conf"
cfg="$(EXITS_DIR="${tmp}/exits" WG_DIR="${tmp}/wg" PGW_RULESET_CACHE="${tmp}/rs" PGW_POLICY_MAP="${tmp}/pm.conf" SINGBOX_BIN=/nonexistent python3 "${gen}" "${tmp}/rules.conf")"
python3 - "$cfg" <<'PY'
import json, sys
c = json.loads(sys.argv[1])
assert "att" in [o["tag"] for o in c["outbounds"]], "AI must resolve to the att outbound"
outs = {tuple(sorted(k for k in r if k != "outbound")): r["outbound"] for r in c["route"]["rules"]}
assert ("domain_suffix",) in outs, "rules missing"
assert c["route"]["final"] == "att", "FINAL must resolve via the policy map"
# the Advertising rule must go to block
assert any(r["outbound"] == "block" for r in c["route"]["rules"]), "Advertising must map to block"
print("policy resolution OK")
PY

# install.sh wiring
for m in 'import_rules()' 'set_policy()' 'regen_smart()' 'init_policy_map()' '--import-rules)' '--set-policy)'; do
    [[ "${install_body}" == *"${m}"* ]] || fail "install.sh missing: ${m}"
done

echo "rules import policy OK"
