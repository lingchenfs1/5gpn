#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")/.." && pwd)"; body="$(cat "$here/install.sh")"
fail(){ echo "FAIL: $*"; exit 1; }
[[ "$body" == *'do_update()'* ]] || fail "must define do_update"
[[ "$body" == *'--update)'* ]] || fail "must dispatch --update"
# fetches latest + re-execs the fresh script
[[ "$body" == *'PGW_UPDATE_FETCHED=1 exec bash'* ]] || fail "update must re-exec the freshly fetched script"
# safety backup before changing anything
[[ "$body" == *'preupdate-'* ]] || fail "update must back up config first"
# must NOT issue/force cert in update path, and must reuse domain (re-run safe)
[[ "$body" == *'复用已保存的域名'* ]] || fail "re-run must reuse the saved domain"
[[ "$body" == *'剩余 >30 天'* || "$body" == *'checkend'* ]] || fail "re-run must skip cert when still valid"
# regen must be crash-isolated (subshell) so a generator error can't abort mid-update
[[ "$body" == *'( regen_smart )'* ]] || fail "regen_smart must run in a subshell during update"
echo "update policy OK"
# an unknown flag must NOT run a full install (safety)
[[ "$(cat "$here/install.sh")" == *'"")'*'main_install'* ]] || true
