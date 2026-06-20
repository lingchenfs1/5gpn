#!/bin/bash
# Tests for the HTTP control API (api-server.py + install.sh wiring).
set -u
here="$(cd "$(dirname "$0")/.." && pwd)"
fail() { echo "FAIL: $*"; exit 1; }

install_body="$(cat "${here}/install.sh")"
api_body="$(cat "${here}/api-server.py")"

# --- api-server.py: compiles and enforces auth/TLS --------------------------
python3 -m py_compile "${here}/api-server.py" || fail "api-server.py must compile"
[[ "${api_body}" == *'hmac.compare_digest'* ]] || fail "API must compare the token in constant time"
[[ "${api_body}" == *'Authorization'* ]] || fail "API must require an Authorization header"
[[ "${api_body}" == *'load_cert_chain'* ]] || fail "API must serve TLS"
[[ "${api_body}" == *'len(TOKEN) < 16'* ]] || fail "API must refuse a missing/short token"
for ep in '/api/health' '/api/status' '/api/exits/set' '/api/exits/add' '/api/exits/del' \
          '/api/exits/check' '/api/policy' '/api/rules' '/api/update-rules'; do
    [[ "${api_body}" == *"${ep}"* ]] || fail "API missing endpoint: ${ep}"
done
# same backend as the bot -> in sync
[[ "${api_body}" == *'proxy-gateway-ctl'* ]] || fail "API must shell out to proxy-gateway-ctl (shared backend)"
# CORS so a web page hosted elsewhere can call it
[[ "${api_body}" == *'Access-Control-Allow-Origin'* ]] || fail "API must send CORS headers"

# --- install.sh wiring ------------------------------------------------------
[[ "${install_body}" == *'setup_api()'* ]] || fail "install.sh must define setup_api"
[[ "${install_body}" == *'--setup-api)'* ]] || fail "install.sh must dispatch --setup-api"
[[ "${install_body}" == *'proxy-gateway-api.service'* ]] || fail "install.sh must define the API systemd unit"
[[ "${install_body}" == *'api.env'* ]] || fail "install.sh must write api.env"
[[ "${install_body}" == *'__TCP_PORTS__'* ]] || fail "firewall must templatize the allowed TCP ports"
[[ "${install_body}" == *'.api_port'* ]] || fail "firewall must read the API port for persistence"
[[ "${install_body}" == *'proxy-gateway-tgbot,proxy-gateway-api}'* ]] || fail "uninstall must remove the API unit"

# --- renew hook restarts the API (cert held in memory) ----------------------
[[ "$(cat "${here}/renew-hook.sh")" == *'proxy-gateway-api'* ]] || fail "renew hook must restart the API"

# --- web panel ships and talks to the API -----------------------------------
[[ -f "${here}/webui/index.html" ]] || fail "web panel index.html must exist"
web="$(cat "${here}/webui/index.html")"
[[ "${web}" == *'/api/status'* && "${web}" == *'Bearer'* ]] || fail "web panel must call the API with a Bearer token"

echo "api control surface OK"
