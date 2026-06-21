#!/usr/bin/env python3
"""
Proxy Gateway HTTP control API.

A small, stdlib-only HTTPS service that exposes the same operations as the
Telegram bot by shelling out to the SAME backend (proxy-gateway-ctl) and reading
the SAME state files. So the web UI and the bot are always in sync — there is
one source of truth (/etc/proxy-gateway + the ctl).

Auth:  every /api/* call (except /api/health) needs  Authorization: Bearer <API_TOKEN>.

Env (systemd EnvironmentFile):
  API_TOKEN         required bearer token (service refuses to start if unset/short)
  API_PORT          listen port                     (default 8443)
  API_BIND          bind address                    (default 0.0.0.0)
  API_TLS_CERT      TLS fullchain                   (default /etc/dnsdist/certs/fullchain.pem)
  API_TLS_KEY       TLS private key                 (default /etc/dnsdist/certs/privkey.pem)
  API_ALLOW_ORIGIN  CORS allowed origin             (default *)
  MGMT              path to proxy-gateway-ctl       (default /opt/proxy-gateway/bin/proxy-gateway-ctl)
  CONF_DIR          gateway state dir               (default /opt/proxy-gateway/etc)
"""
import hmac
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("API_TOKEN", "")
PORT = int(re.sub(r"\D", "", os.environ.get("API_PORT", "8443")) or "8443")
BIND = os.environ.get("API_BIND", "0.0.0.0")
CERT = os.environ.get("API_TLS_CERT", "/etc/dnsdist/certs/fullchain.pem")
KEY = os.environ.get("API_TLS_KEY", "/etc/dnsdist/certs/privkey.pem")
ORIGIN = os.environ.get("API_ALLOW_ORIGIN", "*")
MGMT = os.environ.get("MGMT", "/opt/proxy-gateway/bin/proxy-gateway-ctl")
CONF_DIR = os.environ.get("CONF_DIR", "/opt/proxy-gateway/etc")

PGW_DIR = "/etc/proxy-gateway"
EXITS_DIR = PGW_DIR + "/exits"
POLICY_MAP = PGW_DIR + "/policy-map.conf"
RULES_FILE = PGW_DIR + "/rules.conf"
WG_DIR = "/etc/wireguard"
TRAFFIC_FILE = os.environ.get("TRAFFIC_FILE", CONF_DIR + "/traffic.json")
TRAFFIC_INTERVAL = int(re.sub(r"\D", "", os.environ.get("TRAFFIC_INTERVAL", "300")) or "300")
TRAFFIC_MAX = 24 * 3600 // TRAFFIC_INTERVAL + 2   # ~24h of samples

EXIT_NAME_RE = re.compile(r"^[a-z0-9]{1,11}$")
CAT_RE = re.compile(r"^[A-Za-z0-9_一-鿿-]{1,40}$")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
SERVICES = ["dnsdist", "sniproxy", "quic-proxy", "china-dns-race-proxy",
            "proxy-gateway-tgbot", "proxy-gateway-api"]


def run(argv, inp=None, timeout=180):
    try:
        p = subprocess.run(argv, input=inp, capture_output=True, text=True, timeout=timeout)
        out = ANSI.sub("", (p.stdout or "") + (p.stderr or ""))
        return p.returncode == 0, out.strip()
    except subprocess.TimeoutExpired:
        return False, "操作超时"
    except FileNotFoundError:
        return False, "命令不存在：%s" % argv[0]
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def ctl(*args, inp=None, timeout=180):
    return run(["bash", MGMT, *args], inp=inp, timeout=timeout)


def read_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except Exception:  # noqa: BLE001
        return ""


def current_exit():
    return read_file(CONF_DIR + "/current-exit").strip() or "local"


def list_exits():
    names = set()
    try:
        for f in os.listdir(EXITS_DIR):
            if f.endswith(".type"):
                names.add(f[:-5])
    except Exception:  # noqa: BLE001
        pass
    try:
        for f in os.listdir(WG_DIR):
            if f.startswith("pgw-") and f.endswith(".conf"):
                names.add(f[4:-5])
    except Exception:  # noqa: BLE001
        pass
    cur = current_exit()
    out = []
    for n in sorted(names):
        if n in ("local", "smart"):
            continue
        t = read_file(EXITS_DIR + "/%s.type" % n).strip() or "wireguard"
        server = ""
        try:
            o = json.load(open(EXITS_DIR + "/%s.json" % n))["outbounds"][0]
            if o.get("server"):
                server = "%s:%s" % (o["server"], o.get("server_port", ""))
        except Exception:  # noqa: BLE001
            pass
        out.append({"name": n, "type": t, "server": server, "active": n == cur})
    return out, cur


def policy_map():
    d = {}
    for line in read_file(POLICY_MAP).splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def memory():
    try:
        mi = {}
        for line in read_file("/proc/meminfo").splitlines():
            k, _, v = line.partition(":")
            mi[k.strip()] = int(v.strip().split()[0])  # kB
        total = mi.get("MemTotal", 0) // 1024
        avail = mi.get("MemAvailable", 0) // 1024
        sw_t = mi.get("SwapTotal", 0) // 1024
        sw_f = mi.get("SwapFree", 0) // 1024
        return {"total_mb": total, "available_mb": avail, "used_mb": max(0, total - avail),
                "swap_total_mb": sw_t, "swap_used_mb": max(0, sw_t - sw_f)}
    except Exception:  # noqa: BLE001
        return {}


def parse_rules(text):
    """Parse non-comment rule lines into {i (1-based), raw, type, value, target}."""
    out, i = [], 0
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s[0] in "#;":
            continue
        i += 1
        parts = [p.strip() for p in s.split(",")]
        typ = parts[0].upper() if parts else ""
        if typ == "FINAL" and len(parts) >= 2:
            value, target = "", parts[-1]
        elif len(parts) >= 3:
            value, target = ",".join(parts[1:-1]), parts[-1]
        elif len(parts) == 2:
            value, target = parts[1], ""
        else:
            value, target = "", ""
        out.append({"i": i, "raw": s, "type": typ, "value": value, "target": target})
    return out


def rules_set(text):
    return ctl("--set-rules", inp=text, timeout=400)


def parse_check(out):
    res = []
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 2 and p[-1] in ("UP", "DOWN", "n/a"):
            res.append({"name": p[0], "server": p[1] if len(p) >= 3 else "", "state": p[-1]})
    return res


# --- server resources (CPU / mem / disk / uptime / load) --------------------
def cpu_percent(window=0.25):
    def snap():
        f = [int(x) for x in read_file("/proc/stat").splitlines()[0].split()[1:]]
        idle = f[3] + (f[4] if len(f) > 4 else 0)
        return sum(f), idle
    try:
        t1, i1 = snap()
        time.sleep(window)
        t2, i2 = snap()
        dt, di = t2 - t1, i2 - i1
        return round((1 - di / dt) * 100, 1) if dt > 0 else 0.0
    except Exception:  # noqa: BLE001
        return 0.0


def resources():
    r = memory()
    try:
        s = os.statvfs("/")
        r["disk_total_mb"] = (s.f_blocks * s.f_frsize) // (1024 * 1024)
        r["disk_used_mb"] = ((s.f_blocks - s.f_bfree) * s.f_frsize) // (1024 * 1024)
    except Exception:  # noqa: BLE001
        pass
    try:
        r["uptime_sec"] = int(float(read_file("/proc/uptime").split()[0]))
    except Exception:  # noqa: BLE001
        pass
    try:
        r["load"] = [float(x) for x in read_file("/proc/loadavg").split()[:3]]
    except Exception:  # noqa: BLE001
        pass
    r["cpu_cores"] = os.cpu_count() or 1
    r["cpu_percent"] = cpu_percent()
    return r


# --- 24h traffic ring buffer (per pgw-* exit device + the primary NIC) -------
_traffic_lock = threading.Lock()


def primary_iface():
    try:
        for line in read_file("/proc/net/route").splitlines()[1:]:
            f = line.split()
            if len(f) >= 2 and f[1] == "00000000":
                return f[0]
    except Exception:  # noqa: BLE001
        pass
    return "eth0"


def read_net_dev():
    out = {}
    for line in read_file("/proc/net/dev").splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        f = rest.split()
        if len(f) >= 9:
            try:
                out[name.strip()] = {"rx": int(f[0]), "tx": int(f[8])}
            except ValueError:
                pass
    return out


def tracked(dev, primary):
    # device name -> friendly label ("server" or the exit name)
    m = {}
    for n in dev:
        if n == primary:
            m[n] = "server"
        elif n.startswith("pgw-"):
            m[n] = n[4:]
    return m


def _load_traffic():
    try:
        return json.load(open(TRAFFIC_FILE))
    except Exception:  # noqa: BLE001
        return {"interval_sec": TRAFFIC_INTERVAL, "raw": {}, "raw_ts": 0, "points": []}


def _save_traffic(data):
    try:
        tmp = TRAFFIC_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, TRAFFIC_FILE)
    except Exception:  # noqa: BLE001
        pass


def traffic_tick():
    with _traffic_lock:
        data = _load_traffic()
        primary = primary_iface()
        dev = read_net_dev()
        now = int(time.time())
        raw = data.get("raw", {})
        # Append a delta point, but skip if there was a long gap (avoids a spike
        # lumping all of the downtime's traffic into one bucket).
        if raw and data.get("raw_ts") and 0 < (now - data["raw_ts"]) <= TRAFFIC_INTERVAL * 3:
            d = {}
            for dn, lbl in tracked(dev, primary).items():
                if dn in raw:
                    d[lbl] = [max(0, dev[dn]["rx"] - raw[dn]["rx"]),
                              max(0, dev[dn]["tx"] - raw[dn]["tx"])]
            if d:
                data.setdefault("points", []).append({"t": now, "v": d})
                data["points"] = data["points"][-TRAFFIC_MAX:]
        data["raw"] = {dn: dev[dn] for dn in tracked(dev, primary)}
        data["raw_ts"] = now
        data["interval_sec"] = TRAFFIC_INTERVAL
        _save_traffic(data)


def traffic_loop():
    try:
        traffic_tick()      # establish a baseline immediately
    except Exception:  # noqa: BLE001
        pass
    while True:
        time.sleep(TRAFFIC_INTERVAL)
        try:
            traffic_tick()
        except Exception:  # noqa: BLE001
            pass


class Handler(BaseHTTPRequestHandler):
    server_version = "pgw-api"

    def log_message(self, *a):  # keep the journal quiet
        pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", ORIGIN)
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:  # noqa: BLE001
            pass

    def _auth(self):
        h = self.headers.get("Authorization", "")
        return h.startswith("Bearer ") and hmac.compare_digest(h[7:], TOKEN)

    def _json_body(self):
        try:
            n = int(self.headers.get("Content-Length", "0") or 0)
            if n <= 0 or n > 2_000_000:
                return {}
            data = self.rfile.read(n).decode("utf-8")
            obj = json.loads(data or "{}")
            return obj if isinstance(obj, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/api/health":
            return self._send(200, {"ok": True, "service": "proxy-gateway-api"})
        if not self._auth():
            return self._send(401, {"ok": False, "error": "unauthorized"})
        if path == "/api/status":
            exits, cur = list_exits()
            services = {s: run(["systemctl", "is-active", s], timeout=5)[0] for s in SERVICES}
            res = resources()
            return self._send(200, {"ok": True, "current": cur, "exits": exits,
                                    "resources": res, "memory": res, "services": services,
                                    "policy": policy_map()})
        if path == "/api/traffic":
            with _traffic_lock:
                data = _load_traffic()
            cutoff = int(time.time()) - 24 * 3600
            pts = [p for p in data.get("points", []) if p.get("t", 0) >= cutoff]
            series = sorted({k for p in pts for k in p.get("v", {})})
            return self._send(200, {"ok": True, "now": int(time.time()),
                                    "interval_sec": data.get("interval_sec", TRAFFIC_INTERVAL),
                                    "series": series, "points": pts})
        if path == "/api/exits":
            exits, cur = list_exits()
            return self._send(200, {"ok": True, "current": cur, "exits": exits})
        if path == "/api/policy":
            return self._send(200, {"ok": True, "policy": policy_map()})
        if path == "/api/rules":
            txt = read_file(RULES_FILE)
            entries = parse_rules(txt)
            return self._send(200, {"ok": True, "count": len(entries), "rules": txt, "entries": entries})
        return self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if not self._auth():
            return self._send(401, {"ok": False, "error": "unauthorized"})
        b = self._json_body()

        if path == "/api/exits/set":
            name = str(b.get("name", "")).strip()
            if name not in ("local", "smart") and not EXIT_NAME_RE.match(name):
                return self._send(400, {"ok": False, "error": "invalid name"})
            ok, out = ctl("--set-exit", name, timeout=120)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/exits/add":
            name = str(b.get("name", "")).strip()
            cfg = b.get("config", "")
            if not EXIT_NAME_RE.match(name) or name == "local":
                return self._send(400, {"ok": False, "error": "invalid name (1-11 lowercase/digits, not 'local')"})
            if not isinstance(cfg, str) or not cfg.strip():
                return self._send(400, {"ok": False, "error": "empty config"})
            ok, out = ctl("--add-exit", name, inp=cfg, timeout=200)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/exits/del":
            name = str(b.get("name", "")).strip()
            if not EXIT_NAME_RE.match(name):
                return self._send(400, {"ok": False, "error": "invalid name"})
            ok, out = ctl("--del-exit", name, timeout=90)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/exits/check":
            ok, out = ctl("--check-exits", timeout=150)
            return self._send(200, {"ok": ok, "output": out, "exits": parse_check(out)})

        if path == "/api/policy":
            cat = str(b.get("category", "")).strip()
            tgt = str(b.get("target", "")).strip()
            if not CAT_RE.match(cat):
                return self._send(400, {"ok": False, "error": "invalid category"})
            if tgt not in ("direct", "block") and not EXIT_NAME_RE.match(tgt):
                return self._send(400, {"ok": False, "error": "invalid target"})
            ok, out = ctl("--set-policy", cat, tgt, timeout=300)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/rules":
            rules = b.get("rules", "")
            if not isinstance(rules, str) or not rules.strip():
                return self._send(400, {"ok": False, "error": "empty rules"})
            ok, out = rules_set(rules)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/rules/add":
            rule = str(b.get("rule", "")).strip()
            if not rule or "\n" in rule or len(rule) > 2000:
                return self._send(400, {"ok": False, "error": "invalid rule"})
            txt = read_file(RULES_FILE)
            newtext = (txt.rstrip("\n") + "\n" + rule + "\n") if txt.strip() else (rule + "\n")
            ok, out = rules_set(newtext)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/rules/del":
            try:
                idx = int(b.get("index"))
            except (TypeError, ValueError):
                return self._send(400, {"ok": False, "error": "invalid index"})
            keep, n, dropped = [], 0, False
            for ln in read_file(RULES_FILE).splitlines():
                s = ln.strip()
                if s and s[0] not in "#;":
                    n += 1
                    if n == idx:
                        dropped = True
                        continue
                keep.append(ln)
            if not dropped:
                return self._send(400, {"ok": False, "error": "index out of range"})
            ok, out = rules_set("\n".join(keep) + "\n")
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/update-rules":
            ok, out = ctl("--update-rules", timeout=400)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        return self._send(404, {"ok": False, "error": "not found"})


def main():
    if not TOKEN or len(TOKEN) < 16:
        sys.stderr.write("API_TOKEN unset or too short (need >=16 chars); refusing to start.\n")
        sys.exit(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("TLS cert load failed (%s / %s): %s\n" % (CERT, KEY, e))
        sys.exit(1)
    threading.Thread(target=traffic_loop, daemon=True).start()
    httpd = ThreadingHTTPServer((BIND, PORT), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    sys.stderr.write("proxy-gateway-api listening on %s:%d (TLS)\n" % (BIND, PORT))
    sys.stderr.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
