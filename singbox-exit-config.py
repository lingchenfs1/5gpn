#!/usr/bin/env python3
"""
Generate a sing-box config for one proxy-gateway egress exit from a proxy URI.

Supports:
  socks5://[user:pass@]host:port
  socks://[user:pass@]host:port          (alias of socks5)
  ss://...   Shadowsocks (SIP002 and legacy base64), including Shadowsocks-2022
             methods (2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm,
             2022-blake3-chacha20-poly1305).

Usage:  singbox-exit-config.py <exit-name> <uri>
Emits sing-box JSON on stdout. Exits non-zero with a message on stderr on error.

Env:
  SINGBOX_STACK  TUN network stack: system|gvisor|mixed   (default: system)
  SINGBOX_MTU    TUN MTU                                   (default: 1400)
"""
import base64
import json
import os
import re
import sys
from urllib.parse import unquote, urlparse

SS_METHODS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "chacha20-ietf",
    "aes-128-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "none",
    "plain",
}


def die(msg):
    sys.stderr.write(msg.rstrip() + "\n")
    sys.exit(1)


def b64decode_any(s):
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return dec(s + pad).decode("utf-8")
        except Exception:
            continue
    raise ValueError("not base64")


def parse_hostport(s):
    s = s.strip()
    # [v6]:port
    m = re.match(r"^\[(.+)\]:(\d+)$", s)
    if m:
        return m.group(1), int(m.group(2))
    if s.count(":") == 1:
        host, port = s.rsplit(":", 1)
        return host, int(port)
    die("cannot parse host:port from %r" % s)


def parse_ss(uri):
    rest = uri[len("ss://"):]
    rest = rest.split("#", 1)[0]   # drop tag
    rest = rest.split("?", 1)[0]   # drop plugin/query (plugins unsupported)

    if "@" in rest:
        userinfo, server = rest.rsplit("@", 1)
        method, password = decode_ss_userinfo(userinfo)
        host, port = parse_hostport(server)
    else:
        # legacy: base64(method:password@host:port)
        try:
            dec = b64decode_any(rest)
        except ValueError:
            die("invalid ss:// (not SIP002 and not valid base64)")
        if "@" not in dec or ":" not in dec:
            die("invalid legacy ss:// payload")
        creds, server = dec.rsplit("@", 1)
        method, password = creds.split(":", 1)
        host, port = parse_hostport(server)

    if not method:
        die("ss:// missing method")
    return host, port, method, password


def decode_ss_userinfo(userinfo):
    # SIP002 userinfo is usually base64(method:password); for 2022 it is often
    # the plaintext "method:password" (password itself base64).
    try:
        dec = b64decode_any(userinfo)
        if ":" in dec:
            m = dec.split(":", 1)[0]
            if re.match(r"^[a-z0-9-]+$", m):
                return dec.split(":", 1)
    except ValueError:
        pass
    plain = unquote(userinfo)
    if ":" in plain:
        return plain.split(":", 1)
    die("cannot parse ss:// credentials")


def parse_socks(uri):
    u = urlparse(uri)
    if not u.hostname or not u.port:
        die("socks5:// missing host or port")
    return u.hostname, u.port, (unquote(u.username) if u.username else None), \
        (unquote(u.password) if u.password else None)


def main():
    if len(sys.argv) != 3:
        die("usage: singbox-exit-config.py <name> <uri>")
    name, uri = sys.argv[1], sys.argv[2].strip()
    if not re.match(r"^[a-z0-9]{1,11}$", name) or name == "local":
        die("invalid exit name")

    # gvisor (userspace netstack) is the reliable tun2socks stack; the "system"
    # stack does not forward on many kernels. Override with SINGBOX_STACK if needed.
    stack = os.environ.get("SINGBOX_STACK", "gvisor")
    try:
        mtu = int(os.environ.get("SINGBOX_MTU", "1400"))
    except ValueError:
        mtu = 1400

    # Remote DNS ("socks5h"): resolve the target hostname at the exit server.
    # We recover the hostname by sniffing the TLS ClientHello / HTTP Host in the
    # TUN, then forward the domain (not the IP) to the upstream proxy.
    remote_dns = os.environ.get("PGW_REMOTE_DNS", "").lower() in ("1", "true", "yes", "on")

    low = uri.lower()
    if low.startswith("ss://"):
        host, port, method, password = parse_ss(uri)
        outbound = {
            "type": "shadowsocks",
            "tag": "out",
            "server": host,
            "server_port": port,
            "method": method,
            "password": password,
        }
    elif low.startswith(("socks5h://", "socks5://", "socks://")):
        if low.startswith("socks5h://"):
            remote_dns = True
        host, port, user, password = parse_socks(uri)
        # Credentials supplied out-of-band (PGW_USER/PGW_PASS) win over anything
        # embedded in the URI, so passwords with @ : / # ? need no URL-encoding.
        env_user = os.environ.get("PGW_USER", "")
        env_pass = os.environ.get("PGW_PASS", "")
        if env_user:
            user = env_user
        if env_pass:
            password = env_pass
        outbound = {
            "type": "socks",
            "tag": "out",
            "server": host,
            "server_port": port,
            "version": "5",
        }
        if user:
            outbound["username"] = user
        if password:
            outbound["password"] = password
    else:
        die("unsupported URI scheme (expected ss://, socks5:// or socks5h://)")

    inbound = {
        "type": "tun",
        "tag": "pgw-in",
        "interface_name": "pgw-" + name,
        "inet4_address": "172.19.0.1/30",
        "mtu": mtu,
        "auto_route": False,
        "strict_route": False,
        "stack": stack,
        "sniff": remote_dns,
    }
    if remote_dns:
        # Replace the (locally-resolved) destination IP with the sniffed domain
        # so the upstream proxy performs the DNS lookup.
        inbound["sniff_override_destination"] = True

    config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [inbound],
        "outbounds": [outbound],
        "route": {"final": "out"},
    }
    sys.stdout.write(json.dumps(config, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
