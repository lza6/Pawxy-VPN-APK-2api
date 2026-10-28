"""Generate sing-box configs that turn a Pawxy WireGuard credential into a
local SOCKS5 inbound — the layer new-api consumes as an outbound proxy.

  python gen.py --country AT --port 11080 --out sb_at.json
  python gen.py --all --base-port 11080 --dir ./sb      # one config per country

Requires a harvested credential in <repo>/nodes/nodes.json (see tools/harvest.py)
or pass --config <file> pointing at a single /install JSON response.
"""
import argparse, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def build(entry, tag, socks_port, proxy=None):
    cfg = entry["config"] if "config" in entry else entry
    priv = entry.get("_private_key") or cfg.get("_private_key") or cfg.get("private_key")
    ep = cfg["peer"]
    addr = cfg["interface"]["address"]
    endpoint = {
        "type": "wireguard",
        "tag": tag,
        "system": False,
        "address": [addr["ipv4"], addr["ipv6"]],
        "private_key": priv,
        "peers": [{
            "address": ep["endPoint"],
            "port": ep["port"],
            "public_key": ep["publicKey"],
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "persistent_keepalive_interval": 25,
        }],
        "mtu": 1420,
    }
    if proxy:                      # dial the WG endpoint through a local proxy
        endpoint["detour"] = "upstream"
    out = {
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": socks_port,
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "endpoints": [endpoint],
        "route": {"rules": [{"action": "route", "outbound": tag}], "final": tag},
    }
    if proxy:
        out["outbounds"].append({
            "type": "socks", "tag": "upstream",
            "server": proxy[0], "server_port": proxy[1],
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--country")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--port", type=int, default=11080)
    ap.add_argument("--base-port", type=int, default=11080)
    ap.add_argument("--dir", default=os.path.join(HERE, "sb"))
    ap.add_argument("--nodes", default=os.path.join(ROOT, "nodes", "nodes.json"))
    ap.add_argument("--config")
    ap.add_argument("--socks-upstream", help="host:port — dial WG through this proxy")
    args = ap.parse_args()

    proxy = None
    if args.socks_upstream:
        h, p = args.socks_upstream.rsplit(":", 1)
        proxy = (h, int(p))

    if args.config:
        entry = json.load(open(args.config, encoding="utf-8"))
        print(json.dumps(build(entry, "wg", args.port, proxy), indent=1, ensure_ascii=False))
        return 0

    nodes = json.load(open(args.nodes, encoding="utf-8"))
    os.makedirs(args.dir, exist_ok=True)
    codes = [args.country.upper()] if args.country else sorted(nodes)
    if not args.all and not args.country:
        ap.error("pass --country XX or --all")
    port = args.base_port
    for code in codes:
        v = nodes.get(code)
        if not v or not v.get("config"):
            print(f"skip {code}: no credential", file=sys.stderr)
            continue
        path = os.path.join(args.dir, f"{code}.json")
        json.dump(build(v, f"wg-{code.lower()}", port, proxy), open(path, "w"),
                  indent=1, ensure_ascii=False)
        print(f"{code} -> {path}  socks5 127.0.0.1:{port}")
        port += 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
