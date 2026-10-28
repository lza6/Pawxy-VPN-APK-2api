"""Pawxy node-manager demo server (read-only panel + on-demand credential issue).

Run:  python demo_server.py [--port 8940] [--proxy http://127.0.0.1:10808]

Endpoints
  GET  /                     demo page
  GET  /api/nodes            harvested node summary (nodes/nodes_summary.json)
  GET  /api/countries        live /countries from the upstream API
  POST /api/install          {"country":"AT"} -> fresh WireGuard credential
  GET  /api/probe?code=AT    live WireGuard handshake probe (via SOCKS5 UDP relay)
  GET  /api/stress           run the concurrency stress pass and return stats

Nothing is cached on disk for install calls: every request mints a new X25519
keypair, exactly like the app does.
"""
import argparse, base64, json, os, sys, time, socket, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from pawxy import client as api_client, BASE, HEAD  # noqa: E402
from harvest import kp                              # noqa: E402
import wgprobe                                      # noqa: E402
from socks5udp import Socks5UDP                     # noqa: E402

PROXY = "http://127.0.0.1:10808"
SOCKS = ("127.0.0.1", 10808)


def load_nodes():
    p = os.path.join(ROOT, "nodes", "nodes_summary.json")
    if not os.path.exists(p):
        return {}
    return json.load(open(p, encoding="utf-8"))


def do_install(country):
    priv, pubhex = kp()
    with api_client() as c:
        r = c.post(f"{BASE}/install",
                   data={"country": country, "public-key": pubhex, "stat-unix": "-1"})
    if r.status_code != 200:
        return {"ok": False, "status": r.status_code, "error": r.text[:300]}
    cfg = r.json()
    cfg["private_key"] = priv
    cfg["conf"] = (
        "[Interface]\n"
        f"PrivateKey = {priv}\n"
        f"Address = {cfg['interface']['address']['ipv4']}, {cfg['interface']['address']['ipv6']}\n"
        "DNS = 1.1.1.1, 1.0.0.1\nMTU = 1420\n\n"
        "[Peer]\n"
        f"PublicKey = {cfg['peer']['publicKey']}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {cfg['peer']['endPoint']}:{cfg['peer']['port']}\n"
        "PersistentKeepalive = 25\n"
    )
    return {"ok": True, "config": cfg}


def probe_node(code):
    nodes = load_nodes()
    n = nodes.get(code)
    if not n:
        return {"ok": False, "error": "unknown country"}
    res = {"code": code, "endpoint": n["endpoint"], "port": n["port"],
           "premium": n["premium"], "datacenter": n["datacenter"]}
    # 1. plain UDP reachability via the SOCKS5 relay
    try:
        s = Socks5UDP(proxy=SOCKS, timeout=4)
        relay = s.relay
        s.close()
        res["udp_relay"] = f"{relay[0]}:{relay[1]}"
    except Exception as e:
        res["udp_relay"] = f"unavailable: {e}"
    # 2. WireGuard handshake
    ok, rtt, detail = probe_via_relay(n["endpoint"], n["port"], n["peer_public_key"])
    res.update({"handshake": ok, "rtt_ms": None if rtt is None else round(rtt, 1), "detail": detail})
    return res


def probe_via_relay(ip, port, pub_b64, timeout=4.0):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    static_priv = X25519PrivateKey.generate()
    peer = base64.b64decode(pub_b64)
    sender_index, msg, _ = wgprobe.build_initiation(static_priv, peer)
    s = None
    t0 = time.time()
    try:
        s = Socks5UDP(proxy=SOCKS, timeout=timeout)
        s.sendto(msg, (ip, port))
        data, _ = s.recvfrom()
    except socket.timeout:
        return False, None, "timeout"
    except Exception as e:
        return False, None, f"{type(e).__name__}:{e}"
    finally:
        if s:
            s.close()
    rtt = (time.time() - t0) * 1000
    if len(data) < 60 or data[0] != 2:
        return False, rtt, f"bad_msg type={data[0] if data else None} len={len(data)}"
    if int.from_bytes(data[8:12], "little") != sender_index:
        return False, rtt, "receiver_index_mismatch"
    mac1_key = wgprobe.b2s(wgprobe.LABEL_MAC1 + wgprobe.pub(static_priv))
    if wgprobe.hmac(mac1_key, data[:60])[:16] != data[60:76]:
        return False, rtt, "mac1_invalid"
    return True, rtt, "handshake_ok"


class Handler(BaseHTTPRequestHandler):
    server_version = "PawxyNodePanel/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False, indent=1)
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            p = os.path.join(HERE, "demo.html")
            self._send(200, open(p, encoding="utf-8").read(), "text/html; charset=utf-8")
        elif u.path == "/api/nodes":
            nodes = load_nodes()
            free = [k for k, v in nodes.items() if not v["premium"]]
            self._send(200, {"count": len(nodes), "free": len(free), "nodes": nodes})
        elif u.path == "/api/countries":
            try:
                with api_client() as c:
                    r = c.post(f"{BASE}/countries", data={"ping": "pong"})
                self._send(200, {"ok": r.status_code == 200, "data": r.json()})
            except Exception as e:
                self._send(502, {"ok": False, "error": str(e)})
        elif u.path == "/api/probe":
            code = (q.get("code") or [""])[0].upper()
            self._send(200, probe_node(code))
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except Exception:
            payload = {}
        if u.path == "/api/install":
            code = (payload.get("country") or "AT").upper()
            self._send(200, do_install(code))
        else:
            self._send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8940)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Pawxy node panel -> http://{args.host}:{args.port}/", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
