"""First-round local stress pass for the Pawxy node pool.

  python stress.py --rounds 3 --workers 8 [--probe-timeout 4]

Phase 1  credential issuance: mint a fresh keypair per country, N rounds,
         record HTTP status distribution + issuance latency.
Phase 2  liveness: WireGuard handshake against every harvested endpoint
         through the SOCKS5 UDP relay, record success rate + RTT percentiles.

Exit code 0 if phase 1 fully succeeded, else 1.
"""
import argparse, base64, json, os, statistics, sys, time, socket
import concurrent.futures as cf

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from pawxy import client as api_client, BASE        # noqa: E402
from harvest import kp                              # noqa: E402
import wgprobe                                      # noqa: E402
from socks5udp import Socks5UDP                     # noqa: E402

SOCKS = ("127.0.0.1", 10808)


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = max(0, min(len(xs) - 1, int(round((p / 100) * (len(xs) - 1)))))
    return xs[k]


def issue(country):
    priv, pubhex = kp()
    t0 = time.time()
    try:
        with api_client() as c:
            r = c.post(f"{BASE}/install",
                       data={"country": country, "public-key": pubhex, "stat-unix": "-1"})
        dt = (time.time() - t0) * 1000
        if r.status_code == 200:
            return {"country": country, "status": 200, "ms": dt, "config": r.json(), "priv": priv}
        return {"country": country, "status": r.status_code, "ms": dt}
    except Exception as e:
        return {"country": country, "status": "ERR", "err": f"{type(e).__name__}:{e}",
                "ms": (time.time() - t0) * 1000}


def handshake(ip, port, pub_b64, timeout):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    priv = X25519PrivateKey.generate()
    sender_index, msg, _ = wgprobe.build_initiation(priv, base64.b64decode(pub_b64))
    s = None
    t0 = time.time()
    try:
        s = Socks5UDP(proxy=SOCKS, timeout=timeout)
        s.sendto(msg, (ip, port))
        data, _ = s.recvfrom()
    except socket.timeout:
        return False, None, "timeout"
    except Exception as e:
        return False, None, f"{type(e).__name__}"
    finally:
        if s:
            s.close()
    rtt = (time.time() - t0) * 1000
    if len(data) < 60 or data[0] != 2:
        return False, rtt, f"bad_msg(len={len(data)})"
    if int.from_bytes(data[8:12], "little") != sender_index:
        return False, rtt, "receiver_index_mismatch"
    mac1_key = wgprobe.b2s(wgprobe.LABEL_MAC1 + wgprobe.pub(priv))
    if wgprobe.hmac(mac1_key, data[:60])[:16] != data[60:76]:
        return False, rtt, "mac1_invalid"
    return True, rtt, "handshake_ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--probe-timeout", type=float, default=4.0)
    ap.add_argument("--countries", default="")
    args = ap.parse_args()

    with api_client() as c:
        cc = c.post(f"{BASE}/countries", data={"ping": "pong"}).json()
    codes = [x["code"] for x in cc]
    if args.countries:
        codes = [x.strip().upper() for x in args.countries.split(",") if x.strip()]
    print(f"[phase1] issuing credentials: {len(codes)} countries x {args.rounds} rounds")

    jobs = [(code, r) for r in range(args.rounds) for code in codes]
    results = []
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for res in ex.map(lambda j: issue(j[0]), jobs):
            results.append(res)
    elapsed = time.time() - t0

    from collections import Counter
    status = Counter(r["status"] for r in results)
    lat = [r["ms"] for r in results if isinstance(r["status"], int)]
    print(f"[phase1] done in {elapsed:.1f}s   status={dict(status)}")
    print(f"[phase1] issue latency ms  p50={pct(lat,50):.0f} p95={pct(lat,95):.0f} "
          f"max={max(lat):.0f}" if lat else "[phase1] no latency samples")

    ok_cfgs = {}
    for r in results:
        if r.get("status") == 200:
            ok_cfgs[r["country"]] = r["config"]
    print(f"[phase1] distinct countries with a live credential: {len(ok_cfgs)}")

    print(f"\n[phase2] WireGuard handshake on {len(ok_cfgs)} endpoints "
          f"(timeout {args.probe_timeout}s via SOCKS5 UDP relay)")
    t0 = time.time()
    probes = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        fut = {
            ex.submit(handshake, cfg["peer"]["endPoint"], cfg["peer"]["port"],
                      cfg["peer"]["publicKey"], args.probe_timeout): code
            for code, cfg in ok_cfgs.items()
        }
        for f in cf.as_completed(fut):
            code = fut[f]
            try:
                ok, rtt, detail = f.result()
            except Exception as e:
                ok, rtt, detail = False, None, f"{type(e).__name__}"
            probes.append({"country": code, "ok": ok, "rtt": rtt, "detail": detail,
                           "endpoint": ok_cfgs[code]["peer"]["endPoint"]})
            mark = "OK " if ok else "-- "
            print(f"  {mark}{code}  {ok_cfgs[code]['peer']['endPoint']:<16} "
                  f"{'' if rtt is None else f'{rtt:.0f}ms':>7}  {detail}")
    alive = [p for p in probes if p["ok"]]
    rtts = [p["rtt"] for p in alive if p["rtt"]]
    print(f"\n[phase2] alive {len(alive)}/{len(probes)} in {time.time()-t0:.1f}s")
    if rtts:
        print(f"[phase2] rtt ms  p50={pct(rtts,50):.0f} p95={pct(rtts,95):.0f} "
              f"min={min(rtts):.0f} max={max(rtts):.0f}")

    out = {"ts": int(time.time()), "phase1": {"status": dict(status),
           "distinct_ok": len(ok_cfgs), "elapsed_s": round(elapsed, 1)},
           "phase2": {"total": len(probes), "alive": len(alive), "probes": probes}}
    json.dump(out, open(os.path.join(ROOT, "nodes", "stress_report.json"), "w"), indent=1)
    print(f"\nreport -> nodes/stress_report.json")
    return 0 if status.get(200, 0) == len(jobs) else 1


if __name__ == "__main__":
    sys.exit(main())
