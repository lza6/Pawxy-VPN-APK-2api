import httpx, json, base64, sys, time, concurrent.futures as cf
sys.path.insert(0,'D:/apk-analysis/pawxy/work')
from pawxy import client, keypair, BASE
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

def kp():
    p = X25519PrivateKey.generate()
    priv = p.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub  = p.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), pub.hex()

def one(code):
    priv, pubhex = kp()
    for attempt in range(3):
        try:
            with client() as c:
                r = c.post(f"{BASE}/install", data={"country":code,"public-key":pubhex,"stat-unix":"-1"})
            if r.status_code == 200:
                j = r.json()
                j["_private_key"] = priv
                j["_public_key_hex"] = pubhex
                j["_fetched_at"] = int(time.time())
                return code, "ok", j
            if r.status_code in (409, 429):
                time.sleep(1.5); continue
            return code, f"http{r.status_code}", None
        except Exception as e:
            time.sleep(1.0)
    return code, "retry_exhausted", None

def main():
    with client() as c:
        cc = c.post(f"{BASE}/countries", data={"ping":"pong"}).json()
    codes = [x["code"] for x in cc]
    print("countries:", len(codes), codes)
    out = {}
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for code, st, cfg in ex.map(one, codes):
            out[code] = {"status": st, "config": cfg}
            ep = cfg["peer"]["endPoint"]+":"+str(cfg["peer"]["port"]) if cfg else "-"
            print(f"{code} {st:16s} {ep}")
    json.dump(out, open("D:/apk-analysis/pawxy/work/nodes.json","w"), indent=1)
    ok = sum(1 for v in out.values() if v["status"]=="ok")
    print(f"\nharvested {ok}/{len(codes)}")

if __name__ == "__main__":
    main()
