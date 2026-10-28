import httpx, json, hashlib, uuid, base64, os, time, sys

BASE = "https://api.quxiq.com"
SIG  = "431d8a11-bc0b-3a07-ad36-6da183c62a6c"
PROXY = "http://127.0.0.1:10808"

def device_id(android_id="9774d56d682e549c"):
    u = uuid.UUID(bytes=hashlib.md5(("Pawxy:"+android_id).encode()).digest(), version=3)
    return "1"+str(u)[1:]

HEAD = {"app-version":"103","os-version":"34","token":"none","signature":SIG,
        "device": device_id()}

def client():
    return httpx.Client(proxy=PROXY, timeout=40, headers=HEAD)

# --- X25519 keypair (like WireGuard) ---
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

def keypair():
    priv = X25519PrivateKey.generate()
    priv_b = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub_b  = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv_b).decode(), base64.b64encode(pub_b).decode()

def countries(c):
    r = c.post(f"{BASE}/countries", data={"ping":"pong"})
    r.raise_for_status()
    return r.json()

def install(c, code, pub):
    r = c.post(f"{BASE}/install", data={
        "stat-unix": "-1", "country": code, "public-key": pub})
    return r.status_code, r.text

if __name__ == "__main__":
    with client() as c:
        cc = countries(c)
        print("countries:", len(cc))
        free = [(x["code"], d["name"], d["address"], x.get("premium"), x.get("expensive"))
                for x in cc for d in x.get("datacenters", [])]
        print("datacenters:", len(free))
        json.dump(cc, open("D:/apk-analysis/pawxy/work/countries.json","w"), indent=1)
        for row in free[:5]: print("  ", row)
        # try install on a free country
        priv, pub = keypair()
        code = next(x["code"] for x in cc if not x.get("premium"))
        st, body = install(c, code, pub)
        print(f"\ninstall country={code} -> {st}")
        print(body[:1200])
        open("D:/apk-analysis/pawxy/work/install_sample.txt","w").write(body)
