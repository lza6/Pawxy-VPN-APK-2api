"""WireGuard handshake-initiation prober.
Sends a valid Noise_IKpsk2 initiation and verifies the response mac1,
which can only validate if the responder actually decrypted our message.
"""
import os, time, base64, socket, struct, hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER   = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1   = b"mac1----"

def b2s(data, key=b"", size=32):
    return hashlib.blake2s(data, key=key, digest_size=size).digest()

def hmac(k, d):
    return b2s(d, k, 32)

def pub(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def raw(priv):
    return priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

def x25519(a, b_pub):
    return a.exchange(X25519PublicKey.from_public_bytes(b_pub))

def b64(b): return base64.b64encode(b).decode()
def unb64(s): return base64.b64decode(s)

def tai64n():
    n = time.time()
    sec = int(n); ns = int((n - sec) * 1e9)
    return struct.pack(">QI", 0x4000000000000000 + sec, ns)

def build_initiation(static_priv, peer_static_pub):
    sender_index = struct.unpack("<I", os.urandom(4))[0]
    chaining_key = b2s(CONSTRUCTION)
    h = b2s(chaining_key + IDENTIFIER)
    h = b2s(h + peer_static_pub)

    e_priv = X25519PrivateKey.generate()
    e_pub = pub(e_priv)
    h = b2s(h + e_pub)

    temp = hmac(chaining_key, e_pub)
    chaining_key = hmac(temp, b"\x01")
    temp = hmac(chaining_key, x25519(e_priv, peer_static_pub))
    chaining_key = hmac(temp, b"\x01")
    key = hmac(temp, chaining_key + b"\x02")
    enc_static = ChaCha20Poly1305(key).encrypt(b"\x00"*12, pub(static_priv), h)
    h = b2s(h + enc_static)

    temp = hmac(chaining_key, x25519(static_priv, peer_static_pub))
    chaining_key = hmac(temp, b"\x01")
    key = hmac(temp, chaining_key + b"\x02")
    enc_ts = ChaCha20Poly1305(key).encrypt(b"\x00"*12, tai64n(), h)
    h = b2s(h + enc_ts)

    msg = struct.pack("<B3sI", 1, b"\x00\x00\x00", sender_index) + e_pub + enc_static + enc_ts
    mac1_key = b2s(LABEL_MAC1 + peer_static_pub)
    mac1 = hmac(mac1_key, msg)[:16]
    return sender_index, msg + mac1 + b"\x00"*16, raw(static_priv)

def probe(endpoint_ip, port, peer_pub_b64, timeout=3.0):
    """returns (ok, rtt_ms, detail)"""
    static_priv = X25519PrivateKey.generate()
    peer_pub = unb64(peer_pub_b64)
    sender_index, msg, my_priv = build_initiation(static_priv, peer_pub)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(msg, (endpoint_ip, port))
        data, _ = s.recvfrom(2048)
    except socket.timeout:
        return False, None, "timeout"
    except Exception as e:
        return False, None, f"{type(e).__name__}:{e}"
    finally:
        s.close()
    rtt = (time.time() - t0) * 1000
    if len(data) < 60 or data[0] != 2:
        return False, rtt, f"bad_msg(type={data[0] if data else None},len={len(data)})"
    recv_index = struct.unpack("<I", data[8:12])[0]
    if recv_index != sender_index:
        return False, rtt, "index_mismatch"
    # verify mac1 of response: key = HASH(LABEL_MAC1 || our_static_pub)
    my_static_pub = pub(static_priv)
    mac1_key = b2s(LABEL_MAC1 + my_static_pub)
    expect = hmac(mac1_key, data[:60])[:16]
    if expect != data[60:76]:
        return False, rtt, "mac1_invalid"
    return True, rtt, "handshake_ok"

if __name__ == "__main__":
    import json, sys
    n = json.load(open("D:/apk-analysis/pawxy/work/nodes.json"))
    for code, v in list(n.items())[:4]:
        c = v["config"]
        ok, rtt, det = probe(c["peer"]["endPoint"], c["peer"]["port"], c["peer"]["publicKey"])
        print(f"{code}: ok={ok} rtt={rtt and round(rtt,1)} {det}")
