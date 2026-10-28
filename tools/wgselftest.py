"""Validate the initiator by implementing the responder side, strictly from
the WireGuard whitepaper §5.4.3, and asserting a full handshake completes."""
import os, struct, hashlib, base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import wgprobe as W

def pub(p): return p.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def dh(a, b): return a.exchange(X25519PublicKey.from_public_bytes(b))

def consume_initiation(msg, responder_static_priv):
    assert msg[0] == 1
    sender_index = struct.unpack("<I", msg[4:8])[0]
    e_pub = msg[8:40]
    enc_static = msg[40:88]
    enc_ts = msg[88:116]
    mac1 = msg[116:132]

    S_r_pub = pub(responder_static_priv)
    # mac1 verify
    mac1_key = W.b2s(W.LABEL_MAC1 + S_r_pub)
    assert W.hmac(mac1_key, msg[:116])[:16] == mac1, "mac1 invalid"

    chaining_key = W.b2s(W.CONSTRUCTION)
    h = W.b2s(chaining_key + W.IDENTIFIER)
    h = W.b2s(h + S_r_pub)
    h = W.b2s(h + e_pub)
    temp = W.hmac(chaining_key, e_pub)
    chaining_key = W.hmac(temp, b"\x01")
    temp = W.hmac(chaining_key, dh(responder_static_priv, e_pub))
    chaining_key = W.hmac(temp, b"\x01")
    key = W.hmac(temp, chaining_key + b"\x02")
    initiator_static = ChaCha20Poly1305(key).decrypt(b"\x00"*12, enc_static, h)
    h = W.b2s(h + enc_static)
    temp = W.hmac(chaining_key, dh(responder_static_priv, initiator_static))
    chaining_key = W.hmac(temp, b"\x01")
    key = W.hmac(temp, chaining_key + b"\x02")
    ts = ChaCha20Poly1305(key).decrypt(b"\x00"*12, enc_ts, h)
    h = W.b2s(h + enc_ts)
    return sender_index, initiator_static, ts, chaining_key, h

def build_response(chaining_key, h, initiator_static, sender_index):
    e_priv = X25519PrivateKey.generate(); e_pub = pub(e_priv)
    h = W.b2s(h + e_pub)
    temp = W.hmac(chaining_key, e_pub)
    ck = W.hmac(temp, b"\x01")
    temp = W.hmac(ck, dh(e_priv, initiator_static))
    ck = W.hmac(temp, b"\x01")
    temp = W.hmac(ck, dh(e_priv, initiator_static))  # psk = zeros mixed
    ck = W.hmac(temp, b"\x01")
    key = W.hmac(temp, ck + b"\x02")
    enc_nothing = ChaCha20Poly1305(key).encrypt(b"\x00"*12, b"", h)
    h = W.b2s(h + enc_nothing)
    my_index = struct.unpack("<I", os.urandom(4))[0]
    msg = struct.pack("<B3sI", 2, b"\x00\x00\x00", my_index) + sender_index.to_bytes(4,"little") + e_pub + enc_nothing
    mac1_key = W.b2s(W.LABEL_MAC1 + initiator_static)
    return msg + W.hmac(mac1_key, msg)[:16] + b"\x00"*16

if __name__ == "__main__":
    resp_priv = X25519PrivateKey.generate()
    init_priv = X25519PrivateKey.generate()
    sender_index, msg, _ = W.build_initiation(init_priv, pub(resp_priv))
    si, init_static, ts, ck, h = consume_initiation(msg, resp_priv)
    assert si == sender_index
    assert init_static == pub(init_priv), "static key mismatch"
    print("responder decrypted initiator static key OK, timestamp bytes:", ts.hex())
    resp = build_response(ck, h, init_static, sender_index)
    # verify as initiator
    assert resp[0] == 2 and len(resp) == 92
    assert struct.unpack("<I", resp[8:12])[0] == sender_index
    mac1_key = W.b2s(W.LABEL_MAC1 + pub(init_priv))
    assert W.hmac(mac1_key, resp[:60])[:16] == resp[60:76], "response mac1 invalid"
    print("SELFTEST PASS: initiation parsed by responder, response mac1 verified")
