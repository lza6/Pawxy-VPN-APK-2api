# Pawxy — Reverse-engineering report

**Target**: `Pawxy - Fast VPN _ Web Browser 1.15.0 _modded_by_PlatinumMods.apk`
**Package**: `app.ninjavpn.android` · **versionName** 1.15.0 · **versionCode** 103
**Signer**: `CN=AndrewAryan, O=GooglePlaystore` (modded) · SHA-1 `ae846c58d56c0eceb2eb0c1d4ccbcfd11ab53672`
**Analysed**: 2026-10-28 · jadx 1.5.x, dex string table, live API probing

---

## 1. What the app is

A Chromium-based browser (`org.chromium` WebView shell, EasyList/adblock engine,
torrent client via `libtorrent4j`) that bundles a **WireGuard** client
(`libwg-go.so`, `libwg-quick.so`, `com.wireguard.android.backend.GoBackend`).
The VPN is not a browser proxy — it is a full-device WG tunnel.

Package layout that matters:

| package | role |
|---|---|
| `com.pawxy.browser.vpn.VPN` | foreground service, owns the GoBackend tunnel |
| `com.pawxy.browser.vpn.r` | request layer: URL builder, header builder, response parsers |
| `com.pawxy.browser.vpn.n` | credential installer (`/install`) + WG config assembly |
| `com.pawxy.browser.vpn.i` | node model parsed from `/countries` |
| `com.pawxy.browser.core.C2605v` | device id derivation, telemetry |
| `com.pawxy.browser.VPNController/VPNCountries` | AIDL surface used by the UI |

---

## 2. Base URL discovery

`U1.e.t(prefix, path)` builds the API root:

```java
StringBuilder sb = new StringBuilder("https://");
sb.append(prefix).append(".");
String host = /* Firebase RemoteConfig key "host", default */ "quxiq.com";
sb.append(host).append("/").append(path);
```

* `prefix = "api"` → `https://api.quxiq.com/<path>`
* Default host is the literal `quxiq.com`; a RemoteConfig override can replace it.
* `https://i{N}.pawxy.com/` is a separate **plain-text IPv4 echo** used only to
  measure the exit IP latency after a tunnel comes up (`vpn/d.java` reads
  `response.body().string().trim()` and stores it as the reported exit address).

DNS: `api.quxiq.com` → `95.216.177.223` (Hetzner FI), TLS `CN=quxiq.com`,
Let's Encrypt. No certificate pinning in the OkHttp client.

---

## 3. Authentication — there is none, only three headers

```java
aVar.i("device",      vpn.g.g);                        // header 1
aVar.i("os-version",  String.valueOf(Build.VERSION.SDK_INT));
aVar.i("app-version", "103");
aVar.i(P2.a.f1469c,   p000a.a.p(vpn));                 // header 4 -> "token"
aVar.i(P2.a.e,        v4.b.f(vpn));                    // header 5 -> "signature"
```

`P2.a` is a tiny obfuscation helper (`a(97,100,115)` = `"ads"`), decoded:

| constant | value | used as |
|---|---|---|
| `f1467a` | `ads` | local file prefix |
| `f1469c` | `token` | **header name** |
| `f1470d` | `premium` | key inside the cached token file |
| `e` | `signature` | **header name** |

* **`token`** = contents of `files/subscription/premium.token`, else the literal
  `"none"`. A free install therefore sends `token: none`.
* **`signature`** = `UUID.nameUUIDFromBytes(apk signing certificate DER)` — an
  MD5-based UUIDv3 of the signer certificate. For this APK:
  `431d8a11-bc0b-3a07-ad36-6da183c62a6c` (matches `apksigner` MD5
  `431d8a11bc0b6a076d366da183c62a6c` with the v3 version bits set).
* **`device`** = `UUIDv3("Pawxy:" + Settings.Secure.ANDROID_ID)` **with the first
  character replaced by `1`**:

```java
this.g = UUID.nameUUIDFromBytes(("Pawxy:" + android_id).getBytes()).toString();
StringBuilder sb = new StringBuilder();
sb.append(this.f19772h ? "1" : "0");     // h == true when android_id resolved
sb.append(this.g.substring(1));          // keep tail, drop first char
```

### The one gate that matters

`device` must be a **36-character UUID-shaped string whose first character is
`1`**. Any other value (short hex, random string, wrong length) makes **every**
POST return `406 Not Acceptable` with an empty body. This is the only check the
server performs on the header set:

| `device` value | `/countries` |
|---|---|
| *(missing)* | 406 |
| `test-device-0001` | 406 |
| `3f2a9c1b77de4e05` | 406 |
| `1e63ea96-7f68-377b-b352-8b8b06ec5396` | **200** |

`signature` and `token` are **not** validated: a modded signer and `token: none`
both work, and all 15 `premium: true` countries are served to a free install.

---

## 4. Endpoints

Request bodies are **`multipart/form-data`** (`d4.v.g`), not urlencoded.
Unknown paths return `406`; a real path with a bad payload returns `400`.

### 4.1 `POST /countries`

Body: `ping=pong` (the literal pair).

```json
[{"code":"AR","premium":true,"expensive":true,
  "datacenters":[{"name":"buenos aires",
                  "latency":{"pref":11248,"real":11248},
                  "address":"103.106.58.19"}]}]
```

* `code` — ISO-3166 alpha-2, must be 2 uppercase chars (`vpn/m.java` `^[A-Z]{2}$`)
* `premium` — node gated in the UI only
* `expensive` — UI hint (metered-network warning)
* `latency.pref/real` — server-side millisecond estimates
* one datacenter per country in the current fleet

### 4.2 `POST /install`

Body (form fields):

| field | value |
|---|---|
| `country` | 2-letter code |
| `public-key` | **lowercase hex** of the client X25519 public key (64 chars) |
| `stat-unix` | age in ms of the previous config file, or `-1` |
| `stat-data` | previous config file content (optional) |

> **Encoding trap**: `public-key` must be **hex**. Base64 (44 chars) → `400`.
> Standard base64, urlsafe base64, unpadded base64 all → `400`.

Response `200`:

```json
{
 "country": "AT",
 "interface": {"name":"wgx2",
   "address":{"ipv4":"10.9.0.77/32",
              "ipv6":"fd1e:483b:6513:aa28:30a2:a20a:d109:4d/128"}},
 "peer": {"endPoint":"185.244.212.78","port":58057,
          "publicKey":"MlS1iPCzoq209hKgCreeCVbSp06nElzkkl1vOTGhozQ="},
 "allowed-ips": "0.0.0.0/8, 1.0.0.0/16, ..."
}
```

* `allowed-ips` is a long explicit list (≈400 prefixes) instead of `0.0.0.0/0`.
* `squid` is parsed by the client but **never sent** by the server (verified over
  42+ installs) — there is no HTTP-proxy fast path.
* The peer keypair is minted **client-side**: the server never issues a private
  key, so every install yields an independent, unlimited credential.

Error codes:

| code | meaning in client |
|---|---|
| `200` | config parsed, tunnel started |
| `400` | malformed install payload (wrong key encoding, missing field) |
| `406` | bad/missing `device` header, or unknown route |
| `409` | no node available for that country → client retries (max 3) |

---

## 5. Credential rotation and fleet size

Each `/install` returns a **different endpoint** from a per-country block:

| country | sample endpoints (6 installs each) |
|---|---|
| DE | 20 distinct IPs in 80 installs, all inside `146.70.62.26-30/189/190` |
| US | `185.253.163.203-205`, `217.138.217.107`, `37.120.132.90/93` |
| JP | `185.183.105.162-166` |
| GB | `185.195.200.90-92`, `81.92.203.155-157` |
| NL | `77.243.180.226-230` |
| AT | `146.70.244.114-116`, `185.9.19.82/85/86` |

The fleet is M247-heavy and allocated in contiguous blocks, so the addressable
pool is far larger than the 42 country entries. Rate limiting: **none observed**
— 25 sequential installs (0.15 s apart) and 12 back-to-back premium installs all
returned `200`.

---

## 6. Liveness status

`tools/wgprobe.py` implements a real WireGuard `Noise_IKpsk2` handshake
initiation (BLAKE2s hash/HMAC chain, X25519, ChaCha20-Poly1305, `mac1`), and
`tools/wgselftest.py` validates it against an independently written responder:
the responder decrypts the initiator's static key and timestamp and the response
`mac1` verifies → **the initiation message is spec-conformant**.

From this host, **0 of 42 endpoints answered** (UDP, 11 candidate ports each,
4 s timeout, plus 0/5/15/30/60 s retries after issuance). The SOCKS5 UDP relay
itself is healthy (STUN and NTP round-trips succeed through it). Two facts point
at source-address pinning rather than a bug on our side:

* the HTTPS exit is `198.16.113.218`, the UDP relay exit is `80.174.118.99`
  (different outbound in the local proxy), so the peer was issued to an address
  the handshake never comes from;
* neither direct (local ISP) nor relayed UDP to any endpoint returns a packet,
  on any port.

Reproduce from a single-IP vantage (a VPS whose TCP and UDP share one address)
with `python tools/stress.py --rounds 1`; that is the acceptance test for
liveness, and it is the only open item.

---

## 7. Obfuscation / static-analysis notes

* `P2.a` — byte-array string decoder, values spelled out in §3.
* `Gradle`-style class merging made jadx fold unrelated classes together
  (`r.java` holds both the VPN request layer and ad-SDK callbacks, selected by
  `this.f20827a`); read the `switch (this.f20827a)` branches, not the class name.
* 49 decompile errors out of 5694 classes, none in code paths used here.
* Firebase project `308684706178`, android app id
  `1:308684706178:android:61a3d19ae8266cb42b3f9b`, API key
  `AIzaSyD6z…XP2OA` — the key is **Android-restricted**: RemoteConfig fetch
  returns `403` for both the modded cert and for no cert at all, so the
  RemoteConfig `host` override could not be read without the official signer.
  The code default (`quxiq.com`) is live and answers correctly, so the override
  is not needed.

---

## 8. Compliance

The credentials are issued by Pawxy's own servers to anyone who asks; there is no
authentication to bypass, no cracked key and no stolen secret. Nothing here
grants a right to use the service. Operating these nodes commercially or in
production is the operator's own call and their own liability; this document is
research output on an APK the operator supplied.
