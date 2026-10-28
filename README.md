# Pawxy 2API — 逆向 + 节点池

`app.ninjavpn.android` (Pawxy – Fast VPN & Web Browser 1.15.0) 的协议还原、
节点收割、探活工具与本地管理面板。

> 协议全文见 [`docs/REVERSE_REPORT.md`](docs/REVERSE_REPORT.md)，
> new-api 接入见 [`docs/NEWAPI_INTEGRATION.md`](docs/NEWAPI_INTEGRATION.md)。

---

## 状态

| 能力 | 状态 | 证据 |
|---|---|---|
| 协议还原 | ✅ 完成 | `docs/REVERSE_REPORT.md` |
| `/countries` 节点列表 | ✅ 42 国 | `nodes/countries.json` |
| `/install` 发号 WireGuard 凭证 | ✅ 42/42 成功 | `nodes/nodes.json` |
| WG `.conf` 落盘 | ✅ 42 份 | `nodes/wg/*.conf` |
| sing-box WG→SOCKS5 配置 | ✅ 42/42 通过 `sing-box check` | `demo/singbox/sb/*.json` |
| 本地管理面板 | ✅ 页面 + 4 个 API 实测通过 | `demo/demo_server.py` |
| 发号速率限制 | ✅ 无（25 连续 + 12 突发全 200） | `docs/REVERSE_REPORT.md` §5 |
| 握手报文正确性 | ✅ 独立 responder 自校验 PASS | `tools/wgselftest.py` |
| **节点真实连通** | ❌ **0/42，本机视角被过滤** | `nodes/stress_report.json` |

唯一未闭环项是最后一行：握手报文没问题、中继没问题，但 42 个 endpoint 在
本机（HTTPS 出口 `198.16.113.218` / UDP 出口 `80.174.118.99` 两个不同 IP）
全部无回包，高度怀疑 peer 绑定了申请时的源 IP。验收方式见
`docs/NEWAPI_INTEGRATION.md` §5。

---

## 快速开始

```powershell
# 1. 收割全量节点（42 国，逐个申请 WireGuard 凭证）
python tools/harvest.py

# 2. 起管理面板
python demo/demo_server.py --port 8940
#    http://127.0.0.1:8940/

# 3. 压测 + 探活
python tools/stress.py --rounds 3 --workers 8

# 4. 生成 WG→SOCKS5 转换层配置
python demo/singbox/gen.py --all --base-port 11080 --dir demo/singbox/sb
```

依赖：`python 3.11+`、`httpx`、`cryptography`；可选 `sing-box ≥ 1.11`。

所有请求都经过本地 HTTP/SOCKS 代理（默认 `127.0.0.1:10808`），
UDP 走 SOCKS5 `UDP ASSOCIATE`。改 `tools/pawxy.py` 里的 `PROXY` /
`tools/socks5udp.py` 里的 `SOCKS` 即可。

---

## 面板

`demo/demo_server.py` 提供：

| 端点 | 作用 |
|---|---|
| `GET /` | 节点面板（搜索 / 免费高级筛选 / 单点或全部探活 / 一键取凭证） |
| `GET /api/nodes` | 已收割节点摘要 |
| `GET /api/countries` | 实时拉上游 `/countries` |
| `POST /api/install` | `{"country":"AT"}` → 现场申请一份新凭证，返回可直接导入的 `.conf` |
| `GET /api/probe?code=AT` | 对单个节点做真实 WireGuard 握手探活 |

面板不做任何缓存：每次“取凭证”都现场生成新密钥对，和 App 行为一致。

---

## 目录

```
tools/
  pawxy.py        API 客户端（device/signature 头构造、multipart 请求）
  harvest.py      42 国并发发号
  wgprobe.py      WireGuard Noise_IKpsk2 握手探测（BLAKE2s/X25519/ChaCha20Poly1305/mac1）
  wgselftest.py   用独立实现的 responder 校验握手报文
  socks5udp.py    SOCKS5 UDP ASSOCIATE 客户端
  stress.py       两阶段压测（发号 + 握手）
demo/
  demo_server.py  面板后端
  demo.html       面板前端
  singbox/gen.py  WG → SOCKS5 配置生成
nodes/
  countries.json       上游原始节点表
  nodes.json           每国一份完整凭证（含私钥，勿外传）
  nodes_summary.json   脱敏摘要（面板用）
  wg/*.conf            可直接导入任何 WireGuard 客户端的配置
  stress_report.json   最近一次压测结果
```

---

## 合规

凭证由 Pawxy 自己的接口对外发放，未绕过鉴权、未破解、未使用他人密钥。
本仓库是逆向研究产物，不构成使用授权；生产使用由运营方自行承担全部责任。
`nodes/nodes.json` 与 `nodes/wg/` 含明文私钥，不要提交到公开仓库。
