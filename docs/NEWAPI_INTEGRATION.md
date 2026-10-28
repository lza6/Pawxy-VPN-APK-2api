# new-api 接入指南 — Pawxy 节点池

目标：把 Pawxy 的 42 个 WireGuard 节点变成 new-api 代理池里可用的 **SOCKS5 出站**。

---

## 0. 结论先行

| 项 | 状态 |
|---|---|
| 凭证获取 | ✅ 可无限申请，无需鉴权，无速率限制（实测 25 连续 + 12 突发全 200） |
| 协议 | WireGuard（UDP），**不是** HTTP/SOCKS 代理 |
| 可用国家 | 42（27 free / 15 premium，服务端对两者都不做校验） |
| 节点 IP 池 | 每国一个 /24 级地址段，单国 80 次申请出现 20 个不同 IP |
| 本机连通性 | ❌ 0/42 握手成功，见 §5，需换单 IP 双栈出口复验 |
| 转换层 | ✅ `demo/singbox/gen.py` 生成的 42 份配置全部通过 `sing-box check` |

**必须先解决 §5 的可达性，再谈入池。** 转换层与申请链路已经闭环。

---

## 1. 为什么需要转换层

new-api 的代理池条目是 HTTP/HTTPS/SOCKS5 代理。Pawxy 给的是 WireGuard
peer 配置，所以中间必须有一个 WG → SOCKS5 的进程。选 `sing-box`
（1.11+ 把 wireguard 放在 `endpoints`），理由：单进程、多 endpoint、
每个 endpoint 一个 socks inbound、支持 `detour` 让 WG 的 UDP 走代理。

---

## 2. 生成配置

```powershell
cd demo/singbox
python gen.py --all --base-port 11080 --dir sb
```

产出 `sb/AT.json … sb/ZA.json`，端口从 11080 顺序分配（AT=11080 … ZA=11121），
每个文件结构：

```json
{
 "inbounds": [{"type":"socks","tag":"socks-in","listen":"127.0.0.1","listen_port":11080}],
 "endpoints": [{
   "type":"wireguard","tag":"wg-at","system":false,
   "address":["10.9.0.77/32","fd1e:...:4d/128"],
   "private_key":"<base64>",
   "peers":[{"address":"185.244.212.78","port":58057,
             "public_key":"MlS1iPCzoq209hKgCreeCVbSp06nElzkkl1vOTGhozQ=",
             "allowed_ips":["0.0.0.0/0","::/0"],
             "persistent_keepalive_interval":25}],
   "mtu":1420}],
 "route": {"rules":[{"action":"route","outbound":"wg-at"}],"final":"wg-at"}
}
```

启动单个节点：

```powershell
D:\参考项目\Hypostasis-Cat__HypoMux\bin\sing-box.exe run -c sb\AT.json
curl -s --socks5-hostname 127.0.0.1:11080 https://api.ipify.org   # 期望得到 AT 出口 IP
```

如果要让 WG 的 UDP 也走现有代理（出口 IP 一致这一条见 §5）：

```powershell
python gen.py --country AT --port 11080 --socks-upstream 127.0.0.1:10808
```

---

## 3. 一次性起全部 42 个

写一个合并配置更省资源：把 42 个 endpoint 和 42 个 socks inbound 塞进同一个
`sing-box` 进程，`route.final` 留空、每个 inbound 用 `route.rules`
的 `inbound` 条件绑到对应 endpoint。`gen.py` 当前按“一节点一配置”输出，
批量用法：

```powershell
foreach ($f in Get-ChildItem sb\*.json) {
  Start-Process -WindowStyle Hidden sing-box.exe -ArgumentList "run -c $($f.FullName)"
}
```

生产建议改成合并配置（42 个独立进程的常驻内存 × 42 ≈ 400 MB，合并后 ~60 MB）。

---

## 4. 注册到 new-api 代理池

每个节点对应一条代理记录：

| 字段 | 值 |
|---|---|
| 类型 | SOCKS5 |
| 地址 | `127.0.0.1` |
| 端口 | `11080 + n` |
| 用户名/密码 | 空 |

`socks5://127.0.0.1:11080`。分组建议按国家前缀（`pawxy-AT`、`pawxy-DE`），
便于按国家路由；免费/高级在服务端无差别，分组时按实际出口质量筛。

**健康检查**不要用 TCP connect（WG 是 UDP，socks inbound 永远 TCP 可连），
要用「经该 socks 端口请求 `https://api.ipify.org` 并校验返回 IP 归属国」：

```
GET https://api.ipify.org  via socks5://127.0.0.1:11080
期望：返回该国段的 IP（与 nodes/nodes_summary.json 的 endpoint 同网段）
```

---

## 5. 未解决：本机视角 0/42 可达

实测结论（详见 `docs/REVERSE_REPORT.md` §6）：

* 握手报文已用独立实现的 responder 自校验通过（`tools/wgselftest.py` PASS），
  不存在构造错误。
* 42 个 endpoint、每个 11 个候选端口、4 s 超时，全部无回包；
  申请后 0/5/15/30/60 s 重试也无回包。
* SOCKS5 UDP 中继本身健康（STUN、NTP 均通）。
* 关键线索：本机 HTTPS 出口是 `198.16.113.218`，UDP 中继出口是
  `80.174.118.99`。若服务端把 peer 绑定到**申请时的源 IP**，握手来自另一个
  IP 就一定被丢弃。

复验（唯一验收动作）：

```powershell
# 在一台 TCP 与 UDP 共用一个出口 IP 的机器上（VPS / 家宽直连）
python tools/stress.py --rounds 1 --workers 4
# 期望 [phase2] alive > 0
```

若在 VPS 上仍然 0/N，则说明这些节点对非白名单网段整体封禁，此池不可用，
应停止投入。

备选（不改出口）：让 sing-box 通过同一个上游代理拨 WG（`--socks-upstream`），
使 UDP 与 HTTPS 出口一致 —— 只有当上游代理的 UDP 与 TCP 出口是同一个 IP 时
才等价，本机的代理不满足（见上），需要换支持 UDP 同出口的机场或自建。

---

## 6. 凭证生命周期

* 每个 `/install` 生成一对新 X25519 密钥，服务端只回 peer 公钥，私钥永远在
  客户端 —— 因此一个 device 可以无限次申请，配置天然互不干扰。
* `stat-unix` / `stat-data` 是客户端用来告知“上一份配置用了多久”的字段，
  服务端据此调度节点；填 `-1` 表示没有历史，实测不影响发号。
* `409` 表示该国暂时没有空闲节点，客户端逻辑是重试（最多 3 次）。
* 建议轮换策略：握手/请求失败 → 重新 `/install` 换 IP，而不是反复重试同一个
  peer。由于无频率限制，失败即换的成本很低。

---

## 7. 合规

凭证来自 Pawxy 自己对外发放的接口，没有绕过鉴权、没有破解、没有盗用他人
密钥。是否用于生产、以及由此产生的任何责任，由运营方自行承担。接入前请自行
确认服务条款与当地法律。
