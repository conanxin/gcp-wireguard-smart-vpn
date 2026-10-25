# Stage C P1N-0 — 用户态 WireGuard 真实连通性实验前的只读准入核验

**记录日期：**2026-10-25（Windows 本地，北京时间）
**裁定：**`P1N0_READ_ONLY_PREFLIGHT=PASS`; `P1N0_REAL_WG_CONNECTIVITY=BLOCKED_NOT_AUTHORIZED`; `P1N0_OUTER_UDP_PHYSICAL_BYPASS=UNPROVEN`; `P1N0_GCP_SERVER_CURRENT=UNVERIFIED`; `PRODUCT_READY=False`。

## 为什么必须增加这个关口

用户最初要的是 **中国 IP/域名走本地、非中国走 GCP WireGuard、DNS 正确并可回切**。P1M 确认正在运行的 Xray 26.10.21 能解析 WG 用户态出站、`geosite:cn` / `geoip:cn` 规则，但 `xray run -test` **仅核对配置解析**，没有打开外层 WireGuard UDP 连接。

2026-10-25 Windows 只读观察发现：WLAN 当前唯一默认路由 `InterfaceIndex=8`、下一跳 `192.168.0.1`；现用 `xray_tun` Up，InterfaceIndex=11 且有 `0.0.0.0/0` 默认路由。对历史保存的 GCP endpoint 的一次本地 **Find-NetRoute 只读检查**以及 RFC5737 文档保留地址均选择 `xray_tun`。这一事实说明普通路由查找的外层 UDP 路径可能被 TUN 捕获，**不证明具体 Xray socket 实际选路**。为避免将私有服务器地址写入公用 Git 仓库，本阶段发布的诊断脚本只使用 `192.0.2.1` 这一 RFC5737 文档保留地址。

根据官方 [Xray TUN 使用建议](https://xtls.github.io/en/config/inbounds/tun.html)，Xray 自己发出的外层流量可能被 TUN 再次捕获而回环；官方建议使用 `autoOutboundsInterface` 或显式 `sockopt.interface` 绑定，必要时可考虑 `sendThrough`。根据 [Sockopt 官方文档](https://xtls.github.io/en/config/transports/sockopt.html)，`interface` 可在 Windows 上绑定出站网络接口。**但是文档描述的通用出站 Socket 语义，不等于已经在本机 WireGuard UDP 实测验证绑定成功。**

另据 [WireGuard 出站官方文档](https://xtls.github.io/en/config/outbounds/wireguard.html)，`noKernelTun=true` 只禁用 **内层** WG 的系统 TUN，不能证明外层 UDP 绕开另一个已启用的 TUN。

## 本阶段实际完成

新独立工具：

- `audit/stage_c_p1n0_interface_bind_probe.py`：从 P1M 占位模板产生随机合成密钥与 `192.0.2.1:443` 模拟 Peer；生成普通 WG 和 `streamSettings.sockopt.interface=WLAN` 两种候选，均保持 `inbounds=[]`、`noKernelTun=true`，只调用当前 Xray 的 `run -test`，自动销毁临时 JSON；永不读取生产配置、用户私钥或真实 GCP endpoint。
- `audit/test_stage_c_p1n0_interface_bind_probe.py`：25 个纯离线安全与规则约束用例；WSL Python 3.12.3 与 Windows Python 3.12.10 均 **25/25 PASS**。其中禁止连接真实地址、禁止监听、禁止改默认 WG 出站、禁止把 `xray_tun` 当作期望物理出口。
- `audit/test-stage-c-p1n0-readonly-windows-20261025.ps1`：Windows PowerShell 5.1 独立只读门禁；只查询物理 WLAN、TUN、保留文档地址的路由选择、已有 NRPT/代理/WG 与原生路由哈希；调用合成配置离线解析；**不包含真实 GCP endpoint IP、私钥或网络写入命令**。
- `docs/stage-c-p1n0-prelive-gate.md`：本文件，提供下一次真实实验需满足的客观门禁及阻断原因。

### 实机验证的范围

| 项目 | 本轮执行结果 | 是否等同于真实 WG 连通成功？ |
|---|---|---|
| Xray 26.10.21 对普通 WG 合成配置的 `run -test` | `Configuration OK.` / exit 0 | 否 |
| 增加 `streamSettings.sockopt.interface=WLAN` 后 `run -test` | `Configuration OK.` / exit 0 | 否，**只证明字段语法接受** |
| WSL/Windows Python 合成安全回归 | 各 **25/25 PASS** | 否 |
| Windows 独立路由、环境与 xray 基线核验 | **13/13 PASS**，只读 | 否 |
| 原生 IPv4 路由表 SHA256 before / after | 相等：`6DC81B4D72AF45BC033776FF608281695AACFC39ED7049262E11A533E3B59AAE` | 仅证明本次路由表未变 |
| Windows 已存在代理 | xray 进程仍在，HTTPS 204、NRPT25、TUN Up、WG service=0 | 当前原代理正常 |
| 实际 WG 外层 UDP 是否绕过 TUN | **UNVERIFIED** | 尚未测 |
| GCP VM 当前 wg0、UDP443、NAT、DNS、peer 统计 | **UNVERIFIED：缺已授权并验证身份的 GCP 只读连接** | 尚未测 |
| 真正国内直连、境外 GCP 公网出口、DNS/IPv6/UDP | **NOT_TESTED** | 尚未测 |

## 重新开始任何真实网络连接前必须满足的硬门禁

1. **服务器可验证**：从已有授权的 GCP Cloud Shell 或经过主机身份验证的 SSH 会话读取 `wg0`、UDP443→51820、防火墙、NAT/FORWARD、DNS、peer transfer。仅有旧版 repo 代码、云凭证目录或历史 IP 不足以当作服务器当前可用的证据。可以在经过授权的 GCP VM 上使用 `server/verify-p1m-gcp-readonly.sh`，但当前此脚本仅本地 bash -n PASS，并未在 GCP 上执行。
2. **外层 UDP 真实物理出口**：明确当次 WLAN index/gateway（最近一天 index 从 9→8）、校验 Socket 是否实质绑定 WLAN 或 Xray 既有 TUN 的自动旁路方案。语法 PASS 不算路径 PASS。无此证明，则中止首次握手。
3. **安全实验与回切**：需用户另行明确在 Windows 本机旁、能接受短时网络波动、已经准备人工回切；按最小权限开一次隔离测试入口。保持现有 `127.0.0.1:7897`、`xray_tun` 和 GCP VM 状态可恢复；不得直接替换 v2rayN 主配置、不得新建第二个 TUN、不得触发旧 `smart-on/off` 或安装 5,494 条原生 CN 路由。
4. **国内外与 DNS 证据**：测试时分别记录 CN IP、CN domain、非 CN IP/domain 的 outbound、实际公网出口与解析器；专门覆盖 `routing.domainStrategy=AsIs` 导致的国内域名未命中 geosite 情况，确认 NRPT 与 Xray DNS 优先级以及 IPv6/UDP/QUIC 边界。
5. **恢复审计**：实验停止后对比 Windows IPv4/IPv6 路由、WinINET、NRPT、TUN、WireGuard 服务与 xray HTTPS；其中任意环境漂移或真实路由 owner 不明，不允许自动删除其他程序的路由。

## 安全复现命令

普通 Windows PowerShell（只读，不需管理员）：

```powershell
$root = Join-Path $env:USERPROFILE 'Documents\gcp-wireguard-smart-vpn'
$powershell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
& $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$root\audit\test-stage-c-p1n0-readonly-windows-20261025.ps1"
```

WSL / Python：

```bash
cd /mnt/c/Users/haili/Documents/gcp-wireguard-smart-vpn
python3 audit/test_stage_c_p1n0_interface_bind_probe.py
python3 audit/stage_c_p1n0_interface_bind_probe.py --mode contract
```

**注意：**本阶段的 `READ_ONLY_EVIDENCE_PASS_LIVE_BLOCKED` 中 `PASS` 仅适用于原生路由不变和程序合成配置可解析；`LIVE_BLOCKED` 才是对当前真实 WireGuard 连接的准入裁定。今后不得用 25/25 或 13/13 代替真正到 GCP 的握手。

最终结论：`P1N0_SYNTHETIC_INTERFACE_BIND_SYNTAX=PASS`；`P1N0_RUNTIME_OUTER_UDP_BIND=UNPROVEN`；`P1N0_GCP_VM_STATE=UNVERIFIED`；`P1N_REAL_CONNECTION=NOT_AUTHORIZED`；`PRODUCT_READY=False`。
