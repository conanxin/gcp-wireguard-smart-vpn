# Stage C P1M｜GCP 运行态核验与 Xray 用户态 WireGuard 离线配置方案

**记录日期：**2026-10-25（北京时间）
**最终裁定：**`P1M_XRAY_OFFLINE_POLICY=PASS`；`P1M_WINDOWS_READONLY=PASS`；`P1M_GCP_SERVER_CURRENT=BLOCKED_NO_AUTHORIZED_CONNECTION`；`P1M_GCP_REAL_HANDSHAKE=NOT_RUN`；`P1M_PRODUCT_SPLIT_E2E=NOT_TESTED`。

## 一、P1M 目的与范围

在 P1L 已确认 Xray 26.10.21 能解析基础用户态 WG 的前提下，制作更接近原始“国内直连/境外经 GCP WireGuard”的候选路由配置，验证国内 IP/域名规则所需资产可加载，同时核实是否有可合法访问的当前 GCP SSH 连接。

**安全边界：本轮没有读取生产 v2rayN/Xray JSON 或任何真实 WireGuard PrivateKey，没有启动新的监听端口，没有向 GCP 进行握手，没有改动系统路由、TUN、WinINET、NRPT、DNS、WG 服务、GCP 和本机代理配置。**

## 二、实际核实的 GCP 可连接性

本机 WSL 有 `ssh` 命令及旧 Google Cloud 配置元数据目录，但当前 `~/.ssh/config` 的可用别名属于其他服务器，没有现成的 GCP 主机别名；常规命令 PATH 与已检查的 Windows 常用 SDK 位置均未发现可用 `gcloud` 命令；历史 GCP 服务器地址没有出现在已信任的 SSH known_hosts 中。**无法在不新建信任/新配置凭据的情况下安全执行当天的 GCP 远端只读核验**。

因此下面项目本轮一律判为 **CURRENT_UNVERIFIED**，不能根据早期 Stage B 测试或仓库文件推断：wg-quick@wg0 当前状态、UDP/443 与 UDP/51820、当前 peer 最新握手、服务端 RX/TX、dnsmasq 的 10.66.66.1:53、net.ipv4.ip_forward、NAT/FORWARD、服务端每 peer 统计 timer，以及 GCP 云侧防火墙。

新增独立服务端只读核验工具 `server/verify-p1m-gcp-readonly.sh`，已在 WSL 本地执行 `bash -n` 语法检查 PASS，但**尚未在真正 GCP VM 上执行**。脚本设计仅采集 systemd 单元状态、WireGuard 的监听端口和聚合/匿名统计、sysctl 的只读值、UDP socket、iptables 规则数量与计时器状态；不读取 wg0.conf 或私钥、不输出 peer 公钥、不会修改 systemctl/iptables/NAT/firewall。权限不足时标记 UNAVAILABLE，外部 GCP Cloud Firewall 永远标记为 VM 内无法直接认证。

待取得已授权的 GCP Cloud Shell/SSH 会话后，才在服务器上以只读方式执行：

```bash
bash -n server/verify-p1m-gcp-readonly.sh
bash server/verify-p1m-gcp-readonly.sh
```

输出仅能说明当时 VM 的可见状态，不证明 VPN 端到端可用。务必核对脚本路径已在该 GCP 主机存在，不能直接假设仓库已部署到 VM。若仍缺实际可访问的连接，则保持 BLOCKED，不自动改用其他 VPS 或猜测账号。

## 三、Xray 用户态 WG 候选配置：设计与实际证明

候选配置仅在 `docs/stage-c-p1m-userspace-wg.template.json`：

- **不可部署**：带 `_NOTICE` 文档警示，`secretKey` 与 `peer.publicKey` 均为不可运行的占位字符串，Endpoint 固定 RFC5737 文档保留地址 `192.0.2.1:443`。**禁止把此模板直接覆盖现有 v2rayN 配置**。
- **绝对零监听入口**：`inbounds=[]`，不会争用现有 v2rayN `127.0.0.1:7897`、TUN 或其他端口；仅对 Xray 核心执行 `run -test` 语法解析。
- **首个出站是 WG**：`GCP_WG_OUTBOUND_DRAFT`；Xray 对未命中的路由使用第一个 outbound，防止草案中意外把未匹配的国际流量设为默认直连。**这只是草案结构的 fail-closed 意图，不代表现有生产 Xray 的运行策略已改变**。
- **CN domain**：第一条 `domain: geosite:cn` → `CN_DIRECT_DRAFT`。
- **CN IPv4 / private**：第二条 `ip: [geoip:private, geoip:cn]` → `CN_DIRECT_DRAFT`；不向 Windows 安装 5,494 条原生路由。
- **用户态内层 WG**：`noKernelTun=true`（禁止该 outbound 为内层流量新建系统 TUN）、`allowedIPs=[0.0.0.0/0]`、历史客户端地址 `10.66.66.2`、`remoteDNS=[10.66.66.1]`、MTU=1420（未测速验证）。
- **域名策略**：`domainStrategy=AsIs`，意味着域名不为 `geoip:cn` 自动解出 IP，因此未知但实际位于中国的域名可能进入 WG。此规则是可验证的第一版简化候选，不是完整智能分流的最终方案。
- **DNS 未建立产品证明**：`remoteDNS` 由 WG outbound 自身通过隧道解析目的域名（符合 Xray 官方文档）；CN direct 的最终操作系统 DNS/NRPT 与现用 TUN/WinINET 的交互仍须实测。为避免伪造 DNS 已正确的结论，当前模板暂不包含未经检查的 Xray 全局 `dns` 策略。
- **WG endpoint 回环仍是硬门禁**：现用 `xray_tun=Up` 且有默认路由，Xray WG outbound 在建立外层 UDP/443 连接时可能被原 TUN 再捕获。单凭用户态 `noKernelTun=true` 只决定内层 IP 包处理方式，**不能证明外层 endpoint 的物理网络旁路**；需要后来证明外层 Xray socket 的绕环行为，避免陷入递归 TUN。
- **IPv6 未验收**：当前候选仅为 IPv4 出站；IPv6/QUIC/DNS 泄漏与不同 Windows 应用的 TUN/WinINET 优先级必须后续分别测试。

官方技术依据：[Xray WireGuard outbound](https://xtls.github.io/config/outbounds/wireguard.html)、[Xray routing](https://xtls.github.io/en/config/routing.html)、[Xray 内置 DNS](https://xtls.github.io/en/config/dns.html)。还需检查 geoip/geosite 的更新策略及与原始 5,494 个 APNIC CN 网段的分类差异；两者的资源来源与快照日期不同，不能假定完全一致。

## 四、真正执行的离线测试

新纯 Python 工具 `audit/stage_c_p1m_offline_userspace_plan.py`：从仓库读取上述非生产模板，严格检查安全条件，然后只在 Windows 的自动删除临时目录生成随机 32 字节测试密钥、文档保留 endpoint 的有效 JSON；从已运行 Xray PID 安全读取其映像，仅调用 `version`、`run -test -config`，子进程独立设置 GeoIP/GeoSite 资产目录变量，不修改生产 Xray 进程环境。

本机测得 Xray Core **26.10.21**，`geoip.dat` / `geosite.dat` 已存在并能够被读取，检查时各约 1 天龄；本轮输出只记录文件 SHA256 前 16 位，不公开文件路径或任何模拟密钥。Xray 返回 **Configuration OK. / Exit 0**：完整的模板 CN 规则与 WG outbound 在该二进制上具有**语法解析兼容性**。

| 核验 | 2026-10-25 结果 |
|---|---|
| WSL Python 3.12.3 离线规则与安全测试 | **35/35 PASS** |
| Windows Python 3.12.10 同一套回归 | **35/35 PASS** |
| Xray 26.10.21 + `geosite:cn` / `geoip:cn` / `noKernelTun=true` 的 synthetic-only 解析 | **Configuration OK / Exit 0** |
| Windows 5.1 一键独立只读验收脚本 | **14/14 PASS，退出 0** |
| Windows native route SHA256 before/after | `6DC81B4D72AF45BC033776FF608281695AACFC39ED7049262E11A533E3B59AAE`，两次相同 |
| Windows 现用 NRPT/WinINET/xray_tun/WG 状态 | **全部未变化；xray HTTP 204** |
| CN 文件 SHA256 | `DFCFE4937E81B2B1221E597519B9F0AD172BC0B7BA48577C062CB6D8B65DECEC`，未修改（mtime 2026-09-05） |
| 服务端脚本 bash 语法 | **PASS，尚未在 GCP 上执行** |
| 真实 GCP/WG 握手、DNS 解析、应用公网出口、UDP443 | **NOT_RUN / NOT_VERIFIED** |

可在普通 Windows PowerShell 重复运行 **P1M 只读门禁**：

```powershell
$p = "$env:USERPROFILE\Documents\gcp-wireguard-smart-vpn"
$ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$p\audit\test-stage-c-p1m-offline-windows-20261025.ps1"
```

## 五、P1N 现场准入条件（尚未授权）

必须先完成：GCP 当前服务端 WG/UDP443/NAT/DNS/统计只读核验；核对 endpoint 路由防环；确认接入现有 v2rayN 的配置变更差异与回滚文件身份；考虑 CN DNS 与 IPv6 流量方案；准备固定独立测试入口、手动回切与后验比对。

**真正网络测试须用户再次明确本人在 Windows 本机旁、接受可能短暂断网、人工回切已准备就绪，才能单独启动。** 本次“继续下一阶段”不构成任何新网络写入许可。不得直接执行旧 Windows smart-on/smart-off，也不得关闭 xray/TUN 或静默替换其配置。

## 六、P1M 项目状态

`P1M_OFFLINE_POLICY=PASS`
`P1M_GCP_SERVER=UNVERIFIED_NO_AUTHORIZED_SSH`
`P1M_PRIVATE_KEYS_READ=False`
`P1M_REAL_HANDSHAKE=False`
`P1M_CN_DIRECT_E2E=NOT_TESTED`
`P1M_GCP_EGRESS_E2E=NOT_TESTED`
`P1M_DNS_SPLIT_E2E=NOT_TESTED`
`P1M_WG_ENDPOINT_LOOP_GUARD=NOT_VERIFIED`
`P1M_WINDOWS_CONFIG_MUTATIONS=0`
`PRIMARY=v2rayN/Xray, unchanged`

这份报告附在现有 Draft PR #11 上，不再无必要地继续生成第 12 个堆叠 Draft PR。最终产品完成标准仍以最初的国内直连、境外 GCP、公私 DNS、性能与回退为准。
