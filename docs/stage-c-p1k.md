# Stage C P1K｜SMART VPN 路由架构决策记录（ADR）

**日期：**2026-10-25（Windows 本地北京时间）
**性质：**架构推荐与只读审计已完成；尚未改动线上配置、创建用户态 WireGuard 出站或启动新的代理实例。
**裁定：**`P1K_ARCHITECTURE_RECOMMENDATION=USERSPACE_WIREGUARD_OUTBOUND`；`P1K_IMPLEMENTED=False`；`FULL_CN_NATIVE_SMART_LIVE=NOT_TESTED`。

## 一、要解决的实际问题

最初目标是“国内 IPv4/域名尽量走本地网络，境外流量通过 GCP WireGuard 出口”，而非必须把全部 5,494 条 CN IPv4 网段写进 Windows 路由表。Stage B 已证明 GCP WireGuard 基础隧道短时可用；P1F 的真实实验只证明一条固定 TEST-NET /32 的独立 Watchdog 到期删除。P1G–P1J 的只读与模拟研究发现，Native Get-NetRoute 路由条目没有可验证的本轮 owner，两个来源不同但字段完全一致的路由可能无法区分；即使事务日志完整，也不能自动证明当前对象仍为本轮创建。

因此 P1K 决定：**冻结“直接全量安装 5,494 个原生 CN 路由 + 自动批量回切”作为近期实施主线；保留已有方案与 Draft PR，不废弃研究证据，也不自动合并。优先将分流决策移动到已经运行的 Xray/v2rayN 核心内部，验证用户态 WireGuard 出站能否连接既有 GCP 对端。** 这是下一步设计方向，不代表已成功连接或已取得直播切换授权。

## 二、本机 2026-10-25 实际状态（只读）

| 项目 | 实测 |
|---|---|
| Windows | Windows 10 家庭版，Build 19045（与早期笼统的 Win11 环境描述不同，以本机 WMI 为准） |
| 内存 | 物理总量约 15.88 GiB；多次检查可用量约 0.56–1.26 GiB（动态波动，不能视为长期容量） |
| WSL | Ubuntu/WSL2，当前 7.7 GiB 可见，约 4.1 GiB available；采用单独的 guest 网络（实际默认路由另见本地只读记录） |
| 当前主用程序 | v2rayN 进程 1，xray 进程 1；sing-box 进程 0；进程可执行文件版本尚未获得可靠核实 |
| WinINET | ProxyEnable=1，ProxyServer=127.0.0.1:7897 |
| TUN | `xray_tun` 已 Up，接口索引 11，拥有 `0.0.0.0/0` 系统路由；四条路由挂在该接口 |
| 实际 Windows 路由选择 | 对 `223.5.5.5`、`1.1.1.1`、`8.8.8.8` 的 Find-NetRoute 都选择 xray_tun / 0.0.0.0/0 |
| WLAN | 接口索引 8，网关 192.168.0.1；前一天索引曾为 9，不能硬编码 |
| WireGuard | Native WG tunnel service 未运行，/1 半默认路由为 0 |
| CN 数据与 NRPT | APNIC-derived 本地快照 5,494 个 CIDR、2026-09-05 更新，检查时 50 天；项目 NRPT 25 条仍存在 |
| 真实 CN 原生写入 | 5,494 计划路由均未安装；本阶段网络写入 0 |

特别注意：**Find-NetRoute 选择 TUN 只说明操作系统把数据包交给该虚拟网卡，不等于最终公网出口一定是境外，也不等于国内流量未走直连。** TUN 核心可以进一步做 direct/proxy 出站；需独立验证实际的 outbound、DNS 和流量路径。WinINET 代理和 TUN 同时启用时，也不能仅凭路由表推断应用实际流向。

## 三、候选架构比较

| 方案 | Windows 宿主机需要安装 5,494 条原生路由？ | 原始目标覆盖度 | 所有权与回切边界 | 本机适用性 | P1K 裁定 |
|---|---|---|---|---|---|
| A. 现有 v2rayN/Xray TUN + 核心分流 + **用户态 WireGuard 出站** | **不需要**（仍由现有 TUN 管理少量宿主机路由） | 可能同时支持 CN direct 与非 CN 到 GCP；代理感知应用与 TUN 捕获流量需要分别验收 | 将流量策略置于核心内；不依赖批量 CN Route 的归属推断；仍需要验证 TUN 本身恢复和环路保护 | **优先**。现有 xray/TUN 已启用，额外资源相对少 | **RECOMMENDED_FOR_OFFLINE_PILOT** |
| B. 保留现用 xray 原样，原生 WireGuard 只做人为监督的短时备用 | 不自动批量安装 | 可保留现有日常网络；GCP 全目标仅在人工切换/测试期间覆盖 | 人工定点回切，不宣称自动恢复 | 目前风险最低的基线 | **KEEP_AS_FALLBACK** |
| C. 独立原生路由管理 Windows 服务 + 文件锁 | 需要 | 可能实现原始 native 分流 | 锁只约束遵守锁的进程；无法阻止其他管理员程序写入完全相同的系统路由 | P1J 缺口依然存在，规模大 | **DO_NOT_SHIP_UNATTENDED** |
| D. WSL2 / 独立 VM 内的 WireGuard 和路由表 | 宿主机不需批量 CN Route | 默认只隔离 guest 的应用与网络；不能自动接管全部宿主机 Windows 程序 | 隔离较强，但宿主程序要迁移或显式接代理 | Windows 10 家庭版 + 当前内存偏紧，不适合此刻加 VM | **DEFER** |
| E. 自研 WFP/内核驱动级分流 | 不一定 | 理论上可做更深层流量处理 | 需独立设计驱动生命周期、过滤兼容与故障处理；WFP 不是路由条目的原生 owner 标记 | 复杂度显著超出个人项目当前需要 | **REJECT_FOR_NOW** |

### 选择 A 的技术依据与边界

- [v2rayN 官方 Wiki：系统代理和路由](https://github.com/2dust/v2rayN/wiki/Description-of-system-proxy-routing)明确说明：系统代理接管一部分支持代理的应用，Xray 核心可使用大陆绕过/直连等内部路由规则。它不保证所有 Windows 应用都遵守 WinINET。
- [v2rayN 官方 Wiki：重要界面与 TUN](https://github.com/2dust/v2rayN/wiki/Description-of-some-ui)说明 Windows TUN 的协议栈与规则行为。当前本机已运行 xray_tun；**不应为了 P1K 另启动第二套 TUN**。
- [Xray 官方 WireGuard 出站](https://xtls.github.io/config/outbounds/wireguard.html)明确包含用户态 WG 出站，支持 `noKernelTun=true` 时仅使用进程内 gVisor，避免该 WG 出站额外创建系统 TUN；这不是说现有 v2rayN TUN 会被关闭。是否支持本机当前运行的 Xray 可执行文件版本尚未确认。
- 若改用 sing-box，须按[现行 WireGuard endpoint 文档](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)及[WireGuard outbound 迁移说明](https://sing-box.sagernet.org/migration/)编写，旧 WireGuard outbound 已被弃用/移除，不能沿用老式 outbounds 配置。这只是替代方案，非当前已部署核心。
- [微软 Get-NetRoute 文档](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute)支持 ActiveStore/PersistentStore 区分，但本机返回对象属性确认为 Store；它并未提供能够证明“当前路由由本轮程序独占持有”的可信 owner。
- [微软 WFP 架构](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/windows-filtering-platform-architecture-overview)是针对 TCP/IP 过滤、分类和 callout 的框架，不能简单视为为路由条目添加全局独占所有权标签。
- [微软 WSL2 网络文档](https://learn.microsoft.com/en-us/windows/wsl/networking)表明 WSL 默认通过 NAT/虚拟化网络连接。Guest 内配置 WG 并不自动改变 Windows 宿主所有应用的网络策略。

## 四、推荐方向的逻辑结构（设计图，非现状）

```text
Windows 应用
  ├─ 支持代理的程序 → 当前 WinINET/127.0.0.1:7897
  └─ 非代理感知程序 → 当前 xray_tun (已存在，且须证明覆盖范围)
                          │
                          ▼
                    Xray 内部路由规则
                          ├─ CN 域名 / CN IPv4 → direct → 本地物理网卡
                          └─ 境外目标 → user-space WireGuard outbound → GCP
                          DNS → 为 direct / WG 分开验证解析和实际流向
```

不直接从图推断完成状态。必须独立核对 UDP/443 握手、GCP peer、公网出口、国内 IP 是否绕过 GCP、境外 DNS 是否经私有 DNS、TUN 回环保护、IPv6/QUIC 以及 Windows 应用真实行为。

## 五、P1L 可执行的下一阶段门禁（尚未执行）

1. **离线兼容性调查：**仅查当前 xray 可执行文件版本、v2rayN 支持的核心配置模式；不读取或输出已有 PrivateKey。确认本机 Xray 的用户态 WireGuard outbound 是否支持且不会修改 Windows 路由表。版本未证实前不生成伪称可运行的配置。
2. **制作完全离线的路由策略草案：**只记录 direct/WG 标签、域名/IP 分类、目标 DNS、Endpoint 自身必须走物理网络的环路保护以及关闭时的安全行为；使用占位符，不提交密钥或未经验证的实时配置。
3. **离线语法检查：**若定位到可靠的本机 xray 核心，使用其内置 dry-run/test 能力验证匿名配置（不启动监听、不使用现有系统代理端口）；若核心工具版本不匹配则 BLOCKED，不更改生产配置。
4. **未来受控网络验证：**只有重新确认用户本人在 Windows 电脑旁、接受可能的短时网络影响并准备好人工回切，才能使用与主用系统代理隔离的测试端口进行一次短时 WG outbound 实验。测试主用不变，验证 direct/GCP 公网出口、CN/境外 DNS、TCP/UDP、TUN 和代理优先级，并对照快照确认无新增批量原生路由。
5. **日常状态与失败策略：**保持现有 xray/TUN 为每日可用基线，失败时默认停止实验而不触发全量 native SMART；所有同身份路由所有权不确定时禁止自动删除。

## 六、完成标准与当前状态

- P1K 只读基线脚本：`audit/stage-c-p1k-readonly-inventory-20261025.ps1`；Windows 5.1 只读门禁：`audit/test-stage-c-p1k-readonly-architecture-20261025.ps1`。
- 实测 Windows Gate：**13/13 PASS**；实际 IPv4 路由身份 SHA256 `6DC81B4D72AF45BC033776FF608281695AACFC39ED7049262E11A533E3B59AAE` 在同一次门禁前后不变，WinINET/NRPT/WG 不变；xray HTTPS 204；Windows 19045、xray_tun Up/0.0.0.0/0、WLAN ifIndex 8。
- **未完成：**Xray 可执行文件版本核实、GCP userspace WG outbound 配置生成/连通性、真实 TCP/UDP/DNS 出口对照、应用级透明覆盖、长期故障处理。
- 继续保持 GitHub 历史 Draft PR 不合并；P1K 只新增只读调查和 ADR。原始 5,494 CN CIDR 数据维持只读参考，不在此阶段写入系统。

**状态：`P1K_DECISION=RECOMMEND_A`; `P1K_READ_ONLY=PASS`; `P1K_USERSPACE_WG=PROPOSED_NOT_TESTED`; `NATIVE_5494_ROUTE_INSTALL=FROZEN_NOT_AUTHORIZED`; `PRIMARY=v2rayN/xray`.**
