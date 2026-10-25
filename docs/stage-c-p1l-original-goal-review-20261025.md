# P1L｜GCP WireGuard SMART VPN：从初始目标回看真实进展

**核对日期：**2026-10-25（北京时间）
**阶段性质：**从产品目标重新评估 P1–P1K；核实运行中 Xray 版本；进行一次不启动服务器的用户态 WireGuard 配置语法测试。
**总裁定：**基础 WG 隧道有历史短时实测，单条路由安全回切有现场实测；完整国内外智能分流、境外 GCP 出口、DNS 出站与长稳尚未完成。`PRODUCT_READY=False`。

## 一、最初到底要什么？

README 与 Notion 最初的要求是：Windows 上中国大陆 IPv4 本地直连，国内域名交给国内 DNS；其他 IPv4 和域名走 GCP 的 WireGuard 出站及私有 DNS；UDP/443 能在受限环境下连接；日常 SMART ON/OFF 可恢复，出问题不破坏正常网络；流量可统计，速度、可靠性可衡量，密钥不会暴露，最终可复现发布。

项目成功的判据应是**真实 Windows 应用的国内/境外网络路径、性能及恢复**，而非经过多少次 Mock，或一定要安装 5,494 条原生路由。若改用用户态 WG outbound，需要更新实现层面的 /1/5,494 route 验收方法，但原有产品行为目标不变。

## 二、原始目标与证据对账

| 原始要求 | 最新可靠证据 | 当前判定 |
|---|---|---|
| WG/GCP 基础隧道真实握手与 RX/TX | 2026-10-18 Stage B 用户现场短时测试曾通过 fresh handshake、私有 DNS、双向流量和回切 | HISTORICAL_SHORT_PASS，不代表今日运行 |
| UDP/443 兼容接入 | 旧部署和 Stage B 短时真实测试记录；未再次核实当前服务端 | HISTORICAL_PASS，CURRENT_UNVERIFIED |
| 国内 IPv4 走物理网 | 当前 5,494 条旧方案目标路由均未安装，xray TUN 已 Up | 新架构 END_TO_END_NOT_TESTED |
| 国内域名经国内 DNS | 25 条 NRPT 规则精确覆盖 12,160 个 namespace，但 Xray/TUN 下实际 DNS 路径未逐项抓证 | POLICY_MATCH_PASS，PATH_UNPROVEN |
| 非国内域名走 WG 私有 DNS | Stage B 私有 DNS 有历史短时证据；新用户态 WG DNS 未连通 | NEW_ARCH_NOT_TESTED |
| 境外应用真正以 GCP 出口上网 | 没有新架构下国内/海外 IP、TCP/UDP、实际网页的 GCP 出口对照 | NOT_TESTED |
| SMART ON/OFF 回切、故障恢复 | P1E 真正添加/删除固定 TEST-NET /32；P1F R3 watchdog 真的在父进程 exit 77 后清理同一个残留 /32；批量 5,494 条仅 Mock | SINGLE_ROUTE_PASS，PRODUCTION_FAILOVER_NOT_READY |
| 性能/长稳 | 有诊断脚本和历史探索，但缺少可比较的 RTT、p95、DNS、TTFB、吞吐、PMTU 和重启/断网恢复验收 | ACCEPTANCE_PENDING |
| 服务端 per-peer 流量统计 | 仓库已有 wg-traffic-collect.py、wg-usage.py、systemd service/timer；未直接读取当前 GCP service/timer 数据 | CODE_PRESENT，RUNTIME_UNVERIFIED |
| CN 规则可再生 | CN IPv4=5,494 且合法无重复；NRPT namespace=12,160；快照文件 2026-09-05 更新，约 50 天 | INTEGRITY_PASS，FRESHNESS_PENDING |
| GitHub 开源、真正可发布 | 已有仓库/资料；GitHub PR #1–#11 本轮逐个查询均为 Open/Draft/Unmerged，main 尚不是这些新补丁的发布版本 | DOCUMENTED，RELEASE_NOT_READY |

## 三、历史说“完全测试过”，为什么今天又说“没完成”？

GitHub 旧 README 的确写了“CN routes 5494/5494、NRPT 25、SMART OFF→ON 约 12 秒”。这是**旧版历史测试说明**，不能直接证明 10 月 25 日的这台 Windows 主机现正处于完整 SMART 模式，也不能证明旧脚本对其他程序的同身份路由具有可验证的所有权。近几天的独立检查明确发现当前 5,494 条目标 CN 路由没有安装，旧方案仍有误删风险。两种说法的时间和验证对象不同，不应互相替代。

Stage C P1–P1D 大量 Mock 验证的是故障处理/日志；P1E/P1F 验证固定单 /32 的真实 Windows 原生路由；P1G–P1J 证实在当前 CIM 可见字段内无法总是区分本程序路由和外部相同路由，自动删除必须失效关闭。P1K 因而冻结大批量原生路由安装的近期路线，推荐研究现有 Xray 内部 direct/WG 路由。

## 四、当前真实主机与本轮 P1L 成果

- 本机 Win32_OperatingSystem：**Windows 10 Home Build 19045**，旧文档“Windows 11”是历史口径；v2rayN=1、xray=1，`xray_tun=Up` 且已有 `0.0.0.0/0`；WinINET ProxyEnable=1，ProxyServer=127.0.0.1:7897；Native WireGuard tunnel service=0；WLAN interface index 8（10 月 24 日曾是 9），不允许硬编码。
- 运行中的 Xray 核心：经 Windows PROCESS_QUERY_LIMITED_INFORMATION 查询到本人当前进程的可执行文件；使用不读取生产配置的 `xray version` 命令确认为 **Xray Core 26.10.21**；进程路径和命令行敏感信息没有输出。
- 新增只读程序 `audit/stage_c_p1l_core_version_probe.py`：只查 PID 的系统进程镜像及版本，不触碰任何真实 WG 密钥。
- 新增纯临时程序 `audit/stage_c_p1l_offline_core_compat.py`：生成随机**测试专用**的 32 字节 WireGuard 密钥材料，模拟 peer 采用 RFC5737 文档保留地址 `192.0.2.1:443`、`noKernelTun=true`、`inbounds=[]`、CN direct 规则示例，调用正在运行的同一 Xray 映像执行 `xray run -test -config <临时文件>`。**实测 `Configuration OK.`，exit 0**。临时文件自动销毁，既有路由表 SHA256、NRPT、WinINET 和 TUN 状态前后不变。
- 这一证据说明**此本机 Xray 版本能解析所构造的用户态 WG 出站配置**；并不代表对既有 GCP 对端完成公钥认证、握手、私有 DNS、国内直连或境外出口。项目从未在本次操作读取生产配置或客户端 PrivateKey。
- 真实 GCP 服务器当日 WG、NAT、UDP443、DNS 与流量计数本轮没有从服务器本身读回，仍属 CURRENT_UNVERIFIED，不应把源代码或历史截图当作实时服务状态。

## 五、下一轮究竟怎样算成功？

**新方案的最小可用产品验收**需要同时完成：

1. **真实流向**：CN IP、国内域名实际从本地直连；非 CN IP、境外域名实际经过 GCP 用户态 WG 出站。验证实际出口公网 IP、选中的 Xray outbound、真实 Windows 应用（既有系统代理和 TUN 接管程序各自对照），不能仅凭 Find-NetRoute 结果。
2. **DNS**：国内解析器与 WG 私有 DNS `10.66.66.1` 分别有实际请求/响应证据，检查 TUN 环路、DNS 泄漏、fake-IP/IPv6 和目标地址策略。
3. **GCP 正确**：新鲜握手、双向流量、UDP/443 兼容、服务端 NAT/公网出口及 per-peer 统计；只读检查服务端不等于修改其配置。
4. **性能与稳定**：同一网络下比较当前 xray、国内直连和 GCP WG 的 RTT/p95、丢包、DNS 延迟、TTFB、上下行吞吐、PMTU；定义用户可以接受的门槛，补充网络切换、异常退出、重启后的恢复证据。
5. **安全部署**：不泄露密钥、不破坏原有 v2rayN/xray；恢复到测试前状态有独立实测；在 native 路由所有权不确定时绝不自动删除；完整文档、测试与最终合并发布。

## 六、优先级重排：以后不要继续盲目堆 Mock

- **下一步 P1M（只读/离线）：**核对当前 GCP 服务端运行态（需已授权连接）；制作不含真密钥的 Xray direct/WG/DNS 分流方案，继续 `run -test` 解析检查；规划隔离监听、GCP endpoint 防环与故障退出行为。
- **P1N（需要届时重新取得现场授权）：**短时真实用户态 WG 出站，逐项证明国内直连、境外 GCP 公网出口和 DNS、UDP，结束后核对 xray/TUN/代理/路由表基线。未经当次本地电脑前明确授权，不触发网络变更。
- **P1O（产品化）：**真实性能和长稳报告、服务端统计、用户体验，再决定合并/收敛 GitHub 目前 11 个 Draft PR；不能直接把“代码测试 99/99 PASS”当作“VPN 产品已成功”。

## 七、记录与权限边界

既有 P1E–P1K 已验收脚本和 APNIC 数据快照本轮均未修改。最新 P1L 只创建两份只读/离线验证工具及本报告；不碰真实密钥、系统 route、WinINET、NRPT、DNS、现用 Xray 配置或 WireGuard 隧道。

参考：[Xray WireGuard outbound](https://xtls.github.io/config/outbounds/wireguard.html)、[Xray routing](https://xtls.github.io/config/routing.html)、[xray run -test](https://xtls.github.io/document/command)。

**一语交接：WireGuard 基础隧道曾经可用，单条残留路由真实自动回切曾成功；Xray 26.10.21 的用户态 WireGuard 配置语法现在也已通过。但用户真正要的国内/境外智能分流、GCP 出口、DNS、性能和恢复尚待一轮真实端到端验收。**
