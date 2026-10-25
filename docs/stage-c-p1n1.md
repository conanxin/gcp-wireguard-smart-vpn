# Stage C P1N-1 — current Xray TUN / userspace WireGuard binding contract

Date: 2026-10-25 (local Windows host)

## Verdict

- P1N1_LOCAL_RUNTIME_CONTRACT: PASS
- P1N1_SYNTHETIC_CONFIG_VARIANTS: 4/4 parsed by the installed Xray core
- P1N1_PYTHON_REGRESSION: 36/36 PASS in WSL
- P1N1_WINDOWS_READ_ONLY_GATE: 19/19 PASS
- P1N1_NATIVE_ROUTE_MUTATIONS: 0
- P1N1_PRODUCTION_CONFIG_MODIFIED: False
- P1N1_OUTER_UDP_SOCKET_BINDING_OBSERVED: False
- P1N1_OUTER_UDP_TUN_BYPASS_PROVEN: False
- P1N1_GCP_CURRENT_STATE: UNVERIFIED
- P1N1_REAL_HANDSHAKE: NOT RUN
- P1N1_LIVE_START_AUTHORIZED: False
- PRODUCT_READY: False

This is a source/configuration contract review, not a live WireGuard connection test.

## Current Windows evidence

The read-only audit inspected only structural fields from v2rayN's generated runtime JSON; it did not print configuration values, keys, endpoints, or routing rules.

- Running Xray Core: 26.10.21.
- Exactly one current TUN inbound, named xray_tun.
- autoOutboundsInterface is auto.
- The current TUN route plan includes 0.0.0.0/0.
- WFP guards include dns and misconfigtun.
- Current generated runtime has four outbounds and zero WireGuard outbounds. No proposed WG outbound has been injected into production.
- Current WLAN alias is WLAN, interface index 8, gateway 192.168.0.1; xray_tun is interface index 11.
- WLAN WeakHostSend is Disabled for IPv4 and IPv6; Forwarding is Disabled for both. These are read-only observations, not a claim about which process originally set them.
- No WireGuard service was found. WinINET proxy remains 127.0.0.1:7897.
- Native IPv4 route SHA256 before and after was identical: 6DC81B4D72AF45BC033776FF608281695AACFC39ED7049262E11A533E3B59AAE.
- Existing Xray HTTPS probe returned 204. NRPT, proxy, TUN and WireGuard service state remained unchanged.

## Source-level finding: the existing auto binding covers the WireGuard endpoint dial path

The upstream Xray 26.10.21 source was inspected at release commit 1b1647cd9ddf0abc34b981d4611fc03bcac1ca74:

1. The official TUN documentation states that autoOutboundsInterface binds Xray outbounds to a physical interface to prevent recursive capture by the TUN. If autoSystemRoutingTable is configured and autoOutboundsInterface is omitted, Xray treats it as auto. A manually configured sockopt.interface can override the automatic binding.
2. In proxy/tun/handler.go, the TUN inbound registers a global dialer controller when autoOutboundsInterface is enabled.
3. In proxy/wireguard/client.go, the WireGuard peer endpoint UDP socket is created through internet.DialSystem, passing the outbound's socket settings.
4. In transport/internet/system_dialer.go, registered dialer controllers are applied to UDP sockets before optional outbound sockopt settings. A controller failure aborts the dial; adding a manual interface field is not an independent fallback for a controller failure.
5. In proxy/tun/tun_windows.go and proxy/tun/tun_windows_outbound.go, the Windows TUN implementation selects an outbound interface and guards against Windows weak-host behavior that could otherwise ignore the binding.

This establishes a source-level route for the current TUN anti-loop controller to reach the userspace WireGuard endpoint socket. It does not establish that the current process successfully binds the actual endpoint socket or that packets physically leave through WLAN.

### Candidate decision

Prefer the existing inherited autoOutboundsInterface=auto path as the first candidate. Do not hard-code sockopt.interface=WLAN into the proposed WG outbound yet: it is an explicit override of automatic interface selection and may become stale if the physical interface changes. Four synthetic variants (inherited auto, explicit WLAN override, implicit auto with override, and implicit auto without override) all passed Xray's configuration parser, but parser acceptance is not a socket test.

## Upstream caveats

- Xray issue #7228 reported a TUN-to-WireGuard outbound binding failure on macOS with Xray 26.10.21. Follow-up PR #7230 addresses a Darwin-specific IPv6 socket binding issue and was open/unmerged at inspection time. This is not evidence that the same failure occurs on this Windows host, but it is evidence that configuration parsing alone cannot establish runtime compatibility.
- Upstream PR #7214 discusses a Windows binding failure when the selected adapter lacks one IP family. The current WLAN snapshot has both IPv4 and IPv6, so that specific single-family condition was not observed. The PR was open/unmerged at inspection time.
- These source and upstream findings do not replace an actual endpoint socket observation, fresh GCP server status, handshake, DNS, or egress verification.

## Actual test execution

- WSL Python contract suite: 36 tests, all passed.
- WSL contract CLI: STATIC_P1N1_CONTRACT_PASS.
- Windows PowerShell 5.1 gate: 19 checks passed, zero failed.
- The same installed Xray 26.10.21 parsed all four synthetic TUN/WireGuard configurations with exit 0 and Configuration OK.
- Route hash before/after matched; WinINET, NRPT, TUN and WireGuard service state were unchanged.
- No listener was started, no TUN was created by the synthetic tests, no WG endpoint UDP socket was opened, no live GCP connection was attempted, and no native network settings were changed.

## Next gate

Before any live WG attempt, obtain a verified and authorized read-only session to the current GCP VM and confirm its current WG service, UDP/443 forwarding, NAT/FORWARD, private DNS and aggregate peer state. Then plan a separately authorized, onsite-supervised endpoint-path experiment with manual rollback ready. Do not use a historical endpoint, guess SSH identity, replace the production v2rayN config, or start WireGuard based only on this stage.

Official references:
- Xray TUN docs: https://xtls.github.io/en/config/inbounds/tun.html
- Xray WireGuard outbound source at the installed release: https://github.com/XTLS/Xray-core/blob/1b1647cd9ddf0abc34b981d4611fc03bcac1ca74/proxy/wireguard/client.go
- Xray TUN handler source: https://github.com/XTLS/Xray-core/blob/1b1647cd9ddf0abc34b981d4611fc03bcac1ca74/proxy/tun/handler.go
- Xray system dialer source: https://github.com/XTLS/Xray-core/blob/1b1647cd9ddf0abc34b9811fc03bcac1ca74/transport/internet/system_dialer.go
- Xray Windows TUN source: https://github.com/XTLS/Xray-core/blob/1b1647cd9ddf0abc34b9811fc03bcac1ca74/proxy/tun/tun_windows.go
- Xray issue #7228: https://github.com/XTLS/Xray-core/issues/7228
- Xray PR #7230: https://github.com/XTLS/Xray-core/pull/7230
- Xray PR #7214: https://github.com/XTLS/Xray-core/pull/7214
