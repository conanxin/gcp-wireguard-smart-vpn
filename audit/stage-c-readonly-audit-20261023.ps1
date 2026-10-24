<#
Stage C P0: Windows SMART VPN READ-ONLY audit (2026-10-23).
Never installs WireGuard or runs smart-on/off.
Does NOT modify routes, NRPT, WinINET, DNS, xray, firewall, or data files.
No secrets are read. Safe when WireGuard is OFF and system proxy is ON.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [string]$ChinaDns = '223.5.5.5',
    [string]$NrptPrefix = 'GCP-WG-SMART-FULLCN-'
)
$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}
function Emit([string]$Key, $Value) {
    Write-Output ($Key + '=' + [string]$Value)
}
Emit 'AUDIT_MODE' 'READ_ONLY'
Emit 'AUDIT_DATE_LOCAL' ([DateTimeOffset]::Now.ToString('yyyy-MM-ddTHH:mm:sszzz'))
$ipFile = Join-Path $RepoRoot 'data\cn-ipv4-cidrs.txt'
$nsFile = Join-Path $RepoRoot 'data\cn-nrpt-namespaces.txt'
if (-not (Test-Path -LiteralPath $ipFile -PathType Leaf)) {
    Emit 'AUDIT_RESULT' 'BLOCKED_CIDR_FILE_MISSING'
    exit 2
}
if (-not (Test-Path -LiteralPath $nsFile -PathType Leaf)) {
    Emit 'AUDIT_RESULT' 'BLOCKED_NAMESPACE_FILE_MISSING'
    exit 2
}
$cidrs = @(Get-Content -LiteralPath $ipFile | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$namespaces = @(Get-Content -LiteralPath $nsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ })
Emit 'LOCAL_CIDR_LINES' $cidrs.Count
Emit 'LOCAL_NS_LINES' $namespaces.Count
Emit 'LOCAL_CIDR_SHA256' (Get-FileHash -LiteralPath $ipFile -Algorithm SHA256).Hash
Emit 'LOCAL_NS_SHA256' (Get-FileHash -LiteralPath $nsFile -Algorithm SHA256).Hash

$xray = @(Get-Process -Name xray -ErrorAction SilentlyContinue)
$xrayTun = Get-NetAdapter -Name xray_tun -ErrorAction SilentlyContinue
$wgSvc = Get-Service -Name 'WireGuardTunnel$client1-cndirect' -ErrorAction SilentlyContinue
$wgAd = Get-NetAdapter -Name client1-cndirect -ErrorAction SilentlyContinue
$proxy = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$defaultRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue)
$halfRoutes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') })
Emit 'XRAY_PROCESS_COUNT' $xray.Count
Emit 'XRAY_TUN' $(if ($xrayTun) { $xrayTun.Status } else { 'ABSENT' })
Emit 'WININET_PROXY_ENABLE' $(if ($proxy) { $proxy.ProxyEnable } else { 'UNKNOWN' })
Emit 'WININET_PROXY_SERVER' $(if ($proxy) { $proxy.ProxyServer } else { 'UNKNOWN' })
Emit 'WG_SERVICE' $(if ($wgSvc) { $wgSvc.Status } else { 'ABSENT' })
Emit 'WG_ADAPTER' $(if ($wgAd) { $wgAd.Status } else { 'ABSENT' })
Emit 'HALF_DEFAULT_ROUTES' $halfRoutes.Count
$physical = @($defaultRoutes | Where-Object {
    $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -ne 'client1-cndirect'
} | Sort-Object @{Expression={
    [int]$_.RouteMetric + [int]$_.InterfaceMetric
}} | Select-Object -First 1)
if ($physical.Count) {
    $p = $physical[0]
    Emit 'PHYSICAL_ALIAS' $p.InterfaceAlias
    Emit 'PHYSICAL_GATEWAY' $p.NextHop
    $installed = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($route in @(Get-NetRoute -InterfaceIndex $p.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        if ($route.NextHop -eq $p.NextHop) {
            [void]$installed.Add($route.DestinationPrefix)
        }
    }
    $present = 0
    foreach ($prefix in $cidrs) {
        if ($installed.Contains($prefix)) { $present++ }
    }
    Emit 'CN_ROUTE_PRESENT_ON_PHYSICAL' $present
    Emit 'CN_ROUTE_MISSING_ON_PHYSICAL' ($cidrs.Count - $present)
} else {
    Emit 'PHYSICAL_ALIAS' 'UNKNOWN'
    Emit 'CN_ROUTE_PRESENT_ON_PHYSICAL' 'NOT_TESTED'
    Emit 'CN_ROUTE_MISSING_ON_PHYSICAL' 'NOT_TESTED'
}

$nrptAll = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue)
$projectRules = @($nrptAll | Where-Object { $_.DisplayName -like ($NrptPrefix + '*') })
$expected = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$actual = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($item in $namespaces) { [void]$expected.Add($item) }
$badServers = 0
$rawNames = 0
foreach ($rule in $projectRules) {
    $servers = @($rule.NameServers | Where-Object { $_ })
    if ($servers.Count -ne 1 -or $servers[0] -ne $ChinaDns) {
        $badServers++
    }
    foreach ($item in @($rule.Namespace)) {
        if ($item) {
            $rawNames++
            [void]$actual.Add([string]$item)
        }
    }
}
$missing = 0
$extra = 0
foreach ($item in $expected) {
    if (-not $actual.Contains($item)) { $missing++ }
}
foreach ($item in $actual) {
    if (-not $expected.Contains($item)) { $extra++ }
}
Emit 'NRPT_PROJECT_RULES' $projectRules.Count
Emit 'NRPT_NAMESPACE_ROWS' $rawNames
Emit 'NRPT_UNIQUE_ACTUAL' $actual.Count
Emit 'NRPT_UNIQUE_EXPECTED' $expected.Count
Emit 'NRPT_MISSING' $missing
Emit 'NRPT_EXTRA' $extra
Emit 'NRPT_BAD_NAMESERVERS' $badServers
Emit 'NRPT_BASELINE_EXACT' ($missing -eq 0 -and $extra -eq 0 -and $badServers -eq 0 -and $rawNames -eq $namespaces.Count)

foreach ($domain in @('baidu.com','jd.com','example.cn')) {
    try {
        $policy = @(Get-DnsClientNrptPolicy -Effective -Namespace $domain -ErrorAction Stop)
        $found = @($policy | Where-Object { @($_.NameServers) -contains $ChinaDns })
        Emit ('EFFECTIVE_NRPT_' + $domain.ToUpperInvariant()) $(if ($found.Count) { 'CN_DNS' } else { 'NO_CN_DNS' })
    } catch {
        Emit ('EFFECTIVE_NRPT_' + $domain.ToUpperInvariant()) 'UNAVAILABLE'
    }
}

Emit 'STAGE_C_PROXY_OFF_REQUIRED' ([int]$proxy.ProxyEnable -ne 0)
Emit 'STAGE_C_WG_ACTIVE_REQUIRED' (-not $wgAd)
Emit 'LIVE_MUTATIONS_PERFORMED' 'False'
Emit 'AUDIT_RESULT' 'COMPLETE_READ_ONLY'
