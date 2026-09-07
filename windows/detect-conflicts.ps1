[CmdletBinding()]
param(
    [string]$TunnelName = 'client1-cndirect',
    [string]$WireGuardAddress = '10.66.66.2',
    [string]$PrivateDns = '10.66.66.1',
    [string]$ChinaDns = '223.5.5.5',
    [string]$ExpectedPublicIp = '',
    [switch]$SkipExternalCheck
)

$ErrorActionPreference = 'Stop'

$conflicts = [System.Collections.Generic.List[string]]::new()
$warnings  = [System.Collections.Generic.List[string]]::new()

function Add-Conflict {
    param([string]$Message)

    $script:conflicts.Add($Message)
    Write-Host "CONFLICT=$Message"
}

function Add-Warning {
    param([string]$Message)

    $script:warnings.Add($Message)
    Write-Host "WARNING=$Message"
}

function Get-RouteDecision {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Address
    )

    try {
        return (
            Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop |
            Where-Object {$_.DestinationPrefix} |
            Select-Object -First 1
        )
    }
    catch {
        return $null
    }
}

Write-Host 'WireGuard SMART VPN Conflict Detector'
Write-Host ('=' * 72)

Write-Host ''
Write-Host '=== RELATED PROCESSES ==='

$relatedProcesses=@(
    Get-Process -ErrorAction SilentlyContinue |
    Where-Object {$_.ProcessName -match '^(v2rayN|xray)$'} |
    Select-Object ProcessName,Id,Path
)

if($relatedProcesses.Count){
    $relatedProcesses | Format-Table -AutoSize
    Add-Warning 'V2RAYN_OR_XRAY_PROCESS_PRESENT'
}
else {
    Write-Host 'V2RAYN_OR_XRAY_PROCESS_PRESENT=False'
}

Write-Host ''
Write-Host '=== XRAY TUN ==='

$xrayTun=@(
    Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -eq 'xray_tun' -and
        $_.Status -eq 'Up'
    }
)

Write-Host "XRAY_TUN_UP=$($xrayTun.Count)"

if($xrayTun.Count -gt 0){
    Add-Conflict 'XRAY_TUN_IS_UP'
}

Write-Host ''
Write-Host '=== SYSTEM PROXY ==='

$internetSettings=Get-ItemProperty `
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
    -ErrorAction SilentlyContinue

if($internetSettings){
    $proxyEnabled=([int]$internetSettings.ProxyEnable -eq 1)

    Write-Host "WININET_PROXY_ENABLE=$($internetSettings.ProxyEnable)"
    Write-Host "WININET_PROXY_SERVER=$($internetSettings.ProxyServer)"
    Write-Host "WININET_PROXY_ENABLED=$proxyEnabled"

    if($proxyEnabled){
        Add-Conflict 'WININET_SYSTEM_PROXY_ENABLED'
    }
}
else {
    $proxyEnabled=$false
    Add-Warning 'WININET_PROXY_STATE_UNAVAILABLE'
}

Write-Host ''
Write-Host '=== WIREGUARD ==='

$wgIp=Get-NetIPAddress `
    -AddressFamily IPv4 `
    -IPAddress $WireGuardAddress `
    -ErrorAction SilentlyContinue |
    Where-Object {$_.InterfaceAlias -eq $TunnelName} |
    Select-Object -First 1

if($wgIp){
    Write-Host 'WG_PRESENT=True'
    Write-Host "WG_IF=$($wgIp.InterfaceAlias)"
    Write-Host "WG_INDEX=$($wgIp.InterfaceIndex)"
}
else {
    Write-Host 'WG_PRESENT=False'
    Add-Conflict 'WIREGUARD_TUNNEL_NOT_PRESENT'
}

Write-Host ''
Write-Host '=== HALF ROUTES ==='

$half=@(
    Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.InterfaceAlias -eq $TunnelName -and
        $_.DestinationPrefix -in @(
            '0.0.0.0/1',
            '128.0.0.0/1'
        )
    }
)

Write-Host "WG_HALF_ROUTES=$($half.Count)"

if($half.Count -ne 2){
    Add-Conflict 'WIREGUARD_HALF_ROUTES_NOT_COMPLETE'
}

Write-Host ''
Write-Host '=== DNS ==='

if($wgIp){
    $wgDns=@(
        (
            Get-DnsClientServerAddress `
                -InterfaceIndex $wgIp.InterfaceIndex `
                -AddressFamily IPv4 `
                -ErrorAction SilentlyContinue
        ).ServerAddresses
    )

    Write-Host "WG_DNS=$($wgDns -join ',')"

    if($wgDns -notcontains $PrivateDns){
        Add-Conflict 'WIREGUARD_PRIVATE_DNS_NOT_CONFIGURED'
    }
}

Write-Host ''
Write-Host '=== ROUTE DECISIONS ==='

$chinaRoute=Get-RouteDecision -Address $ChinaDns
$privateDnsRoute=Get-RouteDecision -Address $PrivateDns
$foreignRoute=Get-RouteDecision -Address '8.8.8.8'

if($chinaRoute){
    Write-Host (
        '{0} -> IF={1} PREFIX={2} NEXT={3}' -f
        $ChinaDns,
        $chinaRoute.InterfaceAlias,
        $chinaRoute.DestinationPrefix,
        $chinaRoute.NextHop
    )

    if($chinaRoute.InterfaceAlias -eq $TunnelName){
        Add-Conflict 'CHINA_DNS_ROUTED_THROUGH_WIREGUARD'
    }
}
else {
    Add-Conflict 'CHINA_DNS_HAS_NO_ROUTE'
}

if($privateDnsRoute){
    Write-Host (
        '{0} -> IF={1} PREFIX={2} NEXT={3}' -f
        $PrivateDns,
        $privateDnsRoute.InterfaceAlias,
        $privateDnsRoute.DestinationPrefix,
        $privateDnsRoute.NextHop
    )

    if($privateDnsRoute.InterfaceAlias -ne $TunnelName){
        Add-Conflict 'PRIVATE_DNS_NOT_ROUTED_THROUGH_WIREGUARD'
    }
}
else {
    Add-Conflict 'PRIVATE_DNS_HAS_NO_ROUTE'
}

if($foreignRoute){
    Write-Host (
        '8.8.8.8 -> IF={0} PREFIX={1} NEXT={2}' -f
        $foreignRoute.InterfaceAlias,
        $foreignRoute.DestinationPrefix,
        $foreignRoute.NextHop
    )

    if($foreignRoute.InterfaceAlias -ne $TunnelName){
        Add-Conflict 'FOREIGN_TRAFFIC_NOT_ROUTED_THROUGH_WIREGUARD'
    }
}
else {
    Add-Conflict 'FOREIGN_TEST_IP_HAS_NO_ROUTE'
}

Write-Host ''
Write-Host '=== DEFAULT ROUTES ==='

Get-NetRoute `
    -AddressFamily IPv4 `
    -DestinationPrefix '0.0.0.0/0' `
    -ErrorAction SilentlyContinue |
Select-Object `
    InterfaceAlias,
    InterfaceIndex,
    NextHop,
    RouteMetric,
    InterfaceMetric |
Format-Table -AutoSize

Write-Host ''
Write-Host '=== PUBLIC EGRESS ==='

if($SkipExternalCheck){
    Write-Host 'PUBLIC_EGRESS_CHECK=SKIPPED'
}
elseif($ExpectedPublicIp){
    $curl=Get-Command curl.exe -ErrorAction SilentlyContinue

    if(!$curl){
        Add-Warning 'CURL_NOT_AVAILABLE_FOR_EGRESS_CHECK'
    }
    else {
        try {
            $noProxyIp=(
                & $curl.Source `
                    --silent `
                    --show-error `
                    --fail `
                    --noproxy "*" `
                    --connect-timeout 10 `
                    --max-time 20 `
                    https://api.ipify.org
            ).Trim()

            Write-Host "NO_PROXY_PUBLIC_IP=$noProxyIp"
            Write-Host "EXPECTED_PUBLIC_IP=$ExpectedPublicIp"

            if($noProxyIp -ne $ExpectedPublicIp){
                Add-Conflict 'WIREGUARD_PUBLIC_EGRESS_MISMATCH'
            }

            if($proxyEnabled){
                try {
                    $normalIp=(
                        Invoke-RestMethod `
                            -Uri 'https://api.ipify.org' `
                            -TimeoutSec 15
                    ).Trim()

                    Write-Host "NORMAL_PUBLIC_IP=$normalIp"

                    if($normalIp -ne $noProxyIp){
                        Add-Conflict 'SYSTEM_PROXY_OVERRIDES_WIREGUARD_EGRESS'
                    }
                }
                catch {
                    Add-Warning 'NORMAL_PUBLIC_IP_CHECK_FAILED'
                }
            }
        }
        catch {
            Add-Warning 'NO_PROXY_PUBLIC_IP_CHECK_FAILED'
        }
    }
}
else {
    Write-Host 'EXPECTED_PUBLIC_IP_NOT_SET'
}

Write-Host ''
Write-Host '=== SUMMARY ==='

Write-Host "CONFLICT_COUNT=$($conflicts.Count)"
Write-Host "WARNING_COUNT=$($warnings.Count)"

if($conflicts.Count){
    Write-Host ''
    Write-Host 'Detected conflicts:'

    foreach($conflict in $conflicts){
        Write-Host " - $conflict"
    }
}

if($warnings.Count){
    Write-Host ''
    Write-Host 'Warnings:'

    foreach($warning in $warnings){
        Write-Host " - $warning"
    }
}

Write-Host ''

if($conflicts.Count -eq 0){
    Write-Host 'SMART_CONFLICT_CHECK=PASS'
    exit 0
}
else {
    Write-Host 'SMART_CONFLICT_CHECK=FAIL'
    exit 2
}
