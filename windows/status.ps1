[CmdletBinding()]
param(
    [string]$TunnelName = 'client1-cndirect',
    [string]$WireGuardAddress = '10.66.66.2',
    [string]$PrivateDns = '10.66.66.1',
    [string]$ChinaDns = '223.5.5.5',
    [string]$NrptPrefix = 'GCP-WG-SMART-FULLCN-',
    [string]$CnRouteFile = (Join-Path (Split-Path $PSScriptRoot -Parent) 'data\cn-ipv4-cidrs.txt'),
    [string]$ExpectedPublicIp = '',
    [switch]$SkipExternalCheck
)

$ErrorActionPreference = 'Stop'

function Get-WgExe {
    $candidates = @()

    if($env:ProgramW6432){
        $candidates += (Join-Path $env:ProgramW6432 'WireGuard\wg.exe')
    }

    if($env:ProgramFiles){
        $candidates += (Join-Path $env:ProgramFiles 'WireGuard\wg.exe')
    }

    foreach($candidate in ($candidates | Select-Object -Unique)){
        if(Test-Path -LiteralPath $candidate){
            return $candidate
        }
    }

    $cmd = Get-Command wg.exe -ErrorAction SilentlyContinue

    if($cmd){
        return $cmd.Source
    }

    return $null
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

Write-Host 'WireGuard SMART VPN Status'
Write-Host ('=' * 72)

Write-Host ''
Write-Host '=== CONFLICTS ==='

$xray = @(
    Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -eq 'xray_tun' -and
        $_.Status -eq 'Up'
    }
)

Write-Host "XRAY_TUN_UP=$($xray.Count)"

Write-Host ''
Write-Host '=== WIREGUARD INTERFACE ==='

$wgIp = Get-NetIPAddress `
    -AddressFamily IPv4 `
    -IPAddress $WireGuardAddress `
    -ErrorAction SilentlyContinue |
    Where-Object {$_.InterfaceAlias -eq $TunnelName} |
    Select-Object -First 1

if($wgIp){
    Write-Host 'WG_PRESENT=True'
    Write-Host "WG_IF=$($wgIp.InterfaceAlias)"
    Write-Host "WG_INDEX=$($wgIp.InterfaceIndex)"
    Write-Host "WG_ADDRESS=$($wgIp.IPAddress)/$($wgIp.PrefixLength)"
}
else {
    Write-Host 'WG_PRESENT=False'
}

Write-Host ''
Write-Host '=== WIREGUARD RUNTIME ==='

$wgExe = Get-WgExe

if($wgExe){
    Write-Host "WG_EXE=$wgExe"

    try {
        & $wgExe show $TunnelName
    }
    catch {
        Write-Host "WG_RUNTIME_ERROR=$($_.Exception.Message)"
    }
}
else {
    Write-Host 'WG_EXE_NOT_FOUND'
}

Write-Host ''
Write-Host '=== WIREGUARD DNS ==='

$wgDnsOk = $false

if($wgIp){
    $dns = Get-DnsClientServerAddress `
        -InterfaceIndex $wgIp.InterfaceIndex `
        -AddressFamily IPv4 `
        -ErrorAction SilentlyContinue

    $servers = @($dns.ServerAddresses)

    Write-Host "WG_DNS=$($servers -join ',')"

    $wgDnsOk = ($servers -contains $PrivateDns)

    Write-Host "WG_DNS_IS_PRIVATE=$wgDnsOk"
}
else {
    Write-Host 'WG_DNS=UNAVAILABLE'
    Write-Host 'WG_DNS_IS_PRIVATE=False'
}

Write-Host ''
Write-Host '=== HALF ROUTES ==='

$half = @(
    Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.InterfaceAlias -eq $TunnelName -and
        $_.DestinationPrefix -in @(
            '0.0.0.0/1',
            '128.0.0.0/1'
        )
    }
)

$half |
Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric |
Format-Table -AutoSize

Write-Host "WG_HALF_ROUTES=$($half.Count)"

Write-Host ''
Write-Host '=== PHYSICAL DEFAULT ROUTE ==='

$physical = @(
    Get-NetRoute `
        -AddressFamily IPv4 `
        -DestinationPrefix '0.0.0.0/0' `
        -ErrorAction SilentlyContinue |
    Where-Object {
        $_.NextHop -ne '0.0.0.0' -and
        (
            !$wgIp -or
            $_.InterfaceIndex -ne $wgIp.InterfaceIndex
        )
    } |
    Sort-Object @{
        Expression = {
            [int]$_.RouteMetric + [int]$_.InterfaceMetric
        }
    }
)

$physicalDefault = $physical | Select-Object -First 1

if($physicalDefault){
    Write-Host "PHYSICAL_IF=$($physicalDefault.InterfaceAlias)"
    Write-Host "PHYSICAL_INDEX=$($physicalDefault.InterfaceIndex)"
    Write-Host "PHYSICAL_GATEWAY=$($physicalDefault.NextHop)"
}
else {
    Write-Host 'PHYSICAL_DEFAULT_NOT_FOUND'
}

Write-Host ''
Write-Host '=== CN IPV4 ROUTES ==='

$cnExpected = $null
$cnPresent = $null
$cnMissing = $null

if(
    $physicalDefault -and
    (Test-Path -LiteralPath $CnRouteFile)
){
    $cidrs = @(
        Get-Content -LiteralPath $CnRouteFile |
        ForEach-Object {$_.Trim()} |
        Where-Object {$_}
    )

    $routeSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    Get-NetRoute `
        -AddressFamily IPv4 `
        -InterfaceIndex $physicalDefault.InterfaceIndex `
        -ErrorAction SilentlyContinue |
    Where-Object {
        $_.NextHop -eq $physicalDefault.NextHop
    } |
    ForEach-Object {
        [void]$routeSet.Add($_.DestinationPrefix)
    }

    $present = @(
        $cidrs |
        Where-Object {$routeSet.Contains($_)}
    )

    $cnExpected = $cidrs.Count
    $cnPresent = $present.Count
    $cnMissing = $cnExpected - $cnPresent

    Write-Host "CN_ROUTE_FILE=$CnRouteFile"
    Write-Host "CN_EXPECTED=$cnExpected"
    Write-Host "CN_PRESENT=$cnPresent"
    Write-Host "CN_MISSING=$cnMissing"
}
else {
    Write-Host "CN_ROUTE_FILE=$CnRouteFile"
    Write-Host 'CN_ROUTE_DATASET_NOT_FOUND'
}

Write-Host ''
Write-Host '=== NRPT ==='

$fullRules = @(
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object {$_.DisplayName -like "$NrptPrefix*"}
)

$namespaceTotal = 0

foreach($rule in $fullRules){
    $namespaceTotal += @($rule.Namespace).Count
}

Write-Host "FULLCN_RULES=$($fullRules.Count)"
Write-Host "FULLCN_NAMESPACES=$namespaceTotal"

$pilotNames = @(
    'GCP-WG-SMART-CN-PILOT',
    'GCP-WG-SMART-CAPACITY-500'
)

$pilots = @(
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object {$_.DisplayName -in $pilotNames}
)

Write-Host "PILOT_RULES=$($pilots.Count)"

Write-Host ''
Write-Host '=== SYSTEM PROXY ==='

$internetSettings = Get-ItemProperty `
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
    -ErrorAction SilentlyContinue

if($internetSettings){
    Write-Host "WININET_PROXY_ENABLE=$($internetSettings.ProxyEnable)"
    Write-Host "WININET_PROXY_SERVER=$($internetSettings.ProxyServer)"
}
else {
    Write-Host 'WININET_PROXY_STATE_UNAVAILABLE'
}

Write-Host ''
Write-Host '=== ROUTE DECISIONS ==='

foreach($address in @(
    $ChinaDns,
    $PrivateDns,
    '8.8.8.8',
    '1.1.1.1'
)){
    $route = Get-RouteDecision -Address $address

    if($route){
        Write-Host (
            '{0} -> IF={1} PREFIX={2} NEXT={3}' -f
            $address,
            $route.InterfaceAlias,
            $route.DestinationPrefix,
            $route.NextHop
        )
    }
    else {
        Write-Host "$address -> NO_ROUTE"
    }
}

Write-Host ''
Write-Host '=== PUBLIC EGRESS ==='

$publicIp = $null

if($SkipExternalCheck){
    Write-Host 'PUBLIC_IP_CHECK=SKIPPED'
}
else {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue

    if($curl){
        try {
            $publicIp = (
                & $curl.Source `
                    --silent `
                    --show-error `
                    --fail `
                    --noproxy "*" `
                    --connect-timeout 10 `
                    --max-time 20 `
                    https://api.ipify.org
            ).Trim()

            Write-Host "PUBLIC_IP=$publicIp"

            if($ExpectedPublicIp){
                Write-Host "EXPECTED_PUBLIC_IP=$ExpectedPublicIp"
                Write-Host "PUBLIC_IP_MATCH=$($publicIp -eq $ExpectedPublicIp)"
            }
        }
        catch {
            Write-Host "PUBLIC_IP_CHECK_FAILED=$($_.Exception.Message)"
        }
    }
    else {
        Write-Host 'CURL_NOT_FOUND'
    }
}

Write-Host ''
Write-Host '=== SUMMARY ==='

$localFoundation = (
    $xray.Count -eq 0 -and
    $wgIp -and
    $wgDnsOk -and
    $half.Count -eq 2 -and
    $pilots.Count -eq 0
)

Write-Host "LOCAL_FOUNDATION_PASS=$localFoundation"

if($null -ne $cnExpected){
    $cnRoutePass = (
        $cnExpected -gt 0 -and
        $cnMissing -eq 0
    )

    Write-Host "CN_ROUTE_PASS=$cnRoutePass"
}
else {
    Write-Host 'CN_ROUTE_PASS=UNKNOWN'
}

if($ExpectedPublicIp -and !$SkipExternalCheck){
    Write-Host "PUBLIC_EGRESS_PASS=$($publicIp -eq $ExpectedPublicIp)"
}

Write-Host ('=' * 72)
