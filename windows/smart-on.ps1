[CmdletBinding()]
param(
    [string]$TunnelName = 'client1-cndirect',
    [string]$WireGuardAddress = '10.66.66.2',
    [string]$PrivateDns = '10.66.66.1',
    [string]$ChinaDns = '223.5.5.5',
    [string]$CnRouteFile = (Join-Path (Split-Path $PSScriptRoot -Parent) 'data\cn-ipv4-cidrs.txt'),
    [string]$CnNamespaceFile = (Join-Path (Split-Path $PSScriptRoot -Parent) 'data\cn-nrpt-namespaces.txt'),
    [string]$NrptPrefix = 'GCP-WG-SMART-FULLCN-',
    [int]$NrptChunkSize = 500,
    [int]$RouteMetric = 5,
    [switch]$DryRun
)

$ErrorActionPreference='Stop'

function Assert-Administrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($identity)

    if(
        -not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    ){
        throw 'Administrator privileges are required.'
    }
}

function Get-PhysicalDefaultRoute {
    param(
        [int]$WireGuardInterfaceIndex
    )

    return (
        Get-NetRoute `
            -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' `
            -ErrorAction SilentlyContinue |
        Where-Object {
            $_.NextHop -ne '0.0.0.0' -and
            $_.InterfaceIndex -ne $WireGuardInterfaceIndex
        } |
        Sort-Object @{
            Expression={
                [int]$_.RouteMetric + [int]$_.InterfaceMetric
            }
        } |
        Select-Object -First 1
    )
}

function Get-InstalledRouteSet {
    param(
        [int]$InterfaceIndex,
        [string]$NextHop
    )

    $set=[System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    Get-NetRoute `
        -AddressFamily IPv4 `
        -InterfaceIndex $InterfaceIndex `
        -ErrorAction SilentlyContinue |
    Where-Object {
        $_.NextHop -eq $NextHop
    } |
    ForEach-Object {
        [void]$set.Add($_.DestinationPrefix)
    }

    return ,$set
}

Write-Host 'WireGuard SMART VPN - Enable'
Write-Host ('=' * 72)

Assert-Administrator

Write-Host ''
Write-Host '=== PREFLIGHT ==='

$xray=@(
    Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -eq 'xray_tun' -and
        $_.Status -eq 'Up'
    }
)

Write-Host "XRAY_TUN_UP=$($xray.Count)"

if($xray.Count){
    throw 'XRAY_TUN_IS_UP'
}

$internetSettings=Get-ItemProperty `
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
    -ErrorAction SilentlyContinue

$proxyEnabled=$false

if($internetSettings){
    $proxyEnabled=([int]$internetSettings.ProxyEnable -eq 1)
}

Write-Host "WININET_PROXY_ENABLED=$proxyEnabled"

if($proxyEnabled){
    throw 'WININET_SYSTEM_PROXY_ENABLED'
}

$wg=Get-NetIPAddress `
    -AddressFamily IPv4 `
    -IPAddress $WireGuardAddress `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.InterfaceAlias -eq $TunnelName
    } |
    Select-Object -First 1

if(!$wg){
    throw "WIREGUARD_TUNNEL_NOT_PRESENT: $TunnelName / $WireGuardAddress"
}

Write-Host "WG_IF=$($wg.InterfaceAlias)"
Write-Host "WG_INDEX=$($wg.InterfaceIndex)"
Write-Host "WG_ADDRESS=$($wg.IPAddress)/$($wg.PrefixLength)"

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
    throw 'WIREGUARD_HALF_ROUTES_NOT_COMPLETE'
}

$wgDns=@(
    (
        Get-DnsClientServerAddress `
            -InterfaceIndex $wg.InterfaceIndex `
            -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue
    ).ServerAddresses
)

Write-Host "WG_DNS=$($wgDns -join ',')"

if($wgDns -notcontains $PrivateDns){
    throw "WIREGUARD_PRIVATE_DNS_NOT_CONFIGURED: expected $PrivateDns"
}

$physical=Get-PhysicalDefaultRoute `
    -WireGuardInterfaceIndex $wg.InterfaceIndex

if(!$physical){
    throw 'PHYSICAL_DEFAULT_ROUTE_NOT_FOUND'
}

Write-Host "PHYSICAL_IF=$($physical.InterfaceAlias)"
Write-Host "PHYSICAL_INDEX=$($physical.InterfaceIndex)"
Write-Host "PHYSICAL_GATEWAY=$($physical.NextHop)"

$chinaDnsRoute=(
    Find-NetRoute `
        -RemoteIPAddress $ChinaDns `
        -ErrorAction SilentlyContinue |
    Where-Object {$_.DestinationPrefix} |
    Select-Object -First 1
)

if(
    $chinaDnsRoute -and
    $chinaDnsRoute.InterfaceAlias -eq $TunnelName
){
    Write-Host 'CHINA_DNS_CURRENTLY_VIA_WG=True'
}
else {
    Write-Host 'CHINA_DNS_CURRENTLY_VIA_WG=False'
}

Write-Host ''
Write-Host '=== LOAD CN IPV4 ==='

if(!(Test-Path -LiteralPath $CnRouteFile)){
    throw "CN_ROUTE_FILE_NOT_FOUND: $CnRouteFile"
}

$cidrs=@(
    Get-Content -LiteralPath $CnRouteFile |
    ForEach-Object {$_.Trim()} |
    Where-Object {$_} |
    Sort-Object -Unique
)

if(!$cidrs.Count){
    throw 'CN_ROUTE_DATASET_EMPTY'
}

$invalidCidrs=@(
    $cidrs |
    Where-Object {
        $_ -notmatch '^\d{1,3}(\.\d{1,3}){3}/([0-9]|[12][0-9]|3[0-2])$'
    }
)

Write-Host "CN_ROUTE_FILE=$CnRouteFile"
Write-Host "CN_ROUTE_COUNT=$($cidrs.Count)"
Write-Host "CN_ROUTE_INVALID=$($invalidCidrs.Count)"

if($invalidCidrs.Count){
    throw 'CN_ROUTE_DATASET_FORMAT_INVALID'
}

$installedRoutes=Get-InstalledRouteSet `
    -InterfaceIndex $physical.InterfaceIndex `
    -NextHop $physical.NextHop

$missingRoutes=@(
    $cidrs |
    Where-Object {
        -not $installedRoutes.Contains($_)
    }
)

Write-Host "CN_ROUTE_PRESENT=$($cidrs.Count-$missingRoutes.Count)"
Write-Host "CN_ROUTE_MISSING=$($missingRoutes.Count)"

Write-Host ''
Write-Host '=== LOAD CN DOMAINS ==='

if(!(Test-Path -LiteralPath $CnNamespaceFile)){
    throw "CN_NAMESPACE_FILE_NOT_FOUND: $CnNamespaceFile"
}

$namespaces=@(
    Get-Content -LiteralPath $CnNamespaceFile |
    ForEach-Object {$_.Trim()} |
    Where-Object {$_} |
    Sort-Object -Unique
)

if(!$namespaces.Count){
    throw 'CN_NAMESPACE_DATASET_EMPTY'
}

Write-Host "CN_NAMESPACE_FILE=$CnNamespaceFile"
Write-Host "CN_NAMESPACE_COUNT=$($namespaces.Count)"

$targetSet=[System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

foreach($namespace in $namespaces){
    [void]$targetSet.Add($namespace)
}

$currentRules=@(
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -like "$NrptPrefix*"
    }
)

$currentSet=[System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

foreach($rule in $currentRules){
    foreach($namespace in @($rule.Namespace)){
        if($namespace){
            [void]$currentSet.Add([string]$namespace)
        }
    }
}

$nrptExact=(
    $currentSet.Count -eq $targetSet.Count
)

if($nrptExact){
    foreach($namespace in $namespaces){
        if(!$currentSet.Contains($namespace)){
            $nrptExact=$false
            break
        }
    }
}

Write-Host "NRPT_CURRENT_RULES=$($currentRules.Count)"
Write-Host "NRPT_CURRENT_NAMESPACES=$($currentSet.Count)"
Write-Host "NRPT_TARGET_NAMESPACES=$($targetSet.Count)"
Write-Host "NRPT_EXACT=$nrptExact"

$plannedNrptRules=[Math]::Ceiling(
    $namespaces.Count / [double]$NrptChunkSize
)

Write-Host ''
Write-Host '=== PLAN ==='

Write-Host "DRY_RUN=$([bool]$DryRun)"
Write-Host "ROUTES_TO_ADD=$($missingRoutes.Count)"
Write-Host "NRPT_REBUILD=$(-not $nrptExact)"
Write-Host "NRPT_PLANNED_RULES=$plannedNrptRules"

if($DryRun){
    Write-Host ''
    Write-Host 'SMART_ON_DRY_RUN=PASS'
    Write-Host 'NO_NETWORK_CHANGES=TRUE'
    exit 0
}

Write-Host ''
Write-Host '=== APPLY CN ROUTES ==='

if($missingRoutes.Count){
    $batch=Join-Path $env:TEMP (
        'gcp-wg-smart-routes-' +
        [guid]::NewGuid().ToString('N') +
        '.txt'
    )

    try {
        @(
            foreach($cidr in $missingRoutes){
                'interface ipv4 add route prefix={0} interface="{1}" nexthop={2} metric={3} store=active' -f `
                    $cidr,
                    $physical.InterfaceAlias,
                    $physical.NextHop,
                    $RouteMetric
            }
        ) | Set-Content `
            -LiteralPath $batch `
            -Encoding ASCII

        $netshCandidates=@(
            (Join-Path $env:WINDIR 'Sysnative\netsh.exe'),
            (Join-Path $env:WINDIR 'System32\netsh.exe')
        )

        $netsh=$netshCandidates |
            Where-Object {
                Test-Path -LiteralPath $_
            } |
            Select-Object -First 1

        if(!$netsh){
            $netshCommand=Get-Command netsh.exe -ErrorAction SilentlyContinue

            if($netshCommand){
                $netsh=$netshCommand.Source
            }
        }

        if(!$netsh){
            throw 'NETSH_NOT_FOUND'
        }

        Write-Host "ROUTE_BATCH=$batch"
        Write-Host "NETSH=$netsh"

        & $netsh -f $batch | Out-Host

        if($LASTEXITCODE -ne 0){
            throw "NETSH_ROUTE_BATCH_FAILED: exit=$LASTEXITCODE"
        }
    }
    finally {
        Remove-Item -LiteralPath $batch -Force -ErrorAction SilentlyContinue
    }
}
else {
    Write-Host 'CN_ROUTES_ALREADY_COMPLETE'
}

Write-Host ''
Write-Host '=== APPLY NRPT ==='

if(!$nrptExact){
    foreach($rule in $currentRules){
        Remove-DnsClientNrptRule `
            -Name $rule.Name `
            -Force `
            -ErrorAction Stop
    }

    for(
        $offset=0;
        $offset -lt $namespaces.Count;
        $offset += $NrptChunkSize
    ){
        $end=[Math]::Min(
            $offset+$NrptChunkSize-1,
            $namespaces.Count-1
        )

        $chunk=@(
            $namespaces[$offset..$end]
        )

        $number=[int]($offset/$NrptChunkSize)+1

        $displayName=(
            '{0}{1:D3}' -f
            $NrptPrefix,
            $number
        )

        Add-DnsClientNrptRule `
            -Namespace $chunk `
            -NameServers $ChinaDns `
            -DisplayName $displayName `
            -Comment 'WireGuard SMART CN split DNS' `
            -ErrorAction Stop |
        Out-Null

        Write-Host (
            'NRPT_CREATED={0} COUNT={1}' -f
            $displayName,
            $chunk.Count
        )
    }

    Clear-DnsClientCache
}
else {
    Write-Host 'CN_NRPT_ALREADY_EXACT'
}

Write-Host ''
Write-Host '=== VERIFY ROUTES ==='

$verifiedRoutes=Get-InstalledRouteSet `
    -InterfaceIndex $physical.InterfaceIndex `
    -NextHop $physical.NextHop

$routeMissingAfter=@(
    $cidrs |
    Where-Object {
        -not $verifiedRoutes.Contains($_)
    }
)

Write-Host "CN_ROUTE_EXPECTED=$($cidrs.Count)"
Write-Host "CN_ROUTE_MISSING_AFTER=$($routeMissingAfter.Count)"

Write-Host ''
Write-Host '=== VERIFY NRPT ==='

$verifiedRules=@(
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -like "$NrptPrefix*"
    }
)

$verifiedSet=[System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

foreach($rule in $verifiedRules){
    foreach($namespace in @($rule.Namespace)){
        if($namespace){
            [void]$verifiedSet.Add([string]$namespace)
        }
    }
}

$nrptMissingAfter=0

foreach($namespace in $namespaces){
    if(!$verifiedSet.Contains($namespace)){
        $nrptMissingAfter++
    }
}

$nrptUnexpectedAfter=0

foreach($namespace in $verifiedSet){
    if(!$targetSet.Contains($namespace)){
        $nrptUnexpectedAfter++
    }
}

Write-Host "NRPT_RULES_AFTER=$($verifiedRules.Count)"
Write-Host "NRPT_NAMESPACES_AFTER=$($verifiedSet.Count)"
Write-Host "NRPT_MISSING_AFTER=$nrptMissingAfter"
Write-Host "NRPT_UNEXPECTED_AFTER=$nrptUnexpectedAfter"

Write-Host ''
Write-Host '=== FINAL ==='

$pass=(
    $routeMissingAfter.Count -eq 0 -and
    $nrptMissingAfter -eq 0 -and
    $nrptUnexpectedAfter -eq 0 -and
    $verifiedSet.Count -eq $targetSet.Count
)

if($pass){
    Write-Host 'SMART_ON=PASS'
    exit 0
}
else {
    Write-Host 'SMART_ON=FAIL'
    exit 2
}
