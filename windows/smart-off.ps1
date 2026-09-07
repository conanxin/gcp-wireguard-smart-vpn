[CmdletBinding()]
param(
    [string]$TunnelName = 'client1-cndirect',
    [string]$WireGuardAddress = '10.66.66.2',
    [string]$PrivateDns = '10.66.66.1',
    [string]$CnRouteFile = (Join-Path (Split-Path $PSScriptRoot -Parent) 'data\cn-ipv4-cidrs.txt'),
    [string]$NrptPrefix = 'GCP-WG-SMART-FULLCN-',
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

Write-Host 'WireGuard SMART VPN - Disable Smart Split'
Write-Host ('=' * 72)

Assert-Administrator

Write-Host ''
Write-Host '=== PREFLIGHT ==='

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

Write-Host "CN_ROUTE_FILE=$CnRouteFile"
Write-Host "CN_ROUTE_COUNT=$($cidrs.Count)"

$routeMap=@{}

Get-NetRoute `
    -AddressFamily IPv4 `
    -InterfaceIndex $physical.InterfaceIndex `
    -ErrorAction SilentlyContinue |
Where-Object {
    $_.NextHop -eq $physical.NextHop
} |
ForEach-Object {
    $routeMap[$_.DestinationPrefix]=$true
}

$routesToRemove=@(
    $cidrs |
    Where-Object {
        $routeMap.ContainsKey($_)
    }
)

Write-Host "CN_ROUTE_PRESENT=$($routesToRemove.Count)"
Write-Host "CN_ROUTE_ALREADY_ABSENT=$($cidrs.Count-$routesToRemove.Count)"

Write-Host ''
Write-Host '=== NRPT ==='

$rulesToRemove=@(
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -like "$NrptPrefix*"
    }
)

$namespaceCount=0

foreach($rule in $rulesToRemove){
    $namespaceCount += @($rule.Namespace).Count
}

Write-Host "NRPT_RULES_PRESENT=$($rulesToRemove.Count)"
Write-Host "NRPT_NAMESPACES_PRESENT=$namespaceCount"

Write-Host ''
Write-Host '=== PLAN ==='

Write-Host "DRY_RUN=$([bool]$DryRun)"
Write-Host "ROUTES_TO_REMOVE=$($routesToRemove.Count)"
Write-Host "NRPT_RULES_TO_REMOVE=$($rulesToRemove.Count)"
Write-Host "NRPT_NAMESPACES_TO_REMOVE=$namespaceCount"

if($DryRun){
    Write-Host ''
    Write-Host 'SMART_OFF_DRY_RUN=PASS'
    Write-Host 'NO_NETWORK_CHANGES=TRUE'
    exit 0
}

Write-Host ''
Write-Host '=== REMOVE CN ROUTES ==='

if($routesToRemove.Count){

    $batch=Join-Path $env:TEMP (
        'gcp-wg-smart-routes-remove-' +
        [guid]::NewGuid().ToString('N') +
        '.txt'
    )

    try {
        @(
            foreach($cidr in $routesToRemove){
                'interface ipv4 delete route prefix={0} interface="{1}" nexthop={2} store=active' -f `
                    $cidr,
                    $physical.InterfaceAlias,
                    $physical.NextHop
            }
        ) |
        Set-Content `
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
            throw "NETSH_ROUTE_DELETE_BATCH_FAILED: exit=$LASTEXITCODE"
        }
    }
    finally {
        Remove-Item `
            -LiteralPath $batch `
            -Force `
            -ErrorAction SilentlyContinue
    }
}
else {
    Write-Host 'CN_ROUTES_ALREADY_ABSENT'
}

Write-Host ''
Write-Host '=== REMOVE NRPT ==='

if($rulesToRemove.Count){

    foreach($rule in $rulesToRemove){
        Write-Host "NRPT_REMOVING=$($rule.DisplayName)"

        Remove-DnsClientNrptRule `
            -Name $rule.Name `
            -Force `
            -ErrorAction Stop
    }

    Clear-DnsClientCache
}
else {
    Write-Host 'CN_NRPT_ALREADY_ABSENT'
}

Write-Host ''
Write-Host '=== VERIFY CN ROUTES ==='

$remainingRouteMap=@{}

Get-NetRoute `
    -AddressFamily IPv4 `
    -InterfaceIndex $physical.InterfaceIndex `
    -ErrorAction SilentlyContinue |
Where-Object {
    $_.NextHop -eq $physical.NextHop
} |
ForEach-Object {
    $remainingRouteMap[$_.DestinationPrefix]=$true
}

$remainingCnRoutes=@(
    $cidrs |
    Where-Object {
        $remainingRouteMap.ContainsKey($_)
    }
)

Write-Host "CN_ROUTE_EXPECTED_ABSENT=$($cidrs.Count)"
Write-Host "CN_ROUTE_REMAINING=$($remainingCnRoutes.Count)"

Write-Host ''
Write-Host '=== VERIFY NRPT ==='

$remainingRules=@(
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -like "$NrptPrefix*"
    }
)

$remainingNamespaces=0

foreach($rule in $remainingRules){
    $remainingNamespaces += @($rule.Namespace).Count
}

Write-Host "NRPT_RULES_REMAINING=$($remainingRules.Count)"
Write-Host "NRPT_NAMESPACES_REMAINING=$remainingNamespaces"

Write-Host ''
Write-Host '=== VERIFY FALLBACK ROUTING ==='

foreach($address in @(
    '223.5.5.5',
    '8.8.8.8',
    '1.1.1.1'
)){
    $route=(
        Find-NetRoute `
            -RemoteIPAddress $address `
            -ErrorAction SilentlyContinue |
        Where-Object {$_.DestinationPrefix} |
        Select-Object -First 1
    )

    if($route){
        Write-Host (
            '{0} -> IF={1} PREFIX={2} NEXT={3}' -f `
            $address,
            $route.InterfaceAlias,
            $route.DestinationPrefix,
            $route.NextHop
        )
    }
}

Write-Host ''
Write-Host '=== FINAL ==='

$pass=(
    $remainingCnRoutes.Count -eq 0 -and
    $remainingRules.Count -eq 0 -and
    $remainingNamespaces -eq 0
)

if($pass){
    Write-Host 'SMART_OFF=PASS'
    exit 0
}
else {
    Write-Host 'SMART_OFF=FAIL'
    exit 2
}
