<#
Stage C P1 PlanOnly: PowerShell 5.1, no Windows network mutations.
Works while WireGuard is OFF and WinINET ProxyEnable=1.
NO SMART ON/OFF, netsh, NRPT writes, VPN install, proxy edits, or keys.
#>
[CmdletBinding()]
param([string]$RepoRoot = '',
      [string]$ExpectedResolver='223.5.5.5',
      [string]$NrptPrefix='GCP-WG-SMART-FULLCN-')
$ErrorActionPreference='Stop'
if (-not $RepoRoot) {
    $RepoRoot=Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}
function Emit([string]$Key, $Value) {
    Write-Output ($Key+'='+[string]$Value)
}
function Sha256Text([string]$Text) {
    $hasher=[System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        )).Replace('-','')
    } finally {$hasher.Dispose()}
}
$cnPath=Join-Path $RepoRoot 'data\cn-ipv4-cidrs.txt'
$nsPath=Join-Path $RepoRoot 'data\cn-nrpt-namespaces.txt'
if (-not (Test-Path -LiteralPath $cnPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $nsPath -PathType Leaf)) {
    Emit 'P1_PLANONLY' 'BLOCKED_MISSING_DATA'
    exit 2
}
$cidrs=@(Get-Content -LiteralPath $cnPath |
    ForEach-Object { $_.Trim() } | Where-Object {$_})
$namespaces=@(Get-Content -LiteralPath $nsPath |
    ForEach-Object { $_.Trim() } | Where-Object {$_})
$expected=[System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach($name in $namespaces) {[void]$expected.Add($name)}
Emit 'PLAN_MODE' 'READ_ONLY'
Emit 'LOCAL_TIME' ([DateTimeOffset]::Now.ToString('o'))
Emit 'CIDRS' $cidrs.Count
Emit 'NAMESPACES' $namespaces.Count
Emit 'CIDR_SHA256' (Get-FileHash -LiteralPath $cnPath -Algorithm SHA256).Hash
Emit 'NRPT_SHA256' (Get-FileHash -LiteralPath $nsPath -Algorithm SHA256).Hash

$blockers=[System.Collections.Generic.List[string]]::new()
$routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop)
$defaults=@($routes | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'})
$physical=@($defaults | Where-Object {
    $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -ne 'client1-cndirect'
} | Sort-Object @{Expression={[int]$_.RouteMetric+[int]$_.InterfaceMetric}} |
    Select-Object -First 1)
if($physical.Count -ne 1){$blockers.Add('PHYSICAL_GATEWAY_UNKNOWN')}
$proxy=Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$xray=@(Get-Process -Name xray -ErrorAction SilentlyContinue)
$tun=Get-NetAdapter -Name xray_tun -ErrorAction SilentlyContinue
$svc=Get-Service -Name 'WireGuardTunnel$client1-cndirect' -ErrorAction SilentlyContinue
$wg=Get-NetAdapter -Name client1-cndirect -ErrorAction SilentlyContinue
Emit 'XRAY_PROCESS_COUNT' $xray.Count
Emit 'XRAY_TUN' $(if($tun){$tun.Status}else{'ABSENT'})
Emit 'PROXY_ENABLE' $(if($proxy){$proxy.ProxyEnable}else{'UNKNOWN'})
Emit 'PROXY_SERVER' $(if($proxy){$proxy.ProxyServer}else{'UNKNOWN'})
Emit 'WG_SERVICE' $(if($svc){$svc.Status}else{'ABSENT'})
Emit 'WG_ADAPTER' $(if($wg){$wg.Status}else{'ABSENT'})
if($tun -and $tun.Status -eq 'Up'){$blockers.Add('XRAY_TUN_ACTIVE')}
if(-not $proxy){$blockers.Add('PROXY_STATE_UNKNOWN')}
if($proxy -and $proxy.ProxyEnable -eq 1 -and
    $proxy.ProxyServer -ne '127.0.0.1:7897'){
    $blockers.Add('PROXY_ENDPOINT_UNEXPECTED')
}
if(-not $xray.Count){$blockers.Add('XRAY_PROCESS_ABSENT')}

$borrowed=0;$toAdd=0;$collision=0
$sample=[System.Collections.Generic.List[string]]::new()
if($physical.Count){
    $p=$physical[0]
    Emit 'PHYSICAL_INTERFACE_INDEX' $p.InterfaceIndex
    Emit 'PHYSICAL_INTERFACE_ALIAS' $p.InterfaceAlias
    Emit 'PHYSICAL_GATEWAY' $p.NextHop
    $map=@{}
    foreach($r in $routes){
        $key=$r.DestinationPrefix.ToLowerInvariant()
        if(-not $map.ContainsKey($key)){
            $map[$key]=[System.Collections.Generic.List[object]]::new()
        }
        $map[$key].Add($r)
    }
    foreach($prefix in $cidrs){
        $list=if($map.ContainsKey($prefix.ToLowerInvariant())){
            @($map[$prefix.ToLowerInvariant()])
        }else{@()}
        $mine=@($list | Where-Object {
            $_.InterfaceIndex -eq $p.InterfaceIndex -and $_.NextHop -eq $p.NextHop
        })
        $other=@($list | Where-Object {
            $_.InterfaceIndex -ne $p.InterfaceIndex -or $_.NextHop -ne $p.NextHop
        })
        if($other.Count){$collision++}
        if($mine.Count){$borrowed++}
        elseif(-not $other.Count){
            $toAdd++
            if($sample.Count -lt 4){$sample.Add($prefix)}
        }
    }
}
Emit 'ROUTES_TO_ADD' $toAdd
Emit 'BORROWED_ROUTES_TO_PRESERVE' $borrowed
Emit 'CONFLICTING_PREFIXES' $collision
Emit 'ROUTE_SAMPLE' ($sample -join ',')
if($collision){$blockers.Add('ROUTE_PREFIX_COLLISIONS')}

$rules=@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object {$_.DisplayName -like ($NrptPrefix+'*')})
$actual=[System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$rows=0;$duplicate=0;$badServers=0
$nrptRows=[System.Collections.Generic.List[string]]::new()
foreach($rule in $rules){
    $servers=@($rule.NameServers | Where-Object {$_})
    if($servers.Count -ne 1 -or $servers[0] -ne $ExpectedResolver){$badServers++}
    $nss=@($rule.Namespace | Where-Object {$_})
    foreach($n in $nss){
        $rows++
        if(-not $actual.Add([string]$n)){$duplicate++}
    }
    $nrptRows.Add(('{0}|{1}|{2}|{3}' -f $rule.Name,
        $rule.DisplayName,($servers -join ','),(($nss|Sort-Object) -join ',')))
}
$missing=0;$extra=0
foreach($n in $expected){if(-not $actual.Contains($n)){$missing++}}
foreach($n in $actual){if(-not $expected.Contains($n)){$extra++}}
Emit 'NRPT_RULE_COUNT' $rules.Count
Emit 'NRPT_ROWS' $rows
Emit 'NRPT_MISSING' $missing
Emit 'NRPT_EXTRA' $extra
Emit 'NRPT_BAD_RESOLVER_RULES' $badServers
Emit 'NRPT_DUPLICATE_ROWS' $duplicate
$nrptOk=($missing -eq 0 -and $extra -eq 0 -and
         $badServers -eq 0 -and $duplicate -eq 0 -and
         $rows -eq $namespaces.Count)
Emit 'NRPT_POLICY_MATCH' $nrptOk
if(-not $nrptOk){$blockers.Add('NRPT_POLICY_DRIFT')}

# Full-state fingerprints are for future revalidation, not authorization.
$routeRows=@($routes | ForEach-Object {
    '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.DestinationPrefix,
       $_.InterfaceIndex,$_.NextHop,$_.RouteMetric,$_.InterfaceMetric,$_.PolicyStore
} | Sort-Object)
$routeHash=Sha256Text ([string]::Join([Environment]::NewLine,$routeRows))
$nrptHash=Sha256Text ([string]::Join([Environment]::NewLine,@($nrptRows|Sort-Object)))
$baseHash=Sha256Text ($routeHash+'|'+$nrptHash+'|'+
    [string]$proxy.ProxyEnable+'|'+[string]$proxy.ProxyServer+'|'+
    [string]$xray.Count+'|'+
    $(if($tun){[string]$tun.Status}else{'ABSENT'})+'|'+
    $(if($svc){[string]$svc.Status}else{'ABSENT'})+'|'+
    $(if($wg){[string]$wg.Status}else{'ABSENT'})+'|'+
    $(if($physical.Count){[string]$physical[0].InterfaceIndex}else{'NONE'})+'|'+
    $(if($physical.Count){[string]$physical[0].NextHop}else{'NONE'}))
Emit 'ROUTE_PRESTATE_SHA256' $routeHash
Emit 'NRPT_PRESTATE_SHA256' $nrptHash
Emit 'PRESTATE_FINGERPRINT' $baseHash
Emit 'BLOCKERS' $blockers.Count
foreach($b in $blockers){Emit 'BLOCKER' $b}
Emit 'REQUIRES_PROXY_TRANSITION_FOR_SMART' ([bool]($proxy -and $proxy.ProxyEnable -eq 1))
Emit 'NATIVE_APPLY_IMPLEMENTED' 'False'
Emit 'LIVE_APPROVED' 'False'
Emit 'SYSTEM_MUTATIONS_PERFORMED' 'False'
Emit 'P1_PLANONLY' $(if($blockers.Count){'COMPLETE_WITH_BLOCKERS'}else{'PASS'})
exit 0
