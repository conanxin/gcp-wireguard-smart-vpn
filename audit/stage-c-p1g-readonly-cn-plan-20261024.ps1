<#
Stage C P1G: READ-ONLY CN IPv4 route inventory and candidate classification.
This is NOT SMART ON/OFF. Does not install routes, modify DNS/NRPT,
system proxy, xray, WireGuard, or produce a runnable netsh batch.
Matched pre-existing routes are NEVER treated as owned by this project.
Fixture mode uses ONLY supplied fake route objects, never system route APIs.
#>
[CmdletBinding()]
param(
    [ValidateSet('Live','Fixture')][string]$Mode='Live',
    [string]$RepoRoot='',
    [string]$DatasetPath='',
    [string]$FixturePath='',
    [string]$PhysicalAlias='WLAN',
    [int]$PlannedMetric=5,
    [string]$NrptPrefix='GCP-WG-SMART-FULLCN-',
    [string]$ChinaDns='223.5.5.5'
)
$ErrorActionPreference='Stop'
function Emit([string]$Key,$Value) { Write-Output ($Key+'='+[string]$Value) }
function Read-StoreRoutes([string]$Store) {
    try {
        return @(Get-NetRoute -AddressFamily IPv4 -PolicyStore $Store -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*') {
            return @()
        }
        throw
    }
}
function Valid-Cidr([string]$Line) {
    $m=[regex]::Match($Line,'^(\d{1,3}(?:\.\d{1,3}){3})/(3[0-2]|[12]\d|\d)$')
    if (-not $m.Success) { return $false }
    $bits=[int]$m.Groups[2].Value
    $octets=@($m.Groups[1].Value.Split('.'))
    foreach ($octet in $octets) {
        if ([int]$octet -gt 255 -or ([string][int]$octet) -ne $octet) {return $false}
    }
    [uint64]$ip=(([uint64][int]$octets[0] -shl 24) -bor
                  ([uint64][int]$octets[1] -shl 16) -bor
                  ([uint64][int]$octets[2] -shl 8) -bor
                  [uint64][int]$octets[3])
    [uint64]$mask=if($bits -eq 0){0}else{([uint64]4294967295 -shl (32-$bits)) -band [uint64]4294967295}
    return (($ip -band $mask) -eq $ip)
}
function Objects($Maybe) {
    if ($null -eq $Maybe) { return @() }
    return @($Maybe)
}
try {
    if (-not $RepoRoot) {$RepoRoot=Split-Path -Parent $PSScriptRoot}
    if (-not $DatasetPath) {$DatasetPath=Join-Path $RepoRoot 'data\cn-ipv4-cidrs.txt'}
    if (-not (Test-Path -LiteralPath $DatasetPath -PathType Leaf)) {throw 'DATASET_NOT_FOUND'}
    if ($Mode -eq 'Fixture' -and [string]::IsNullOrWhiteSpace($FixturePath)) {throw 'FIXTURE_PATH_REQUIRED'}
    if ($Mode -eq 'Live' -and $FixturePath) {throw 'FIXTURE_NOT_ALLOWED_IN_LIVE'}
    Emit 'P1G_MODE' $(if($Mode -eq 'Live'){'LIVE_READ_ONLY'}else{'FIXTURE_NO_SYSTEM_QUERY'})
    Emit 'P1G_SNAPSHOT_AT' ([DateTimeOffset]::Now.ToString('o'))
    $raw=@(Get-Content -LiteralPath $DatasetPath -Encoding UTF8 | ForEach-Object {$_.Trim()} | Where-Object {$_})
    $expected=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $invalid=0
    foreach ($cidr in $raw) {
        if (-not (Valid-Cidr $cidr)) {$invalid++;continue}
        if (-not $expected.Add($cidr)) {$invalid++}
    }
    Emit 'P1G_CIDR_LINES' $raw.Count
    Emit 'P1G_CIDR_UNIQUE_VALID' $expected.Count
    Emit 'P1G_CIDR_INVALID_OR_DUPLICATE' $invalid
    Emit 'P1G_CIDR_SHA256' (Get-FileHash -LiteralPath $DatasetPath -Algorithm SHA256).Hash
    $age=[int][Math]::Floor(((Get-Date)-(Get-Item -LiteralPath $DatasetPath).LastWriteTime).TotalDays)
    Emit 'P1G_DATASET_AGE_DAYS' $age
    Emit 'P1G_DATASET_OLDER_THAN_30_DAYS' ($age -gt 30)
    if ($invalid -or $expected.Count -eq 0) {throw 'DATASET_INVALID_OR_EMPTY'}

    if($Mode -eq 'Fixture') {
        $f=(Get-Content -LiteralPath $FixturePath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
        $active=@($f.activeRoutes | Where-Object {$null -ne $_})
        $persistent=@($f.persistentRoutes | Where-Object {$null -ne $_})
        $defaults=@($f.physicalDefaults | Where-Object {$null -ne $_})
        $proxyState=[string]$f.proxyEnabled
        $xrayCount=[int]$f.xrayCount
        $wgPresent=[bool]$f.wgPresent
        $halfCount=[int]$f.halfCount
        $nrptRuleCount=[int]$f.nrptRuleCount
        $nrptNamespaceCount=[int]$f.nrptNamespaceCount
        $nrptExact=[bool]$f.nrptExact
        $nrptMissing=[int]$f.nrptMissing
        $nrptExtra=[int]$f.nrptExtra
        $nrptBadServers=[int]$f.nrptBadServers
    } else {
        $active=@(Read-StoreRoutes 'ActiveStore')
        $persistent=@(Read-StoreRoutes 'PersistentStore')
        $defaults=@($active|Where-Object {
            $_.DestinationPrefix -eq '0.0.0.0/0' -and
            $_.InterfaceAlias -eq $PhysicalAlias -and
            $_.NextHop -ne '0.0.0.0'
        })
        $proxy=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $proxyState=[string]$proxy.ProxyEnable
        $xrayCount=@(Get-Process -Name xray -ErrorAction SilentlyContinue).Count
        $wgService=Get-Service -Name 'WireGuardTunnel$client1-cndirect' -ErrorAction SilentlyContinue
        $wgAdapter=Get-NetAdapter -Name 'client1-cndirect' -ErrorAction SilentlyContinue
        $wgPresent=([bool]$wgService -or [bool]$wgAdapter)
        $halfCount=@($active|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')}).Count
        $nsPath=Join-Path $RepoRoot 'data\cn-nrpt-namespaces.txt'
        if (-not (Test-Path -LiteralPath $nsPath -PathType Leaf)) {throw 'NAMESPACE_SOURCE_MISSING'}
        $nsRaw=@(Get-Content -LiteralPath $nsPath -Encoding UTF8|ForEach-Object {$_.Trim()}|Where-Object{$_})
        $nsExpected=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($ns in $nsRaw) {[void]$nsExpected.Add($ns)}
        $rules=@(Get-DnsClientNrptRule -ErrorAction Stop|Where-Object {$_.DisplayName -like ($NrptPrefix+'*')})
        $nsActual=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $nrptBadServers=0;$nrptNamespaceCount=0
        foreach($rule in $rules){
            $servers=@($rule.NameServers|Where-Object {$_})
            if($servers.Count -ne 1 -or $servers[0] -ne $ChinaDns){$nrptBadServers++}
            foreach($ns in @($rule.Namespace)){
                if($ns){$nrptNamespaceCount++;[void]$nsActual.Add([string]$ns)}
            }
        }
        $nrptMissing=0;$nrptExtra=0
        foreach($ns in $nsExpected){if(-not $nsActual.Contains($ns)){$nrptMissing++}}
        foreach($ns in $nsActual){if(-not $nsExpected.Contains($ns)){$nrptExtra++}}
        $nrptRuleCount=$rules.Count
        $nrptExact=($nrptMissing -eq 0 -and $nrptExtra -eq 0 -and
                    $nrptBadServers -eq 0 -and $nsRaw.Count -eq $nrptNamespaceCount)
    }
    Emit 'P1G_ACTIVE_IPV4_ROUTE_OBJECTS' $active.Count
    Emit 'P1G_PERSISTENT_IPV4_ROUTE_OBJECTS' $persistent.Count
    Emit 'P1G_PHYSICAL_DEFAULT_MATCHES' $defaults.Count
    $selected=$null
    if($defaults.Count -eq 1){$selected=$defaults[0]}
    if($selected) {
        Emit 'P1G_PHYSICAL_IF' $selected.InterfaceIndex
        Emit 'P1G_PHYSICAL_GATEWAY' $selected.NextHop
        Emit 'P1G_PHYSICAL_ALIAS' $PhysicalAlias
    } else {
        Emit 'P1G_PHYSICAL_GATE' 'BLOCKED_MISSING_OR_AMBIGUOUS'
    }
    $noRoute=0;$exactUnowned=0;$activeConflict=0;$persistConflict=0
    $conflictSamples=[Collections.Generic.List[string]]::new()
    foreach($prefix in $expected) {
        $a=@($active|Where-Object {$_.DestinationPrefix -eq $prefix})
        $p=@($persistent|Where-Object {$_.DestinationPrefix -eq $prefix})
        if($a.Count -eq 0 -and $p.Count -eq 0) {$noRoute++;continue}
        if($p.Count -gt 0) {$persistConflict++}
        if($a.Count -gt 0){
            $matching=@($a|Where-Object {
                $selected -and
                [int]$_.InterfaceIndex -eq [int]$selected.InterfaceIndex -and
                [string]$_.NextHop -eq [string]$selected.NextHop -and
                [int]$_.RouteMetric -eq $PlannedMetric
            })
            if($a.Count -eq 1 -and $matching.Count -eq 1 -and $p.Count -eq 0){
                $exactUnowned++
            }else{
                $activeConflict++
                if($conflictSamples.Count -lt 5){$conflictSamples.Add($prefix)}
            }
        }elseif($conflictSamples.Count -lt 5){$conflictSamples.Add($prefix)}
    }
    Emit 'P1G_CN_NO_EXACT_PREFIX_ROUTE_CANDIDATES' $noRoute
    Emit 'P1G_CN_MATCHING_BUT_UNOWNED_PREFIXES' $exactUnowned
    Emit 'P1G_CN_ACTIVE_CONFLICT_PREFIXES' $activeConflict
    Emit 'P1G_CN_PERSISTENT_CONFLICT_PREFIXES' $persistConflict
    Emit 'P1G_CN_CONFLICT_SAMPLE' ($conflictSamples.ToArray() -join ',')
    Emit 'P1G_PLANNED_ROUTE_METRIC' $PlannedMetric
    Emit 'P1G_NRPT_PROJECT_RULES' $nrptRuleCount
    Emit 'P1G_NRPT_NAMESPACE_ROWS' $nrptNamespaceCount
    Emit 'P1G_NRPT_MISSING' $nrptMissing
    Emit 'P1G_NRPT_EXTRA' $nrptExtra
    Emit 'P1G_NRPT_BAD_SERVERS' $nrptBadServers
    Emit 'P1G_NRPT_EXACT' $nrptExact
    Emit 'P1G_WININET_PROXY_ENABLE' $proxyState
    Emit 'P1G_XRAY_PROCESS_COUNT' $xrayCount
    Emit 'P1G_WG_PRESENT' $wgPresent
    Emit 'P1G_HALF_DEFAULT_ROUTE_COUNT' $halfCount
    $resting=($proxyState -eq '1' -and $xrayCount -ge 1 -and
              -not $wgPresent -and $halfCount -eq 0)
    Emit 'P1G_RESTING_XRAY_MODE' $resting
    Emit 'P1G_EXISTING_PREFIX_OWNERSHIP' 'UNKNOWN_NEVER_ADOPT'
    Emit 'P1G_FULL_CN_WRITE_AUTHORIZED' 'False'
    Emit 'P1G_NETWORK_MUTATIONS_PERFORMED' 'False'
    if(-not $selected){
        Emit 'P1G_RESULT' 'BLOCKED_PHYSICAL_GATE'
        exit 2
    }
    if($activeConflict -gt 0 -or $persistConflict -gt 0){
        Emit 'P1G_RESULT' 'BLOCKED_PREFIX_COLLISIONS'
        exit 2
    }
    if($Mode -eq 'Fixture'){
        Emit 'P1G_RESULT' 'FIXTURE_PLAN_COMPLETE'
    }else{
        Emit 'P1G_RESULT' 'READ_ONLY_PLAN_COMPLETE'
    }
    exit 0
} catch {
    Emit 'P1G_ERROR' $_.Exception.Message
    Emit 'P1G_NETWORK_MUTATIONS_PERFORMED' 'False'
    Emit 'P1G_RESULT' 'BLOCKED_INCOMPLETE'
    exit 4
}
