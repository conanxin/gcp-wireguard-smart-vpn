<#
Stage C P1I: Windows PowerShell 5.1 read-only native CIM route snapshot.
READS ONLY. No administrator rights, no native route/proxy/DNS/NRPT/WG writes.
Outputs normalized native Store as a STRING, not PolicyStore.
No secrets / private keys / adapter MAC addresses collected.
#>
[CmdletBinding()]
param([ValidateSet('Snapshot','Human')][string]$Mode='Snapshot', [string]$OutputPath='')
$ErrorActionPreference='Stop'
function Read-Routes([string]$PolicyStore) {
    try {
        return @(Get-NetRoute -AddressFamily IPv4 -PolicyStore $PolicyStore -ErrorAction Stop)
    } catch {
        if($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*') {return @()}
        throw
    }
}
function Project-Routes($Rows) {
    $out=[Collections.Generic.List[object]]::new()
    foreach($r in @($Rows)) {
        if($null -eq $r) {continue}
        $storeName=[string]$r.Store
        if($storeName -notin @('ActiveStore','PersistentStore')) {
            throw 'UNRECOGNIZED_CIM_ROUTE_STORE'
        }
        $out.Add([pscustomobject][ordered]@{
            DestinationPrefix=[string]$r.DestinationPrefix
            InterfaceIndex=[int]$r.InterfaceIndex
            NextHop=[string]$r.NextHop
            RouteMetric=[int]$r.RouteMetric
            Store=$storeName
            InterfaceAlias=[string]$r.InterfaceAlias
            Protocol=[string]$r.Protocol
            CompartmentId=[int]$r.CompartmentId
            InstanceID=[string]$r.InstanceID
        })
    }
    return $out.ToArray()
}
try {
    $active=@(Read-Routes 'ActiveStore')
    $persistent=@(Read-Routes 'PersistentStore')
    $projectedActive=@(Project-Routes $active)
    $projectedPersistent=@(Project-Routes $persistent)
    $wlan=@($projectedActive|Where-Object {
        $_.DestinationPrefix -eq '0.0.0.0/0' -and
        $_.InterfaceAlias -eq 'WLAN' -and
        $_.NextHop -ne '0.0.0.0'
    })
    $proxy=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    $nrpt=@(Get-DnsClientNrptRule -ErrorAction Stop)
    $wg=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue)
    $xray=@(Get-Process -Name 'xray' -ErrorAction SilentlyContinue)
    $half=@($projectedActive|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
    $wlanIf=$null
    $wlanHop=$null
    if($wlan.Count -eq 1) {
        $wlanIf=[int]$wlan[0].InterfaceIndex
        $wlanHop=[string]$wlan[0].NextHop
    }
    $sample=$null
    if($wlan.Count -eq 1) {
        $sample=@($active|Where-Object {
            $_.DestinationPrefix -eq '0.0.0.0/0' -and
            $_.InterfaceAlias -eq 'WLAN' -and $_.NextHop -ne '0.0.0.0'
        })|Select-Object -First 1
    } elseif($active.Count -gt 0) {
        $sample=$active[0]
    }
    $hasPolicyStore=$false
    $cimClassName=''
    if($sample) {
        $hasPolicyStore=[bool]$sample.PSObject.Properties['PolicyStore']
        $cimClassName=[string]$sample.CimClass.CimClassName
    }
    $envObj=[pscustomobject][ordered]@{
        PhysicalDefaultCount=$wlan.Count
        PhysicalInterfaceIndex=$wlanIf
        PhysicalNextHop=$wlanHop
        WinINETProxyEnable=[int]$proxy.ProxyEnable
        WinINETProxyServer=[string]$proxy.ProxyServer
        NRPTCount=$nrpt.Count
        WGServiceCount=$wg.Count
        XrayProcessCount=$xray.Count
        HalfDefaultRouteCount=$half.Count
    }
    $snapshot=[pscustomobject][ordered]@{
        schema='stage-c-p1i-native-cim-snapshot-v1'
        observedAt=[DateTimeOffset]::Now.ToString('o')
        nativeAccess='READ_ONLY_GET'
        cmdlet='Get-NetRoute'
        cimClass=$cimClassName
        sampleHasPolicyStoreProperty=$hasPolicyStore
        sampleStoreString=$(if($sample){[string]$sample.Store}else{''})
        activeRouteCount=$projectedActive.Count
        persistentRouteCount=$projectedPersistent.Count
        activeRoutes=$projectedActive
        persistentRoutes=$projectedPersistent
        environment=$envObj
        testnetTarget='198.51.100.77/32'
        testnetActiveCount=@($projectedActive|Where-Object{$_.DestinationPrefix -eq '198.51.100.77/32'}).Count
        testnetPersistentCount=@($projectedPersistent|Where-Object{$_.DestinationPrefix -eq '198.51.100.77/32'}).Count
        networkMutationsPerformed=$false
        nativeWriteAuthorized=$false
    }
    if($Mode -eq 'Human') {
        Write-Output ('P1I_CIM_CLASS='+$snapshot.cimClass)
        Write-Output ('P1I_STORE_FIELD='+$snapshot.sampleStoreString)
        Write-Output ('P1I_POLICY_STORE_PROPERTY_PRESENT='+$snapshot.sampleHasPolicyStoreProperty)
        Write-Output ('P1I_ACTIVE_COUNT='+$snapshot.activeRouteCount)
        Write-Output ('P1I_PERSISTENT_COUNT='+$snapshot.persistentRouteCount)
        Write-Output ('P1I_WLAN_DEFAULT_COUNT='+$envObj.PhysicalDefaultCount)
        Write-Output ('P1I_TESTNET_ROUTE_COUNT='+($snapshot.testnetActiveCount+$snapshot.testnetPersistentCount))
        Write-Output 'P1I_NETWORK_MUTATIONS_PERFORMED=False'
        Write-Output 'P1I_RESULT=READ_ONLY_NATIVE_CIM_SNAPSHOT_PASS'
    } else {
        $json=ConvertTo-Json -InputObject $snapshot -Depth 8 -Compress
        if ($OutputPath) {
            # Optional UTF-8 direct-to-file output avoids console code-page data loss.
            # Accept only snapshot.json inside a dedicated p1i-fixture-* temp child.
            $full=[IO.Path]::GetFullPath($OutputPath)
            $parent=[IO.Path]::GetDirectoryName($full)
            $root=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
            if ([IO.Path]::GetFileName($full) -notmatch '^snapshot(?:-[12])?\.json$' -or
                [IO.Path]::GetDirectoryName($parent) -ne $root -or
                [IO.Path]::GetFileName($parent) -notlike 'p1i-fixture-*' -or
                (Test-Path -LiteralPath $full) -or
                -not (Test-Path -LiteralPath $parent -PathType Container) -or
                (Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'P1I_OUTPUT_PATH_OUTSIDE_TEMP_FIXTURE'
            }
            [IO.File]::WriteAllText($full,$json,[Text.UTF8Encoding]::new($false))
            Write-Output 'P1I_SNAPSHOT_UTF8_WRITTEN=True'
        } else {
            Write-Output $json
        }
    }
    exit 0
} catch {
    Write-Output ('P1I_ERROR='+$_.Exception.Message)
    Write-Output 'P1I_NETWORK_MUTATIONS_PERFORMED=False'
    Write-Output 'P1I_RESULT=READ_ONLY_SNAPSHOT_BLOCKED'
    exit 4
}
