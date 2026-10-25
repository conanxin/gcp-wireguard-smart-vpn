<#
P1K architecture decision: read-only host networking snapshot.
Windows PowerShell 5.1. No elevated token, config reads or network changes.
Only prints a JSON object or short text to standard output.
#>
[CmdletBinding()]
param([ValidateSet('Json','Human')][string]$Mode='Json')
$ErrorActionPreference='Stop'
function Hash-Routes($Routes){
 $lines=@($Routes|ForEach-Object {
  [string]$_.DestinationPrefix+'|'+[string]$_.InterfaceIndex+'|'+
  [string]$_.NextHop+'|'+[string]$_.RouteMetric+'|'+[string]$_.Store
 }|Sort-Object)
 $sha=[Security.Cryptography.SHA256]::Create()
 try{
  $bytes=[Text.Encoding]::UTF8.GetBytes(($lines -join [Environment]::NewLine))
  return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')
 }finally{$sha.Dispose()}
}
try{
 $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop)
 $adapter=Get-NetAdapter -Name 'xray_tun' -ErrorAction SilentlyContinue
 $tunIndex=$null
 if($adapter){$tunIndex=[int]$adapter.InterfaceIndex}
 $tunRoutes=@($routes|Where-Object{
   $adapter -and [int]$_.InterfaceIndex -eq $tunIndex
 })
 $tunDefault=@($tunRoutes|Where-Object{
  $_.DestinationPrefix -eq '0.0.0.0/0'
 })
 $wlanDefaults=@($routes|Where-Object{
  $_.DestinationPrefix -eq '0.0.0.0/0' -and
  $_.InterfaceAlias -eq 'WLAN' -and $_.NextHop -ne '0.0.0.0'
 })
 $proxy=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
 $nrptAll=@(Get-DnsClientNrptRule -ErrorAction Stop)
 $nrptProject=@($nrptAll|Where-Object{
  $_.DisplayName -like 'GCP-WG-SMART-FULLCN-*'
 })
 $wg=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue)
 $xray=@(Get-Process -Name 'xray' -ErrorAction SilentlyContinue)
 $v2=@(Get-Process -Name 'v2rayN' -ErrorAction SilentlyContinue)
 $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
 $half=@($routes|Where-Object{
  $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')
 })
 $targets=[Collections.Generic.List[object]]::new()
 foreach($ip in @('223.5.5.5','1.1.1.1','8.8.8.8')){
  $status='UNKNOWN';$interfaceAlias='';$ifIndex=$null;$prefix=''
  try{
   $result=@(Find-NetRoute -RemoteIPAddress $ip -ErrorAction Stop|
     Where-Object{$_.DestinationPrefix}|Select-Object -First 1)
   if($result.Count -eq 1){
    $status='READ'
    $interfaceAlias=[string]$result[0].InterfaceAlias
    $ifIndex=[int]$result[0].InterfaceIndex
    $prefix=[string]$result[0].DestinationPrefix
   }
  }catch{$status='UNAVAILABLE'}
  $targets.Add([pscustomobject][ordered]@{
   address=$ip
   status=$status
   interfaceAlias=$interfaceAlias
   interfaceIndex=$ifIndex
   selectedPrefix=$prefix
  })
 }
 $source=Join-Path (Split-Path -Parent $PSScriptRoot) 'data\cn-ipv4-cidrs.txt'
 if(-not(Test-Path -LiteralPath $source -PathType Leaf)){throw 'CN_SOURCE_MISSING'}
 $cidrCount=@(Get-Content -LiteralPath $source -Encoding UTF8|
   Where-Object{$_ -and $_.Trim()}).Count
 $meta=Get-Item -LiteralPath $source
 $memTotal=[math]::Round($os.TotalVisibleMemorySize/1MB,2)
 $memFree=[math]::Round($os.FreePhysicalMemory/1MB,2)
 $physicalIndex=$null;$gateway=''
 if($wlanDefaults.Count -eq 1){
  $physicalIndex=[int]$wlanDefaults[0].InterfaceIndex
  $gateway=[string]$wlanDefaults[0].NextHop
 }
 $snapshot=[pscustomobject][ordered]@{
  schema='stage-c-p1k-architecture-inventory-v1'
  observedAt=[DateTimeOffset]::Now.ToString('o')
  mode='READ_ONLY'
  windowsBuild=[int]$os.BuildNumber
  windowsCaption=[string]$os.Caption
  memoryTotalGiB=$memTotal
  memoryFreeGiB=$memFree
  ipv4RouteCount=$routes.Count
  ipv4RouteIdentitySHA256=(Hash-Routes $routes)
  wlanDefaultCount=$wlanDefaults.Count
  wlanIndex=$physicalIndex
  wlanGateway=$gateway
  xrayProcessCount=$xray.Count
  v2rayNProcessCount=$v2.Count
  xrayTunPresent=[bool]$adapter
  xrayTunStatus=$(if($adapter){[string]$adapter.Status}else{'ABSENT'})
  xrayTunIndex=$tunIndex
  xrayTunRouteCount=$tunRoutes.Count
  xrayTunDefaultCount=$tunDefault.Count
  wininetProxyEnable=[int]$proxy.ProxyEnable
  wininetProxyServer=[string]$proxy.ProxyServer
  nrptProjectRules=$nrptProject.Count
  wireGuardTunnelServices=$wg.Count
  halfDefaultRoutes=$half.Count
  cnDatasetCIDRs=$cidrCount
  cnDatasetSHA256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
  cnDatasetAgeDays=[int][math]::Floor(((Get-Date)-$meta.LastWriteTime).TotalDays)
  selectedRouteChecks=$targets.ToArray()
  proposedDirection='USERSPACE_WG_OUTBOUND_IN_EXISTING_CORE_OFFLINE_PILOT'
  proposalImplemented=$false
  nativeCNRouteWriteAuthorized=$false
  nativeDeleteAuthorized=$false
  networkMutationsPerformed=$false
 }
 if($Mode -eq 'Human'){
  Write-Output ('P1K_OS_BUILD='+$snapshot.windowsBuild)
  Write-Output ('P1K_RAM_AVAILABLE_GIB='+$snapshot.memoryFreeGiB)
  Write-Output ('P1K_XRAY_TUN_STATUS='+$snapshot.xrayTunStatus)
  Write-Output ('P1K_XRAY_TUN_DEFAULT_COUNT='+$snapshot.xrayTunDefaultCount)
  Write-Output ('P1K_WLAN_INDEX='+$snapshot.wlanIndex)
  Write-Output ('P1K_CN_DATASET_COUNT='+$snapshot.cnDatasetCIDRs)
  Write-Output ('P1K_PROPOSAL_IMPLEMENTED=False')
  Write-Output ('P1K_NETWORK_MUTATIONS=False')
  Write-Output 'P1K_RESULT=READ_ONLY_INVENTORY_COMPLETE'
 }else{
  ConvertTo-Json -InputObject $snapshot -Depth 7 -Compress
 }
 exit 0
}catch{
 Write-Output ('P1K_ERROR='+$_.Exception.Message)
 Write-Output 'P1K_NETWORK_MUTATIONS=False'
 Write-Output 'P1K_RESULT=READ_ONLY_INVENTORY_BLOCKED'
 exit 4
}
