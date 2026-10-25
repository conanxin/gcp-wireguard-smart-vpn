<#
P1K read-only Windows architecture inventory regression.
No native network modifications; all checks use getters and safe HTTPS204 read.
No administrator required.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$script:Pass=0;$script:Fail=0
function Check([bool]$Ok,[string]$Key){
 if($Ok){Write-Output ('PASS_'+$Key);$script:Pass++}
 else{Write-Output ('FAIL_'+$Key);$script:Fail++}
}
function RouteSHA {
 $r=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop|ForEach-Object{
  "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)|$($_.Store)"
 }|Sort-Object)
 $h=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes(($r -join [Environment]::NewLine))))).Replace('-','')}
 finally{$h.Dispose()}
}
$scriptFile=Join-Path $PSScriptRoot 'stage-c-p1k-readonly-inventory-20261025.ps1'
$ps='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
try{
 $routeBefore=RouteSHA
 $proxyBefore=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
 $nrptBefore=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wgBefore=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 $astErr=$null;$t=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($scriptFile,[ref]$t,[ref]$astErr)
 Check (@($astErr).Count -eq 0) 'INVENTORY_AST_ZERO'
 $forbidden=@('New-NetRoute','Remove-NetRoute','Set-NetRoute','New-DnsClientNrptRule',
  'Remove-DnsClientNrptRule','Set-DnsClientNrptRule','Set-DnsClientServerAddress',
  'Set-ItemProperty','Set-NetIPInterface','Disable-NetAdapter','Enable-NetAdapter',
  'Stop-Service','Start-Service','netsh','route.exe','Invoke-Expression')
 $commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true))
 Check (@($commands|Where-Object{$_.GetCommandName() -in $forbidden}).Count -eq 0) 'INVENTORY_NO_NATIVE_MUTATORS'
 $raw1=@(& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scriptFile -Mode Json)
 $exit1=$LASTEXITCODE
 $raw2=@(& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scriptFile -Mode Json)
 $exit2=$LASTEXITCODE
 $a=$null;$b=$null
 try{$a=($raw1 -join '')|ConvertFrom-Json -ErrorAction Stop
     $b=($raw2 -join '')|ConvertFrom-Json -ErrorAction Stop}catch{}
 Check ($exit1 -eq 0 -and $exit2 -eq 0 -and $a -and $b) 'TWO_JSON_SNAPSHOTS_PARSE'
 if(-not $a -or -not $b){throw 'SNAPSHOT_UNAVAILABLE'}
 Check ($a.schema -eq 'stage-c-p1k-architecture-inventory-v1' -and
        $a.mode -eq 'READ_ONLY') 'SCHEMA_AND_MODE'
 Check ($a.proposalImplemented -eq $false -and
        $a.nativeCNRouteWriteAuthorized -eq $false -and
        $a.nativeDeleteAuthorized -eq $false -and
        $a.networkMutationsPerformed -eq $false) 'NO_LIVE_AUTHORIZATION'
 Check ($a.xrayTunPresent -and $a.xrayTunDefaultCount -ge 1 -and
        $a.xrayTunStatus -eq 'Up') 'XRAY_TUN_DEFAULT_PRESENT'
 Check ($a.v2rayNProcessCount -ge 1 -and
        $a.xrayProcessCount -ge 1) 'PRIMARY_PROXY_PROCESSES'
 Check ($a.cnDatasetCIDRs -eq 5494 -and $a.cnDatasetSHA256 -eq $b.cnDatasetSHA256) 'CN_DATA_FROZEN'
 Check ($a.ipv4RouteIdentitySHA256 -eq $b.ipv4RouteIdentitySHA256) 'REPEATED_ROUTE_ENUMERATION_STABLE'
 $routeAfter=RouteSHA
 $proxyAfter=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
 $nrptAfter=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wgAfter=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 Check ($routeBefore -eq $routeAfter) 'NATIVE_ROUTE_HASH_UNCHANGED'
 Check ($proxyBefore.ProxyEnable -eq $proxyAfter.ProxyEnable -and
        $proxyBefore.ProxyServer -eq $proxyAfter.ProxyServer -and
        $nrptBefore -eq $nrptAfter) 'NRPT_AND_WININET_UNCHANGED'
 Check ($wgBefore -eq $wgAfter) 'WIREGUARD_SERVICE_UNCHANGED'
 $xray=@(Get-Process -Name 'xray' -ErrorAction SilentlyContinue)
 $http=& curl.exe --max-time 12 --proxy 'http://127.0.0.1:7897' -s -o NUL -w '%{http_code}' 'https://www.gstatic.com/generate_204'
 Check ($xray.Count -gt 0 -and $http -eq '204' -and $LASTEXITCODE -eq 0) 'XRAY_HTTPS_204'
 Write-Output ('P1K_WINDOWS_BUILD='+$a.windowsBuild)
 Write-Output ('P1K_TUN='+$a.xrayTunStatus+'|DEFAULT='+$a.xrayTunDefaultCount)
 Write-Output ('P1K_WLAN_IFINDEX='+$a.wlanIndex)
 Write-Output ('P1K_MEMORY_GIB_FREE='+$a.memoryFreeGiB)
 Write-Output ('P1K_ROUTE_SHA_BEFORE='+$routeBefore)
 Write-Output ('P1K_ROUTE_SHA_AFTER='+$routeAfter)
 Write-Output ('P1K_CHECKS_PASSED='+$script:Pass)
 Write-Output ('P1K_CHECKS_FAILED='+$script:Fail)
 Write-Output 'P1K_NETWORK_MUTATIONS_PERFORMED=False'
 if($script:Fail){exit 2}
 Write-Output 'P1K_RESULT=ARCHITECTURE_READ_ONLY_GATE_PASS'
 exit 0
}catch{
 Write-Output ('P1K_ERROR='+$_.Exception.Message)
 Write-Output 'P1K_NETWORK_MUTATIONS_PERFORMED=False'
 Write-Output 'P1K_RESULT=ARCHITECTURE_GATE_BLOCKED'
 exit 4
}
