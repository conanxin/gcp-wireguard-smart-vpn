<#
Stage C P1N-0: Windows PowerShell 5.1 READ-ONLY pre-live admission check.

This script is NOT the P1N live test and deliberately cannot approve
starting a WireGuard peer. It checks existing host paths and runs only
Python offline/ephemeral synthetic Xray run -test with ZERO listeners.
It never loads real GCP/private WG keys or v2rayN production configuration.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$script:Pass=0;$script:Fail=0
function Verify([bool]$Ok,[string]$Name){
 if($Ok){Write-Output ('PASS_'+$Name);$script:Pass++}
 else{Write-Output ('FAIL_'+$Name);$script:Fail++}
}
function RouteHash {
 $r=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop|ForEach-Object{
  "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)|$($_.Store)"
 }|Sort-Object)
 $h=[Security.Cryptography.SHA256]::Create()
 try {
  return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes(($r -join [Environment]::NewLine))))).Replace('-','')
 }finally{$h.Dispose()}
}
function LaunchPython([string]$Python,[string[]]$Arguments,[string]$Folder,[string]$Name){
 $o=Join-Path $Folder ($Name+'-stdout.txt')
 $e=Join-Path $Folder ($Name+'-stderr.txt')
 $p=Start-Process -FilePath $Python -ArgumentList $Arguments -PassThru -Wait -NoNewWindow -RedirectStandardOutput $o -RedirectStandardError $e -ErrorAction Stop
 return [pscustomobject]@{
  ExitCode=$p.ExitCode
  Stdout=[string](Get-Content -LiteralPath $o -Raw -Encoding UTF8)
  Stderr=[string](Get-Content -LiteralPath $e -Raw -Encoding UTF8)
 }
}
$py=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'
$unit=Join-Path $PSScriptRoot 'test_stage_c_p1n0_interface_bind_probe.py'
$engine=Join-Path $PSScriptRoot 'stage_c_p1n0_interface_bind_probe.py'
$tmp=Join-Path $env:TEMP ('p1n0-no-network-'+[guid]::NewGuid().ToString('N'))
try {
 $before=RouteHash
 $proxyBefore=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
 $nrptBefore=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wgBefore=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 $tunBefore=(Get-NetAdapter -Name 'xray_tun' -ErrorAction SilentlyContinue).Status
 $wlan=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop|
   Where-Object{$_.InterfaceAlias -eq 'WLAN' -and $_.NextHop -ne '0.0.0.0'})
 $documentationTarget='192.0.2.1'
 $chosen=@(Find-NetRoute -RemoteIPAddress $documentationTarget -ErrorAction Stop|
   Where-Object{$_.DestinationPrefix}|Select-Object -First 1)
 Verify ((Test-Path -LiteralPath $py -PathType Leaf) -and
   (Test-Path -LiteralPath $unit -PathType Leaf) -and
   (Test-Path -LiteralPath $engine -PathType Leaf)) 'OFFLINE_TOOLS_PRESENT'
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($PSCommandPath,[ref]$tokens,[ref]$errors)
 Verify (@($errors).Count -eq 0) 'PREFLIGHT_AST_ZERO'
 $banned=@('New-NetRoute','Remove-NetRoute','Set-NetRoute',
   'New-DnsClientNrptRule','Remove-DnsClientNrptRule','Set-DnsClientServerAddress',
   'Set-ItemProperty','Set-NetIPInterface','Disable-NetAdapter','Enable-NetAdapter',
   'Stop-Service','Start-Service','netsh','route.exe','Invoke-Expression')
 $commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true))
 Verify (@($commands|Where-Object{$_.GetCommandName() -in $banned}).Count -eq 0) 'NO_NATIVE_NETWORK_MUTATOR_COMMANDS'
 Verify ($wlan.Count -eq 1) 'ONE_PHYSICAL_WLAN_DEFAULT'
 Verify ($chosen.Count -eq 1) 'DOCUMENTATION_ROUTE_OBSERVABLE'
 $xray=@(Get-Process -Name 'xray' -ErrorAction SilentlyContinue|Select-Object -First 1)
 Verify ($xray.Count -eq 1 -and $tunBefore -eq 'Up') 'EXISTING_XRAY_TUN_HEALTHY'
 [void][IO.Directory]::CreateDirectory($tmp)
 $unitResult=LaunchPython $py @('-u',('"' + $unit + '"')) $tmp 'unit'
 Verify ($unitResult.ExitCode -eq 0 -and
   $unitResult.Stdout.Contains('P1N0_REGRESSIONS_PASS=25') -and
   $unitResult.Stdout.Contains('P1N0_REGRESSIONS_FAIL=0')) 'PYTHON_25_REGRESSIONS_PASS'
 if($xray.Count -ne 1){throw 'NO_VERIFIED_XRAY_PROCESS'}
 $core=LaunchPython $py @(('"' + $engine + '"'),'--mode','core-test','--pid',[string]$xray[0].Id) $tmp 'core'
 $report=$null
 if($core.ExitCode -eq 0){$report=$core.Stdout|ConvertFrom-Json -ErrorAction Stop}
 Verify ($report -and $report.allSyntaxParsed -eq $true -and
   $report.wlanBindSyntax.syntaxParsed -eq $true -and
   $report.baseSyntax.syntaxParsed -eq $true) 'WG_SOCKOPT_WLAN_SYNTAX_ACCEPTED'
 Verify ($report -and $report.wireguardOuterUDPBypassedTunProven -eq $false -and
   $report.liveStartAuthorized -eq $false -and $report.realClientSecretsRead -eq $false) 'LIVE_PROOF_NOT_PRETENDED'
 $after=RouteHash
 $proxyAfter=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
 $nrptAfter=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wgAfter=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 $tunAfter=(Get-NetAdapter -Name 'xray_tun' -ErrorAction SilentlyContinue).Status
 Verify ($before -eq $after) 'NATIVE_IPV4_ROUTE_HASH_UNCHANGED'
 Verify ($proxyBefore.ProxyEnable -eq $proxyAfter.ProxyEnable -and
   $proxyBefore.ProxyServer -eq $proxyAfter.ProxyServer -and
   $nrptBefore -eq $nrptAfter) 'WININET_NRPT_UNCHANGED'
 Verify ($wgBefore -eq $wgAfter -and $tunBefore -eq $tunAfter) 'WG_TUN_STATUS_UNCHANGED'
 $https=& curl.exe --max-time 12 --proxy 'http://127.0.0.1:7897' -s -o NUL -w '%{http_code}' 'https://www.gstatic.com/generate_204'
 Verify ($https -eq '204' -and $LASTEXITCODE -eq 0) 'XRAY_HTTPS_204'
 Write-Output ('P1N0_OBSERVED_AT='+(Get-Date -Format o))
 Write-Output ('P1N0_WLAN_INDEX='+$(if($wlan.Count -eq 1){$wlan[0].InterfaceIndex}else{'AMBIGUOUS'}))
 Write-Output ('P1N0_DOCUMENTATION_TARGET_NATIVE_INTERFACE='+$(if($chosen.Count -eq 1){$chosen[0].InterfaceAlias}else{'UNKNOWN'}))
 Write-Output ('P1N0_XRAY_OUTER_UDP_BOUND_TO_WLAN_AT_RUNTIME=NOT_VERIFIED')
 Write-Output ('P1N0_GCP_SERVER_CURRENT=UNVERIFIED')
 Write-Output ('P1N0_DNS_SPLIT_E2E=NOT_VERIFIED')
 Write-Output ('P1N0_REAL_LIVE_TEST_AUTHORIZED=False')
 Write-Output ('P1N0_ROUTE_SHA_BEFORE='+$before)
 Write-Output ('P1N0_ROUTE_SHA_AFTER='+$after)
 Write-Output ('P1N0_CHECKS_PASSED='+$script:Pass)
 Write-Output ('P1N0_CHECKS_FAILED='+$script:Fail)
 Write-Output 'P1N0_NETWORK_MUTATIONS_PERFORMED=False'
 if($script:Fail -gt 0){exit 2}
 Write-Output 'P1N0_RESULT=READ_ONLY_EVIDENCE_PASS_LIVE_BLOCKED'
 exit 0
}catch{
 Write-Output ('P1N0_ERROR='+$_.Exception.Message)
 Write-Output 'P1N0_NETWORK_MUTATIONS_PERFORMED=False'
 Write-Output 'P1N0_RESULT=READ_ONLY_GATE_BLOCKED'
 exit 4
}finally {
 if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue}
}
