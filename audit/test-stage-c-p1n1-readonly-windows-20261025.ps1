<#
P1N-1 Windows PowerShell 5.1 read-only integration-contract gate.

Reads only non-secret structural fields from v2rayN's generated runtime JSON,
then runs Xray run-test against synthetic configs. It does not print production
config values, start a server, create a TUN, open WG UDP, or modify network state.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$script:Pass=0;$script:Fail=0
function Check([bool]$Ok,[string]$Name){
 if($Ok){Write-Output ('PASS_'+$Name);$script:Pass++}
 else{Write-Output ('FAIL_'+$Name);$script:Fail++}
}
function RouteHash{
 $rows=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop|ForEach-Object{
  "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)|$($_.Store)"
 }|Sort-Object)
 $sha=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($rows -join [Environment]::NewLine))))).Replace('-','')}
 finally{$sha.Dispose()}
}
function RunPython([string]$Python,[string[]]$Arguments,[string]$Folder,[string]$Name){
 $o=Join-Path $Folder ($Name+'-stdout.txt')
 $e=Join-Path $Folder ($Name+'-stderr.txt')
 $proc=Start-Process -FilePath $Python -ArgumentList $Arguments -PassThru -Wait -NoNewWindow -RedirectStandardOutput $o -RedirectStandardError $e -ErrorAction Stop
 return [pscustomobject]@{
  ExitCode=[int]$proc.ExitCode
  Stdout=[string](Get-Content -LiteralPath $o -Raw -Encoding UTF8)
  Stderr=[string](Get-Content -LiteralPath $e -Raw -Encoding UTF8)
 }
}
$py=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'
$tests=Join-Path $PSScriptRoot 'test_stage_c_p1n1_tun_wg_contract.py'
$engine=Join-Path $PSScriptRoot 'stage_c_p1n1_tun_wg_contract.py'
$data=Join-Path (Split-Path -Parent $PSScriptRoot) 'data\cn-ipv4-cidrs.txt'
$tmp=Join-Path $env:TEMP ('p1n1-synthetic-only-'+[guid]::NewGuid().ToString('N'))
try{
 $before=RouteHash
 $proxyBefore=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
 $nrptBefore=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wgBefore=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 $tunBefore=(Get-NetAdapter -Name 'xray_tun' -ErrorAction SilentlyContinue).Status
 $dataBefore=(Get-FileHash -LiteralPath $data -Algorithm SHA256).Hash
 Check ((Test-Path -LiteralPath $py -PathType Leaf) -and
        (Test-Path -LiteralPath $tests -PathType Leaf) -and
        (Test-Path -LiteralPath $engine -PathType Leaf)) 'TOOLS_AVAILABLE'
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($PSCommandPath,[ref]$tokens,[ref]$errors)
 Check (@($errors).Count -eq 0) 'HARNESS_AST_ZERO'
 $banned=@('New-NetRoute','Remove-NetRoute','Set-NetRoute','New-DnsClientNrptRule',
  'Remove-DnsClientNrptRule','Set-DnsClientServerAddress','Set-ItemProperty',
  'Set-NetIPInterface','Enable-NetAdapter','Disable-NetAdapter','Start-Service',
  'Stop-Service','netsh','route.exe','Invoke-Expression')
 $commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true))
 Check (@($commands|Where-Object{$_.GetCommandName() -in $banned}).Count -eq 0) 'NO_NETWORK_MUTATOR_COMMANDS'
 [void][IO.Directory]::CreateDirectory($tmp)
 $unit=RunPython $py @('-u',('"' + $tests + '"')) $tmp 'unit'
 Check ($unit.ExitCode -eq 0 -and
        $unit.Stdout.Contains('P1N1_REGRESSIONS_PASS=36') -and
        $unit.Stdout.Contains('P1N1_REGRESSIONS_FAIL=0')) 'PYTHON_36_TESTS_PASS'
 $xray=@(Get-Process -Name 'xray' -ErrorAction SilentlyContinue|Select-Object -First 1)
 $v2=@(Get-Process -Name 'v2rayN' -ErrorAction SilentlyContinue|Select-Object -First 1)
 if($xray.Count -ne 1 -or $v2.Count -ne 1){throw 'CURRENT_XRAY_V2RAYN_PROCESSES_REQUIRED'}
 $core=RunPython $py @(('"' + $engine + '"'),'--mode','core-test',
        '--xray-pid',[string]$xray[0].Id,'--v2rayn-pid',[string]$v2[0].Id) $tmp 'core'
 $report=$null
 if($core.ExitCode -eq 0){$report=$core.Stdout|ConvertFrom-Json -ErrorAction Stop}
 Check ($report -and $report.runtimeContractPass -eq $true -and
        $report.result -eq 'CURRENT_TUN_CONTRACT_AND_SYNTHETIC_WG_PARSED') 'CURRENT_RUNTIME_TUN_CONTRACT'
 Check ($report -and $report.runtime.currentXrayVersion -eq '26.10.21' -and
        $report.runtime.currentTunInboundCount -eq 1 -and
        $report.runtime.currentTunNameExpected -eq $true) 'RUNNING_CORE_AND_TUN_MATCH'
 Check ($report -and $report.runtime.currentAutoOutboundsInterface -eq 'auto' -and
        $report.runtime.currentIPv4DefaultIntoTun -eq $true) 'CURRENT_AUTO_OUTBOUND_INTERFACE'
 Check ($report -and $report.runtime.currentWfpDNSBlockEnabled -eq $true -and
        $report.runtime.currentWfpMisconfigTunBlockEnabled -eq $true) 'CURRENT_WFP_DNS_MISCONFIG_GUARDS'
 Check ($report -and $report.runtime.currentWireguardOutboundCount -eq 0) 'PRODUCTION_RUNTIME_HAS_NO_WG_ADDED'
 Check ($report -and $report.allVariantsParsed -eq $true -and
        $report.variants.auto_inherited.syntaxParsed -eq $true) 'WG_INHERITED_AUTO_BIND_CONFIG_PARSED'
 Check ($report -and $report.variants.auto_with_explicit_wlan_override.syntaxParsed -eq $true -and
        $report.variants.implicit_auto_with_explicit_wlan.syntaxParsed -eq $true) 'EXPLICIT_WLAN_VARIANTS_PARSED'
 Check ($report -and $report.variants.implicit_auto_without_manual_override.syntaxParsed -eq $true) 'IMPLICIT_AUTO_VARIANT_PARSED'
 Check ($report -and $report.actualOuterUdpBypassedTunProven -eq $false -and
        $report.actualGcpHandshakeProven -eq $false -and
        $report.liveStartAuthorized -eq $false) 'RUNTIME_SOCKET_PROOF_NOT_PRETENDED'
 Check ($report -and $report.runtime.productionConfigValuesPrinted -eq $false -and
        $report.runtime.productionConfigModified -eq $false -and
        $report.nativeNetworkMutationsPerformed -eq $false) 'PRODUCTION_CONFIG_NOT_EXPOSED_OR_MODIFIED'
 $dataAfter=(Get-FileHash -LiteralPath $data -Algorithm SHA256).Hash
 Check ($dataBefore -eq $dataAfter) 'CN_DATASET_UNCHANGED'
 $after=RouteHash
 $proxyAfter=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
 $nrptAfter=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wgAfter=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 $tunAfter=(Get-NetAdapter -Name 'xray_tun' -ErrorAction SilentlyContinue).Status
 Check ($before -eq $after) 'NATIVE_IPV4_ROUTE_SHA_UNCHANGED'
 Check ($proxyBefore.ProxyEnable -eq $proxyAfter.ProxyEnable -and
        $proxyBefore.ProxyServer -eq $proxyAfter.ProxyServer -and
        $nrptBefore -eq $nrptAfter) 'WININET_AND_NRPT_UNCHANGED'
 Check ($wgBefore -eq $wgAfter -and $tunBefore -eq $tunAfter) 'WG_AND_TUN_UNCHANGED'
 $https=& curl.exe --max-time 12 --proxy 'http://127.0.0.1:7897' -s -o NUL -w '%{http_code}' 'https://www.gstatic.com/generate_204'
 Check ($https -eq '204' -and $LASTEXITCODE -eq 0) 'EXISTING_XRAY_HTTPS_204'
 Write-Output ('P1N1_ROUTE_SHA_BEFORE='+$before)
 Write-Output ('P1N1_ROUTE_SHA_AFTER='+$after)
 Write-Output ('P1N1_CURRENT_AUTO_OUTBOUNDS_INTERFACE='+$report.runtime.currentAutoOutboundsInterface)
 Write-Output ('P1N1_CURRENT_WFP_GUARDS=dns,misconfigtun')
 Write-Output ('P1N1_GCP_HANDSHAKE=NOT_RUN')
 Write-Output ('P1N1_OUTER_UDP_BYPASS=NOT_PROVEN')
 Write-Output ('P1N1_CHECKS_PASSED='+$script:Pass)
 Write-Output ('P1N1_CHECKS_FAILED='+$script:Fail)
 Write-Output 'P1N1_NETWORK_MUTATIONS_PERFORMED=False'
 if($script:Fail){exit 2}
 Write-Output 'P1N1_RESULT=READ_ONLY_INTEGRATION_CONTRACT_PASS_LIVE_BLOCKED'
 exit 0
}catch{
 Write-Output ('P1N1_ERROR='+$_.Exception.Message)
 Write-Output 'P1N1_NETWORK_MUTATIONS_PERFORMED=False'
 Write-Output 'P1N1_RESULT=READ_ONLY_GATE_BLOCKED'
 exit 4
}finally{
 if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue}
}
