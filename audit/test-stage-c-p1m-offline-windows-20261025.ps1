<#
P1M Windows 5.1 safe offline gate.
Runs pure Python synthetic tests and Xray run -test only, no network edits.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$script:Pass=0;$script:Fail=0
function Check([bool]$Ok,[string]$Key){
 if($Ok){Write-Output ('PASS_'+$Key);$script:Pass++}
 else{Write-Output ('FAIL_'+$Key);$script:Fail++}
}
function RouteHash{
 $rows=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop|ForEach-Object{
  "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)|$($_.Store)"
 }|Sort-Object)
 $sha=[Security.Cryptography.SHA256]::Create()
 try{
  return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($rows -join [Environment]::NewLine))))).Replace('-','')
 }finally{$sha.Dispose()}
}
function RunPython([string]$Python,[string[]]$Arguments,[string]$Folder,[string]$Tag){
 $out=Join-Path $Folder ($Tag+'-out.txt')
 $err=Join-Path $Folder ($Tag+'-err.txt')
 $proc=Start-Process -FilePath $Python -ArgumentList $Arguments -PassThru -Wait -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err -ErrorAction Stop
 return [pscustomobject]@{Code=$proc.ExitCode;Out=[string](Get-Content -LiteralPath $out -Raw -Encoding UTF8);Err=[string](Get-Content -LiteralPath $err -Raw -Encoding UTF8)}
}
$py=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'
$tests=Join-Path $PSScriptRoot 'test_stage_c_p1m_offline_userspace_plan.py'
$driver=Join-Path $PSScriptRoot 'stage_c_p1m_offline_userspace_plan.py'
$data=Join-Path (Split-Path -Parent $PSScriptRoot) 'data\cn-ipv4-cidrs.txt'
$tmp=Join-Path $env:TEMP ('p1m-synthetic-only-'+[guid]::NewGuid().ToString('N'))
try{
 $before=RouteHash
 $proxy0=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
 $nrpt0=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wg0=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 $tun0=(Get-NetAdapter -Name 'xray_tun' -ErrorAction SilentlyContinue).Status
 $data0=(Get-FileHash -LiteralPath $data -Algorithm SHA256).Hash
 Check ((Test-Path -LiteralPath $py) -and (Test-Path -LiteralPath $driver) -and (Test-Path -LiteralPath $tests)) 'TOOLS_PRESENT'
 $astErr=$null;$tok=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($PSCommandPath,[ref]$tok,[ref]$astErr)
 Check (@($astErr).Count -eq 0) 'HARNESS_AST_ZERO'
 $banned=@('New-NetRoute','Remove-NetRoute','Set-NetRoute','New-DnsClientNrptRule','Remove-DnsClientNrptRule','Set-ItemProperty','Set-NetIPInterface','Stop-Service','Start-Service','netsh','route.exe')
 $commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true))
 Check (@($commands|Where-Object{$_.GetCommandName() -in $banned}).Count -eq 0) 'HARNESS_NO_MUTATORS'
 [void][IO.Directory]::CreateDirectory($tmp)
 $unit=RunPython $py @('-u',('"' + $tests + '"')) $tmp 'unit'
 Check ($unit.Code -eq 0 -and $unit.Out.Contains('P1M_OFFLINE_TESTS_PASS=35') -and $unit.Out.Contains('P1M_OFFLINE_TESTS_FAIL=0')) 'PYTHON_35_OF_35'
 $contract=RunPython $py @(('"' + $driver + '"'),'--mode','contract') $tmp 'contract'
 $c=$null;if($contract.Code -eq 0){$c=$contract.Out|ConvertFrom-Json}
 Check ($c -and $c.result -eq 'TEMPLATE_CONTRACT_PASS' -and $c.templateIsDeployable -eq $false -and $c.networkMutationsPerformed -eq $false) 'NONDEPLOYABLE_TEMPLATE'
 $xray=@(Get-Process -Name 'xray' -ErrorAction SilentlyContinue|Select-Object -First 1)
 if(-not $xray.Count){throw 'RUNNING_XRAY_REQUIRED'}
 $core=RunPython $py @(('"' + $driver + '"'),'--mode','core-test','--pid',[string]$xray[0].Id) $tmp 'core'
 $report=$null;if($core.Code -eq 0){$report=$core.Out|ConvertFrom-Json}
 Check ($report -and $report.parserExitCode -eq 0 -and $report.configOKMarker -eq $true -and $report.syntaxTestPass -eq $true) 'XRAY_CONFIG_SYNTAX_PASS'
 Check ($report -and $report.assetsFound -eq $true -and $report.geoipSHA256Prefix -and $report.geositeSHA256Prefix) 'GEODATA_AVAILABLE'
 Check ($report -and $report.readUserKeys -eq $false -and $report.readProductionConfig -eq $false -and $report.liveConfigChanged -eq $false -and $report.realWGHandshake -eq $false) 'NO_USER_SECRETS_NO_HANDSHAKE'
 Check ($report -and $report.dnsE2EVerified -eq $false -and $report.wgEndpointLoopProtectionVerified -eq $false -and $report.foreignGcpEgressVerified -eq $false) 'E2E_NOT_PRETENDED'
 $data1=(Get-FileHash -LiteralPath $data -Algorithm SHA256).Hash
 Check ($data0 -eq $data1) 'APNIC_FILE_UNCHANGED'
 $after=RouteHash
 $proxy1=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
 $nrpt1=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wg1=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 $tun1=(Get-NetAdapter -Name 'xray_tun' -ErrorAction SilentlyContinue).Status
 Check ($before -eq $after) 'ROUTE_TABLE_UNCHANGED'
 Check ($proxy0.ProxyEnable -eq $proxy1.ProxyEnable -and $proxy0.ProxyServer -eq $proxy1.ProxyServer -and $nrpt0 -eq $nrpt1) 'NRPT_PROXY_UNCHANGED'
 Check ($wg0 -eq $wg1 -and $tun0 -eq $tun1) 'WG_TUN_UNCHANGED'
 $http=& curl.exe --max-time 10 --proxy 'http://127.0.0.1:7897' -s -o NUL -w '%{http_code}' 'https://www.gstatic.com/generate_204'
 Check ($http -eq '204' -and $LASTEXITCODE -eq 0) 'XRAY_HTTPS_204'
 Write-Output ('P1M_ROUTE_SHA_BEFORE='+$before)
 Write-Output ('P1M_ROUTE_SHA_AFTER='+$after)
 Write-Output ('P1M_GEODATA_AGE_DAYS='+$report.geoipAgeDays+','+$report.geositeAgeDays)
 Write-Output ('P1M_GCP_SERVER_CURRENT=UNVERIFIED_AUTHORIZED_SSH_NOT_AVAILABLE')
 Write-Output ('P1M_WINDOWS_CHECKS_PASSED='+$script:Pass)
 Write-Output ('P1M_WINDOWS_CHECKS_FAILED='+$script:Fail)
 Write-Output 'P1M_NETWORK_MUTATIONS_PERFORMED=False'
 if($script:Fail){exit 2}
 Write-Output 'P1M_RESULT=OFFLINE_WINDOWS_GATE_PASS'
 exit 0
}catch{
 Write-Output ('P1M_ERROR='+$_.Exception.Message)
 Write-Output 'P1M_NETWORK_MUTATIONS_PERFORMED=False'
 Write-Output 'P1M_RESULT=WINDOWS_GATE_BLOCKED'
 exit 4
}finally{
 if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue}
}
