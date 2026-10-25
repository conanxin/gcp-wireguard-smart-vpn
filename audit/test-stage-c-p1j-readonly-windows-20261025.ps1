<#
P1J Windows PowerShell 5.1 read-only gate.
No Windows route writes, no NRPT/WinINET/WG changes.
Writes only disposable stdout/stderr files beneath %TEMP%\p1j-fixture-*.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$script:Passed=0
$script:Failed=0
function Check([bool]$Condition,[string]$Name) {
 if($Condition){Write-Output ('PASS_'+$Name);$script:Passed++}
 else{Write-Output ('FAIL_'+$Name);$script:Failed++}
}
function RouteHash {
 $r=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop|ForEach-Object{
  "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)|$($_.Store)"
 }|Sort-Object)
 $h=[Security.Cryptography.SHA256]::Create()
 try{
  $bytes=[Text.Encoding]::UTF8.GetBytes(($r -join [Environment]::NewLine))
  return ([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','')
 }finally{$h.Dispose()}
}
function HalfRoutes {
 return (@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue).Count+@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '128.0.0.0/1' -ErrorAction SilentlyContinue).Count)
}
function RunPython([string]$Python,[string[]]$Arguments,[string]$Folder,[string]$Label){
 $out=Join-Path $Folder ($Label+'-stdout.txt')
 $err=Join-Path $Folder ($Label+'-stderr.txt')
 $p=Start-Process -FilePath $Python -ArgumentList $Arguments -PassThru -Wait -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err -ErrorAction Stop
 return [pscustomobject]@{
  Code=[int]$p.ExitCode
  Out=[string](Get-Content -LiteralPath $out -Raw -Encoding UTF8)
  Err=[string](Get-Content -LiteralPath $err -Raw -Encoding UTF8)
 }
}
$py=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'
$test=Join-Path $PSScriptRoot 'test_stage_c_p1j_native_race_model.py'
$model=Join-Path $PSScriptRoot 'stage_c_p1j_native_race_model.py'
$data=Join-Path (Split-Path -Parent $PSScriptRoot) 'data\cn-ipv4-cidrs.txt'
$tmp=Join-Path $env:TEMP ('p1j-fixture-'+[guid]::NewGuid().ToString('N'))
try{
 $before=RouteHash
 $proxyBefore=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
 $nrptBefore=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wgBefore=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 $halfBefore=HalfRoutes
 $sourceHashBefore=(Get-FileHash -LiteralPath $data -Algorithm SHA256).Hash
 Check ((Test-Path -LiteralPath $py -PathType Leaf) -and (Test-Path -LiteralPath $test -PathType Leaf) -and (Test-Path -LiteralPath $model -PathType Leaf)) 'PYTHON_AND_MODEL_AVAILABLE'
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($PSCommandPath,[ref]$tokens,[ref]$errors)
 Check (@($errors).Count -eq 0) 'WINDOWS_HARNESS_AST_ZERO'
 $banned=@('New-NetRoute','Remove-NetRoute','Set-NetRoute','New-DnsClientNrptRule','Remove-DnsClientNrptRule','Set-DnsClientNrptRule','Set-DnsClientServerAddress','Set-ItemProperty','Enable-NetAdapter','Disable-NetAdapter','Stop-Service','Start-Service','netsh','route.exe','Invoke-Expression')
 $commands=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true))
 Check (@($commands|Where-Object{$_.GetCommandName() -in $banned}).Count -eq 0) 'NO_NETWORK_MUTATOR_COMMANDS'
 [void][IO.Directory]::CreateDirectory($tmp)
 $unit=RunPython $py @('-u',('"' + $test + '"')) $tmp 'unit'
 Check ($unit.Code -eq 0 -and $unit.Out.Contains('P1J_TESTS_PASSED=99') -and $unit.Out.Contains('P1J_TESTS_FAILED=0')) 'WINDOWS_99_TESTS_PASS'
 $matrix=RunPython $py @(('"' + $model + '"'),'--matrix') $tmp 'matrix'
 $matrixReport=$null
 if($matrix.Code -eq 0){$matrixReport=$matrix.Out|ConvertFrom-Json -ErrorAction Stop}
 Check ($matrixReport -and $matrixReport.cases -eq 44 -and $matrixReport.allObservablePairsEquivalent -eq $true -and $matrixReport.unsafeNativeDeleteApprovals -eq 0 -and $matrixReport.nativeDeleteAuthorized -eq $false) 'RACE_WINDOWS_44_FAIL_CLOSED'
 $corpus=RunPython $py @(('"' + $model + '"'),'--corpus',('"' + $data + '"')) $tmp 'corpus'
 $corpusReport=$null
 if($corpus.Code -eq 0){$corpusReport=$corpus.Out|ConvertFrom-Json -ErrorAction Stop}
 Check ($corpusReport -and $corpusReport.sourceCount -eq 5494 -and $corpusReport.batchCount -eq 11 -and $corpusReport.blockedWitnesses -eq 1 -and $corpusReport.reviewOnlyWitnesses -eq 5493 -and $corpusReport.nativeDeleteAuthorized -eq $false) 'CN_CORPUS_5494_EVIDENCE'
 $sourceHashAfter=(Get-FileHash -LiteralPath $data -Algorithm SHA256).Hash
 Check ($sourceHashBefore -eq $sourceHashAfter) 'FROZEN_CIDR_SOURCE_UNCHANGED'
 $after=RouteHash
 $proxyAfter=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
 $nrptAfter=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wgAfter=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 $halfAfter=HalfRoutes
 Check ($before -eq $after) 'NATIVE_ROUTE_TABLE_UNCHANGED'
 Check ($proxyBefore.ProxyEnable -eq $proxyAfter.ProxyEnable -and $proxyBefore.ProxyServer -eq $proxyAfter.ProxyServer -and $nrptBefore -eq $nrptAfter) 'WININET_AND_NRPT_UNCHANGED'
 Check ($wgBefore -eq $wgAfter -and $halfBefore -eq $halfAfter) 'WG_AND_HALF_DEFAULT_UNCHANGED'
 $testnet=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '198.51.100.77/32' -ErrorAction SilentlyContinue)
 Check ($testnet.Count -eq 0) 'NO_TESTNET_ROUTE_RESIDUE'
 $xray=@(Get-Process -Name 'xray' -ErrorAction SilentlyContinue)
 $https=& curl.exe --max-time 12 --proxy 'http://127.0.0.1:7897' -s -o NUL -w '%{http_code}' 'https://www.gstatic.com/generate_204'
 $curlExit=$LASTEXITCODE
 Check ($xray.Count -ge 1 -and $https -eq '204' -and $curlExit -eq 0) 'XRAY_HTTPS_204'
 Write-Output ('P1J_ROUTE_SHA_BEFORE='+$before)
 Write-Output ('P1J_ROUTE_SHA_AFTER='+$after)
 Write-Output ('P1J_NRPT_RULES='+$nrptAfter)
 Write-Output ('P1J_XRAY_PROCESS_COUNT='+$xray.Count)
 Write-Output ('P1J_CHECKS_PASSED='+$script:Passed)
 Write-Output ('P1J_CHECKS_FAILED='+$script:Failed)
 Write-Output 'P1J_NATIVE_NETWORK_WRITES_EXECUTED=False'
 if($script:Failed -gt 0){exit 2}
 Write-Output 'P1J_RESULT=READ_ONLY_WINDOWS_GATE_PASS'
 exit 0
}catch{
 Write-Output ('P1J_ERROR='+$_.Exception.Message)
 Write-Output 'P1J_NATIVE_NETWORK_WRITES_EXECUTED=False'
 Write-Output 'P1J_RESULT=READ_ONLY_WINDOWS_GATE_BLOCKED'
 exit 4
}finally{
 if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue}
}
