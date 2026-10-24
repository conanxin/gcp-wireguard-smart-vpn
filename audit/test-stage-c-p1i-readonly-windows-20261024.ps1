<#
P1I reproducible Windows 5.1 read-only audit; no native network writes.
Checks CIM route properties, two independent enumerations, Python 55 tests,
native route set, NRPT, WinINET and WG baseline. Uses disposable temp files.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$script:Pass=0;$script:Fail=0
function Test-Condition([bool]$Ok,[string]$Name){
 if($Ok){Write-Output ('PASS_'+$Name);$script:Pass++}
 else{Write-Output ('FAIL_'+$Name);$script:Fail++}
}
function Route-Hash{
 $rows=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop|ForEach-Object{
  "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)|$($_.Store)"
 }|Sort-Object)
 $sha=[Security.Cryptography.SHA256]::Create()
 try{
  $bytes=[Text.Encoding]::UTF8.GetBytes(($rows -join [Environment]::NewLine))
  return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')
 }finally{$sha.Dispose()}
}
function Run-Python([string]$Python,[string[]]$Arguments,[string]$Tmp,[string]$Tag){
 $out=Join-Path $Tmp ($Tag+'-stdout.txt')
 $err=Join-Path $Tmp ($Tag+'-stderr.txt')
 $proc=Start-Process -FilePath $Python -ArgumentList $Arguments -PassThru -Wait -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err -ErrorAction Stop
 return [pscustomobject]@{
  ExitCode=$proc.ExitCode
  Stdout=(Get-Content -LiteralPath $out -Raw -Encoding UTF8)
  Stderr=(Get-Content -LiteralPath $err -Raw -Encoding UTF8)
 }
}
$psFile=Join-Path $PSScriptRoot 'stage-c-p1i-readonly-cim-20261024.ps1'
$engine=Join-Path $PSScriptRoot 'stage_c_p1i_native_contract.py'
$tests=Join-Path $PSScriptRoot 'test_stage_c_p1i_native_contract.py'
$py=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'
$exe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$tmp=Join-Path $env:TEMP ('p1i-fixture-'+[guid]::NewGuid().ToString('N'))
try{
 $routeBefore=Route-Hash
 $proxyBefore=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
 $nrptBefore=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wgBefore=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($psFile,[ref]$tokens,[ref]$errors)
 Test-Condition (@($errors).Count -eq 0) 'SNAPSHOT_AST_ZERO'
 $banned=@('New-NetRoute','Remove-NetRoute','Set-NetRoute','New-DnsClientNrptRule',
  'Remove-DnsClientNrptRule','Set-DnsClientNrptRule','Set-DnsClientServerAddress',
  'Set-ItemProperty','Enable-NetAdapter','Disable-NetAdapter','Stop-Service',
  'Start-Service','netsh','route.exe','Invoke-Expression')
 $commands=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true))
 Test-Condition (@($commands|Where-Object{$_.GetCommandName() -in $banned}).Count -eq 0) 'SNAPSHOT_HAS_NO_MUTATOR_COMMANDS'
 if(-not(Test-Path -LiteralPath $py -PathType Leaf)){throw 'PYTHON_312_MISSING'}
 [void][IO.Directory]::CreateDirectory($tmp)
 $snapshots=[Collections.Generic.List[object]]::new()
 for($i=1;$i -le 2;$i++){
  $path=Join-Path $tmp ('snapshot-'+$i+'.json')
  $receipt=@(& $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $psFile -Mode Snapshot -OutputPath $path)
  if($LASTEXITCODE -ne 0 -or $receipt -notcontains 'P1I_SNAPSHOT_UTF8_WRITTEN=True'){
   throw ('SNAPSHOT_'+$i+'_FAILED')
  }
  $r=Run-Python $py @(('"' + $engine + '"'),'--snapshot-json',('"' + $path + '"')) $tmp ('inspect-'+$i)
  if($r.ExitCode -ne 0){throw ('INSPECT_'+$i+'_FAILED '+$r.Stdout)}
  $value=$r.Stdout|ConvertFrom-Json
  Test-Condition ($value.result -eq 'READ_ONLY_NATIVE_CIM_INSPECTED' -and $value.storeField -eq 'Store' -and $value.nativeDeleteAuthorized -eq $false) ('NATIVE_CIM_SNAPSHOT_'+$i)
  $snapshots.Add($value)
 }
 Test-Condition ($snapshots[0].routeIdentityDigest -eq $snapshots[1].routeIdentityDigest) 'ROUTE_REENUMERATION_DIGEST_STABLE'
 $unit=Run-Python $py @('-u',('"' + $tests + '"')) $tmp 'tests'
 Test-Condition ($unit.ExitCode -eq 0 -and $unit.Stdout.Contains('P1I_TESTS_PASSED=55') -and $unit.Stdout.Contains('P1I_TESTS_FAILED=0')) 'WINDOWS_PYTHON_55_TESTS'
 $routeAfter=Route-Hash
 $proxyAfter=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
 $nrptAfter=@(Get-DnsClientNrptRule -ErrorAction Stop).Count
 $wgAfter=@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue).Count
 Test-Condition ($routeBefore -eq $routeAfter) 'WINDOWS_NATIVE_ROUTE_SET_UNCHANGED'
 Test-Condition ($nrptBefore -eq $nrptAfter -and $proxyBefore.ProxyEnable -eq $proxyAfter.ProxyEnable -and $proxyBefore.ProxyServer -eq $proxyAfter.ProxyServer) 'NRPT_AND_WININET_UNCHANGED'
 Test-Condition ($wgBefore -eq $wgAfter) 'WIREGUARD_SERVICE_UNCHANGED'
 Write-Output ('P1I_STORE_FIELD='+$snapshots[0].storeField)
 Write-Output ('P1I_POLICY_STORE_PROPERTY_PRESENT='+$snapshots[0].policyStorePropertyExposed)
 Write-Output ('P1I_WINDOWS_ROUTE_SHA_BEFORE='+$routeBefore)
 Write-Output ('P1I_WINDOWS_ROUTE_SHA_AFTER='+$routeAfter)
 Write-Output ('P1I_WINDOWS_CHECKS_PASSED='+$script:Pass)
 Write-Output ('P1I_WINDOWS_CHECKS_FAILED='+$script:Fail)
 Write-Output 'P1I_NATIVE_NETWORK_WRITES_EXECUTED=False'
 if($script:Fail){exit 2}
 Write-Output 'P1I_RESULT=READ_ONLY_WINDOWS_GATE_PASS'
 exit 0
}catch{
 Write-Output ('P1I_ERROR='+$_.Exception.Message)
 Write-Output 'P1I_NATIVE_NETWORK_WRITES_EXECUTED=False'
 Write-Output 'P1I_RESULT=READ_ONLY_WINDOWS_GATE_BLOCKED'
 exit 4
}finally{
 if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue}
}
