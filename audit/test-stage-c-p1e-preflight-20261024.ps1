<#
Stage C P1E NON-MUTATING smoke test for the one-route TEST-NET canary.
Calls only CheckOnly and intentionally invalid/blocked modes.
Never calls Run with IAmAtThePC, and never touches Windows routes.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$driver=Join-Path $PSScriptRoot 'stage-c-p1e-testnet-canary-20261024.ps1'
$ps='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$prefix='198.51.100.77/32'
$passes=0;$fails=0
function Check([bool]$ok,[string]$title){
 if($ok){Write-Output ('PASS_'+$title);$script:passes++}
 else{Write-Output ('FAIL_'+$title);$script:fails++}
}
function Call([string[]]$flags){
 $errorActionPreference='Continue'
 $out=@(& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $driver @flags 2>&1)
 return [pscustomobject]@{text=(($out|ForEach-Object{[string]$_}) -join [char]10);exit=[int]$LASTEXITCODE}
}
$preRoute=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue)
$t=$null;$errors=$null
[void][System.Management.Automation.Language.Parser]::ParseFile($driver,[ref]$t,[ref]$errors)
Check (@($errors).Count -eq 0) 'AST_ZERO'
Check ($preRoute.Count -eq 0) 'TESTNET_NOT_PREEXISTING'
$test=Call @('-Mode','CheckOnly')
Check ($test.exit -eq 0 -and $test.text.Contains('P1E_PREFLIGHT=PASS_NEEDS_ELEVATED_LOCAL_EXECUTION')) 'CHECKONLY_PASS'
Check ($test.text.Contains('P1E_NETWORK_WRITES=NOT_ATTEMPTED')) 'CHECKONLY_NO_NETWORK_WRITES'
$denied=Call @('-Mode','Run')
Check ($denied.exit -eq 2 -and
       ($denied.text.Contains('BLOCKED_IN_PERSON_FLAG_REQUIRED') -or
        $denied.text.Contains('BLOCKED_NOT_ELEVATED'))) 'LIVE_WITHOUT_IN_PERSON_SWITCH_DENIED'
$rollbackBad=Call @('-Mode','Rollback','-RunId','invalid_identifier')
Check ($rollbackBad.exit -ne 0) 'INVALID_ROLLBACK_RUNID_DENIED'
$watchBad=Call @('-Mode','Watchdog','-RunId','invalid_identifier')
Check ($watchBad.exit -ne 0) 'INVALID_WATCHDOG_RUNID_DENIED'
$afterRoute=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue)
Check ($afterRoute.Count -eq $preRoute.Count) 'TARGET_ROUTE_UNCHANGED'
$half=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
Check ($half.Count -eq 0) 'NO_WG_HALF_DEFAULT_ROUTES'
Write-Output ('P1E_SMOKE_PASSED='+$passes)
Write-Output ('P1E_SMOKE_FAILED='+$fails)
Write-Output 'REAL_NETWORK_MUTATIONS_PERFORMED=False'
if($fails){exit 2}
exit 0
