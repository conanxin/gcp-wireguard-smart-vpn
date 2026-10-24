<#
Stage C P1F non-mutating Windows PowerShell 5.1 test.
Never passes both live-authorization switches to Run.
Never adds/deletes native Windows routes, starts a watchdog, or launches WG.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$base=$PSScriptRoot
$controller=Join-Path $base 'stage-c-p1f-watchdog-stranded-test-20261024.ps1'
$worker=Join-Path $base 'stage-c-p1f-independent-watchdog-20261024.ps1'
$p1e=Join-Path $base 'stage-c-p1e-testnet-canary-20261024.ps1'
$ps='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$passes=0;$fails=0
function Assert([bool]$ok,[string]$name){
 if($ok){$script:passes++;Write-Output ('PASS_'+$name)}
 else{$script:fails++;Write-Output ('FAIL_'+$name)}
}
function Execute([string]$file,[string[]]$argv){
 $old=$ErrorActionPreference;$ErrorActionPreference='Continue'
 try{
  $out=@(& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $file @argv 2>&1)
  $exitcode=$LASTEXITCODE
 }finally{$ErrorActionPreference=$old}
 return [pscustomobject]@{
  code=[int]$exitcode
  output=(($out|ForEach-Object{[string]$_}) -join [char]10)
 }
}
foreach($p in @($controller,$worker)){
 $tokens=$null;$errors=$null
 [void][System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$tokens,[ref]$errors)
 Assert (@($errors).Count -eq 0) ('AST_ZERO_'+[IO.Path]::GetFileNameWithoutExtension($p))
}
$cont=Get-Content -LiteralPath $controller -Raw -Encoding UTF8
$work=Get-Content -LiteralPath $worker -Raw -Encoding UTF8
Assert ($cont.Contains("198.51.100.77/32") -and $work.Contains("198.51.100.77/32")) 'PREFIX_PINNED_TEST_NET'
Assert ((Get-FileHash -LiteralPath $p1e -Algorithm SHA256).Hash -eq '36427E5BE890785AE37D4A81953CD4FFF7789153B8BF13C6CC6B4264E4ADA738') 'LEGACY_WATCHDOG_SOURCE_PINNED'
$workerHash=(Get-FileHash -LiteralPath $worker -Algorithm SHA256).Hash
Assert ($cont.Contains($workerHash)) 'WORKER_SHA_PINNED_IN_CONTROLLER'
Assert ((@($cont -split [char]10 | Where-Object {$_ -match '^\s*New-NetRoute @args'}).Count -eq 1) -and
        (-not $cont.Contains('Remove-NetRoute')) -and
        (-not $work.Contains('Remove-NetRoute'))) 'ONE_NATIVE_ADD_ONLY_ROLLBACK_DELEGATED_TO_P1E'
$before=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '198.51.100.77/32' -ErrorAction SilentlyContinue)
$check=Execute $controller @('-Mode','CheckOnly')
Assert ($check.code -eq 0 -and $check.output.Contains('P1F_CHECK=PASS')) 'READONLY_CHECKONLY_PASS'
Assert ($check.output.Contains('P1F_REAL_NETWORK_MUTATIONS=NONE_CHECKONLY')) 'READONLY_REPORTS_ZERO_WRITES'
$status=Execute $controller @('-Mode','Status')
Assert ($status.code -eq 0 -and $status.output.Contains('P1F_RESULT=')) 'READONLY_STATUS_AVAILABLE'
$deny=Execute $controller @('-Mode','Run')
Assert ($deny.code -ne 0 -and $deny.output.Contains('BLOCKED_OR_INCOMPLETE')) 'RUN_WITHOUT_TWO_FLAGS_BLOCKED'
$deny2=Execute $controller @('-Mode','Run','-IAmAtThePC')
Assert ($deny2.code -ne 0 -and $deny2.output.Contains('BLOCKED_OR_INCOMPLETE')) 'RUN_WITHOUT_CRASH_SWITCH_BLOCKED'
$deny3=Execute $controller @('-Mode','Run','-SimulateParentCrash')
Assert ($deny3.code -ne 0 -and $deny3.output.Contains('BLOCKED_OR_INCOMPLETE')) 'RUN_WITHOUT_ONSITE_SWITCH_BLOCKED'
$workerDeny=Execute $worker @('-Mode','Worker','-RunId','invalid')
Assert ($workerDeny.code -ne 0 -and $workerDeny.output.Contains('P1F_WORKER_ERROR')) 'WATCHDOG_INVALID_RUNID_DENIED'
$after=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '198.51.100.77/32' -ErrorAction SilentlyContinue)
Assert ($after.Count -eq $before.Count) 'ROUTE_COUNT_UNCHANGED'
$half=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
Assert ($half.Count -eq 0) 'HALF_DEFAULT_ROUTE_COUNT_ZERO'
Write-Output ('P1F_TESTS_PASSED='+$passes)
Write-Output ('P1F_TESTS_FAILED='+$fails)
Write-Output 'P1F_NATIVE_ROUTE_WRITES_EXECUTED=False'
if($fails){exit 2}
exit 0
