<#
P1F independent 120-second one-shot watchdog for a FIXED TEST-NET /32.
Spawned only by the elevated P1F controller after a saved P1E-compatible
run-scoped INTENT manifest. Does not install WireGuard or change
WinINET, NRPT, DNS, xray, GCP or the default route.

The only native route DELETE is performed through the previously tested
P1E fixed-route Rollback -RunId. The worker records whether the exact
native route WAS PRESENT at deadline and was REMOVED by this child.
Never claim a stranded-route cleanup PASS if the route was already absent.
#>
[CmdletBinding()]
param(
 [ValidateSet('Worker')][string]$Mode='Worker',
 [string]$RunId='',
 [ValidateRange(90,240)][int]$WatchSeconds=120
)
$ErrorActionPreference='Stop'
$script:Target='198.51.100.77/32'
$script:Metric=171
$script:P1E=Join-Path $PSScriptRoot 'stage-c-p1e-testnet-canary-20261024.ps1'
$script:P1ESha='36427E5BE890785AE37D4A81953CD4FFF7789153B8BF13C6CC6B4264E4ADA738'
$script:Exe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$script:Root=Join-Path $env:LOCALAPPDATA 'GcpWGStageC\P1ECanary'

function Emit([string]$Name,$Value){Write-Output ($Name+'='+[string]$Value)}
function IsAdmin{
 return ([Security.Principal.WindowsPrincipal]::new(
   [Security.Principal.WindowsIdentity]::GetCurrent()
 )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function ValidateRun {
 if(-not (IsAdmin)){throw 'ADMIN_REQUIRED_FOR_WATCHDOG'}
 if($RunId -notmatch '^[a-f0-9]{32}$'){throw 'INVALID_WATCHDOG_RUN_ID'}
 if(-not (Test-Path -LiteralPath $script:P1E -PathType Leaf)){throw 'PINNED_P1E_MISSING'}
 if((Get-FileHash -LiteralPath $script:P1E -Algorithm SHA256).Hash -ne $script:P1ESha){throw 'PINNED_P1E_SHA_CHANGED'}
 if(-not (Test-Path -LiteralPath $script:Root -PathType Container)){throw 'ROOT_MISSING'}
 $dir=Get-Item -LiteralPath $script:Root -Force
 if(($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ROOT_REPARSE_POINT'}
 if(-not (Get-Acl -LiteralPath $script:Root).AreAccessRulesProtected){throw 'ROOT_ACL_UNPROTECTED'}
}
function F([string]$prefix){return Join-Path $script:Root ($prefix+$RunId+'.json')}
function ReadSafe([string]$File) {
 $info=Get-Item -LiteralPath $File -Force -ErrorAction Stop
 if(($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'REPARSE_POINT_RECORD'}
 return (Get-Content -LiteralPath $File -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop)
}
function SaveSafe([string]$File,$Object) {
 $temp=$File+'.'+$PID+'.p1f.tmp';$backup=$File+'.'+$PID+'.p1f.bak'
 [IO.File]::WriteAllText($temp,(ConvertTo-Json -InputObject $Object -Depth 12),[Text.UTF8Encoding]::new($false))
 try {
  if(Test-Path -LiteralPath $File){[IO.File]::Replace($temp,$File,$backup,$true)}
  else{[IO.File]::Move($temp,$File)}
 }finally{
  if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}
  if(Test-Path -LiteralPath $backup){Remove-Item -LiteralPath $backup -Force}
 }
}
function TargetRows([string]$Store='ActiveStore'){
 return @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $script:Target -PolicyStore $Store -ErrorAction SilentlyContinue)
}
function IdentityMatches($Row,$Record){
 return ($Row.DestinationPrefix -eq $script:Target -and
  [int]$Row.InterfaceIndex -eq [int]$Record.ifIndex -and
  [string]$Row.NextHop -eq [string]$Record.gateway -and
  [int]$Row.RouteMetric -eq $script:Metric -and
  [string]$Row.PolicyStore -eq 'ActiveStore')
}
function BaselineAfter {
 $out=@(& $script:Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:P1E -Mode CheckOnly 2>&1)
 return ($LASTEXITCODE -eq 0 -and
  @($out|Where-Object{[string]$_ -eq 'P1E_PREFLIGHT=PASS_NEEDS_ELEVATED_LOCAL_EXECUTION'}).Count -eq 1)
}
$result=[pscustomobject][ordered]@{
 schema='stage-c-p1f-independent-watch-v1'
 runId=$RunId
 pid=$PID
 watchSeconds=$WatchSeconds
 outcome='NOT_STARTED'
 routeCountBefore=-1
 routeCountAfter=-1
 nativeRollbackExit=-1
 nativeRouteRemovedByWatchdog=$false
 baselineRestored=$false
 observedAt=''
 error=''
}
try{
 ValidateRun
 $manifest=ReadSafe (F 'run-')
 if($manifest.schema -ne 'stage-c-p1e-canary-v1' -or
    $manifest.purpose -ne 'P1F_STRANDED_ROUTE_WATCHDOG_TEST' -or
    $manifest.runId -ne $RunId -or
    $manifest.target -ne $script:Target -or
    [int]$manifest.metric -ne $script:Metric -or
    [int]$manifest.beforeCount -ne 0 -or
    $manifest.status -ne 'INTENT'){
  throw 'INCOMPATIBLE_P1F_MANIFEST'
 }
 if(Test-Path -LiteralPath (F 'p1f-armed-')){throw 'WATCHDOG_ALREADY_ARMED'}
 $armed=[pscustomobject][ordered]@{
   runId=$RunId
   pid=$PID
   target=$script:Target
   at=[DateTimeOffset]::Now.ToString('o')
   watchSeconds=$WatchSeconds
 }
 SaveSafe (F 'p1f-armed-') $armed
 Emit 'P1F_WORKER_ARMED' 'True'
 Start-Sleep -Seconds $WatchSeconds
 $atDeadline=ReadSafe (F 'run-')
 if($atDeadline.runId -ne $RunId -or
    $atDeadline.purpose -ne 'P1F_STRANDED_ROUTE_WATCHDOG_TEST'){
  throw 'MANIFEST_CHANGED_BEFORE_DEADLINE'
 }
 $rows=@(TargetRows)
 $persistent=@(TargetRows 'PersistentStore')
 $result.routeCountBefore=$rows.Count
 if($persistent.Count -ne 0){throw 'PERSISTENT_TEST_ROUTE_PRESENT_ABORT'}
 if($rows.Count -gt 1){throw 'AMBIGUOUS_TEST_ROUTES_ABORT'}
 if($rows.Count -eq 1 -and -not (IdentityMatches $rows[0] $atDeadline)){
  throw 'UNOWNED_ROUTE_IDENTITY_ABORT'
 }
 if($rows.Count -eq 1){
  if($atDeadline.status -notin @('INTENT','ACTIVE')){throw 'ROUTE_PRESENT_BUT_MANIFEST_CLOSED'}
  # This is the causal evidence the previous P1E idempotent timer lacked.
  Emit 'P1F_WORKER_NATIVE_ROUTE_PRESENT_BEFORE' 'True'
 }else{
  Emit 'P1F_WORKER_NATIVE_ROUTE_PRESENT_BEFORE' 'False'
 }
 $lines=@(& $script:Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:P1E -Mode Rollback -RunId $RunId 2>&1)
 $result.nativeRollbackExit=$LASTEXITCODE
 if($result.nativeRollbackExit -ne 0 -or
    @($lines|Where-Object{[string]$_ -eq 'P1E_ROLLBACK=PASS'}).Count -ne 1){
  throw ('PINNED_P1E_ROLLBACK_FAILED_EXIT_'+$result.nativeRollbackExit)
 }
 $after=@(TargetRows)
 $afterPersistent=@(TargetRows 'PersistentStore')
 $result.routeCountAfter=$after.Count
 if($after.Count -ne 0 -or $afterPersistent.Count -ne 0){throw 'TARGET_ROUTE_STILL_PRESENT'}
 if((ReadSafe (F 'run-')).status -ne 'ROLLBACK_VERIFIED'){throw 'MANIFEST_NOT_CLOSED'}
 $result.baselineRestored=BaselineAfter
 if(-not $result.baselineRestored){throw 'XRAY_OR_NETWORK_BASELINE_DRIFT'}
 if($rows.Count -eq 1){
  $result.nativeRouteRemovedByWatchdog=$true
  $result.outcome='STRANDED_NATIVE_ROUTE_REMOVED_BY_WATCHDOG'
 }else{
  $result.outcome='IDEMPOTENT_EMPTY_ROUTE_AT_DEADLINE'
 }
 $result.observedAt=[DateTimeOffset]::Now.ToString('o')
 SaveSafe (F 'p1f-watch-result-') $result
 Emit 'P1F_WORKER_RESULT' $result.outcome
 exit 0
}catch{
 $result.outcome='ERROR_MANUAL_REVIEW_REQUIRED'
 $result.error=$_.Exception.Message
 $result.observedAt=[DateTimeOffset]::Now.ToString('o')
 try{
  if($RunId -match '^[a-f0-9]{32}$' -and
    (Test-Path -LiteralPath $script:Root -PathType Container)){
    SaveSafe (F 'p1f-watch-result-') $result
  }
 }catch{}
 Emit 'P1F_WORKER_ERROR' $result.error
 exit 5
}
