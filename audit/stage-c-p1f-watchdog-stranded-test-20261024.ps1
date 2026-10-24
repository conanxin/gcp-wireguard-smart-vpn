<#
Stage C P1F: fixed one-route independent-watchdog STRANDED cleanup test.
CheckOnly/Status: READ ONLY; Run requires administrator + two opt-in flags.
Run creates only 198.51.100.77/32 in ActiveStore and intentionally ends
its own elevated PowerShell child with exit 77; the existing PINNED P1E
watchdog is an independent process due to remove the exact owned route.
NEVER enables WireGuard, changes WinINET/xray, NRPT, DNS or default routes.
#>
[CmdletBinding()]
param(
 [ValidateSet('CheckOnly','Status','Run')][string]$Mode='CheckOnly',
 [switch]$IAmAtThePC,
 [switch]$SimulateParentCrash
)
$ErrorActionPreference='Stop'
$script:Prefix='198.51.100.77/32'
$script:Destination='198.51.100.77'
$script:Metric=171
$script:TimerSeconds=120
$script:Exe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$script:P1E=Join-Path $PSScriptRoot 'stage-c-p1e-testnet-canary-20261024.ps1'
$script:P1ESha256='36427E5BE890785AE37D4A81953CD4FFF7789153B8BF13C6CC6B4264E4ADA738'
$script:Worker=Join-Path $PSScriptRoot 'stage-c-p1f-independent-watchdog-20261024.ps1'
$script:WorkerSha256='1A7E0BD3D61F1ECDBB53638D58AB11C7F317BBEFBF6597C70020370E7058A6F9'
$script:Root=Join-Path $env:LOCALAPPDATA 'GcpWGStageC\P1ECanary'
$script:WriterLock=$null

function Emit([string]$Key,$Value){Write-Output ($Key+'='+[string]$Value)}
function Admin {
 return ([Security.Principal.WindowsPrincipal]::new(
  [Security.Principal.WindowsIdentity]::GetCurrent()
 )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function TargetRoutes([string]$Store='ActiveStore') {
 return @(Get-NetRoute -AddressFamily IPv4 -PolicyStore $Store -DestinationPrefix $script:Prefix -ErrorAction SilentlyContinue)
}
function JsonRead([string]$Path){
 $info=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
 if(($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0){throw 'RECORD_REPARSE_POINT_REJECTED'}
 return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json -ErrorAction Stop)
}
function JsonWrite([string]$Path,$Object){
 $tmp=$Path+'.'+$PID+'.p1f.tmp';$backup=$Path+'.'+$PID+'.p1f.bak'
 [IO.File]::WriteAllText($tmp,(ConvertTo-Json -InputObject $Object -Depth 12),[Text.UTF8Encoding]::new($false))
 try{
  if(Test-Path -LiteralPath $Path){[IO.File]::Replace($tmp,$Path,$backup,$true)}
  else{[IO.File]::Move($tmp,$Path)}
 }finally{
  if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force}
  if(Test-Path -LiteralPath $backup){Remove-Item -LiteralPath $backup -Force}
 }
}
function VerifyP1E {
 if(-not (Test-Path -LiteralPath $script:P1E -PathType Leaf)){throw 'PINNED_P1E_FILE_MISSING'}
 $sha=(Get-FileHash -LiteralPath $script:P1E -Algorithm SHA256).Hash
 if($sha -ne $script:P1ESha256){throw 'PINNED_P1E_SHA256_CHANGED'}
 if(-not (Test-Path -LiteralPath $script:Worker -PathType Leaf)){throw 'PINNED_P1F_WORKER_MISSING'}
 if((Get-FileHash -LiteralPath $script:Worker -Algorithm SHA256).Hash -ne $script:WorkerSha256){throw 'PINNED_P1F_WORKER_CHANGED'}
}
function VerifyRoot {
 if(-not (Test-Path -LiteralPath $script:Root -PathType Container)){throw 'P1E_CANARY_ROOT_MISSING'}
 $dir=Get-Item -LiteralPath $script:Root -Force
 if(($dir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0){throw 'CANARY_ROOT_REPARSE_POINT'}
 if(-not (Get-Acl -LiteralPath $script:Root).AreAccessRulesProtected){throw 'CANARY_ROOT_ACL_NOT_PROTECTED'}
}
function MPath([string]$id){return Join-Path $script:Root ('run-'+$id+'.json')}
function APath([string]$id){return Join-Path $script:Root ('p1f-armed-'+$id+'.json')}
function WPath([string]$id){return Join-Path $script:Root ('p1f-watch-result-'+$id+'.json')}
function PPath([string]$id){return Join-Path $script:Root ('p1f-parent-'+$id+'.json')}
function VerifyP1EBaseline {
 $lines=@(& $script:Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:P1E -Mode CheckOnly 2>&1)
 if($LASTEXITCODE -ne 0){return $false}
 return (@($lines|Where-Object{[string]$_ -eq 'P1E_PREFLIGHT=PASS_NEEDS_ELEVATED_LOCAL_EXECUTION'}).Count -eq 1)
}
function OpenManifestIds {
 $ids=[Collections.Generic.List[string]]::new()
 foreach($file in @(Get-ChildItem -LiteralPath $script:Root -File -Filter 'run-*.json' -ErrorAction Stop)){
  $m=JsonRead $file.FullName
  if($m.status -ne 'ROLLBACK_VERIFIED'){$ids.Add([string]$m.runId)}
 }
 return $ids.ToArray()
}
function RouteIdentical($Route,$Manifest){
 return ($Route.DestinationPrefix -eq $script:Prefix -and
  [int]$Route.InterfaceIndex -eq [int]$Manifest.ifIndex -and
  [string]$Route.NextHop -eq [string]$Manifest.gateway -and
  [int]$Route.RouteMetric -eq $script:Metric -and
  [string]$Route.PolicyStore -eq 'ActiveStore')
}
function ReadOnlyCheck {
 VerifyP1E
 VerifyRoot
 $baseline=VerifyP1EBaseline
 Emit 'P1F_P1E_BASELINE_PASS' $baseline
 $active=@(TargetRoutes)
 $persistent=@(TargetRoutes 'PersistentStore')
 $open=@(OpenManifestIds)
 Emit 'P1F_TARGET' $script:Prefix
 Emit 'P1F_ACTIVE_ROUTE_COUNT' $active.Count
 Emit 'P1F_PERSISTENT_ROUTE_COUNT' $persistent.Count
 Emit 'P1F_UNCLOSED_MANIFESTS' $open.Count
 Emit 'P1F_FIXED_WATCH_SECONDS' $script:TimerSeconds
 Emit 'P1F_REAL_NETWORK_MUTATIONS' 'NONE_CHECKONLY'
 if(-not $baseline -or $active.Count -ne 0 -or $persistent.Count -ne 0 -or $open.Count -gt 0){
  Emit 'P1F_CHECK' 'BLOCKED'
  exit 2
 }
 Emit 'P1F_CHECK' 'PASS'
 exit 0
}
function ReadOnlyStatus {
 VerifyP1E
 VerifyRoot
 $mine=[Collections.Generic.List[object]]::new()
 foreach($f in @(Get-ChildItem -LiteralPath $script:Root -Filter 'run-*.json' -File|Sort-Object LastWriteTime -Descending)){
  $m=JsonRead $f.FullName
  if($m.PSObject.Properties['purpose'] -and $m.purpose -eq 'P1F_STRANDED_ROUTE_WATCHDOG_TEST'){
    $mine.Add($m)
  }
 }
 $active=@(TargetRoutes)
 $persistent=@(TargetRoutes 'PersistentStore')
 Emit 'P1F_RELEVANT_MANIFEST_COUNT' $mine.Count
 Emit 'P1F_ACTIVE_ROUTE_COUNT' $active.Count
 Emit 'P1F_PERSISTENT_ROUTE_COUNT' $persistent.Count
 if($mine.Count -eq 0){Emit 'P1F_RESULT' 'NOT_STARTED';return}
 $m=$mine[0];$id=[string]$m.runId
 if($id -notmatch '^[a-f0-9]{32}$'){throw 'INVALID_RUN_ID_IN_RECORD'}
 Emit 'P1F_RUN_ID' $id
 Emit 'P1F_MANIFEST_STATUS' $m.status
 $receipt=$null
 if(Test-Path -LiteralPath (PPath $id)){
  $receipt=JsonRead (PPath $id)
  Emit 'P1F_PARENT_EXIT_PLANNED' $receipt.intentionalExit
  Emit 'P1F_PARENT_ROUTE_COUNT' $receipt.routeCount
  Emit 'P1F_PARENT_PID' $receipt.pid
 }
 if(Test-Path -LiteralPath (APath $id)){
  $a=JsonRead (APath $id)
  Emit 'P1F_WATCHDOG_PID' $a.pid
  Emit 'P1F_WATCHDOG_ARMED_AT' $a.at
  $wp=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$a.pid) -ErrorAction SilentlyContinue
  Emit 'P1F_WATCHDOG_RUNNING' ([bool]($wp -and $wp.CommandLine -like ('*-Mode Worker -RunId '+$id+'*')))
 }
 $done=$false
 if(Test-Path -LiteralPath (WPath $id)){
  $w=JsonRead (WPath $id)
  Emit 'P1F_WATCHDOG_RESULT' $w.outcome
  Emit 'P1F_WATCHDOG_RESULT_AT' $w.observedAt
  Emit 'P1F_WATCHDOG_ROUTE_BEFORE' $w.routeCountBefore
  Emit 'P1F_WATCHDOG_ROUTE_AFTER' $w.routeCountAfter
  Emit 'P1F_WATCHDOG_REMOVED_ROUTE' $w.nativeRouteRemovedByWatchdog
  Emit 'P1F_WATCHDOG_NATIVE_ROLLBACK_EXIT' $w.nativeRollbackExit
  $done=($w.outcome -eq 'STRANDED_NATIVE_ROUTE_REMOVED_BY_WATCHDOG' -and
    $w.nativeRouteRemovedByWatchdog -eq $true -and
    [int]$w.routeCountBefore -eq 1 -and [int]$w.routeCountAfter -eq 0 -and
    [int]$w.nativeRollbackExit -eq 0 -and $w.baselineRestored -eq $true)
 }else{Emit 'P1F_WATCHDOG_RESULT' 'PENDING_OR_MISSING'}
 if($m.status -eq 'ROLLBACK_VERIFIED' -and $done -and $active.Count -eq 0 -and $persistent.Count -eq 0 -and $receipt -and $receipt.intentionalExit -eq 77 -and $receipt.routeCount -eq 1){
  $ok=VerifyP1EBaseline
  Emit 'P1F_FINAL_NETWORK_BASELINE_PASS' $ok
  if($ok){Emit 'P1F_RESULT' 'STRANDED_NATIVE_ROUTE_WATCHDOG_CLEANUP_PASS'}
  else{Emit 'P1F_RESULT' 'ROUTE_CLEAN_BUT_NETWORK_BASELINE_FAILED'}
  return
 }
 if($active.Count -eq 1 -and $m.status -in @('INTENT','ACTIVE')){
  if(RouteIdentical $active[0] $m){Emit 'P1F_RESULT' 'STRANDED_NATIVE_ROUTE_AWAITING_WATCHDOG'}
  else{Emit 'P1F_RESULT' 'UNEXPECTED_ROUTE_IDENTITY'}
  return
 }
 Emit 'P1F_RESULT' 'PENDING_OR_MANUAL_REVIEW_REQUIRED'
}
function Run {
 if(-not (Admin)){throw 'LOCAL_ADMIN_REQUIRED'}
 if(-not $IAmAtThePC -or -not $SimulateParentCrash){throw 'TWO_EXPLICIT_APPROVAL_SWITCHES_REQUIRED'}
 VerifyP1E
 VerifyRoot
 if(-not (VerifyP1EBaseline)){throw 'P1E_BASELINE_NOT_PASS'}
 if(@(OpenManifestIds).Count){throw 'PREVIOUS_RUN_NOT_CLOSED'}
 if(@(TargetRoutes).Count -or @(TargetRoutes 'PersistentStore').Count){throw 'TARGET_ROUTE_ALREADY_PRESENT'}
 $lockFile=Join-Path $script:Root 'p1f-single-writer.lock'
 $script:WriterLock=[IO.File]::Open($lockFile,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
 if(-not (VerifyP1EBaseline)){throw 'NETWORK_BASELINE_CHANGED_AFTER_LOCK'}
 if(@(OpenManifestIds).Count){throw 'ANOTHER_RUN_STARTED_AFTER_LOCK'}
 $defaults=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop|Where-Object{$_.InterfaceAlias -eq 'WLAN' -and $_.NextHop -ne '0.0.0.0'})
 if($defaults.Count -ne 1){throw 'WLAN_PHYSICAL_GATEWAY_NOT_UNIQUE'}
 $idx=[int]$defaults[0].InterfaceIndex
 $gateway=[string]$defaults[0].NextHop
 $id=[guid]::NewGuid().ToString('N')
 $m=[pscustomobject][ordered]@{
  schema='stage-c-p1e-canary-v1'
  purpose='P1F_STRANDED_ROUTE_WATCHDOG_TEST'
  runId=$id
  target=$script:Prefix
  ifIndex=$idx
  gateway=$gateway
  metric=$script:Metric
  beforeCount=0
  status='INTENT'
  createdAt=[DateTimeOffset]::Now.ToString('o')
  rollbackAt=''
 }
 JsonWrite (MPath $id) $m
 Emit 'P1F_RUN_ID' $id
 Emit 'P1F_PERSISTENT_INTENT' 'True'
 try{
  $argsLine='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$script:Worker+'" -Mode Worker -RunId '+$id+' -WatchSeconds '+$script:TimerSeconds
  $watch=Start-Process -FilePath $script:Exe -ArgumentList $argsLine -PassThru -WindowStyle Hidden -ErrorAction Stop
  $armed=$false
  for($i=0;$i -lt 16;$i++){
   Start-Sleep -Milliseconds 500
   if(Test-Path -LiteralPath (APath $id)){
    $a=JsonRead (APath $id)
    if($a.runId -eq $id -and [int]$a.pid -eq [int]$watch.Id){
     $armed=$true;break
    }
   }
  }
  if(-not $armed){throw 'INDEPENDENT_WATCHDOG_NOT_ARMED'}
  $proc=Get-CimInstance Win32_Process -Filter ('ProcessId='+$watch.Id) -ErrorAction SilentlyContinue
  if(-not $proc -or $proc.CommandLine -notlike ('*-Mode Worker -RunId '+$id+'*')){throw 'WATCHDOG_PID_COMMANDLINE_MISMATCH'}
  $latest=JsonRead (MPath $id)
  if($latest.status -ne 'INTENT'){throw 'WATCHDOG_ALREADY_CLOSED_MANIFEST'}
  $safeDue=[DateTimeOffset]::Parse([string]$a.at).AddSeconds($script:TimerSeconds-35)
  if([DateTimeOffset]::Now -ge $safeDue){throw 'INSUFFICIENT_WATCHDOG_TIME'}
  Emit 'P1F_WATCHDOG_ARMED' 'True'
  Emit 'P1F_WATCHDOG_PID' $watch.Id
  Emit 'P1F_WATCHDOG_SECONDS' $script:TimerSeconds
  if(-not (VerifyP1EBaseline)){throw 'NETWORK_BASELINE_CHANGED_BEFORE_WRITE'}
  $fresh=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop|Where-Object{$_.InterfaceAlias -eq 'WLAN' -and $_.NextHop -ne '0.0.0.0'})
  if($fresh.Count -ne 1 -or [int]$fresh[0].InterfaceIndex -ne $idx -or [string]$fresh[0].NextHop -ne $gateway){throw 'GATEWAY_CHANGED'}
  if((JsonRead (MPath $id)).status -ne 'INTENT'){throw 'WATCHDOG_ALREADY_MODIFIED_MANIFEST'}
  if(-not (Get-CimInstance Win32_Process -Filter ('ProcessId='+$watch.Id) -ErrorAction SilentlyContinue)){throw 'WATCHDOG_STOPPED_PRE_WRITE'}
  if([DateTimeOffset]::Now -ge $safeDue){throw 'WATCHDOG_TIME_EXPIRED_PRE_WRITE'}
  $args=@{
   AddressFamily='IPv4'
   DestinationPrefix=$script:Prefix
   InterfaceIndex=$idx
   NextHop=$gateway
   RouteMetric=$script:Metric
   PolicyStore='ActiveStore'
   ErrorAction='Stop'
  }
  New-NetRoute @args|Out-Null
  $routes=@(TargetRoutes)
  if($routes.Count -ne 1 -or -not (RouteIdentical $routes[0] $m)){throw 'NATIVE_POSTWRITE_ROUTE_IDENTITY_INVALID'}
  $best=@(Find-NetRoute -RemoteIPAddress $script:Destination -ErrorAction Stop)
  if(@($best|Where-Object{$_.DestinationPrefix -eq $script:Prefix}).Count -ne 1){throw 'FIND_NET_ROUTE_DID_NOT_SELECT_TESTNET'}
  $m.status='ACTIVE'
  JsonWrite (MPath $id) $m
  $receipt=[pscustomobject][ordered]@{
    schema='stage-c-p1f-parent-receipt-v1'
    runId=$id
    pid=$PID
    intentionalExit=77
    routeCount=1
    watchdogPid=[int]$watch.Id
    createdAt=[DateTimeOffset]::Now.ToString('o')
  }
  JsonWrite (PPath $id) $receipt
  Emit 'P1F_NATIVE_ROUTE_LEFT_PRESENT' 'True'
  Emit 'P1F_ROUTE_IDENTITY' ($script:Prefix+'|IF='+$idx+'|GATEWAY='+$gateway+'|METRIC='+$script:Metric)
  Emit 'P1F_PARENT_INTENTIONAL_EXIT' '77'
  Emit 'P1F_RESULT' 'STRANDED_ROUTE_WAITING_FOR_INDEPENDENT_WATCHDOG'
  [Console]::Out.Flush()
  [Environment]::Exit(77)
 }catch{
  Emit 'P1F_NATIVE_TEST_FAILURE' $_.Exception.Message
  $recovery=@(& $script:Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:P1E -Mode Rollback -RunId $id 2>&1)
  Emit 'P1F_IMMEDIATE_RECOVERY_EXIT' $LASTEXITCODE
  foreach($line in $recovery){Emit 'P1F_RECOVERY_DETAIL' $line}
  throw
 }finally{
  if($script:WriterLock){$script:WriterLock.Dispose()}
 }
}
try{
 VerifyP1E
 if($Mode -eq 'CheckOnly'){ReadOnlyCheck}
 if($Mode -eq 'Status'){ReadOnlyStatus;exit 0}
 if($Mode -eq 'Run'){Run;exit 3}
}catch{
 Emit 'P1F_ERROR' $_.Exception.Message
 Emit 'P1F_RESULT' 'BLOCKED_OR_INCOMPLETE'
 exit 4
}
