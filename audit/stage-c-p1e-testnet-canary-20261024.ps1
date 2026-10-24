<#
Stage C P1E supervised native route MICRO-canary.
Only ONE RFC5737 TEST-NET /32 (198.51.100.77/32) in ActiveStore.
No WireGuard installation, no WinINET, DNS, NRPT, firewall, xray or GCP edits.
Modes CheckOnly (default), Run (requires admin + IAmAtThePC), Rollback
and independent Watchdog (user-local elevated child).
This is not native SMART routing, unattended production or failover.
#>
[CmdletBinding()]
param(
 [ValidateSet('CheckOnly','Run','Rollback','Watchdog')][string]$Mode='CheckOnly',
 [switch]$IAmAtThePC,
 [string]$RunId='',
 [ValidateRange(90,240)][int]$WatchSeconds=150
)
$ErrorActionPreference='Stop'
$script:Target='198.51.100.77/32'
$script:Destination='198.51.100.77'
$script:Metric=171
$script:Root=Join-Path $env:LOCALAPPDATA 'GcpWGStageC\P1ECanary'
$script:Exe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
function Emit([string]$Key,$Value){Write-Output ($Key+'='+[string]$Value)}
function IsAdmin {
 return ([Security.Principal.WindowsPrincipal]::new(
 [Security.Principal.WindowsIdentity]::GetCurrent()
 )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function RPath([string]$id){return Join-Path $script:Root ('run-'+$id+'.json')}
function APath([string]$id){return Join-Path $script:Root ('armed-'+$id+'.json')}
function SPath([string]$id){return Join-Path $script:Root ('watch-result-'+$id+'.json')}
function IDCheck([string]$id){if($id -notmatch '^[a-f0-9]{32}$'){throw 'INVALID_RUN_ID'}}
function JsonLoad([string]$p){
 $f=Get-Item -LiteralPath $p -Force -ErrorAction Stop
 if(($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'REPARSE_POINT_RECORD'}
 return (Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop)
}
function JsonWrite([string]$p,$obj){
 $temp=$p+'.p1e-'+$PID+'.tmp';$bak=$p+'.p1e-'+$PID+'.bak'
 [IO.File]::WriteAllText($temp,(ConvertTo-Json -InputObject $obj -Depth 10),[Text.UTF8Encoding]::new($false))
 try {
  if(Test-Path -LiteralPath $p){[IO.File]::Replace($temp,$p,$bak,$true)}
  else{[IO.File]::Move($temp,$p)}
 }finally{
  if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}
  if(Test-Path -LiteralPath $bak){Remove-Item -LiteralPath $bak -Force}
 }
}
function InitRoot {
 if(-not (Test-Path -LiteralPath $script:Root)){
  [IO.Directory]::CreateDirectory($script:Root)|Out-Null
  $acl=Get-Acl -LiteralPath $script:Root
  $acl.SetAccessRuleProtection($true,$false)
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
  $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
  $ace=New-Object Security.AccessControl.FileSystemAccessRule(
    $sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Allow)
  $acl.AddAccessRule($ace)
  [IO.Directory]::SetAccessControl($script:Root,$acl)
 }
 $dir=Get-Item -LiteralPath $script:Root -Force
 if(($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ROOT_SYMLINK_NOT_ALLOWED'}
 if(-not (Get-Acl -LiteralPath $script:Root).AreAccessRulesProtected){throw 'ROOT_ACL_UNPROTECTED'}
}
function Routes {return @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $script:Target -ErrorAction SilentlyContinue)}
function RouteEquals($r,$m){
 return ($r.DestinationPrefix -eq $script:Target -and
  [int]$r.InterfaceIndex -eq [int]$m.ifIndex -and
  [string]$r.NextHop -eq [string]$m.gateway -and
  [int]$r.RouteMetric -eq $script:Metric -and
  ([string]$r.PolicyStore -eq 'ActiveStore' -or [string]$r.Store -eq 'ActiveStore'))
}
function Baseline {
 $svc=Get-Service -Name 'WireGuardTunnel$client1-cndirect' -ErrorAction SilentlyContinue
 $wg=Get-NetAdapter -Name 'client1-cndirect' -ErrorAction SilentlyContinue
 $tun=Get-NetAdapter -Name 'xray_tun' -ErrorAction SilentlyContinue
 $ie=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
 $x=@(Get-Process -Name 'xray' -ErrorAction SilentlyContinue)
 $half=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
 $defs=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceAlias -eq 'WLAN' -and $_.NextHop -ne '0.0.0.0'})
 $nr=@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like 'GCP-WG-SMART-FULLCN-*'})
 $http=& 'C:\Windows\System32\curl.exe' --silent --show-error --max-time 7 --proxy 'http://127.0.0.1:7897' --output NUL --write-out '%{http_code}' 'https://www.gstatic.com/generate_204'
 $code=$LASTEXITCODE
 return [pscustomobject]@{
  admin=(IsAdmin);wgService=[bool]$svc;wgAdapter=[bool]$wg
  xrayTunUp=[bool]($tun -and $tun.Status -eq 'Up')
  xrayProcessCount=$x.Count;halfRouteCount=$half.Count
  proxyEnabled=if($ie){[int]$ie.ProxyEnable}else{-1}
  proxyServer=if($ie){[string]$ie.ProxyServer}else{'UNKNOWN'}
  wlanDefaults=$defs.Count
  wlanIndex=if($defs.Count -eq 1){[int]$defs[0].InterfaceIndex}else{0}
  wlanGateway=if($defs.Count -eq 1){[string]$defs[0].NextHop}else{''}
  projectNRPT=$nr.Count;http=[string]$http;curlExit=$code
  targetRouteCount=@(Routes).Count
  targetPersistentCount=@(Get-NetRoute -AddressFamily IPv4 -PolicyStore PersistentStore -DestinationPrefix $script:Target -ErrorAction SilentlyContinue).Count
 }
}
function Problems($b,[bool]$mustAdmin,[bool]$mustAbsent){
 $list=[Collections.Generic.List[string]]::new()
 if($mustAdmin -and -not $b.admin){$list.Add('NOT_ELEVATED')}
 if($b.wgService -or $b.wgAdapter -or $b.halfRouteCount -gt 0){$list.Add('WG_STATE_CHANGED')}
 if($b.xrayTunUp){$list.Add('XRAY_TUN_UP')}
 if($b.xrayProcessCount -lt 1){$list.Add('XRAY_ABSENT')}
 if($b.proxyEnabled -ne 1 -or $b.proxyServer -ne '127.0.0.1:7897'){$list.Add('WININET_CHANGED')}
 if($b.wlanDefaults -ne 1 -or $b.wlanIndex -le 0 -or -not $b.wlanGateway){$list.Add('WLAN_DEFAULT_AMBIGUOUS')}
 if($b.projectNRPT -ne 25){$list.Add('NRPT_CHANGED')}
 if($b.http -ne '204' -or $b.curlExit -ne 0){$list.Add('XRAY_HTTP204_FAILED')}
 if($mustAbsent -and ($b.targetRouteCount -gt 0 -or $b.targetPersistentCount -gt 0)){$list.Add('CANARY_ROUTE_ALREADY_EXISTS')}
 return $list.ToArray()
}
function PrintBase($b){
 foreach($name in @('admin','wgService','wgAdapter','xrayTunUp','xrayProcessCount',
 'halfRouteCount','proxyEnabled','proxyServer','wlanDefaults','wlanIndex',
 'wlanGateway','projectNRPT','http','curlExit','targetRouteCount','targetPersistentCount')){
  Emit ('BASE_'+$name.ToUpperInvariant()) $b.$name
 }
}
function Rollback([string]$id) {
 IDCheck $id
 if(-not (Test-Path -LiteralPath $script:Root -PathType Container)){throw 'MISSING_P1E_MANIFEST_ROOT'}
 InitRoot
 $m=JsonLoad (RPath $id)
 if($m.schema -ne 'stage-c-p1e-canary-v1' -or $m.runId -ne $id -or
    $m.target -ne $script:Target -or [int]$m.metric -ne $script:Metric -or
    [int]$m.beforeCount -ne 0 -or [int]$m.ifIndex -le 0 -or
    -not $m.gateway){throw 'MANIFEST_IDENTITY_INVALID'}
 $found=@(Routes)
 if($found.Count -gt 1){throw 'CANARY_ROUTE_IDENTITY_AMBIGUOUS'}
 if($m.status -eq 'ROLLBACK_VERIFIED') {
  if($found.Count -ne 0){throw 'ROUTE_REAPPEARED_AFTER_OWNERSHIP_ENDED'}
  Emit 'P1E_EXACT_TARGET_ABSENT' 'True'
  return $true
 }
 if($m.status -notin @('INTENT','ACTIVE')){throw 'MANIFEST_STATUS_NOT_RECOVERABLE'}
 if($found.Count -eq 1){
  if(-not (RouteEquals $found[0] $m)){throw 'CANARY_ROUTE_DOES_NOT_MATCH_OWNED_IDENTITY'}
  $found[0] | Remove-NetRoute -Confirm:$false -ErrorAction Stop
 }
 if(@(Routes).Count -ne 0){throw 'CANARY_ROUTE_STILL_PRESENT'}
 $m.status='ROLLBACK_VERIFIED'
 $m.rollbackAt=[DateTimeOffset]::Now.ToString('o')
 JsonWrite (RPath $id) $m
 Emit 'P1E_EXACT_TARGET_ABSENT' 'True'
 return $true
}
if($Mode -eq 'CheckOnly'){
 $b=Baseline;PrintBase $b
 $issues=@(Problems $b $false $true)
 foreach($i in $issues){Emit 'P1E_PRECHECK_BLOCKER' $i}
 Emit 'P1E_TEST_PREFIX_FIXED' $script:Target
 Emit 'P1E_NETWORK_WRITES' 'NOT_ATTEMPTED'
 if($issues.Count -gt 0){Emit 'P1E_PREFLIGHT' 'BLOCKED';exit 2}
 Emit 'P1E_PREFLIGHT' 'PASS_NEEDS_ELEVATED_LOCAL_EXECUTION'
 exit 0
}
if(-not (IsAdmin)){Emit 'P1E_RESULT' 'BLOCKED_NOT_ELEVATED';exit 2}
if($Mode -eq 'Rollback'){
 try{
  if(-not $RunId){
   if(-not (Test-Path -LiteralPath $script:Root -PathType Container)){throw 'MISSING_MANIFEST_ROOT'}
   InitRoot
   $open=[Collections.Generic.List[string]]::new()
   foreach($candidate in @(Get-ChildItem -LiteralPath $script:Root -Filter 'run-*.json' -File)){
    $r=JsonLoad $candidate.FullName
    if($r.status -in @('INTENT','ACTIVE')){$open.Add([string]$r.runId)}
   }
   if($open.Count -ne 1){throw 'MANIFEST_AMBIGUOUS_OR_NONE'}
   $RunId=$open[0]
  }
  [void](Rollback $RunId);Emit 'P1E_ROLLBACK' 'PASS';exit 0
 }
 catch{Emit 'P1E_ROLLBACK_ERROR' $_.Exception.Message;exit 3}
}
if($Mode -eq 'Watchdog'){
 try{
  IDCheck $RunId;InitRoot
  $m=JsonLoad (RPath $RunId)
  if($m.runId -ne $RunId -or $m.status -notin @('INTENT','ACTIVE','ROLLBACK_VERIFIED')){throw 'WATCHDOG_MANIFEST_INVALID'}
  JsonWrite (APath $RunId) ([pscustomobject]@{runId=$RunId;pid=$PID;at=[DateTimeOffset]::Now.ToString('o')})
  Start-Sleep -Seconds $WatchSeconds
  [void](Rollback $RunId)
  JsonWrite (SPath $RunId) ([pscustomobject]@{runId=$RunId;status='CLEAN';at=[DateTimeOffset]::Now.ToString('o')})
  exit 0
 }catch{Emit 'P1E_WATCHDOG_ERROR' $_.Exception.Message;exit 5}
}
if($Mode -eq 'Run'){
 if(-not $IAmAtThePC){Emit 'P1E_RESULT' 'BLOCKED_IN_PERSON_FLAG_REQUIRED';exit 2}
 $b=Baseline;PrintBase $b
 $issues=@(Problems $b $true $true)
 if($issues.Count -gt 0){
  foreach($i in $issues){Emit 'P1E_PRECHECK_BLOCKER' $i}
  Emit 'P1E_RESULT' 'BLOCKED_PRECHECK';exit 2
 }
 foreach($name in @('Get-NetRoute','New-NetRoute','Remove-NetRoute','Find-NetRoute')){
  if(-not (Get-Command $name -ErrorAction SilentlyContinue)){
   Emit 'P1E_RESULT' ('BLOCKED_MISSING_'+$name);exit 2
  }
 }
 InitRoot
 foreach($file in @(Get-ChildItem -LiteralPath $script:Root -Filter 'run-*.json' -File -ErrorAction SilentlyContinue)){
  $old=JsonLoad $file.FullName
  if($old.status -ne 'ROLLBACK_VERIFIED'){
   Emit 'P1E_RESULT' 'BLOCKED_PREVIOUS_UNCLOSED_MANIFEST';exit 2
  }
 }
 $newid=[guid]::NewGuid().ToString('N')
 $m=[pscustomobject][ordered]@{
  schema='stage-c-p1e-canary-v1';runId=$newid;target=$script:Target
  ifIndex=$b.wlanIndex;gateway=$b.wlanGateway;metric=$script:Metric
  beforeCount=0;status='INTENT'
  createdAt=[DateTimeOffset]::Now.ToString('o');rollbackAt=''
 }
 JsonWrite (RPath $newid) $m
 Emit 'P1E_RUN_ID' $newid
 Emit 'P1E_WAL_INTENT_SAVED' 'True'
 $argLine='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+
  $PSCommandPath+'" -Mode Watchdog -RunId '+$newid+
  ' -WatchSeconds '+$WatchSeconds
 $watch=Start-Process -FilePath $script:Exe -ArgumentList $argLine -PassThru -WindowStyle Hidden
 $armed=$false
 for($i=0;$i -lt 16;$i++){
  Start-Sleep -Milliseconds 500
  if(Test-Path -LiteralPath (APath $newid)){
   $a=JsonLoad (APath $newid)
   if($a.runId -eq $newid -and [int]$a.pid -eq [int]$watch.Id){
    $armed=$true;break
   }
  }
 }
 if(-not $armed){Emit 'P1E_RESULT' 'BLOCKED_WATCHDOG_NOT_ARMED';exit 3}
 $watchProcess=Get-CimInstance Win32_Process -Filter ("ProcessId="+$watch.Id) -ErrorAction SilentlyContinue
 if(-not $watchProcess -or
    $watchProcess.CommandLine -notlike '*stage-c-p1e-testnet-canary-20261024.ps1*' -or
    $watchProcess.CommandLine -notlike ('*-Mode Watchdog -RunId '+$newid+'*')){
  Emit 'P1E_RESULT' 'BLOCKED_WATCHDOG_PROCESS_IDENTITY';exit 3
 }
 Emit 'P1E_WATCHDOG_ARMED' 'True'
 Emit 'P1E_WATCHDOG_PID' $watch.Id
 Emit 'P1E_WATCHDOG_SECONDS' $WatchSeconds
 $status='PENDING'
 try{
  $re=Baseline
  $reissues=@(Problems $re $true $true)
  if($reissues.Count -gt 0){throw ('PRE_WRITE_BASELINE_DRIFT_'+($reissues -join ','))}
  if($re.wlanIndex -ne $m.ifIndex -or $re.wlanGateway -ne $m.gateway){throw 'PHYSICAL_GATEWAY_DRIFT'}
  $latest=JsonLoad (RPath $newid)
  if($latest.status -ne 'INTENT'){throw 'WATCHDOG_ALREADY_COMPLETED_NO_ROUTE_ALLOWED'}
  $a=JsonLoad (APath $newid)
  $due=[DateTimeOffset]::Parse([string]$a.at).AddSeconds($WatchSeconds-30)
  $watchStill=Get-CimInstance Win32_Process -Filter ("ProcessId="+$watch.Id) -ErrorAction SilentlyContinue
  if([DateTimeOffset]::Now -ge $due -or
     -not $watchStill -or
     $watchStill.CommandLine -notlike ('*-Mode Watchdog -RunId '+$newid+'*')){
   throw 'WATCHDOG_TIME_REMAINING_TOO_SHORT'
  }
  $routeArguments=@{
   AddressFamily='IPv4';DestinationPrefix=$script:Target
   InterfaceIndex=$m.ifIndex;NextHop=$m.gateway
   RouteMetric=$script:Metric;PolicyStore='ActiveStore'
   ErrorAction='Stop'
  }
  New-NetRoute @routeArguments|Out-Null
  $found=@(Routes)
  if($found.Count -ne 1 -or -not (RouteEquals $found[0] $m)){throw 'NATIVE_ROUTE_POSTWRITE_MISMATCH'}
  $m.status='ACTIVE'
  JsonWrite (RPath $newid) $m
  Emit 'P1E_NATIVE_ROUTE_ADDED' 'True'
  Emit 'P1E_ROUTE_IDENTITY' ($script:Target+'|IF='+$m.ifIndex+'|GATEWAY='+$m.gateway+'|METRIC='+$m.metric)
  $best=@(Find-NetRoute -RemoteIPAddress $script:Destination -ErrorAction Stop)
  $choice=@($best|Where-Object{$_.DestinationPrefix -eq $script:Target})
  if($choice.Count -ne 1){throw 'NATIVE_BEST_ROUTE_NOT_TESTNET'}
  Emit 'P1E_ROUTE_SELECTED' 'True'
  $status='PASS'
 }catch{
  $status='FAILED'
  Emit 'P1E_NATIVE_ERROR' $_.Exception.Message
 }finally{
  try{
   [void](Rollback $newid)
   Emit 'P1E_IMMEDIATE_ROLLBACK' 'PASS'
  }catch{
   $status='FAILED_ROLLBACK_INCOMPLETE'
   Emit 'P1E_IMMEDIATE_ROLLBACK_ERROR' $_.Exception.Message
   Emit 'P1E_KEEP_WATCHDOG_ARMED' 'True'
  }
 }
 $post=Baseline
 $issues=@(Problems $post $true $true)
 foreach($i in $issues){Emit 'P1E_POSTCHECK_BLOCKER' $i}
 Emit 'P1E_FINAL_TARGET_ROUTE_COUNT' $post.targetRouteCount
 Emit 'P1E_XRAY_HTTP_CODE' $post.http
 Emit 'P1E_TEST_RESULT' $status
 if($status -eq 'PASS' -and $issues.Count -eq 0){exit 0}
 exit 4
}
