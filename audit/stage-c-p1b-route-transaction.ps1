<#
Stage C P1B route transaction -- draft, not a live switcher.
PlanOnly delegates to P1 read-only. MockPlan/MockApply/MockRollback touch only
JSON fixture files inside %TEMP%\wg-stage-c-p1b-fixture-*.
NativeApply/NativeRollback are HARD DISABLED in this source version.
No WireGuard, WinINET, xray, NRPT or Windows route changes are allowed.
#>
[CmdletBinding()]
param(
 [ValidateSet('PlanOnly','MockPlan','MockApply','MockRollback','NativeApply','NativeRollback')]
 [string]$Mode='PlanOnly',
 [string]$MockRoot='',
 [string]$RunId='P1B-SIM-001',
 [ValidateRange(0,10000)][int]$FailBeforeRoute=0,
 [ValidateRange(0,10000)][int]$CrashAfterRoute=0,
 [ValidateRange(0,10000)][int]$CollideAtRoute=0,
 [ValidateRange(0,10000)][int]$NrptDriftAtRoute=0,
 [ValidateRange(0,10000)][int]$ProxyDriftAtRoute=0,
 [ValidateRange(0,10000)][int]$GatewayDriftAtRoute=0,
 [ValidateRange(0,10000)][int]$TimeoutAtRoute=0
)
$ErrorActionPreference='Stop'
$Script:NativeWriteGate=$false
$Script:Schema='stage-c-p1b-route-v1'
function Emit([string]$Key,$Value){Write-Output ($Key+'='+[string]$Value)}
if($Mode -like 'Native*'){
 Emit 'NATIVE_GATE' 'HARD_DISABLED_REVIEW_REQUIRED'
 Emit 'SYSTEM_MUTATIONS_PERFORMED' 'False'
 exit 40
}
if($Mode -eq 'PlanOnly'){
 $p=Join-Path $PSScriptRoot 'stage-c-p1-planonly-20261024.ps1'
 & 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -ExecutionPolicy Bypass -File $p
 exit $LASTEXITCODE
}
# No arbitrary mock output paths; strictly constrain fixture IO to user TEMP.
if(-not $MockRoot -or $MockRoot -match '[\r\n]'){
 Emit 'MOCK_RESULT' 'BLOCKED_NO_MOCKROOT';exit 41
}
$full=[System.IO.Path]::GetFullPath($MockRoot).TrimEnd('\')
$temp=[System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
if(-not $full.StartsWith($temp+'\wg-stage-c-p1b-fixture-',[StringComparison]::OrdinalIgnoreCase)){
 Emit 'MOCK_RESULT' 'BLOCKED_OUTSIDE_TEMP_FIXTURE';exit 41
}
if(-not (Test-Path -LiteralPath $full -PathType Container)){
 Emit 'MOCK_RESULT' 'BLOCKED_FIXTURE_FOLDER_MISSING';exit 41
}
$fixtureInfo=Get-Item -LiteralPath $full -Force
if(($fixtureInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0){
 Emit 'MOCK_RESULT' 'BLOCKED_REPARSE_POINT_FIXTURE';exit 41
}
if($RunId -notmatch '^[A-Za-z0-9_-]{3,64}$'){
 Emit 'MOCK_RESULT' 'BLOCKED_BAD_RUN_ID';exit 41
}
$worldPath=Join-Path $full 'mockworld.json'
$prefixPath=Join-Path $full 'prefixes.txt'
$journalPath=Join-Path $full ("journal-"+$RunId+".json")
$planPath=Join-Path $full ("plan-"+$RunId+".json")
if(-not (Test-Path -LiteralPath $worldPath -PathType Leaf)){
 Emit 'MOCK_RESULT' 'BLOCKED_WORLD_MISSING';exit 41
}
function ReadJson([string]$Path){
 $text=Get-Content -LiteralPath $Path -Raw -Encoding UTF8
 return ($text | ConvertFrom-Json -ErrorAction Stop)
}
function SaveJsonAtomic([string]$Path,$Object){
 $tempPath=$Path+".stagec-$PID.tmp"
 $previous=$Path+".stagec-$PID.previous.tmp"
 $text=ConvertTo-Json -InputObject $Object -Depth 15
 [System.IO.File]::WriteAllText($tempPath,$text,[System.Text.UTF8Encoding]::new($false))
 try {
  if(Test-Path -LiteralPath $Path -PathType Leaf){
   # Win32 ReplaceFile requires a real backup path on this installation.
   [System.IO.File]::Replace($tempPath,$Path,$previous,$true)
  }else{[System.IO.File]::Move($tempPath,$Path)}
 }finally{
  if(Test-Path -LiteralPath $tempPath){Remove-Item -LiteralPath $tempPath -Force}
  if(Test-Path -LiteralPath $previous){Remove-Item -LiteralPath $previous -Force}
 }
}
function HashText([string]$Value){
 $h=[System.Security.Cryptography.SHA256]::Create()
 try {
  $bytes=[System.Text.Encoding]::UTF8.GetBytes($Value)
  return ([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','')
 }finally{$h.Dispose()}
}
function RouteKey($Route){
 return ('{0}|{1}|{2}|{3}|{4}' -f $Route.prefix,$Route.ifIndex,$Route.nextHop,$Route.metric,$Route.store)
}
function WorldHash($World){
 $routeKeys=@(@($World.routes)|ForEach-Object{RouteKey $_}|Sort-Object)
 $nrptKeys=@(@($World.nrpt)|ForEach-Object{
   '{0}|{1}|{2}' -f $_.id,$_.server,((@($_.namespaces)|Sort-Object) -join ',')
 }|Sort-Object)
 $part=@(
  ('physical='+$World.physicalIndex+'|'+$World.gateway)
  ('proxy='+$World.proxyEnabled+'|'+$World.proxyServer)
  ('wg='+$World.wgActive)
  ('routes='+($routeKeys -join ';'))
  ('nrpt='+($nrptKeys -join ';'))
 ) -join ([char]10)
 return HashText $part
}
function PrefixRoutes($World,[string]$Prefix){
 return @(@($World.routes)|Where-Object{$_.prefix -eq $Prefix})
}
function ExactRoutes($World,$Route){
 $key=RouteKey $Route
 return @(@($World.routes)|Where-Object{(RouteKey $_) -ceq $key})
}
function ValidatePrefix([string]$Prefix){
 if($Prefix -notmatch '^(\d{1,3}\.){3}\d{1,3}/(\d|[12]\d|3[0-2])$'){
   throw 'INVALID_PREFIX_FORMAT'
 }
 $parts=$Prefix.Split('/')
 $raw=[System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
 if($raw.Length -ne 4){throw 'NOT_IPV4'}
 [uint64]$value=([uint64]$raw[0] -shl 24) -bor ([uint64]$raw[1] -shl 16) -bor ([uint64]$raw[2] -shl 8) -bor [uint64]$raw[3]
 [uint64]$size=[uint64][Math]::Pow(2,32-[int]$parts[1])
 if(($value % $size) -ne 0){throw 'UNALIGNED_PREFIX'}
}
function PrefixRange([string]$Prefix){
 ValidatePrefix $Prefix
 $parts=$Prefix.Split('/')
 $bytes=[System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
 [uint64]$start=([uint64]$bytes[0] -shl 24) -bor ([uint64]$bytes[1] -shl 16) -bor ([uint64]$bytes[2] -shl 8) -bor [uint64]$bytes[3]
 [uint64]$size=[uint64][Math]::Pow(2,32-[int]$parts[1])
 return [pscustomobject]@{Start=$start;End=($start+$size-1)}
}
function ValidateWorld($World,[string[]]$Prefixes){
 foreach($prop in @('routes','nrpt','physicalIndex','gateway','proxyEnabled','proxyServer','wgActive')){
  if(-not $World.PSObject.Properties[$prop]){throw ('WORLD_MISSING_'+$prop)}
 }
 if([bool]$World.wgActive){throw 'WG_ALREADY_ON'}
 if([int]$World.proxyEnabled -ne 1 -or $World.proxyServer -ne '127.0.0.1:7897'){
  throw 'PROXY_NOT_XRAY_BASELINE'
 }
 if([int]$World.physicalIndex -le 0 -or -not $World.gateway){
  throw 'PHYSICAL_GATEWAY_INVALID'
 }
 foreach($rule in @($World.nrpt)){
  if($rule.server -ne '223.5.5.5'){throw 'NRPT_RESOLVER_INVALID'}
 }
 if(@($World.nrpt).Count -eq 0){throw 'NRPT_MISSING'}
 if($Prefixes.Count -lt 1 -or $Prefixes.Count -gt 5494){throw 'PREFIX_COUNT_OUT_OF_RANGE'}
 $ranges=@($Prefixes|ForEach-Object{PrefixRange $_}|Sort-Object Start,End)
 [int64]$previousEnd=-1
 foreach($r in $ranges){
  if([int64]$r.Start -le $previousEnd){throw 'OVERLAPPING_PREFIXES'}
  $previousEnd=[int64]$r.End
 }
 $seen=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
 foreach($p in $Prefixes){
  ValidatePrefix $p
  if(-not $seen.Add($p)){throw 'DUPLICATE_PREFIX'}
  $oldRoutes=@(PrefixRoutes $World $p)
  if($oldRoutes.Count -gt 1){throw 'AMBIGUOUS_PREEXISTING_ROUTE'}
  foreach($route in $oldRoutes){
   if([int]$route.ifIndex -ne [int]$World.physicalIndex -or [string]$route.nextHop -ne [string]$World.gateway){
    throw ('FOREIGN_ROUTE_COLLISION_'+$p)
   }
  }
 }
}
# Future Windows native adapter, IMPOSSIBLE to call through today's CLI gate.
# Native writes are untested and have no live authorization.
function NativeAdd($Route){
 if(-not $Script:NativeWriteGate){throw 'NATIVE_APPLY_HARD_DISABLED'}
 New-NetRoute -AddressFamily IPv4 -DestinationPrefix $Route.prefix -InterfaceIndex $Route.ifIndex -NextHop $Route.nextHop -RouteMetric $Route.metric -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
}
function NativeRemove($Route){
 if(-not $Script:NativeWriteGate){throw 'NATIVE_ROLLBACK_HARD_DISABLED'}
 $match=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $Route.prefix -InterfaceIndex $Route.ifIndex -ErrorAction Stop|Where-Object{$_.NextHop -eq $Route.nextHop -and $_.RouteMetric -eq $Route.metric -and $_.PolicyStore -eq $Route.store})
 if($match.Count -ne 1){throw 'NATIVE_ROUTE_OWNERSHIP_AMBIGUOUS'}
 $match[0]|Remove-NetRoute -Confirm:$false -ErrorAction Stop
}
if($Mode -eq 'MockPlan'){
 if(-not (Test-Path -LiteralPath $prefixPath -PathType Leaf)){Emit 'MOCK_RESULT' 'BLOCKED_NO_PREFIX_INPUT';exit 42}
 if((Test-Path -LiteralPath $planPath -PathType Leaf) -or
    (Test-Path -LiteralPath $journalPath -PathType Leaf)){
    Emit 'MOCK_RESULT' 'BLOCKED_PREVIOUS_PLAN_OR_JOURNAL';exit 42
 }
 $world=ReadJson $worldPath
 $prefixes=@(Get-Content -LiteralPath $prefixPath|ForEach-Object{$_.Trim()}|Where-Object{$_})
 try{ValidateWorld $world $prefixes}catch{
  Emit 'MOCK_RESULT' ('BLOCKED_'+$_.Exception.Message);exit 42
 }
 $toAdd=0;$borrowed=0
 foreach($prefix in $prefixes){
  if(@(PrefixRoutes $world $prefix).Count){$borrowed++}else{$toAdd++}
 }
 $plan=[pscustomobject][ordered]@{
  schema=$Script:Schema;runId=$RunId;worldHash=(WorldHash $world)
  prefixesHash=(HashText ($prefixes -join ([char]10)))
  targetCount=$prefixes.Count;addCount=$toAdd;borrowedCount=$borrowed
  type='MOCK_ONLY_NOT_LIVE'
 }
 SaveJsonAtomic $planPath $plan
 Emit 'MOCK_RESULT' 'PLAN_SAVED_IN_TEMP'
 Emit 'ROUTES_TO_ADD' $toAdd
 Emit 'BORROWED_TO_PRESERVE' $borrowed
 Emit 'SYSTEM_MUTATIONS_PERFORMED' 'False'
 exit 0
}
if($Mode -eq 'MockApply'){
 if(-not (Test-Path -LiteralPath $prefixPath -PathType Leaf)){Emit 'MOCK_RESULT' 'BLOCKED_NO_PREFIX_INPUT';exit 42}
 if(-not (Test-Path -LiteralPath $planPath -PathType Leaf)){
  Emit 'MOCK_RESULT' 'BLOCKED_MOCK_PLAN_REQUIRED';exit 42
 }
 if(Test-Path -LiteralPath $journalPath -PathType Leaf){Emit 'MOCK_RESULT' 'BLOCKED_EXISTING_JOURNAL';exit 42}
 $world=ReadJson $worldPath
 $prefixes=@(Get-Content -LiteralPath $prefixPath|ForEach-Object{$_.Trim()}|Where-Object{$_})
 $plan=ReadJson $planPath
 $snapshotHash=WorldHash $world
 $prefixesHash=HashText ($prefixes -join ([char]10))
 if($plan.schema -ne $Script:Schema -or $plan.runId -ne $RunId -or
    $plan.worldHash -ne $snapshotHash -or $plan.prefixesHash -ne $prefixesHash){
  Emit 'MOCK_RESULT' 'BLOCKED_STALE_PLAN_OR_PREFIXES'
  exit 42
 }
 try{ValidateWorld $world $prefixes}catch{
  Emit 'MOCK_RESULT' ('BLOCKED_'+$_.Exception.Message);exit 42
 }
 $before=$snapshotHash
 $journal=[pscustomobject][ordered]@{
  schema=$Script:Schema;runId=$RunId;status='APPLYING'
  beforeHash=$before;beforeGateway=[string]$world.gateway
  beforeIndex=[int]$world.physicalIndex
  beforeRoutes=@(@($world.routes)|ForEach-Object{RouteKey $_})
  entries=@();events=@('SNAPSHOT_PERSISTED')
 }
 SaveJsonAtomic $journalPath $journal
 $index=0
 try{
  foreach($prefix in $prefixes){
   $index++
   if([string]$world.gateway -ne $journal.beforeGateway -or [int]$world.physicalIndex -ne $journal.beforeIndex){
    throw 'PHYSICAL_GATEWAY_DRIFT'
   }
   $existing=@(PrefixRoutes $world $prefix)
   if($existing.Count){
    $journal.events=@($journal.events)+@('BORROWED_'+$prefix)
    SaveJsonAtomic $journalPath $journal
    continue
   }
   $route=[pscustomobject][ordered]@{
     prefix=$prefix;ifIndex=[int]$world.physicalIndex
     nextHop=[string]$world.gateway;metric=5;store='ActiveStore'
   }
   # Two-phase journal: record intent BEFORE the mock write.
   $entry=[pscustomobject][ordered]@{
      prefix=$route.prefix;ifIndex=$route.ifIndex;nextHop=$route.nextHop
      metric=$route.metric;store=$route.store;state='INTENT'
   }
   $journal.entries=@($journal.entries)+@($entry)
   SaveJsonAtomic $journalPath $journal
   if($FailBeforeRoute -eq $index){throw ('FAULT_BEFORE_ROUTE_'+$index)}
   $world.routes=@($world.routes)+@($route)
   SaveJsonAtomic $worldPath $world
   if($CrashAfterRoute -eq $index){throw ('CRASH_AFTER_WRITE_'+$index)}
   if($CollideAtRoute -eq $index){
     $alien=[pscustomobject][ordered]@{
       prefix=$prefix;ifIndex=99;nextHop='192.0.2.99';metric=1;store='ActiveStore'
     }
     $world.routes=@($world.routes)+@($alien)
     SaveJsonAtomic $worldPath $world
     throw 'THIRD_PARTY_ROUTE_INSERTED'
   }
   if($NrptDriftAtRoute -eq $index){
     $world.nrpt[0].server='8.8.8.8'
     SaveJsonAtomic $worldPath $world
     throw 'NRPT_DRIFT'
   }
   if($GatewayDriftAtRoute -eq $index){
     $world.gateway='198.51.100.1'
     SaveJsonAtomic $worldPath $world
     throw 'GATEWAY_DRIFT'
   }
   if($ProxyDriftAtRoute -eq $index){
     $world.proxyServer='127.0.0.1:19999'
     SaveJsonAtomic $worldPath $world
     throw 'PROXY_DRIFT'
   }
   if($TimeoutAtRoute -eq $index){
     $journal.events=@($journal.events)+@('MOCK_TIMEOUT_FIRED')
     SaveJsonAtomic $journalPath $journal
     throw 'MOCK_TIMER_TIMEOUT'
   }
   if(@(ExactRoutes $world $route).Count -ne 1){throw 'POSTWRITE_IDENTITY_NOT_UNIQUE'}
   $journal.entries[-1].state='VERIFIED'
   $journal.events=@($journal.events)+@('ADD_VERIFIED_'+$index)
   SaveJsonAtomic $journalPath $journal
  }
  $journal.status='MOCK_APPLY_COMPLETE_AWAIT_ROLLBACK'
  SaveJsonAtomic $journalPath $journal
  Emit 'MOCK_RESULT' 'APPLY_SIMULATION_PASS'
  Emit 'JOURNAL_ENTRY_COUNT' @($journal.entries).Count
  Emit 'SYSTEM_MUTATIONS_PERFORMED' 'False'
  exit 0
 }catch{
  $journal.status='MOCK_APPLY_FAILED_AWAIT_ROLLBACK'
  $journal.events=@($journal.events)+@('FAULT_'+$_.Exception.Message)
  SaveJsonAtomic $journalPath $journal
  Emit 'MOCK_RESULT' 'APPLY_FAILED_ROLLBACK_REQUIRED'
  Emit 'FAILURE_CAUSE' $_.Exception.Message
  Emit 'JOURNAL_ENTRY_COUNT' @($journal.entries).Count
  Emit 'SYSTEM_MUTATIONS_PERFORMED' 'False'
  exit 3
 }
}
if($Mode -eq 'MockRollback'){
 if(-not (Test-Path -LiteralPath $journalPath -PathType Leaf)){Emit 'MOCK_RESULT' 'BLOCKED_JOURNAL_MISSING';exit 43}
 $world=ReadJson $worldPath
 $journal=ReadJson $journalPath
 if($journal.schema -ne $Script:Schema -or $journal.runId -ne $RunId){
  Emit 'MOCK_RESULT' 'BLOCKED_RUNID_SCHEMA_MISMATCH';exit 43
 }
 if(-not (Test-Path -LiteralPath $planPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $prefixPath -PathType Leaf)){
  Emit 'MOCK_RESULT' 'BLOCKED_MISSING_PLAN_EVIDENCE';exit 43
 }
 $plan=ReadJson $planPath
 $originalPrefixes=@(Get-Content -LiteralPath $prefixPath | ForEach-Object {$_.Trim()} | Where-Object {$_})
 $expectedPrefixHash=HashText ($originalPrefixes -join ([char]10))
 if($plan.schema -ne $Script:Schema -or $plan.runId -ne $RunId -or
    $plan.worldHash -ne $journal.beforeHash -or
    $plan.prefixesHash -ne $expectedPrefixHash){
  Emit 'MOCK_RESULT' 'BLOCKED_PLAN_JOURNAL_MISMATCH';exit 43
 }
 $approved=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
 foreach($prefix in $originalPrefixes){[void]$approved.Add($prefix)}
 foreach($entry in @($journal.entries)){
  if(-not $approved.Contains([string]$entry.prefix) -or
     [int]$entry.ifIndex -ne [int]$journal.beforeIndex -or
     [string]$entry.nextHop -ne [string]$journal.beforeGateway){
   Emit 'MOCK_RESULT' 'BLOCKED_JOURNAL_ROUTE_IDENTITY';exit 43
  }
 }
 if($journal.status -eq 'MOCK_ROLLBACK_VERIFIED' -and (WorldHash $world) -eq $journal.beforeHash){
  Emit 'MOCK_RESULT' 'ROLLBACK_IDEMPOTENT'
  Emit 'BASELINE_RESTORED' 'True'
  exit 0
 }
 $errors=[System.Collections.Generic.List[string]]::new()
 $entries=@($journal.entries)
 for($i=$entries.Count-1;$i -ge 0;$i--){
  $entry=$entries[$i]
  if($entry.state -eq 'REMOVED' -or $entry.state -eq 'NOT_PRESENT'){continue}
  $same=@(PrefixRoutes $world $entry.prefix)
  $exact=@(ExactRoutes $world $entry)
  if($same.Count -eq 0){
   $entry.state='NOT_PRESENT'
   SaveJsonAtomic $journalPath $journal
   continue
  }
  if($same.Count -ne 1 -or $exact.Count -ne 1){
   $errors.Add('AMBIGUOUS_OWNERSHIP_'+$entry.prefix)
   continue
  }
  if(@($journal.beforeRoutes) -contains (RouteKey $entry)){
   $errors.Add('PREEXISTING_ROUTE_MUST_NOT_DELETE_'+$entry.prefix)
   continue
  }
  $removeOnce=$false
  $kept=[System.Collections.Generic.List[object]]::new()
  foreach($route in @($world.routes)){
   if(-not $removeOnce -and (RouteKey $route) -ceq (RouteKey $entry)){
     $removeOnce=$true
   }else{$kept.Add($route)}
  }
  $world.routes=@($kept)
  SaveJsonAtomic $worldPath $world
  $entry.state='REMOVED'
  $journal.events=@($journal.events)+@('REMOVED_'+$entry.prefix)
  SaveJsonAtomic $journalPath $journal
 }
 $sameHash=(WorldHash $world) -eq $journal.beforeHash
 if(-not $sameHash){$errors.Add('ORIGINAL_BASELINE_NOT_RESTORED')}
 if($errors.Count){
   $journal.status='MOCK_ROLLBACK_INCOMPLETE'
   SaveJsonAtomic $journalPath $journal
   Emit 'MOCK_RESULT' 'ROLLBACK_INCOMPLETE'
   Emit 'BASELINE_RESTORED' 'False'
   Emit 'PROBLEM_COUNT' $errors.Count
   foreach($e in $errors){Emit 'ROLLBACK_PROBLEM' $e}
   Emit 'SYSTEM_MUTATIONS_PERFORMED' 'False'
   exit 4
 }
 $journal.status='MOCK_ROLLBACK_VERIFIED'
 $journal.events=@($journal.events)+@('VERIFY_HASH_MATCH')
 SaveJsonAtomic $journalPath $journal
 Emit 'MOCK_RESULT' 'ROLLBACK_SIMULATION_PASS'
 Emit 'BASELINE_RESTORED' 'True'
 Emit 'SYSTEM_MUTATIONS_PERFORMED' 'False'
 exit 0
}
