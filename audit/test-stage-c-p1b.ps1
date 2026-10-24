<#
Windows PowerShell 5.1 Stage C P1B native-adapter contract MOCK tests.
Creates only synthetic fixture JSON/journals in this user's TEMP.
No real route service, NRPT, DNS, xray, WinINET, WG or firewall writes.
-Group 1 / 2 / 3 distributes tests across short processes.
#>
[CmdletBinding()]
param([ValidateSet('1','2','3')][string]$Group='1')
$ErrorActionPreference='Stop'
$Script:passed=0
$Script:failed=0
$Script:total=0
$Script:ps='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$Script:driver=Join-Path $PSScriptRoot 'stage-c-p1b-route-transaction.ps1'
$Script:fixtures=[System.Collections.Generic.List[string]]::new()
function Check([bool]$Ok,[string]$Name){
 $Script:total++
 if($Ok){$Script:passed++;Write-Output ('PASS '+$Name)}
 else{$Script:failed++;Write-Output ('FAIL '+$Name)}
}
function New-Fixture {
 param([string[]]$Prefixes=@('1.0.1.0/24','223.5.5.0/24','36.0.0.0/8'),
       [object[]]$Routes=@(),
       [string]$Proxy='127.0.0.1:7897',
       [string]$Resolver='223.5.5.5',
       [bool]$WgActive=$false)
 $base=[System.IO.Path]::GetTempPath()
 $folder=Join-Path $base ('wg-stage-c-p1b-fixture-'+[Guid]::NewGuid().ToString('N'))
 [void][System.IO.Directory]::CreateDirectory($folder)
 $Script:fixtures.Add($folder)
 $world=[ordered]@{
  physicalIndex=13;gateway='192.0.2.1'
  proxyEnabled=1;proxyServer=$Proxy;wgActive=$WgActive
  routes=@($Routes)
  nrpt=@([ordered]@{id='F001';server=$Resolver;namespaces=@('.baidu.com','baidu.com')})
 }
 [System.IO.File]::WriteAllText((Join-Path $folder 'mockworld.json'),
  ($world | ConvertTo-Json -Depth 12),[System.Text.UTF8Encoding]::new($false))
 [System.IO.File]::WriteAllLines((Join-Path $folder 'prefixes.txt'),
  [string[]]$Prefixes,[System.Text.UTF8Encoding]::new($false))
 return $folder
}
function Invoke-Driver {
 param([string]$Fixture,[string]$Mode,[string]$RunId='TEST-001',[hashtable]$Extra=@{})
 $args=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
         '-File',$Script:driver,'-Mode',$Mode,'-RunId',$RunId)
 if($Fixture){$args+=@('-MockRoot',$Fixture)}
 foreach($key in @($Extra.Keys|Sort-Object)){
  $args+=('-'+$key)
  $args+=([string]$Extra[$key])
 }
 $save=$ErrorActionPreference
 $ErrorActionPreference='Continue'
 try {
  $out=@(& $Script:ps @args 2>&1)
  $exitCode=$LASTEXITCODE
 } finally {$ErrorActionPreference=$save}
 return [pscustomobject]@{
    Exit=[int]$exitCode
    Text=(($out|ForEach-Object { [string]$_ }) -join [char]10)
 }
}
function Has($Result,[string]$Text){
 return ($Result.Text.Contains($Text))
}
function Read-World([string]$Folder) {
 return (Get-Content -LiteralPath (Join-Path $Folder 'mockworld.json') -Raw | ConvertFrom-Json)
}
function Read-Journal([string]$Folder,[string]$Id='TEST-001'){
 return (Get-Content -LiteralPath (Join-Path $Folder ('journal-'+$Id+'.json')) -Raw | ConvertFrom-Json)
}
function Start-ApplyRollback([string]$Folder,[hashtable]$Extra=@{}){
 $plan=Invoke-Driver $Folder 'MockPlan'
 $apply=if($plan.Exit -eq 0){Invoke-Driver $Folder 'MockApply' -Extra $Extra}else{$null}
 $rollback=if($apply -and (Test-Path (Join-Path $Folder 'journal-TEST-001.json'))){
    Invoke-Driver $Folder 'MockRollback'
 }else{$null}
 return [pscustomobject]@{Plan=$plan;Apply=$apply;Rollback=$rollback}
}
function Borrowed([string]$Prefix){
 return [ordered]@{prefix=$Prefix;ifIndex=13;nextHop='192.0.2.1';metric=19;store='ActiveStore'}
}
function Alien([string]$Prefix){
 return [ordered]@{prefix=$Prefix;ifIndex=99;nextHop='198.51.100.1';metric=1;store='ActiveStore'}
}

try {
 if($Group -eq '1'){
  $a=Invoke-Driver '' 'NativeApply'
  Check ($a.Exit -eq 40 -and (Has $a 'NATIVE_GATE=HARD_DISABLED')) 'native-apply-hard-gate'
  $a=Invoke-Driver '' 'NativeRollback'
  Check ($a.Exit -eq 40 -and (Has $a 'NATIVE_GATE=HARD_DISABLED')) 'native-rollback-hard-gate'
  $a=Invoke-Driver $env:USERPROFILE 'MockApply'
  Check ($a.Exit -eq 41 -and (Has $a 'BLOCKED_OUTSIDE_TEMP_FIXTURE')) 'outside-temp-blocked'
  $folder=New-Fixture
  $o=Start-ApplyRollback $folder
  Check ($o.Plan.Exit -eq 0 -and $o.Apply.Exit -eq 0 -and
         $o.Rollback.Exit -eq 0 -and
         (Has $o.Rollback 'BASELINE_RESTORED=True')) 'separate-process-cycle'
  $again=Invoke-Driver $folder 'MockRollback'
  Check ($again.Exit -eq 0 -and (Has $again 'ROLLBACK_IDEMPOTENT')) 'repeat-rollback-idempotent'
  $folder=New-Fixture -Routes @((Borrowed '223.5.5.0/24'))
  $o=Start-ApplyRollback $folder
  $world=Read-World $folder
  $journal=Read-Journal $folder
  Check ($o.Apply.Exit -eq 0 -and
         (Has $o.Plan 'BORROWED_TO_PRESERVE=1') -and
         $o.Rollback.Exit -eq 0 -and
         @($world.routes).Count -eq 1 -and
         [int]$world.routes[0].metric -eq 19 -and
         @($journal.entries).Count -eq 2) 'borrowed-route-not-deleted'
  $folder=New-Fixture
  $plan=Invoke-Driver $folder 'MockPlan'
  $world=Read-World $folder
  $world.proxyEnabled=0
  [IO.File]::WriteAllText((Join-Path $folder 'mockworld.json'),
   ($world|ConvertTo-Json -Depth 12))
  $apply=Invoke-Driver $folder 'MockApply'
  Check ($plan.Exit -eq 0 -and $apply.Exit -eq 42 -and
         (Has $apply 'BLOCKED_STALE_PLAN_OR_PREFIXES') -and
         -not (Test-Path (Join-Path $folder 'journal-TEST-001.json'))) 'stale-world-aborts-before-journal'
  $folder=New-Fixture
  $plan=Invoke-Driver $folder 'MockPlan'
  [IO.File]::AppendAllText((Join-Path $folder 'prefixes.txt'),
   [Environment]::NewLine+'11.0.0.0/24')
  $apply=Invoke-Driver $folder 'MockApply'
  Check ($plan.Exit -eq 0 -and $apply.Exit -eq 42 -and
         (Has $apply 'BLOCKED_STALE_PLAN_OR_PREFIXES')) 'edited-prefix-input-blocked'
 }
 if($Group -eq '2'){
  $folder=New-Fixture -Routes @((Alien '223.5.5.0/24'))
  $plan=Invoke-Driver $folder 'MockPlan'
  Check ($plan.Exit -eq 42 -and
         (Has $plan 'FOREIGN_ROUTE_COLLISION')) 'third-party-conflict-preflight'
  $folder=New-Fixture -Resolver '8.8.8.8'
  $plan=Invoke-Driver $folder 'MockPlan'
  Check ($plan.Exit -eq 42 -and
         (Has $plan 'NRPT_RESOLVER_INVALID')) 'wrong-nrpt-server'
  $folder=New-Fixture -Proxy '127.0.0.1:7898'
  $plan=Invoke-Driver $folder 'MockPlan'
  Check ($plan.Exit -eq 42 -and
         (Has $plan 'PROXY_NOT_XRAY_BASELINE')) 'unexpected-proxy-blocked'
  $folder=New-Fixture -Prefixes @('11.0.0.0/24','11.0.0.0/25')
  $plan=Invoke-Driver $folder 'MockPlan'
  Check ($plan.Exit -eq 42 -and
         (Has $plan 'OVERLAPPING_PREFIXES')) 'overlapping-cidrs-rejected'
  $folder=New-Fixture -Prefixes @('11.0.0.0/24','11.0.0.0/24')
  $plan=Invoke-Driver $folder 'MockPlan'
  Check ($plan.Exit -eq 42 -and
         (Has $plan 'OVERLAPPING_PREFIXES')) 'duplicate-cidrs-rejected'
  $routeOne=Borrowed '223.5.5.0/24'
  $routeTwo=Borrowed '223.5.5.0/24'
  $routeTwo.metric=23
  $folder=New-Fixture -Routes @($routeOne,$routeTwo)
  $plan=Invoke-Driver $folder 'MockPlan'
  Check ($plan.Exit -eq 42 -and
         (Has $plan 'AMBIGUOUS_PREEXISTING_ROUTE')) 'multiple-preexisting-routes-fail-closed'
  $prefixes=[System.Collections.Generic.List[string]]::new()
  for($i=0;$i -lt 150;$i++){$prefixes.Add(('11.0.{0}.0/24' -f $i))}
  $folder=New-Fixture -Prefixes @($prefixes)
  $o=Start-ApplyRollback $folder -Extra @{FailBeforeRoute=100}
  $journal=Read-Journal $folder
  Check ($o.Plan.Exit -eq 0 -and $o.Apply.Exit -eq 3 -and
         (Has $o.Apply 'FAULT_BEFORE_ROUTE_100') -and
         @($journal.entries).Count -eq 100 -and
         $journal.entries[99].state -eq 'NOT_PRESENT' -and
         $o.Rollback.Exit -eq 0 -and
         (Has $o.Rollback 'BASELINE_RESTORED=True')) 'route-100-failure-separate-rollback'
  $folder=New-Fixture
  $o=Start-ApplyRollback $folder -Extra @{CrashAfterRoute=2}
  Check ($o.Apply.Exit -eq 3 -and
         (Has $o.Apply 'CRASH_AFTER_WRITE_2') -and
         $o.Rollback.Exit -eq 0 -and
         (Has $o.Rollback 'BASELINE_RESTORED=True')) 'crash-after-write-journal-recovers'
 }
 if($Group -eq '3'){
  $folder=New-Fixture
  $o=Start-ApplyRollback $folder -Extra @{CollideAtRoute=1}
  $w=Read-World $folder
  Check ($o.Apply.Exit -eq 3 -and $o.Rollback.Exit -eq 4 -and
         (Has $o.Rollback 'AMBIGUOUS_OWNERSHIP_') -and
         @($w.routes).Count -eq 2) 'third-party-collision-fail-closed'
  $folder=New-Fixture
  $o=Start-ApplyRollback $folder -Extra @{NrptDriftAtRoute=1}
  $w=Read-World $folder
  Check ($o.Apply.Exit -eq 3 -and $o.Rollback.Exit -eq 4 -and
         (Has $o.Rollback 'ORIGINAL_BASELINE_NOT_RESTORED') -and
         $w.nrpt[0].server -eq '8.8.8.8') 'external-nrpt-drift-preserved-and-incomplete'
  $folder=New-Fixture
  $o=Start-ApplyRollback $folder -Extra @{GatewayDriftAtRoute=1}
  Check ($o.Apply.Exit -eq 3 -and $o.Rollback.Exit -eq 4 -and
         (Has $o.Rollback 'ORIGINAL_BASELINE_NOT_RESTORED')) 'gateway-drift-not-false-pass'
  $folder=New-Fixture
  $o=Start-ApplyRollback $folder -Extra @{TimeoutAtRoute=2}
  Check ($o.Apply.Exit -eq 3 -and $o.Rollback.Exit -eq 0 -and
         (Has $o.Apply 'MOCK_TIMER_TIMEOUT') -and
         (Has $o.Rollback 'BASELINE_RESTORED=True')) 'mock-timer-expiry-separate-process-recovery'
  $folder=New-Fixture
  $o=Start-ApplyRollback $folder -Extra @{ProxyDriftAtRoute=1}
  $w=Read-World $folder
  Check ($o.Apply.Exit -eq 3 -and $o.Rollback.Exit -eq 4 -and
         $w.proxyServer -eq '127.0.0.1:19999') 'proxy-drift-not-overwritten'
  $folder=New-Fixture
  $rollback=Invoke-Driver $folder 'MockRollback'
  Check ($rollback.Exit -eq 43 -and
         (Has $rollback 'BLOCKED_JOURNAL_MISSING')) 'no-journal-rollback-blocked'
  $folder=New-Fixture
  $plan=Invoke-Driver $folder 'MockPlan'
  $apply=Invoke-Driver $folder 'MockApply'
  $secondApply=Invoke-Driver $folder 'MockApply'
  $rollback=Invoke-Driver $folder 'MockRollback'
  Check ($plan.Exit -eq 0 -and $apply.Exit -eq 0 -and
         $secondApply.Exit -eq 42 -and
         (Has $secondApply 'BLOCKED_EXISTING_JOURNAL') -and
         $rollback.Exit -eq 0) 'repeat-apply-blocked-no-double-writes'
  $folder=New-Fixture
  $plan=Invoke-Driver $folder 'MockPlan'
  $apply=Invoke-Driver $folder 'MockApply'
  $journal=Read-Journal $folder
  $journal.runId='OTHER-RUN'
  [IO.File]::WriteAllText((Join-Path $folder 'journal-TEST-001.json'),
   ($journal|ConvertTo-Json -Depth 12))
  $rollback=Invoke-Driver $folder 'MockRollback'
  Check ($plan.Exit -eq 0 -and $apply.Exit -eq 0 -and
         $rollback.Exit -eq 43 -and
         (Has $rollback 'BLOCKED_RUNID_SCHEMA_MISMATCH')) 'journal-runid-tamper-fail-closed'
  $folder=New-Fixture
  $plan=Invoke-Driver $folder 'MockPlan'
  $apply=Invoke-Driver $folder 'MockApply'
  $journal=Read-Journal $folder
  $journal.entries[0].prefix='8.8.8.0/24'
  [IO.File]::WriteAllText((Join-Path $folder 'journal-TEST-001.json'),
    ($journal|ConvertTo-Json -Depth 12))
  $rollback=Invoke-Driver $folder 'MockRollback'
  Check ($plan.Exit -eq 0 -and $apply.Exit -eq 0 -and
         $rollback.Exit -eq 43 -and
         (Has $rollback 'BLOCKED_JOURNAL_ROUTE_IDENTITY')) 'tampered-ledger-route-identity-blocked'
  $folder=New-Fixture
  $plan=Invoke-Driver $folder 'MockPlan'
  $secondPlan=Invoke-Driver $folder 'MockPlan'
  Check ($plan.Exit -eq 0 -and $secondPlan.Exit -eq 42 -and
         (Has $secondPlan 'BLOCKED_PREVIOUS_PLAN_OR_JOURNAL')) 'double-plan-blocked'
 }
}finally{
 foreach($folder in $Script:fixtures){
  if(Test-Path -LiteralPath $folder){
   [IO.Directory]::Delete($folder,$true)
  }
 }
 Write-Output ('FIXTURES_CLEANED='+$Script:fixtures.Count)
 Write-Output 'REAL_NETWORK_MUTATIONS_PERFORMED=False'
 Write-Output ('P1B_GROUP='+$Group)
 Write-Output ('P1B_GROUP_TOTAL='+$Script:total)
 Write-Output ('P1B_GROUP_PASSED='+$Script:passed)
 Write-Output ('P1B_GROUP_FAILED='+$Script:failed)
}
if($Script:failed -gt 0){exit 2}
exit 0
