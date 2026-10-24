<#
Stage C P1G non-mutating regression: PowerShell 5.1 AST, fake-route
classification and before/after native route identity verification.
Fixture mode must NEVER issue system network queries.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$script:Source=Join-Path $PSScriptRoot 'stage-c-p1g-readonly-cn-plan-20261024.ps1'
$script:Exe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$pass=0;$fail=0
function Verify([bool]$Condition,[string]$Name){
    if($Condition){Write-Output ('PASS_'+$Name);$script:pass++}
    else{Write-Output ('FAIL_'+$Name);$script:fail++}
}
function RouteFingerprint {
    $r=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop|
        ForEach-Object{[string]$_.DestinationPrefix+'|'+[string]$_.InterfaceIndex+'|'+[string]$_.NextHop+'|'+[string]$_.RouteMetric}|
        Sort-Object)
    return ($r -join ';')
}
function FixtureRun($Fixture,[string[]]$Expected,[int]$Exit,[string]$Dataset){
    $json=ConvertTo-Json -InputObject $Fixture -Compress -Depth 12
    $fixturePath=Join-Path $root 'fixture-current.json'
    [IO.File]::WriteAllText($fixturePath,$json,[Text.UTF8Encoding]::new($false))
    $argsList=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
        '-File',$script:Source,'-Mode','Fixture','-DatasetPath',$Dataset,
        '-FixturePath',$fixturePath)
    $output=@(& $script:Exe @argsList 2>&1|ForEach-Object{[string]$_})
    $actualExit=$LASTEXITCODE
    $matches=($actualExit -eq $Exit)
    foreach($item in $Expected){
        if($output -notcontains $item){$matches=$false}
    }
    if($output -notcontains 'P1G_NETWORK_MUTATIONS_PERFORMED=False'){$matches=$false}
    return $matches
}
$root=Join-Path $env:TEMP ('p1g-fixtures-'+[guid]::NewGuid().ToString('N'))
try{
    $before=RouteFingerprint
    New-Item -Path $root -ItemType Directory -ErrorAction Stop|Out-Null
    $dataset=Join-Path $root 'expected.txt'
    [IO.File]::WriteAllLines($dataset,@('1.2.3.0/24','5.6.0.0/16'),[Text.UTF8Encoding]::new($false))
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($script:Source,[ref]$tokens,[ref]$errors)
    Verify (@($errors).Count -eq 0) 'AST_ZERO'
    $dangerous=@('New-NetRoute','Remove-NetRoute','Set-NetRoute','New-DnsClientNrptRule',
        'Remove-DnsClientNrptRule','Set-DnsClientNrptRule','Set-DnsClientServerAddress',
        'Set-ItemProperty','Set-NetIPInterface','Enable-NetAdapter','Disable-NetAdapter',
        'Start-Process','Invoke-Expression','Invoke-Command','Clear-DnsClientCache',
        'netsh','route','reg','sc')
    $cmds=@($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.CommandAst]
    },$true))
    $mutators=@($cmds|Where-Object{$_.GetCommandName() -in $dangerous})
    Verify ($mutators.Count -eq 0) 'NO_MUTATOR_COMMANDS'
    $fixture=[ordered]@{
        physicalDefaults=@([ordered]@{
            DestinationPrefix='0.0.0.0/0';InterfaceAlias='WLAN'
            InterfaceIndex=9;NextHop='192.168.0.1';RouteMetric=0
        })
        activeRoutes=@()
        persistentRoutes=@()
        proxyEnabled=1
        xrayCount=1
        wgPresent=$false
        halfCount=0
        nrptRuleCount=25
        nrptNamespaceCount=12160
        nrptExact=$true
        nrptMissing=0
        nrptExtra=0
        nrptBadServers=0
    }
    Verify (FixtureRun $fixture @(
        'P1G_CN_NO_EXACT_PREFIX_ROUTE_CANDIDATES=2',
        'P1G_CN_MATCHING_BUT_UNOWNED_PREFIXES=0',
        'P1G_CN_ACTIVE_CONFLICT_PREFIXES=0',
        'P1G_RESULT=FIXTURE_PLAN_COMPLETE',
        'P1G_FULL_CN_WRITE_AUTHORIZED=False'
    ) 0 $dataset) 'EMPTY_FIXTURE_TWO_CANDIDATES'

    $same=@{DestinationPrefix='1.2.3.0/24';InterfaceIndex=9;NextHop='192.168.0.1';RouteMetric=5}
    $fixture.activeRoutes=@($same)
    Verify (FixtureRun $fixture @(
        'P1G_CN_NO_EXACT_PREFIX_ROUTE_CANDIDATES=1',
        'P1G_CN_MATCHING_BUT_UNOWNED_PREFIXES=1',
        'P1G_RESULT=FIXTURE_PLAN_COMPLETE',
        'P1G_EXISTING_PREFIX_OWNERSHIP=UNKNOWN_NEVER_ADOPT'
    ) 0 $dataset) 'EXACT_EXISTING_ROUTE_NOT_CLAIMED_AS_OWNED'

    $fixture.activeRoutes=@(@{DestinationPrefix='1.2.3.0/24';InterfaceIndex=99;NextHop='192.168.0.1';RouteMetric=5})
    Verify (FixtureRun $fixture @(
        'P1G_CN_NO_EXACT_PREFIX_ROUTE_CANDIDATES=1',
        'P1G_CN_ACTIVE_CONFLICT_PREFIXES=1',
        'P1G_RESULT=BLOCKED_PREFIX_COLLISIONS'
    ) 2 $dataset) 'WRONG_INTERFACE_COLLISION_BLOCKED'

    $fixture.activeRoutes=@(@{DestinationPrefix='1.2.3.0/24';InterfaceIndex=9;NextHop='192.168.0.1';RouteMetric=8})
    Verify (FixtureRun $fixture @('P1G_CN_ACTIVE_CONFLICT_PREFIXES=1','P1G_RESULT=BLOCKED_PREFIX_COLLISIONS') 2 $dataset) 'WRONG_METRIC_COLLISION_BLOCKED'

    $fixture.activeRoutes=@()
    $fixture.persistentRoutes=@(@{DestinationPrefix='1.2.3.0/24';InterfaceIndex=9;NextHop='192.168.0.1';RouteMetric=5})
    Verify (FixtureRun $fixture @(
        'P1G_CN_PERSISTENT_CONFLICT_PREFIXES=1',
        'P1G_CN_NO_EXACT_PREFIX_ROUTE_CANDIDATES=1',
        'P1G_RESULT=BLOCKED_PREFIX_COLLISIONS'
    ) 2 $dataset) 'PERSISTENT_ROUTE_BLOCKED'

    $fixture.persistentRoutes=@()
    $fixture.physicalDefaults+=@{DestinationPrefix='0.0.0.0/0';InterfaceAlias='WLAN';InterfaceIndex=44;NextHop='10.0.0.1'}
    Verify (FixtureRun $fixture @(
        'P1G_PHYSICAL_DEFAULT_MATCHES=2',
        'P1G_RESULT=BLOCKED_PHYSICAL_GATE'
    ) 2 $dataset) 'AMBIGUOUS_PHYSICAL_GATE_BLOCKED'

    $fixture.physicalDefaults=@()
    Verify (FixtureRun $fixture @(
        'P1G_PHYSICAL_DEFAULT_MATCHES=0',
        'P1G_RESULT=BLOCKED_PHYSICAL_GATE'
    ) 2 $dataset) 'MISSING_PHYSICAL_GATE_BLOCKED'

    $fixture.physicalDefaults=@(@{DestinationPrefix='0.0.0.0/0';InterfaceAlias='WLAN';InterfaceIndex=9;NextHop='192.168.0.1'})
    $invalid=Join-Path $root 'invalid.txt'
    [IO.File]::WriteAllLines($invalid,@('1.2.3.1/24'),[Text.UTF8Encoding]::new($false))
    Verify (FixtureRun $fixture @(
        'P1G_CIDR_INVALID_OR_DUPLICATE=1',
        'P1G_RESULT=BLOCKED_INCOMPLETE'
    ) 4 $invalid) 'NONCANONICAL_CIDR_REJECTED'

    $duplicates=Join-Path $root 'duplicates.txt'
    [IO.File]::WriteAllLines($duplicates,@('1.2.3.0/24','1.2.3.0/24'),[Text.UTF8Encoding]::new($false))
    Verify (FixtureRun $fixture @(
        'P1G_CIDR_INVALID_OR_DUPLICATE=1',
        'P1G_RESULT=BLOCKED_INCOMPLETE'
    ) 4 $duplicates) 'DUPLICATE_CIDR_REJECTED'

    $argsBad=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
        '-File',$script:Source,'-Mode','Fixture','-DatasetPath',$dataset)
    $bad=@(& $script:Exe @argsBad 2>&1)
    Verify ($LASTEXITCODE -eq 4 -and @($bad|Where-Object{[string]$_ -eq 'P1G_RESULT=BLOCKED_INCOMPLETE'}).Count -eq 1) 'MISSING_FIXTURE_REJECTED'
    $after=RouteFingerprint
    Verify ($before -eq $after) 'NATIVE_ROUTE_IDENTITY_UNCHANGED'
    Write-Output ('P1G_TESTS_PASSED='+$pass)
    Write-Output ('P1G_TESTS_FAILED='+$fail)
    Write-Output 'P1G_TEST_NATIVE_NETWORK_WRITES=False'
    if($fail -gt 0){exit 2}
    exit 0
} catch {
    Write-Output ('P1G_TEST_FATAL='+$_.Exception.Message)
    exit 4
} finally {
    if(Test-Path -LiteralPath $root){
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
