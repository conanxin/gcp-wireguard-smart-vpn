[CmdletBinding()]
param(
    [string]$BaseUrl = 'https://github.com/v2fly/domain-list-community/releases/latest/download',
    [string]$OutputFile = (Join-Path (Split-Path $PSScriptRoot -Parent) 'data\cn-nrpt-namespaces.txt'),
    [string]$UnsupportedRegexpFile = (Join-Path (Split-Path $PSScriptRoot -Parent) 'data\cn-nrpt-unsupported-regexp.txt'),
    [switch]$DryRun
)

$ErrorActionPreference='Stop'

function Test-NamespaceMatch {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.HashSet[string]]$Namespaces
    )

    $name=$Domain.ToLowerInvariant()

    if($Namespaces.Contains($name)){
        return $true
    }

    $parts=$name -split '\.'

    for($i=1;$i-lt$parts.Count;$i++){
        $suffix='.'+($parts[$i..($parts.Count-1)] -join '.')

        if($Namespaces.Contains($suffix)){
            return $true
        }
    }

    return $false
}

Write-Host 'WireGuard SMART VPN - Update CN Domain Dataset'
Write-Host ('=' * 72)

Write-Host ''
Write-Host '=== SOURCE ==='

$ymlUrl="$BaseUrl/dlc.dat_plain.yml"
$shaUrl="$BaseUrl/dlc.dat_plain.yml.sha256sum"

Write-Host "YAML_URL=$ymlUrl"
Write-Host "SHA_URL=$shaUrl"
Write-Host "OUTPUT=$OutputFile"
Write-Host "UNSUPPORTED_REGEXP_OUTPUT=$UnsupportedRegexpFile"
Write-Host "DRY_RUN=$([bool]$DryRun)"

$curl=Get-Command curl.exe -ErrorAction SilentlyContinue

if(!$curl){
    throw 'CURL_NOT_FOUND'
}

$tmpYml=Join-Path $env:TEMP (
    'dlc-dat-plain-' +
    [guid]::NewGuid().ToString('N') +
    '.yml'
)

$tmpSha=Join-Path $env:TEMP (
    'dlc-dat-plain-' +
    [guid]::NewGuid().ToString('N') +
    '.sha256sum'
)

try {

    Write-Host ''
    Write-Host '=== DOWNLOAD ==='

    $commonCurlArgs=@(
        '--silent',
        '--show-error',
        '--http1.1',
        '-fL',
        '--retry','3',
        '--retry-all-errors',
        '--connect-timeout','15'
    )

    $ymlCurlArgs=@(
        $commonCurlArgs +
        @(
            '--max-time',
            '180',
            '-o',
            $tmpYml,
            $ymlUrl
        )
    )

    & $curl.Source @ymlCurlArgs

    if($LASTEXITCODE -ne 0){
        throw "DOMAIN_LIST_DOWNLOAD_FAILED exit=$LASTEXITCODE"
    }

    $shaCurlArgs=@(
        $commonCurlArgs +
        @(
            '--max-time',
            '60',
            '-o',
            $tmpSha,
            $shaUrl
        )
    )

    & $curl.Source @shaCurlArgs

    if($LASTEXITCODE -ne 0){
        throw "DOMAIN_LIST_SHA_DOWNLOAD_FAILED exit=$LASTEXITCODE"
    }

    if(
        !(Test-Path -LiteralPath $tmpYml) -or
        !(Test-Path -LiteralPath $tmpSha)
    ){
        throw 'DOMAIN_LIST_DOWNLOAD_ARTIFACT_MISSING'
    }

    $ymlItem=Get-Item -LiteralPath $tmpYml

    Write-Host "DOWNLOAD_SIZE=$($ymlItem.Length)"

    if($ymlItem.Length -lt 1000000){
        throw 'DOMAIN_LIST_DOWNLOAD_TOO_SMALL'
    }

    $shaText=(
        Get-Content -LiteralPath $tmpSha -Raw
    ).Trim()

    $expectedSha=(
        $shaText -split '\s+'
    )[0].ToUpperInvariant()

    $actualSha=(
        Get-FileHash `
            -LiteralPath $tmpYml `
            -Algorithm SHA256
    ).Hash.ToUpperInvariant()

    Write-Host "EXPECTED_SHA256=$expectedSha"
    Write-Host "ACTUAL_SHA256=$actualSha"

    if($expectedSha -notmatch '^[0-9A-F]{64}$'){
        throw 'INVALID_RELEASE_SHA256_FORMAT'
    }

    if($expectedSha -ne $actualSha){
        throw 'RELEASE_SHA256_MISMATCH'
    }

    Write-Host 'SHA256_VERIFY=PASS'

    Write-Host ''
    Write-Host '=== EXTRACT CN RULES ==='

    $inside=$false
    $found=$false
    $declaredLength=$null

    $rules=[System.Collections.Generic.List[string]]::new()

    foreach($line in Get-Content -LiteralPath $tmpYml){

        if($line -match '^\s*-\s+name:\s+"([^"]+)"\s*$'){

            if($inside){
                break
            }

            $inside=($Matches[1] -eq 'cn')

            if($inside){
                $found=$true
            }

            continue
        }

        if(!$inside){
            continue
        }

        if($line -match '^\s+length:\s+(\d+)\s*$'){
            $declaredLength=[int]$Matches[1]
            continue
        }

        if($line -match '^\s+-\s+"(.*)"\s*$'){
            $rules.Add($Matches[1])
        }
    }

    Write-Host "CN_SECTION_FOUND=$found"
    Write-Host "DECLARED_LENGTH=$declaredLength"
    Write-Host "EXTRACTED_RULES=$($rules.Count)"

    if(!$found){
        throw 'CN_RULE_SECTION_NOT_FOUND'
    }

    if($null -eq $declaredLength){
        throw 'CN_RULE_DECLARED_LENGTH_NOT_FOUND'
    }

    if($declaredLength -ne $rules.Count){
        throw 'CN_RULE_LENGTH_MISMATCH'
    }

    Write-Host 'LENGTH_MATCH=PASS'

    Write-Host ''
    Write-Host '=== CLASSIFY RULES ==='

    $domainSet=[System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $fullSet=[System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $regexpRules=[System.Collections.Generic.List[string]]::new()
    $keywordRules=[System.Collections.Generic.List[string]]::new()
    $otherRules=[System.Collections.Generic.List[string]]::new()

    foreach($rule in $rules){

        if($rule -match '^domain:([^:]+)'){
            $value=$Matches[1].Trim().ToLowerInvariant()

            if($value){
                [void]$domainSet.Add($value)
            }

            continue
        }

        if($rule -match '^full:([^:]+)'){
            $value=$Matches[1].Trim().ToLowerInvariant()

            if($value){
                [void]$fullSet.Add($value)
            }

            continue
        }

        if($rule -match '^regexp:'){
            $regexpRules.Add($rule)
            continue
        }

        if($rule -match '^keyword:'){
            $keywordRules.Add($rule)
            continue
        }

        $otherRules.Add($rule)
    }

    Write-Host "DOMAIN_RAW=$($domainSet.Count)"
    Write-Host "FULL_RAW=$($fullSet.Count)"
    Write-Host "REGEXP_UNSUPPORTED=$($regexpRules.Count)"
    Write-Host "KEYWORD_UNSUPPORTED=$($keywordRules.Count)"
    Write-Host "OTHER_UNSUPPORTED=$($otherRules.Count)"

    if($keywordRules.Count){
        Write-Host '--- KEYWORD RULE SAMPLE ---'
        $keywordRules | Select-Object -First 20 | Out-Host

        throw 'KEYWORD_RULES_REQUIRE_MANUAL_SUPPORT'
    }

    if($otherRules.Count){
        Write-Host '--- UNKNOWN RULE SAMPLE ---'
        $otherRules | Select-Object -First 20 | Out-Host

        throw 'UNKNOWN_RULE_TYPES_FOUND'
    }

    Write-Host ''
    Write-Host '=== MINIMIZE DOMAIN RULES ==='

    $domainList=@(
        $domainSet |
        Sort-Object `
            @{Expression={($_ -split '\.').Count}},
            @{Expression={$_.Length}},
            @{Expression={$_}}
    )

    $keptDomains=[System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach($domainName in $domainList){

        $parts=$domainName -split '\.'
        $covered=$false

        for($i=1;$i-lt$parts.Count;$i++){

            $parent=(
                $parts[$i..($parts.Count-1)] -join '.'
            )

            if($keptDomains.Contains($parent)){
                $covered=$true
                break
            }
        }

        if(!$covered){
            [void]$keptDomains.Add($domainName)
        }
    }

    Write-Host "DOMAIN_MINIMIZED=$($keptDomains.Count)"
    Write-Host "DOMAIN_REDUNDANT=$($domainSet.Count-$keptDomains.Count)"

    Write-Host ''
    Write-Host '=== MINIMIZE FULL RULES ==='

    $keptFull=[System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $fullCovered=0

    foreach($fullName in ($fullSet | Sort-Object)){

        $parts=$fullName -split '\.'
        $covered=$keptDomains.Contains($fullName)

        if(!$covered){

            for($i=1;$i-lt$parts.Count;$i++){

                $parent=(
                    $parts[$i..($parts.Count-1)] -join '.'
                )

                if($keptDomains.Contains($parent)){
                    $covered=$true
                    break
                }
            }
        }

        if($covered){
            $fullCovered++
        }
        else {
            [void]$keptFull.Add($fullName)
        }
    }

    Write-Host "FULL_MINIMIZED=$($keptFull.Count)"
    Write-Host "FULL_COVERED_BY_DOMAIN=$fullCovered"

    Write-Host ''
    Write-Host '=== BUILD NRPT NAMESPACES ==='

    $namespaceSet=[System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach($domainName in $keptDomains){
        [void]$namespaceSet.Add($domainName)
        [void]$namespaceSet.Add('.'+$domainName)
    }

    foreach($fullName in $keptFull){
        [void]$namespaceSet.Add($fullName)
    }

    $namespaces=@(
        $namespaceSet |
        Sort-Object
    )

    Write-Host "NAMESPACE_FINAL=$($namespaces.Count)"
    Write-Host "UNIQUE_NAMESPACES=$(($namespaces | Sort-Object -Unique).Count)"

    if(!$namespaces.Count){
        throw 'EMPTY_NRPT_NAMESPACE_RESULT'
    }

    if(
        $namespaces.Count -ne
        ($namespaces | Sort-Object -Unique).Count
    ){
        throw 'DUPLICATE_NRPT_NAMESPACES'
    }

    Write-Host ''
    Write-Host '=== GENERIC TLD RISK ==='

    $genericTlds=@(
        'com',
        'net',
        'org',
        'io',
        'dev',
        'ai',
        'app',
        'cloud',
        'xyz',
        'top',
        'biz',
        'info',
        'me',
        'tv',
        'co'
    )

    $dangerousTlds=[System.Collections.Generic.List[string]]::new()

    foreach($tld in $genericTlds){

        if(
            $namespaceSet.Contains($tld) -or
            $namespaceSet.Contains('.'+$tld)
        ){
            $dangerousTlds.Add($tld)
        }
    }

    Write-Host "GENERIC_TLD_RISK_COUNT=$($dangerousTlds.Count)"

    if($dangerousTlds.Count){
        Write-Host (
            'GENERIC_TLD_RISKS=' +
            ($dangerousTlds -join ',')
        )

        throw 'DANGEROUS_GENERIC_TLD_NAMESPACE_FOUND'
    }

    Write-Host ''
    Write-Host '=== SEMANTIC SANITY ==='

    $directTests=@(
        'baidu.com',
        'www.baidu.com',
        'bilibili.com',
        'www.bilibili.com',
        'jd.com',
        'www.jd.com',
        'taobao.com',
        'www.taobao.com',
        'qq.com',
        'www.qq.com',
        'example.cn',
        'www.example.cn'
    )

    $vpnTests=@(
        'google.com',
        'www.google.com',
        'github.com',
        'api.github.com',
        'openai.com',
        'api.openai.com',
        'youtube.com',
        'www.youtube.com',
        'x.com'
    )

    $semanticPass=$true

    foreach($domain in $directTests){

        $match=Test-NamespaceMatch `
            -Domain $domain `
            -Namespaces $namespaceSet

        Write-Host "$domain DIRECT=$match"

        if(!$match){
            $semanticPass=$false
        }
    }

    foreach($domain in $vpnTests){

        $match=Test-NamespaceMatch `
            -Domain $domain `
            -Namespaces $namespaceSet

        Write-Host "$domain IN_CN=$match"

        if($match){
            $semanticPass=$false
        }
    }

    Write-Host "SEMANTIC_SANITY=$semanticPass"

    if(!$semanticPass){
        throw 'DOMAIN_SEMANTIC_SANITY_FAILED'
    }

    Write-Host ''
    Write-Host '=== REGEXP AUDIT ==='

    Write-Host "REGEXP_UNSUPPORTED=$($regexpRules.Count)"

    if($regexpRules.Count){
        $regexpRules |
        Select-Object -First 20 |
        Out-Host
    }

    Write-Host ''
    Write-Host '=== RESULT ==='

    if($DryRun){

        Write-Host 'OUTPUT_WRITE=SKIPPED'
        Write-Host 'UPDATE_CN_DOMAINS_DRY_RUN=PASS'
        Write-Host 'NO_DATASET_CHANGED=TRUE'
        exit 0
    }

    $outputParent=Split-Path -Parent $OutputFile

    if(!(Test-Path -LiteralPath $outputParent)){
        New-Item `
            -ItemType Directory `
            -Force `
            -Path $outputParent |
        Out-Null
    }

    $unsupportedParent=Split-Path -Parent $UnsupportedRegexpFile

    if(!(Test-Path -LiteralPath $unsupportedParent)){
        New-Item `
            -ItemType Directory `
            -Force `
            -Path $unsupportedParent |
        Out-Null
    }

    $namespaces |
    Set-Content `
        -LiteralPath $OutputFile `
        -Encoding ASCII

    $regexpRules |
    Set-Content `
        -LiteralPath $UnsupportedRegexpFile `
        -Encoding ASCII

    $writtenNamespaces=@(
        Get-Content -LiteralPath $OutputFile |
        ForEach-Object {$_.Trim()} |
        Where-Object {$_}
    )

    $writtenRegexp=@(
        Get-Content -LiteralPath $UnsupportedRegexpFile |
        Where-Object {$_.Trim()}
    )

    Write-Host "OUTPUT_WRITE=YES"
    Write-Host "OUTPUT_SIZE=$((Get-Item -LiteralPath $OutputFile).Length)"
    Write-Host "OUTPUT_LINES=$($writtenNamespaces.Count)"
    Write-Host "OUTPUT_SHA256=$((Get-FileHash -LiteralPath $OutputFile -Algorithm SHA256).Hash)"

    Write-Host "REGEXP_OUTPUT_LINES=$($writtenRegexp.Count)"
    Write-Host "REGEXP_OUTPUT_SHA256=$((Get-FileHash -LiteralPath $UnsupportedRegexpFile -Algorithm SHA256).Hash)"

    if($writtenNamespaces.Count -ne $namespaces.Count){
        throw 'OUTPUT_NAMESPACE_LINE_COUNT_MISMATCH'
    }

    if($writtenRegexp.Count -ne $regexpRules.Count){
        throw 'OUTPUT_REGEXP_LINE_COUNT_MISMATCH'
    }

    Write-Host 'UPDATE_CN_DOMAINS=PASS'
}
finally {

    Remove-Item `
        -LiteralPath $tmpYml,$tmpSha `
        -Force `
        -ErrorAction SilentlyContinue
}
