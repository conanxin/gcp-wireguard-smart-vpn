[CmdletBinding()]
param(
    [string]$SourceUrl = 'https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest',
    [string]$OutputFile = (Join-Path (Split-Path $PSScriptRoot -Parent) 'data\cn-ipv4-cidrs.txt'),
    [switch]$DryRun
)

$ErrorActionPreference='Stop'

function Convert-IPv4ToUInt64 {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Address
    )

    $bytes=[System.Net.IPAddress]::Parse($Address).GetAddressBytes()

    if($bytes.Length -ne 4){
        throw "NOT_IPV4=$Address"
    }

    return (
        ([uint64]$bytes[0] -shl 24) -bor
        ([uint64]$bytes[1] -shl 16) -bor
        ([uint64]$bytes[2] -shl 8)  -bor
        [uint64]$bytes[3]
    )
}

function Convert-UInt64ToIPv4 {
    param(
        [Parameter(Mandatory=$true)]
        [uint64]$Value
    )

    return (
        '{0}.{1}.{2}.{3}' -f
        (($Value -shr 24) -band 255),
        (($Value -shr 16) -band 255),
        (($Value -shr 8) -band 255),
        ($Value -band 255)
    )
}

function Convert-RangeToCidrs {
    param(
        [Parameter(Mandatory=$true)]
        [uint64]$Start,

        [Parameter(Mandatory=$true)]
        [uint64]$End
    )

    $result=[System.Collections.Generic.List[string]]::new()

    while($Start -le $End){

        $remaining=$End-$Start+1

        if($Start -eq 0){
            [uint64]$block=4294967296
        }
        else {
            [uint64]$block=1

            while(
                $block -lt 4294967296 -and
                ($Start % ($block*2)) -eq 0
            ){
                $block*=2
            }
        }

        while($block -gt $remaining){
            $block=[uint64]($block/2)
        }

        $bits=0
        [uint64]$temp=$block

        while($temp -gt 1){
            $bits++
            $temp=[uint64]($temp/2)
        }

        $prefix=32-$bits

        $result.Add(
            ('{0}/{1}' -f
                (Convert-UInt64ToIPv4 -Value $Start),
                $prefix
            )
        )

        $Start+=$block
    }

    return $result
}

function Test-AddressInRanges {
    param(
        [string]$Address,
        [object[]]$Ranges
    )

    [uint64]$value=Convert-IPv4ToUInt64 $Address

    foreach($range in $Ranges){
        if(
            $value -ge $range.Start -and
            $value -le $range.End
        ){
            return $true
        }
    }

    return $false
}

Write-Host 'WireGuard SMART VPN - Update CN IPv4 Dataset'
Write-Host ('=' * 72)

Write-Host ''
Write-Host '=== SOURCE ==='
Write-Host "URL=$SourceUrl"
Write-Host "OUTPUT=$OutputFile"
Write-Host "DRY_RUN=$([bool]$DryRun)"

$curl=Get-Command curl.exe -ErrorAction SilentlyContinue

if(!$curl){
    throw 'CURL_NOT_FOUND'
}

$tmp=Join-Path $env:TEMP (
    'delegated-apnic-' +
    [guid]::NewGuid().ToString('N') +
    '.txt'
)

try {

    Write-Host ''
    Write-Host '=== DOWNLOAD ==='

    $curlArgs=@(
        '--http1.1',
        '-fL',
        '--retry','3',
        '--retry-all-errors',
        '--connect-timeout','15',
        '--max-time','180',
        '-o',$tmp,
        $SourceUrl
    )

    & $curl.Source @curlArgs

    if($LASTEXITCODE -ne 0){
        throw "APNIC_DOWNLOAD_FAILED exit=$LASTEXITCODE"
    }

    if(!(Test-Path -LiteralPath $tmp)){
        throw 'APNIC_DOWNLOAD_FILE_MISSING'
    }

    $download=Get-Item -LiteralPath $tmp

    Write-Host "DOWNLOAD_SIZE=$($download.Length)"
    Write-Host "DOWNLOAD_SHA256=$((Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash)"

    if($download.Length -lt 1000000){
        throw 'APNIC_DOWNLOAD_TOO_SMALL'
    }

    Write-Host ''
    Write-Host '=== PARSE CN IPV4 ==='

    $sourceRows=@(
        Get-Content -LiteralPath $tmp |
        Where-Object {
            $_ -match '^apnic\|CN\|ipv4\|'
        }
    )

    Write-Host "SOURCE_RECORDS=$($sourceRows.Count)"

    if($sourceRows.Count -lt 1000){
        throw 'CN_IPV4_RECORD_COUNT_UNEXPECTEDLY_LOW'
    }

    $ranges=[System.Collections.Generic.List[object]]::new()

    [uint64]$sourceAddressTotal=0

    foreach($line in $sourceRows){

        $fields=$line -split '\|'

        if($fields.Count -lt 7){
            throw "INVALID_APNIC_ROW=$line"
        }

        $startIp=$fields[3]
        [uint64]$count=$fields[4]

        if($count -eq 0){
            throw "INVALID_APNIC_COUNT=$line"
        }

        [uint64]$start=Convert-IPv4ToUInt64 $startIp
        [uint64]$end=$start+$count-1

        $ranges.Add(
            [PSCustomObject]@{
                Start=$start
                End=$end
                Count=$count
            }
        )

        $sourceAddressTotal+=$count
    }

    $ranges=@(
        $ranges |
        Sort-Object Start,End
    )

    Write-Host "SOURCE_ADDRESSES=$sourceAddressTotal"

    Write-Host ''
    Write-Host '=== MERGE CONTIGUOUS RANGES ==='

    $merged=[System.Collections.Generic.List[object]]::new()

    if($ranges.Count){

        [uint64]$currentStart=$ranges[0].Start
        [uint64]$currentEnd=$ranges[0].End

        for($i=1;$i-lt$ranges.Count;$i++){

            [uint64]$nextStart=$ranges[$i].Start
            [uint64]$nextEnd=$ranges[$i].End

            if($nextStart -le ($currentEnd+1)){

                if($nextEnd -gt $currentEnd){
                    $currentEnd=$nextEnd
                }
            }
            else {
                $merged.Add(
                    [PSCustomObject]@{
                        Start=$currentStart
                        End=$currentEnd
                    }
                )

                $currentStart=$nextStart
                $currentEnd=$nextEnd
            }
        }

        $merged.Add(
            [PSCustomObject]@{
                Start=$currentStart
                End=$currentEnd
            }
        )
    }

    [uint64]$mergedAddressTotal=0

    foreach($range in $merged){
        $mergedAddressTotal+=(
            [uint64]$range.End -
            [uint64]$range.Start +
            1
        )
    }

    Write-Host "MERGED_RANGES=$($merged.Count)"
    Write-Host "MERGED_ADDRESSES=$mergedAddressTotal"

    Write-Host ''
    Write-Host '=== GENERATE CIDRS ==='

    $cidrs=[System.Collections.Generic.List[string]]::new()

    foreach($range in $merged){

        foreach(
            $cidr in (
                Convert-RangeToCidrs `
                    -Start $range.Start `
                    -End $range.End
            )
        ){
            $cidrs.Add($cidr)
        }
    }

    $uniqueCidrs=@(
        $cidrs |
        Sort-Object -Unique
    )

    Write-Host "CIDR_COUNT=$($cidrs.Count)"
    Write-Host "UNIQUE_CIDRS=$($uniqueCidrs.Count)"

    if($cidrs.Count -ne $uniqueCidrs.Count){
        throw 'DUPLICATE_CIDRS_FOUND'
    }

    [uint64]$cidrAddressTotal=0
    $invalidCidrs=[System.Collections.Generic.List[string]]::new()

    foreach($cidr in $uniqueCidrs){

        $parts=$cidr -split '/'

        if($parts.Count -ne 2){
            $invalidCidrs.Add($cidr)
            continue
        }

        [int]$prefix=$parts[1]

        if($prefix -lt 0 -or $prefix -gt 32){
            $invalidCidrs.Add($cidr)
            continue
        }

        [uint64]$start=Convert-IPv4ToUInt64 $parts[0]
        [uint64]$size=[uint64][Math]::Pow(
            2,
            32-$prefix
        )

        if(($start % $size) -ne 0){
            $invalidCidrs.Add($cidr)
            continue
        }

        $cidrAddressTotal+=$size
    }

    Write-Host "CIDR_ADDRESSES=$cidrAddressTotal"
    Write-Host "INVALID_OR_UNALIGNED=$($invalidCidrs.Count)"

    $conservationPass=(
        $sourceAddressTotal -eq $mergedAddressTotal -and
        $mergedAddressTotal -eq $cidrAddressTotal
    )

    Write-Host "ADDRESS_CONSERVATION=$conservationPass"

    if(!$conservationPass){
        throw 'ADDRESS_CONSERVATION_FAILED'
    }

    if($invalidCidrs.Count){
        throw 'CIDR_VALIDATION_FAILED'
    }

    Write-Host ''
    Write-Host '=== SANITY ==='

    $cnTest=Test-AddressInRanges `
        -Address '223.5.5.5' `
        -Ranges $merged

    $foreignTest=Test-AddressInRanges `
        -Address '8.8.8.8' `
        -Ranges $merged

    Write-Host "223.5.5.5_IN_CN=$cnTest"
    Write-Host "8.8.8.8_IN_CN=$foreignTest"

    if(!$cnTest){
        throw 'CN_SANITY_TEST_FAILED'
    }

    if($foreignTest){
        throw 'FOREIGN_SANITY_TEST_FAILED'
    }

    Write-Host ''
    Write-Host '=== RESULT ==='

    if($DryRun){

        Write-Host 'OUTPUT_WRITE=SKIPPED'
        Write-Host 'UPDATE_CN_IP_DRY_RUN=PASS'
        Write-Host 'NO_DATASET_CHANGED=TRUE'
        exit 0
    }

    $parent=Split-Path -Parent $OutputFile

    if(!(Test-Path -LiteralPath $parent)){
        New-Item `
            -ItemType Directory `
            -Force `
            -Path $parent |
        Out-Null
    }

    $uniqueCidrs |
    Set-Content `
        -LiteralPath $OutputFile `
        -Encoding ASCII

    $written=Get-Item -LiteralPath $OutputFile
    $writtenLines=@(
        Get-Content -LiteralPath $OutputFile |
        Where-Object {$_.Trim()}
    )

    Write-Host "OUTPUT_WRITE=YES"
    Write-Host "OUTPUT_SIZE=$($written.Length)"
    Write-Host "OUTPUT_LINES=$($writtenLines.Count)"
    Write-Host "OUTPUT_SHA256=$((Get-FileHash -LiteralPath $OutputFile -Algorithm SHA256).Hash)"

    if($writtenLines.Count -ne $uniqueCidrs.Count){
        throw 'OUTPUT_LINE_COUNT_MISMATCH'
    }

    Write-Host 'UPDATE_CN_IP=PASS'
}
finally {

    Remove-Item `
        -LiteralPath $tmp `
        -Force `
        -ErrorAction SilentlyContinue
}
