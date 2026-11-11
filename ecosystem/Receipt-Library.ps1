# Independent infrastructure verification of the MATLAB public event format.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Numerics
function Get-KonaetDigest([byte[]]$Bytes) {
    $hash=[Security.Cryptography.SHA256]::Create()
    try {return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()} finally {$hash.Dispose()}
}
function Convert-KonaetHex([string]$Hex) {
    if($Hex -cnotmatch '^(?:[0-9a-f]{2})+$'){throw 'Noncanonical hexadecimal bytes'}
    $bytes=New-Object byte[] ($Hex.Length/2)
    for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[Convert]::ToByte($Hex.Substring(2*$i,2),16)}
    return ,$bytes
}
function Assert-KonaetFields($Object,[string[]]$Names) {
    if($null -eq $Object -or $Object -isnot [pscustomobject]){throw 'Expected JSON object'}
    $keys=@($Object.PSObject.Properties.Name | Sort-Object -CaseSensitive)
    $expected=@($Names | Sort-Object -CaseSensitive)
    if(($keys -join ',') -cne ($expected -join ',')){throw 'Unexpected evidence fields'}
}
function Read-KonaetEvidence([string]$Path,[long]$Limit=16777216) {
    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer -or $item.Length -gt $Limit){throw 'Evidence file exceeds its limit'}
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked evidence is not accepted'}
    for($parent=$item.Directory;$null -ne $parent;$parent=$parent.Parent) {
        if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked evidence directory'}
    }
    return ,([IO.File]::ReadAllBytes($item.FullName))
}
function Read-KonaetJson([string]$Path,[long]$Limit=1048576) {
    $encoding=New-Object Text.UTF8Encoding($false,$true)
    return ($encoding.GetString((Read-KonaetEvidence $Path $Limit)) | ConvertFrom-Json)
}
function Get-KonaetCanonicalDocument($Document) {
    $keys=@('artifactName','artifactSha256','executionCommit','executionRepository','kind',
        'parentEventId','runAttempt','runId','schema','sourceCommit','sourceRepository')
    Assert-KonaetFields $Document $keys
    $pairs=foreach($key in $keys) {
        $value=$Document.$key
        if($value -isnot [string] -or $value.Length -gt 160 -or $value -cnotmatch '^[A-Za-z0-9._/-]+$'){throw 'Noncanonical document string'}
        '"'+$key+'":"'+$value+'"'
    }
    return '{'+($pairs -join ',')+'}'
}
function New-KonaetPublicEvent($Document,[byte[]]$Artifact,[string]$Salt) {
    if($Salt -cnotmatch '^[0-9a-f]{64}$'){throw 'Invalid receipt salt'}
    $Document.artifactSha256=Get-KonaetDigest $Artifact
    $canonical=Get-KonaetCanonicalDocument $Document
    $bytes=[Text.Encoding]::ASCII.GetBytes($canonical)
    $eventId=Get-KonaetDigest ([Text.Encoding]::ASCII.GetBytes("KONAET/RUN-EVENT/v1`0")+$bytes)
    $commitment=Get-KonaetDigest ([Text.Encoding]::ASCII.GetBytes("KONAET/SOCIAL-RECEIPT/v1`0")+(Convert-KonaetHex $Salt)+$bytes)
    $hex=([BitConverter]::ToString($bytes)).Replace('-','').ToLowerInvariant()
    $arguments=@([Numerics.BigInteger]::Parse(('0'+$commitment.Substring(0,32)),[Globalization.NumberStyles]::HexNumber).ToString(),
        [Numerics.BigInteger]::Parse(('0'+$commitment.Substring(32)),[Globalization.NumberStyles]::HexNumber).ToString())
    return [pscustomobject]@{schema='konaet.public-run-receipt.v1';eventId=$eventId;document=$Document;
        commitment=$commitment;args=$arguments;frame="$Salt`n$hex`n$commitment`n"}
}
function Test-KonaetEventEvidence([string]$Directory,[string]$TrustFile) {
    $output=[IO.Path]::GetFullPath($Directory).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
    if(([IO.Path]::GetFullPath($TrustFile)).StartsWith($output,[StringComparison]::OrdinalIgnoreCase)){throw 'Trust must be outside the artifact directory'}
    $trust=Read-KonaetJson $TrustFile
    Assert-KonaetFields $trust @('schema','sources','executionRepository','executionCommit','runId','runAttempt')
    Assert-KonaetFields $trust.sources @('laboratory','bot','sovereign')
    $repos=@('7dsolv/RealidadeQuantica','7dsolv/konaet-bot','7dsol3/konaet-sovereign-spec')
    if($trust.schema -cne 'konaet.receipt-trust.v1' -or $trust.executionRepository -cnotin $repos -or
        $trust.executionCommit -cnotmatch '^[0-9a-f]{40}$' -or $trust.runId -isnot [string] -or
        $trust.runId -cnotmatch '^[1-9][0-9]{0,19}$' -or $trust.runAttempt -isnot [string] -or
        $trust.runAttempt -cnotmatch '^[1-9][0-9]{0,3}$'){throw 'Invalid trusted execution context'}
    foreach($name in @('laboratory','bot','sovereign')) {
        if($trust.sources.$name -isnot [string] -or $trust.sources.$name -cnotmatch '^[0-9a-f]{40}$'){throw 'Invalid trusted source revision'}
    }
    $report=Read-KonaetJson (Join-Path $Directory 'ecosystem-report.json')
    if($report.schema -cne 'konaet.ecosystem-validation.v1' -or @($report.events).Count -ne 3){throw 'Expected three-repository execution report'}
    Assert-KonaetFields $report.sources @('laboratory','bot','sovereign')
    foreach($name in @('laboratory','bot','sovereign')) {
        if($report.sources.$name -cne $trust.sources.$name){throw 'Report source differs from trusted checkout'}
    }
    $files=@('wavepacket.csv','bot-validation.json','causal-inputs.txt'); $kinds=@('science','automation-validation','integration')
    $revisions=@($trust.sources.laboratory,$trust.sources.bot,$trust.sources.sovereign)
    $parent='0'*64; $ids=@(); $verified=@()
    for($i=0;$i -lt 3;$i++) {
        $event=$report.events[$i]
        Assert-KonaetFields $event @('schema','eventId','document','commitment','args','frame')
        $document=$event.document; $null=Get-KonaetCanonicalDocument $document
        $expected=@{schema='konaet.run-event.v1';artifactName=$files[$i];sourceRepository=$repos[$i];sourceCommit=$revisions[$i];
            executionRepository=$trust.executionRepository;executionCommit=$trust.executionCommit;runId=$trust.runId;
            runAttempt=$trust.runAttempt;kind=$kinds[$i];parentEventId=$parent}
        foreach($key in $expected.Keys){if($document.$key -cne $expected[$key]){throw "Event differs from trusted context: $key"}}
        $bytes=Read-KonaetEvidence (Join-Path $Directory $files[$i])
        if($i -eq 2 -and [Text.Encoding]::ASCII.GetString($bytes) -cne ($ids[0]+"`n"+$ids[1]+"`n")){throw 'Causal input file differs from predecessor events'}
        if($event.frame -isnot [string] -or $event.frame.Length -lt 64){throw 'Invalid event frame'}
        $savedHash=$document.artifactSha256
        $actual=New-KonaetPublicEvent $document $bytes $event.frame.Substring(0,64)
        if($event.schema -cne $actual.schema -or $savedHash -cne $actual.document.artifactSha256 -or
            $event.eventId -cne $actual.eventId -or $event.commitment -cne $actual.commitment -or
            $event.frame -cne $actual.frame -or @($event.args).Count -ne 2){throw 'Event bytes, causal ID or commitment mismatch'}
        for($j=0;$j -lt 2;$j++){if($event.args[$j] -isnot [string] -or $event.args[$j] -cne $actual.args[$j]){throw 'Exact decimal u128 arguments required'}}
        $verified+=,$actual; $ids+=,$actual.eventId; $parent=$actual.eventId
    }
    $final=$verified[2]; $parts=$final.frame.Split([char]10)
    if([Text.Encoding]::ASCII.GetString((Read-KonaetEvidence (Join-Path $Directory 'frame.txt') 32900)) -cne $final.frame){throw 'Published frame differs from verified integration'}
    $vector=Read-KonaetJson (Join-Path $Directory 'receipt-vector.json')
    Assert-KonaetFields $vector @('schema','cases')
    if($vector.schema -cne 'konaet.polyglot-vectors.v1' -or @($vector.cases).Count -ne 1){throw 'Invalid execution vector'}
    $row=$vector.cases[0]; Assert-KonaetFields $row @('name','salt','documentHex','commitment','args')
    if($row.name -cne 'real-three-repository-event' -or $row.salt -cne $parts[0] -or $row.documentHex -cne $parts[1] -or
        $row.commitment -cne $final.commitment -or @($row.args).Count -ne 2){throw 'Unrelated finality vector rejected'}
    for($j=0;$j -lt 2;$j++){if($row.args[$j] -isnot [string] -or $row.args[$j] -cne $final.args[$j]){throw 'Vector argument mismatch'}}
    return [pscustomobject]@{verified=$true;artifactFilesVerified=3;eventIds=$ids;finalCommitment=$final.commitment;trust=$trust;vector=$vector}
}
