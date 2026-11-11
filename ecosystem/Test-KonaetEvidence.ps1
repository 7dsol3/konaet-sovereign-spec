param([string]$NodePath='node',[switch]$Finalize)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Receipt-Library.ps1')
$root=Split-Path $PSScriptRoot -Parent
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('konaet-evidence-tests-'+[Guid]::NewGuid().ToString('N'))
$output=Join-Path $fixture 'artifacts'; [IO.Directory]::CreateDirectory($output) | Out-Null
$trust=[pscustomobject]@{schema='konaet.receipt-trust.v1';sources=[pscustomobject]@{
    laboratory=('1'*40);bot=('2'*40);sovereign=(& git -C $root rev-parse HEAD).Trim()};
    executionRepository='7dsol3/konaet-sovereign-spec';executionCommit=(& git -C $root rev-parse HEAD).Trim();runId='123';runAttempt='1'}
$trustFile=Join-Path $fixture 'trusted.json'
function Write-Json([string]$Path,$Value){[IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 30),(New-Object Text.UTF8Encoding($false)))}
Write-Json $trustFile $trust
$events=@(); $parent='0'*64; $files=@('wavepacket.csv','bot-validation.json','causal-inputs.txt')
$repos=@('7dsolv/RealidadeQuantica','7dsolv/konaet-bot','7dsol3/konaet-sovereign-spec')
$shas=@($trust.sources.laboratory,$trust.sources.bot,$trust.sources.sovereign)
$kinds=@('science','automation-validation','integration')
for($i=0;$i -lt 3;$i++) {
    $text=if($i -eq 0){"x,probability`n0,1`n"}elseif($i -eq 1){'{"syntheticFixture":true}'}else{$events[0].eventId+"`n"+$events[1].eventId+"`n"}
    $bytes=[Text.Encoding]::ASCII.GetBytes($text); [IO.File]::WriteAllBytes((Join-Path $output $files[$i]),$bytes)
    $document=[pscustomobject]@{schema='konaet.run-event.v1';artifactName=$files[$i];artifactSha256='';sourceRepository=$repos[$i];sourceCommit=$shas[$i];
        executionRepository=$trust.executionRepository;executionCommit=$trust.executionCommit;runId=$trust.runId;runAttempt=$trust.runAttempt;kind=$kinds[$i];parentEventId=$parent}
    $event=New-KonaetPublicEvent $document $bytes ('a'*64); $events+=,$event; $parent=$event.eventId
}
$report=[pscustomobject]@{schema='konaet.ecosystem-validation.v1';sources=$trust.sources;events=$events}
$reportFile=Join-Path $output 'ecosystem-report.json'; Write-Json $reportFile $report
[IO.File]::WriteAllText((Join-Path $output 'frame.txt'),$events[2].frame,[Text.Encoding]::ASCII)
$parts=$events[2].frame.Split([char]10)
$vector=[pscustomobject]@{schema='konaet.polyglot-vectors.v1';cases=@([pscustomobject]@{
    name='real-three-repository-event';salt=$parts[0];documentHex=$parts[1];commitment=$parts[2];args=$events[2].args})}
$vectorFile=Join-Path $output 'receipt-vector.json'; Write-Json $vectorFile $vector
$null=Test-KonaetEventEvidence $output $trustFile; $checks=1
function Reject([scriptblock]$Action) {
    $denied=$false; try {& $Action} catch {$denied=$true}
    if(!$denied){throw 'Expected altered evidence rejection'}
}
foreach($file in $files) {
    $path=Join-Path $output $file; $saved=[IO.File]::ReadAllBytes($path)
    try {[IO.File]::AppendAllText($path,'altered'); Reject {$null=Test-KonaetEventEvidence $output $trustFile}; $checks++}
    finally {[IO.File]::WriteAllBytes($path,$saved)}
}
foreach($field in @('runId','sourceCommit','parentEventId','artifactSha256','executionCommit')) {
    $saved=$events[1].document.$field
    try {$events[1].document.$field='wrong'; Write-Json $reportFile $report; Reject {$null=Test-KonaetEventEvidence $output $trustFile}; $checks++}
    finally {$events[1].document.$field=$saved; Write-Json $reportFile $report}
}
$saved=$events[2].args[0]
try {$events[2].args[0]=123; Write-Json $reportFile $report; Reject {$null=Test-KonaetEventEvidence $output $trustFile}; $checks++}
finally {$events[2].args[0]=$saved; Write-Json $reportFile $report}
$public=Read-KonaetJson (Join-Path $root 'polyglot/vectors.json')
try {Write-Json $vectorFile ([pscustomobject]@{schema=$public.schema;cases=@($public.cases[0])}); Reject {$null=Test-KonaetEventEvidence $output $trustFile}; $checks++}
finally {Write-Json $vectorFile $vector}
try {[IO.File]::WriteAllText((Join-Path $output 'frame.txt'),'unrelated'); Reject {$null=Test-KonaetEventEvidence $output $trustFile}; $checks++}
finally {[IO.File]::WriteAllText((Join-Path $output 'frame.txt'),$events[2].frame,[Text.Encoding]::ASCII)}
$saved=$trust.runId
try {$trust.runId='124'; Write-Json $trustFile $trust; Reject {$null=Test-KonaetEventEvidence $output $trustFile}; $checks++}
finally {$trust.runId=$saved; Write-Json $trustFile $trust}
Reject {$null=Test-KonaetEventEvidence $output (Join-Path $output 'trusted.json')}; $checks++
if($Finalize) {& (Join-Path $PSScriptRoot 'Test-KonaetReceipt.ps1') -OutputDirectory $output -TrustFile $trustFile -NodePath $NodePath; $checks++}
Write-Output "Evidence binding checks: $checks passed. Synthetic fixtures; no MATLAB or App claim. $output"
