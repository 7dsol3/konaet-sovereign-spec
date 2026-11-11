param([Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][string]$TrustFile,[string]$NodePath='node',[switch]$EvidenceOnly)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Receipt-Library.ps1')
$root=Split-Path $PSScriptRoot -Parent
$output=[IO.Path]::GetFullPath($OutputDirectory)
$verified=Test-KonaetEventEvidence $output $TrustFile
if($EvidenceOnly){Write-Output 'Three artifacts, causal events, frame, vector and independent source context verified.'; return}
$head=(& git -C $root rev-parse HEAD).Trim()
if($LASTEXITCODE -ne 0 -or $head -cne $verified.trust.sources.sovereign){throw 'Runtime revision differs from trusted Sovereign source'}
# Run only the committed runtime. Never replace the checkout's public vectors.
$isolated=Join-Path ([IO.Path]::GetTempPath()) ('konaet-receipt-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($isolated) | Out-Null
$archive=Join-Path $isolated 'runtime.zip'; $runtime=Join-Path $isolated 'runtime'
& git -C $root archive --format=zip --output=$archive HEAD
if($LASTEXITCODE -ne 0){throw 'Cannot snapshot committed runtime'}
Expand-Archive -LiteralPath $archive -DestinationPath $runtime
[IO.File]::WriteAllText((Join-Path $runtime 'polyglot/vectors.json'),($verified.vector | ConvertTo-Json -Depth 20),(New-Object Text.UTF8Encoding($false)))
$savedReport=$env:KONAET_POLYGLOT_REPORT; $savedPath=$env:PATH
try {
    $node=(Get-Command $NodePath -ErrorAction Stop).Source
    $env:PATH=(Split-Path $node -Parent)+[IO.Path]::PathSeparator+$env:PATH
    $npm=if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){'npm.cmd'}else{'npm'}
    $env:KONAET_POLYGLOT_REPORT=Join-Path $output 'sovereign-finality.json'
    Push-Location $runtime
    try {
        & $npm ci --offline --ignore-scripts --no-audit --no-fund *> (Join-Path $output 'finality-install.log')
        if($LASTEXITCODE -ne 0){throw 'Offline vendored runtime installation failed'}
        & $node 'polyglot/conformance.mjs' node *> (Join-Path $output 'finality.log')
        if ($LASTEXITCODE -ne 0) { throw 'Sovereign finality verification failed; inspect finality.log' }
    } finally { Pop-Location }
    $report=Read-KonaetJson $env:KONAET_POLYGLOT_REPORT 16777216
    if($report.realFourProcessFinality -cne $true -or $report.finalityVerification.verified -cne $true -or
        $report.finalityVerification.commitment -cne $verified.finalCommitment){throw 'Finality does not cover the verified execution'}
    $again=Test-KonaetEventEvidence $output $TrustFile
    if($again.finalCommitment -cne $verified.finalCommitment){throw 'Evidence changed during finalization'}
    Write-Output 'Three-source execution evidence finalized and verified in four real local validator processes.'
} finally {$env:KONAET_POLYGLOT_REPORT=$savedReport; $env:PATH=$savedPath}
