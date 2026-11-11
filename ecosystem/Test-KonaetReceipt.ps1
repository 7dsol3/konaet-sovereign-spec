param([Parameter(Mandatory=$true)][string]$OutputDirectory,[string]$NodePath='node')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$output=[IO.Path]::GetFullPath($OutputDirectory)
$vectorFile=Join-Path $root 'polyglot/vectors.json'
$original=[IO.File]::ReadAllBytes($vectorFile)
$previous=$env:KONAET_POLYGLOT_REPORT
$vector=Get-Content -LiteralPath (Join-Path $output 'receipt-vector.json') -Raw | ConvertFrom-Json
if (@($vector.cases).Count -ne 1 -or $vector.cases[0].commitment -notmatch '^[a-f0-9]{64}$') { throw 'Invalid execution vector' }
try {
    # The unchanged four-process harness consumes the real MATLAB-produced event.
    [IO.File]::WriteAllBytes($vectorFile,[IO.File]::ReadAllBytes((Join-Path $output 'receipt-vector.json')))
    $env:KONAET_POLYGLOT_REPORT=Join-Path $output 'sovereign-finality.json'
    Push-Location $root
    try {
        & $NodePath 'polyglot/conformance.mjs' node *> (Join-Path $output 'finality.log')
        if ($LASTEXITCODE -ne 0) { throw 'Sovereign finality verification failed; inspect finality.log' }
    } finally { Pop-Location }
    $report=Get-Content -LiteralPath $env:KONAET_POLYGLOT_REPORT -Raw | ConvertFrom-Json
    if (!$report.realFourProcessFinality -or !$report.finalityVerification.verified -or
        $report.finalityVerification.commitment -cne $vector.cases[0].commitment) { throw 'Receipt does not cover this execution' }
    Write-Output 'MATLAB event finalized and verified by the existing four-process Sovereign runtime.'
} finally {
    [IO.File]::WriteAllBytes($vectorFile,$original)
    $env:KONAET_POLYGLOT_REPORT=$previous
}
