param([string]$DotnetPath='dotnet',[switch]$Build)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Build-KonaetBtc.ps1')
$lock=Get-KonaetBtcSources $PSScriptRoot
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('konaet-build-tests-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture) | Out-Null
foreach($row in $lock.files) {
    $path=Join-Path $fixture $row.path
    [IO.Directory]::CreateDirectory((Split-Path $path -Parent)) | Out-Null
    [IO.File]::Copy((Join-Path $PSScriptRoot $row.path),$path)
}
[IO.File]::Copy((Join-Path $PSScriptRoot 'source-lock.json'),(Join-Path $fixture 'source-lock.json'))
$checks=0
$null=Get-KonaetBtcSources $fixture; $checks++
foreach($name in @('src/Directory.Build.targets','src/Directory.Build.props',
    'src/Konaet.BtcLab/Injected.cs','src/NuGet.Config','tests/extra.txt','data/extra.json')) {
    $path=Join-Path $fixture $name; [IO.File]::WriteAllText($path,'inert regression input')
    try {
        $denied=$false; try {$null=Get-KonaetBtcSources $fixture} catch {$denied=$_.Exception.Message.StartsWith('Unlisted BTC source input:')}
        if(!$denied){throw "Unlisted build input accepted: $name"}; $checks++
    } finally {[IO.File]::Delete($path)}
}
$source=Join-Path $fixture $lock.files[0].path; $saved=[IO.File]::ReadAllBytes($source)
try {
    [IO.File]::AppendAllText($source,'changed')
    $denied=$false; try {$null=Get-KonaetBtcSources $fixture} catch {$denied=$_.Exception.Message.StartsWith('BTC source hash mismatch:')}
    if(!$denied){throw 'Changed imported bytes accepted'}; $checks++
} finally {[IO.File]::WriteAllBytes($source,$saved)}
if($Build) {
    # Ancestor controls cannot run: generated project disables imports, default
    # source discovery, automatic response files and external package sources.
    $marker=Join-Path $fixture 'unexpected-marker.txt'
    [IO.File]::WriteAllText((Join-Path $fixture 'Directory.Build.targets'),
        '<Project><Target Name="Injected" BeforeTargets="Build"><WriteLinesToFile File="'+$marker+'" Lines="unexpected" /></Target></Project>')
    $output=Join-Path $fixture 'output'
    $result=Build-KonaetBtc $fixture $output $DotnetPath
    if([IO.File]::Exists($marker) -or $result.directoryImports -or $result.automaticSourceInclusion){throw 'Build isolation failed'}; $checks++
    Push-Location $fixture
    try {
        & $DotnetPath (Join-Path $output 'Konaet.BtcLab.dll') selftest > (Join-Path $output 'selftest.json')
        if($LASTEXITCODE -ne 0){throw 'Known-answer cryptographic tests failed'}; $checks++
    } finally {Pop-Location}
}
Write-Output "Isolated build checks: $checks passed. Diagnostic fixture: $fixture"
