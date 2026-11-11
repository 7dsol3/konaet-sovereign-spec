param([Parameter(Mandatory=$true)][string]$Laboratory,[Parameter(Mandatory=$true)][string]$Bot,
    [Parameter(Mandatory=$true)][string]$Sovereign,[Parameter(Mandatory=$true)][string]$TrustFile)
$ErrorActionPreference='Stop'
function Revision([string]$Directory) {
    $revision=(& git -C $Directory rev-parse HEAD).Trim()
    if($LASTEXITCODE -ne 0 -or $revision -cnotmatch '^[0-9a-f]{40}$'){throw 'Cannot read checked-out revision'}
    $status=& git -C $Directory status --porcelain --untracked-files=normal
    if($LASTEXITCODE -ne 0 -or $status){throw 'Trusted sources must be committed and clean'}
    return $revision
}
$sources=[ordered]@{laboratory=(Revision $Laboratory);bot=(Revision $Bot);sovereign=(Revision $Sovereign)}
$repository=$env:GITHUB_REPOSITORY; $runId=$env:GITHUB_RUN_ID; $attempt=$env:GITHUB_RUN_ATTEMPT
if(!$repository){$repository='7dsol3/konaet-sovereign-spec'}
if(!$runId){$runId='1'}; if(!$attempt){$attempt='1'}
$revision=switch -CaseSensitive ($repository) {
    '7dsolv/RealidadeQuantica' {$sources.laboratory}
    '7dsol3/konaet-sovereign-spec' {$sources.sovereign}
    default {throw 'Unsupported execution repository'}
}
$context=[ordered]@{schema='konaet.receipt-trust.v1';sources=$sources;executionRepository=$repository;
    executionCommit=$revision;runId=[string]$runId;runAttempt=[string]$attempt}
$path=[IO.Path]::GetFullPath($TrustFile)
if([IO.File]::Exists($path)){throw 'Refusing to overwrite a pre-existing trust context'}
[IO.File]::WriteAllText($path,($context | ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)))
Write-Output 'Independent expected checkout and run context captured before calculation.'
