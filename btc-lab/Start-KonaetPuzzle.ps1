param(
    [ValidateRange(1,60)][int]$Minutes=10,
    [string]$StateDirectory=(Join-Path $env:LOCALAPPDATA 'Konaet/PuzzleWorker/state'),
    [switch]$ValidateOnly
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Numerics
$script:KonaetAddress='1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU'
$script:KonaetCatalog='97ad3092f01c37049bf7ef461f740d34187c4244aa5223e5f16a4772743365e0'
function Read-KonaetInteger([string]$Hex) {
    if ($Hex -cnotmatch '^[0-9a-f]{64}$') { throw 'Non-canonical checkpoint integer' }
    return [Numerics.BigInteger]::Parse(('0'+$Hex),[Globalization.NumberStyles]::HexNumber)
}
function Format-KonaetInteger([Numerics.BigInteger]$Value) {
    if ($Value -lt 0 -or $Value -ge [Numerics.BigInteger]::Pow(2,256)) { throw 'Integer outside u256' }
    return $Value.ToString('x').TrimStart('0').PadLeft(64,'0')
}
function Update-KonaetCheckpoint($State,$Result,[int]$Count) {
    if ($Result.found -isnot [bool] -or $Result.completed -isnot [bool] -or
        $Result.puzzle -ne 71 -or $Result.address -cne $script:KonaetAddress -or
        $Result.start -cne $State.nextHex -or $Result.requestedCount -cne [string]$Count -or
        $Result.keysScanned -notmatch '^(0|[1-9][0-9]*)$') { throw 'Worker result identity mismatch' }
    $scanned=[Numerics.BigInteger]::Parse([string]$Result.keysScanned)
    if ($scanned -gt $Count -or (!$Result.found -and $null -ne $Result.privateKey)) { throw 'Worker result inconsistent' }
    if ($Result.found) { return $false } # The caller protects the hit before any public write.
    if (!$Result.completed) { return $false } # Never infer a contiguous prefix from an aggregate count.
    if ($scanned -ne $Count) { throw 'Incomplete interval cannot advance the checkpoint' }
    $next=(Read-KonaetInteger $State.nextHex)+$Count
    if ($next -gt [Numerics.BigInteger]::Pow(2,71)) { throw 'Checkpoint outside public interval' }
    $State.nextHex=Format-KonaetInteger $next
    $State.keysCompleted=([Numerics.BigInteger]::Parse([string]$State.keysCompleted)+$Count).ToString()
    return $true
}
function Write-KonaetAtomic([string]$Path,[byte[]]$Bytes) {
    $temporary=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try {
        [IO.File]::WriteAllBytes($temporary,$Bytes)
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary,$Path,[NullString]::Value) }
        else { [IO.File]::Move($temporary,$Path) }
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}
function Invoke-KonaetChunk([string]$Dll,[string]$Registry,[string]$Start,[int]$Count) {
    foreach($path in @($Dll,$Registry)) { if ($path -match '["\r\n]') { throw 'Invalid process path' } }
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName='dotnet'; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $info.Arguments='"'+$Dll+'" solve-chunk --puzzle 71 --start '+$Start+' --count '+$Count+
        ' --jobs 1 --seconds 5 --registry "'+$Registry+'"'
    $process=New-Object Diagnostics.Process; $process.StartInfo=$info
    try {
        if (!$process.Start()) { throw 'Worker did not start' }
        try { $process.PriorityClass=[Diagnostics.ProcessPriorityClass]::BelowNormal } catch { }
        $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit(10000)) { $process.Kill(); $process.WaitForExit(); throw 'Worker timed out; checkpoint unchanged' }
        $text=$stdout.GetAwaiter().GetResult(); $errors=$stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or $text.Length -gt 16384 -or $errors.Length -gt 0) {
            throw 'Worker failed; private process output withheld and checkpoint unchanged'
        }
        return ($text | ConvertFrom-Json)
    } finally { $process.Dispose() }
}
if ($MyInvocation.InvocationName -eq '.') { return }
if ($env:GITHUB_ACTIONS -eq 'true' -and !$ValidateOnly) { throw 'Prize searches run only on an owner-operated local machine' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows DPAPI is required for this launcher' }
$root=$PSScriptRoot; $registry=Join-Path $root 'data/puzzle_addresses.json'
if ((Get-FileHash -LiteralPath $registry -Algorithm SHA256).Hash.ToLowerInvariant() -cne $script:KonaetCatalog) { throw 'Public catalog hash mismatch' }
$lockFile=Join-Path $root 'source-lock.json'
$sourceLock=Get-Content -LiteralPath $lockFile -Raw | ConvertFrom-Json
foreach($entry in $sourceLock.files) {
    if ($entry.path -notmatch '^(src/Konaet\.BtcLab/[A-Za-z0-9./_-]+|data/[A-Za-z0-9._-]+|tests/[A-Za-z0-9._-]+)$' -or $entry.path.Contains('..')) { throw 'Invalid source lock path' }
    if ((Get-FileHash -LiteralPath (Join-Path $root $entry.path)).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'Imported BTC source changed; revalidate before running' }
}
if ($ValidateOnly) { Write-Output 'Pinned BTC sources and public puzzle catalog verified.'; return }
$statePath=[IO.Path]::GetFullPath($StateDirectory)
$repo=[IO.Path]::GetFullPath((Split-Path $root -Parent)).TrimEnd('\')+'\'
if ($statePath.StartsWith($repo,[StringComparison]::OrdinalIgnoreCase)) { throw 'Private state must remain outside the repository' }
[IO.Directory]::CreateDirectory($statePath) | Out-Null
if ((Get-Item -LiteralPath $statePath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'State directory cannot be a reparse point' }
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=[IO.Directory]::GetAccessControl($statePath,[Security.AccessControl.AccessControlSections]::Access)
$acl.SetAccessRuleProtection($true,$false)
foreach($entry in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($entry) }
$rule=New-Object Security.AccessControl.FileSystemAccessRule($owner,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
$acl.AddAccessRule($rule); [IO.Directory]::SetAccessControl($statePath,$acl)
$lease=[IO.File]::Open((Join-Path $statePath 'worker.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    $installation=Split-Path $statePath -Parent; $binary=Join-Path $installation 'bin'
    $build=Join-Path $installation 'build.log'
    & dotnet build (Join-Path $root 'src/Konaet.BtcLab/Konaet.BtcLab.csproj') -c Release --nologo -o $binary *> $build
    if ($LASTEXITCODE -ne 0) { throw 'Build failed; inspect local build.log' }
    $dll=Join-Path $binary 'Konaet.BtcLab.dll'; $digest=(Get-FileHash -LiteralPath $dll).Hash.ToLowerInvariant()
    $checkpoint=Join-Path $statePath 'checkpoint.json'; $minimum=[Numerics.BigInteger]::Pow(2,70); $end=[Numerics.BigInteger]::Pow(2,71)
    if (Test-Path -LiteralPath $checkpoint) {
        $state=Get-Content -LiteralPath $checkpoint -Raw | ConvertFrom-Json
        if ($state.schema -cne 'konaet.public-puzzle-checkpoint.v1' -or $state.puzzle -ne 71 -or $state.address -cne $script:KonaetAddress -or
            $state.catalogSha256 -cne $script:KonaetCatalog -or $state.binarySha256 -cne $digest -or
            $state.keysCompleted -notmatch '^(0|[1-9][0-9]*)$') { throw 'Checkpoint belongs to a different validated worker' }
        $next=Read-KonaetInteger $state.nextHex
        if ($next -lt $minimum -or $next -gt $end) { throw 'Checkpoint outside public interval' }
        if (Test-Path -LiteralPath (Join-Path $statePath 'solution.dpapi')) { throw 'Protected result already exists; search remains stopped' }
    } else {
        $entropy=New-Object byte[] 10; $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($entropy) } finally { $rng.Dispose() }; $entropy[9]=0
        $offset=[Numerics.BigInteger]::new($entropy)%($minimum-32768)
        $state=[pscustomobject]@{schema='konaet.public-puzzle-checkpoint.v1';puzzle=71;address=$script:KonaetAddress;
            catalogSha256=$script:KonaetCatalog;binarySha256=$digest;nextHex=(Format-KonaetInteger ($minimum+$offset));keysCompleted='0';status='ready'}
    }
    $clock=[Diagnostics.Stopwatch]::StartNew(); $sessionKeys=[Numerics.BigInteger]::Zero
    while ($clock.Elapsed.TotalMinutes -lt $Minutes -and !(Test-Path -LiteralPath (Join-Path $statePath 'STOP'))) {
        $remaining=$end-(Read-KonaetInteger $state.nextHex); if ($remaining -eq 0) { $state.status='interval-end'; break }
        $count=[int][Numerics.BigInteger]::Min(32768,$remaining)
        $result=Invoke-KonaetChunk $dll $registry $state.nextHex $count
        $advanced=Update-KonaetCheckpoint $state $result $count
        if ($result.found) {
            if ($result.privateKey -cnotmatch '^[a-f0-9]{64}$' -or $result.address -cne $script:KonaetAddress) { throw 'Invalid private result' }
            Add-Type -AssemblyName System.Security
            $privateBytes=[Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Compress))
            try {
                $protected=[Security.Cryptography.ProtectedData]::Protect($privateBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
                Write-KonaetAtomic (Join-Path $statePath 'solution.dpapi') $protected
            } finally { [Array]::Clear($privateBytes,0,$privateBytes.Length); $result.privateKey=$null }
            $state.status='protected-hit'; break
        }
        if (!$advanced) { $state.status='incomplete-retry'; break }
        $sessionKeys+=$count; $state.status='running'
        Write-KonaetAtomic $checkpoint ([Text.Encoding]::UTF8.GetBytes(($state | ConvertTo-Json)))
        Start-Sleep -Milliseconds 150
    }
    if ($state.status -eq 'running' -or $state.status -eq 'ready') { $state.status='session-finished' }
    Write-KonaetAtomic $checkpoint ([Text.Encoding]::UTF8.GetBytes(($state | ConvertTo-Json)))
    $summary=[ordered]@{schema='konaet.public-puzzle-session.v1';puzzle=71;address=$script:KonaetAddress;
        completedKeys=$sessionKeys.ToString();seconds=[Math]::Round($clock.Elapsed.TotalSeconds,3);status=$state.status;
        checkpointedKeys=$state.keysCompleted;privateResultPublished=$false;transactionsBroadcast=0;checkedAt=[DateTime]::UtcNow.ToString('o')}
    Write-KonaetAtomic (Join-Path $statePath 'session.json') ([Text.Encoding]::UTF8.GetBytes(($summary | ConvertTo-Json)))
    $summary | ConvertTo-Json
} finally { $lease.Dispose() }
