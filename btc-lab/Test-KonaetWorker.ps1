$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Start-KonaetPuzzle.ps1')
$checks=0
function Expect-Rejection([scriptblock]$Operation) {
    $denied=$false; try { & $Operation } catch { $denied=$true }; if (!$denied) { throw 'Expected rejection' }
}
function Fixture {
    $start=Format-KonaetInteger ([Numerics.BigInteger]::Pow(2,70))
    $s=[pscustomobject]@{nextHex=$start;keysCompleted='9007199254740993'}
    $r=[pscustomobject]@{puzzle=71;address=$script:KonaetAddress;start=$start;requestedCount='32768';keysScanned='32768';found=$false;completed=$true;privateKey=$null}
    return @($s,$r)
}
$s,$r=Fixture
if (!(Update-KonaetCheckpoint $s $r 32768) -or $s.keysCompleted -cne '9007199254773761' -or
    (Read-KonaetInteger $s.nextHex) -ne ([Numerics.BigInteger]::Pow(2,70)+32768)) { throw 'Exact checkpoint advancement failed' }; $checks++
$s,$r=Fixture; $before=$s.nextHex; $r.completed=$false; $r.keysScanned='1000'
if ((Update-KonaetCheckpoint $s $r 32768) -or $s.nextHex -cne $before) { throw 'Partial range advanced' }; $checks++
$s,$r=Fixture; $r.found=$true; $r.privateKey='private-fixture'
if ((Update-KonaetCheckpoint $s $r 32768) -or $s.keysCompleted -cne '9007199254740993') { throw 'Hit advanced a public checkpoint' }; $checks++
foreach($field in @('address','start','requestedCount','puzzle','keysScanned','privateKey')) {
    $s,$r=Fixture; $r.$field=if($field -eq 'puzzle'){72}else{'invalid'}
    Expect-Rejection { Update-KonaetCheckpoint $s $r 32768 }; $checks++
}
$s,$r=Fixture; $r.keysScanned='32767'; Expect-Rejection { Update-KonaetCheckpoint $s $r 32768 }; $checks++
$s,$r=Fixture; $r.completed='true'; Expect-Rejection { Update-KonaetCheckpoint $s $r 32768 }; $checks++
Expect-Rejection { Read-KonaetInteger '400000000000000000' }; $checks++
foreach($n in @([Numerics.BigInteger]::Zero,[Numerics.BigInteger]::Pow(2,70),([Numerics.BigInteger]::Pow(2,256)-1))) {
    if ((Read-KonaetInteger (Format-KonaetInteger $n)) -ne $n) { throw 'u256 roundtrip failed' }; $checks++
}
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('konaet-atomic-'+[Guid]::NewGuid().ToString('N')+'.json')
try {
    Write-KonaetAtomic $temporary ([Text.Encoding]::UTF8.GetBytes('first'))
    Write-KonaetAtomic $temporary ([Text.Encoding]::UTF8.GetBytes('second'))
    if ([IO.File]::ReadAllText($temporary) -cne 'second') { throw 'Atomic checkpoint replacement failed' }; $checks++
} finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    Add-Type -AssemblyName System.Security
    $sample=[Text.Encoding]::UTF8.GetBytes('synthetic-dpapi-fixture-no-key')
    $cipher=[Security.Cryptography.ProtectedData]::Protect($sample,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $plain=[Security.Cryptography.ProtectedData]::Unprotect($cipher,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    if ([Text.Encoding]::UTF8.GetString($plain) -cne 'synthetic-dpapi-fixture-no-key') { throw 'DPAPI roundtrip failed' }; $checks++
}
Write-Output "Worker checkpoint checks: $checks passed. No prize search performed."
