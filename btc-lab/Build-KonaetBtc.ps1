param([string]$BuildDestination,[string]$BuildDotnetPath='dotnet',[switch]$VerifyInventory)
$ErrorActionPreference='Stop'
$script:KonaetBtcSdk='10.0.404'
$script:KonaetBtcLock='604d5d7aa6eaed1a0f86c287c34be434f98efa28c8d8ab2b3132b5a0ecf63682'
function Get-KonaetBtcSources([string]$Root) {
    $rootPath=[IO.Path]::GetFullPath($Root)
    $lockFile=Join-Path $rootPath 'source-lock.json'
    if((Get-FileHash -LiteralPath $lockFile).Hash.ToLowerInvariant() -cne $script:KonaetBtcLock){throw 'BTC import lock differs from the reviewed distribution'}
    $lock=Get-Content -LiteralPath $lockFile -Raw | ConvertFrom-Json
    if($lock.schema -cne 'konaet.btc-import.v1'){throw 'Unknown BTC source schema'}
    $expected=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach($row in $lock.files) {
        if($row.path -cnotmatch '^(src/Konaet\.BtcLab/[A-Za-z0-9._/-]+|data/[A-Za-z0-9._-]+|tests/[A-Za-z0-9._-]+)$' -or
            $row.path.Contains('..') -or !$expected.Add($row.path)){throw 'Invalid or duplicate locked source path'}
    }
    $actual=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $pending=New-Object 'System.Collections.Generic.Stack[string]'
    foreach($folder in @('src','data','tests')){$pending.Push((Join-Path $rootPath $folder))}
    while($pending.Count -gt 0) {
        $directory=$pending.Pop()
        if((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked source directory rejected'}
        foreach($item in Get-ChildItem -LiteralPath $directory -Force) {
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked source input rejected'}
            if($item.PSIsContainer) {
                # Old build outputs are never copied into the isolated build.
                if($item.Name -notin @('bin','obj')){$pending.Push($item.FullName)}
            } else {
                $relative=$item.FullName.Substring($rootPath.Length+1).Replace('\','/')
                if(!$expected.Contains($relative)){throw "Unlisted BTC source input: $relative"}
                [void]$actual.Add($relative)
            }
        }
    }
    if(!$actual.SetEquals($expected)){throw 'BTC source inventory differs from the reviewed import'}
    foreach($row in $lock.files) {
        $path=Join-Path $rootPath $row.path
        if((Get-Item -LiteralPath $path).Length -ne $row.bytes -or
            (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $row.sha256){throw "BTC source hash mismatch: $($row.path)"}
    }
    return $lock
}
function Build-KonaetBtc([string]$Root,[string]$Output,[string]$Sdk='dotnet') {
    $lock=Get-KonaetBtcSources $Root
    $version=(& $Sdk --version).Trim()
    if($LASTEXITCODE -ne 0 -or $version -cne $script:KonaetBtcSdk){throw "Validated SDK $script:KonaetBtcSdk required"}
    $target=[IO.Path]::GetFullPath($Output)
    [IO.Directory]::CreateDirectory($target) | Out-Null
    $isolated=Join-Path ([IO.Path]::GetTempPath()) ('konaet-btc-build-'+[Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($isolated) | Out-Null
    $sources=Join-Path $isolated 'source'; [IO.Directory]::CreateDirectory($sources) | Out-Null
    $compile=New-Object 'System.Collections.Generic.List[string]'
    foreach($entry in $lock.files | Where-Object {$_.path.EndsWith('.cs',[StringComparison]::Ordinal)}) {
        $destination=Join-Path $sources $entry.path
        [IO.Directory]::CreateDirectory((Split-Path $destination -Parent)) | Out-Null
        [IO.File]::Copy((Join-Path $Root $entry.path),$destination,$false)
        if((Get-FileHash -LiteralPath $destination).Hash.ToLowerInvariant() -cne $entry.sha256){throw 'Source changed while copying'}
        $compile.Add('    <Compile Include="source/'+$entry.path+'" />')
    }
    # The imported project is hashed for provenance but is not executed. This
    # generated project has explicit inputs and a supported, pinned runtime.
    $project=@'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable>
    <EnableDefaultItems>false</EnableDefaultItems><EnableDefaultCompileItems>false</EnableDefaultCompileItems>
    <AssemblyName>Konaet.BtcLab</AssemblyName><Deterministic>true</Deterministic>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors><GenerateAssemblyInfo>false</GenerateAssemblyInfo>
    <EnableNETAnalyzers>false</EnableNETAnalyzers><NuGetAudit>false</NuGetAudit>
  </PropertyGroup>
  <ItemGroup>
{INPUTS}
  </ItemGroup>
</Project>
'@
    $utf8=New-Object Text.UTF8Encoding($false)
    $projectFile=Join-Path $isolated 'Konaet.BtcLab.csproj'
    [IO.File]::WriteAllText($projectFile,$project.Replace('{INPUTS}',($compile -join "`n")),$utf8)
    [IO.File]::WriteAllText((Join-Path $isolated 'NuGet.Config'),'<configuration><packageSources><clear /></packageSources></configuration>',$utf8)
    [IO.File]::WriteAllText((Join-Path $isolated 'global.json'),('{"sdk":{"version":"'+$script:KonaetBtcSdk+'","rollForward":"disable","allowPrerelease":false}}'),$utf8)
    $properties=@('-p:ImportDirectoryBuildProps=false','-p:ImportDirectoryBuildTargets=false',
        '-p:ImportDirectoryPackagesProps=false','-p:RestoreIgnoreFailedSources=false','-noAutoResponse')
    $buildLog=Join-Path $target 'build.log'
    $saved=@{}; $variables=@('DOTNET_CLI_HOME','NUGET_PACKAGES','DOTNET_CLI_TELEMETRY_OPTOUT','DOTNET_NOLOGO',
        'DOTNET_STARTUP_HOOKS','DOTNET_ADDITIONAL_DEPS','MSBUILD_EXE_PATH','MSBuildSDKsPath','MSBuildExtensionsPath')
    foreach($name in $variables){$saved[$name]=[Environment]::GetEnvironmentVariable($name);[Environment]::SetEnvironmentVariable($name,$null)}
    try {
        $env:DOTNET_CLI_HOME=Join-Path $isolated '.dotnet'; $env:NUGET_PACKAGES=Join-Path $isolated '.packages'
        $env:DOTNET_CLI_TELEMETRY_OPTOUT='1'; $env:DOTNET_NOLOGO='1'
        Push-Location $isolated
        try {
            & $Sdk restore $projectFile --configfile (Join-Path $isolated 'NuGet.Config') --disable-parallel @properties *> $buildLog
            if($LASTEXITCODE -ne 0){throw 'Isolated BTC restore failed; inspect build.log'}
            & $Sdk build $projectFile --no-restore -c Release --nologo --disable-build-servers -o $target @properties *>> $buildLog
            if($LASTEXITCODE -ne 0){throw 'Isolated BTC build failed; inspect build.log'}
        } finally { Pop-Location }
        $dll=Join-Path $target 'Konaet.BtcLab.dll'
        $provenance=[ordered]@{schema='konaet.btc-isolated-build.v1';sourceLockSha256=$script:KonaetBtcLock;
            sdk=$version;targetFramework='net10.0';automaticSourceInclusion=$false;directoryImports=$false;
            nugetPackageSources=@();compiledSources=@($compile).Count;binarySha256=(Get-FileHash -LiteralPath $dll).Hash.ToLowerInvariant()}
        [IO.File]::WriteAllText((Join-Path $target 'build-provenance.json'),($provenance | ConvertTo-Json -Depth 5),$utf8)
        return $provenance
    } finally {
        foreach($name in $variables){[Environment]::SetEnvironmentVariable($name,$saved[$name])}
        # Keep this source-only build directory for diagnostics. It contains no
        # puzzle results or credentials and is outside the repository.
    }
}
if($MyInvocation.InvocationName -eq '.'){return}
if($VerifyInventory){$null=Get-KonaetBtcSources $PSScriptRoot; Write-Output 'Exact reviewed BTC source inventory verified.'; return}
if([string]::IsNullOrWhiteSpace($BuildDestination)){throw '-BuildDestination is required'}
Build-KonaetBtc $PSScriptRoot $BuildDestination $BuildDotnetPath | ConvertTo-Json -Depth 5
