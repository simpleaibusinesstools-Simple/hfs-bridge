param([string]$OutputDirectory='dist/app')
$ErrorActionPreference='Stop'
$buildRoot=(Resolve-Path -LiteralPath (Split-Path $PSScriptRoot -Parent)).Path
$output=[IO.Path]::GetFullPath($OutputDirectory,$buildRoot)
if(-not $output.StartsWith($buildRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $output)) {throw 'Choose a NEW output directory inside this checkout.'}
$null=New-Item -ItemType Directory -Path (Join-Path $output 'bin/runtime') -Force
$previousDllOutput=$env:WINFSP_DLL_OUTPUT_PATH
Push-Location $buildRoot
try {
    $env:WINFSP_DLL_OUTPUT_PATH=Join-Path $output 'bin/runtime'
    cargo build --locked --release --features native-mount
    if($LASTEXITCODE -ne 0){throw 'Native build failed; retain the output.'}
    $dll=Join-Path $output 'bin/runtime/winfsp-x64.dll'
    if(-not (Test-Path -LiteralPath $dll) -or (Get-FileHash -LiteralPath $dll).Hash -ne '08D7389B8D030770A4DE108A60A86047D5CDD00B9ECAFC6DD66E957BC51C2437') {throw 'The required WinFsp runtime is missing or changed.'}
    Copy-Item -LiteralPath 'target/release/hfs-bridge.exe' -Destination (Join-Path $output 'bin/hfs-bridge.exe')
    dotnet build app/desktop/HfsBridge.Manager.csproj -c Release -p:Platform=x64 --artifacts-path (Join-Path $output 'build')
    if($LASTEXITCODE -ne 0){throw 'GUI build failed; retain the output.'}
    foreach($name in @('HfsBridge.Manager.exe','HfsBridge.Manager.dll','HfsBridge.Manager.deps.json','HfsBridge.Manager.runtimeconfig.json')) {
        Copy-Item -LiteralPath (Join-Path $output ('build/bin/HfsBridge.Manager/release/'+$name)) -Destination (Join-Path $output $name)
    }
    Copy-Item -LiteralPath LICENSE,README.md,THIRD-PARTY-NOTICES.md -Destination $output
    $files=@(Get-ChildItem -LiteralPath $output -File -Recurse | Where-Object {$_.FullName -notlike ($output+[IO.Path]::DirectorySeparatorChar+'build'+[IO.Path]::DirectorySeparatorChar+'*')} | ForEach-Object {
        [pscustomobject]@{Path=[IO.Path]::GetRelativePath($output,$_.FullName);Bytes=$_.Length;SHA256=(Get-FileHash -LiteralPath $_.FullName).Hash}
    })
    [pscustomobject]@{Purpose='Local source build';Files=$files} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output 'manifest.json') -Encoding utf8
    Write-Output ('Built '+$output+'. Custom native builds need reviewed startup hash pins before startup setup.')
}finally{Pop-Location;$env:WINFSP_DLL_OUTPUT_PATH=$previousDllOutput}
