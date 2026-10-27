# Builds the plugin's sc-mcp for this machine and sc-server for Linux.
#   .\build.ps1            plugin binary + Linux server binaries
#   .\build.ps1 -AllPlugin also cross-builds sc-mcp for every desktop platform into bin/
#   .\build.ps1 -Mcpb      also packs bin/server-control.mcpb (Claude Desktop bundle; needs Node.js)
#   .\build.ps1 -Release   -Mcpb plus bin/THIRD_PARTY_LICENSES.txt and bin/SHA256SUMS, the
#                          assets of a GitHub Release (needs a clean, tagged checkout)
param([switch]$AllPlugin, [switch]$Mcpb, [switch]$Release)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if ($Release) {
    $Mcpb = $true
    if (git status --porcelain) { throw 'release builds need a clean working tree (commit or stash first)' }
}

$version = 'dev'
try {
    $ErrorActionPreference = 'Continue'
    $v = (git describe --tags --always --dirty 2>$null)
    if ($LASTEXITCODE -eq 0 -and $v) { $version = $v }
} catch {} finally { $ErrorActionPreference = 'Stop' }
$ldflags = "-s -w -X github.com/adee42/mcp-server-control/internal/server.Version=$version -X github.com/adee42/mcp-server-control/internal/mcpserver.Version=$version"

function Build($goos, $goarch, $out, $pkg) {
    $env:GOOS = $goos; $env:GOARCH = $goarch; $env:CGO_ENABLED = '0'
    go build -trimpath -ldflags $ldflags -o $out $pkg
    if ($LASTEXITCODE -ne 0) { throw "build failed: $out" }
    Write-Host "built $out"
}

try {
    $hostOS = (go env GOHOSTOS); $hostArch = (go env GOHOSTARCH)
    $ext = if ($hostOS -eq 'windows') { '.exe' } else { '' }
    Build $hostOS $hostArch "plugin/bin/sc-mcp$ext" ./cmd/sc-mcp

    foreach ($arch in 'amd64', 'arm64') {
        Build linux $arch "bin/sc-server-linux-$arch" ./cmd/sc-server
    }
    if ($AllPlugin) {
        foreach ($t in 'windows/amd64', 'windows/arm64', 'darwin/amd64', 'darwin/arm64', 'linux/amd64', 'linux/arm64') {
            $os, $arch = $t.Split('/')
            $e = if ($os -eq 'windows') { '.exe' } else { '' }
            Build $os $arch "bin/sc-mcp-$os-$arch$e" ./cmd/sc-mcp
        }
    }
    if ($Mcpb) {
        # Windows on ARM runs the amd64 build under emulation, so one .exe covers both.
        Remove-Item mcpb/server/sc-mcp-* -ErrorAction SilentlyContinue
        foreach ($t in 'windows/amd64', 'darwin/amd64', 'darwin/arm64', 'linux/amd64', 'linux/arm64') {
            $os, $arch = $t.Split('/')
            $e = if ($os -eq 'windows') { '.exe' } else { '' }
            Build $os $arch "mcpb/server/sc-mcp-$os-$arch$e" ./cmd/sc-mcp
        }
        Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
        # The bundle ships binaries, so it has to carry the third-party license notices.
        go run ./tools/thirdparty -o mcpb/THIRD_PARTY_LICENSES.txt
        if ($LASTEXITCODE -ne 0) { throw 'collecting third-party licenses failed' }
        npx -y @anthropic-ai/mcpb@2.1.2 validate mcpb/manifest.json
        if ($LASTEXITCODE -ne 0) { throw 'mcpb manifest validation failed' }
        New-Item -ItemType Directory -Force bin | Out-Null
        npx -y @anthropic-ai/mcpb@2.1.2 pack mcpb bin/server-control.mcpb
        if ($LASTEXITCODE -ne 0) { throw 'mcpb pack failed' }
    }
    if ($Release) {
        Copy-Item mcpb/THIRD_PARTY_LICENSES.txt bin/
        # Same format as `sha256sum`, so `sha256sum -c SHA256SUMS` verifies the downloads.
        $assets = 'sc-server-linux-amd64', 'sc-server-linux-arm64', 'server-control.mcpb', 'THIRD_PARTY_LICENSES.txt'
        $sums = foreach ($a in $assets) { '{0}  {1}' -f (Get-FileHash "bin/$a" -Algorithm SHA256).Hash.ToLower(), $a }
        [IO.File]::WriteAllText("$PSScriptRoot/bin/SHA256SUMS", ($sums -join "`n") + "`n")
        Write-Host "release $version assets in bin/:"
        Get-Content bin/SHA256SUMS
    }
} finally {
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
}
