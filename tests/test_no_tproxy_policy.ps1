$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

$paths = @(
    "install.sh",
    "README.md"
)

$forbiddenMarkers = @(
    "TPROXY",
    "tproxy-proxy",
    "tproxy_prerouting",
    "proxy_gateway_tproxy",
    "TPROXY_PORT",
    "TPROXY_MARK",
    "TPROXY_TABLE",
    "TCP IP透明代理"
)

foreach ($relativePath in $paths) {
    $path = Join-Path $root $relativePath
    $content = Get-Content -Path $path -Raw -Encoding UTF8

    foreach ($marker in $forbiddenMarkers) {
        if ($content.Contains($marker)) {
            throw "Forbidden TPROXY marker remains in ${relativePath}: ${marker}"
        }
    }
}

$removedFiles = @(
    "tproxy-proxy.go",
    "tproxy_linux.go",
    "tproxy_unsupported.go",
    "tests/test_tproxy_policy.ps1"
)

foreach ($relativePath in $removedFiles) {
    $path = Join-Path $root $relativePath
    if (Test-Path $path) {
        throw "TPROXY file should be removed: ${relativePath}"
    }
}

Write-Output "TPROXY removal markers OK"
