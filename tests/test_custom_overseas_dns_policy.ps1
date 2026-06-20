$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$install = Get-Content -Path (Join-Path $root "install.sh") -Raw -Encoding UTF8
$template = Get-Content -Path (Join-Path $root "dnsdist.conf.template") -Raw -Encoding UTF8
$rules = Get-Content -Path (Join-Path $root "update-rules.sh") -Raw -Encoding UTF8
$readme = Get-Content -Path (Join-Path $root "README.md") -Raw -Encoding UTF8

function Assert-Contains {
    param(
        [string]$Haystack,
        [string]$Needle,
        [string]$Description
    )

    if (-not $Haystack.Contains($Needle)) {
        throw "Missing custom overseas DNS marker: $Description ($Needle)"
    }
}

Assert-Contains $install 'DEFAULT_OVERSEAS_DNS=("1.1.1.1" "8.8.8.8" "9.9.9.9")' 'default overseas DNS array'
Assert-Contains $install 'configure_overseas_dns()' 'installer overseas DNS function'
Assert-Contains $install 'OVERSEAS_DNS' 'installer environment variable'
Assert-Contains $install 'PRIVATE_OVERSEAS_DNS' 'installer private overseas DNS variable'
Assert-Contains $install 'PUBLIC_OVERSEAS_DNS' 'installer public overseas DNS variable'
Assert-Contains $install 'SNIPROXY_DNS' 'installer sniproxy DNS variable'
Assert-Contains $install '/etc/dnsdist/.overseas_dns' 'installer saves overseas DNS config'
Assert-Contains $install '/etc/dnsdist/.overseas_private_dns' 'installer saves private overseas DNS config'
Assert-Contains $install '/etc/dnsdist/.overseas_public_dns' 'installer saves public overseas DNS config'
Assert-Contains $install '/etc/dnsdist/.sniproxy_dns' 'installer saves sniproxy DNS config'
Assert-Contains $template '__OVERSEAS_PRIVATE_DNS_SERVERS__' 'dnsdist private overseas server placeholder'
Assert-Contains $template '__OVERSEAS_PUBLIC_DNS_SERVERS__' 'dnsdist public overseas server placeholder'
Assert-Contains $rules '.overseas_dns' 'rule updater reads saved overseas DNS config'
Assert-Contains $rules '.overseas_private_dns' 'rule updater reads saved private overseas DNS config'
Assert-Contains $rules '.overseas_public_dns' 'rule updater reads saved public overseas DNS config'
Assert-Contains $rules '__OVERSEAS_PRIVATE_DNS_SERVERS__' 'rule updater replaces private overseas placeholder'
Assert-Contains $rules '__OVERSEAS_PUBLIC_DNS_SERVERS__' 'rule updater replaces public overseas placeholder'
Assert-Contains $rules 'useClientSubnet=true' 'overseas upstreams can receive neutral ECS'
Assert-Contains $readme 'OVERSEAS_DNS' 'README documents overseas DNS variable'
Assert-Contains $readme 'PRIVATE_OVERSEAS_DNS' 'README documents private overseas DNS variable'
Assert-Contains $readme 'PUBLIC_OVERSEAS_DNS' 'README documents public overseas DNS variable'
Assert-Contains $readme 'SNIPROXY_DNS' 'README documents sniproxy DNS variable'

Write-Output "custom overseas DNS markers OK"
