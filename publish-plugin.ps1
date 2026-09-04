param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Dev", "Production")]
    [string]$Channel,

    [string]$ApiBaseUrl = "https://api.overseer-bot.com",

    [string]$Token
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildRoot = Join-Path $Root "out"

if (-not $Token) {
    $Token = $env:PLUGIN_PUBLISH_TOKEN
}

if (-not $Token) {
    $BackendEnv = "C:\Projects\overseer-bot\.env"

    if (Test-Path $BackendEnv) {
        $Match = Select-String `
            -Path $BackendEnv `
            -Pattern '^PLUGIN_PUBLISH_TOKEN=(.+)$' |
            Select-Object -First 1

        if ($Match) {
            $Token = $Match.Matches[0].Groups[1].Value.Trim()
        }
    }
}

if (-not $Token) {
    throw "PLUGIN_PUBLISH_TOKEN was not found."
}

$Dll = Get-ChildItem `
    -Path $BuildRoot `
    -Recurse `
    -File `
    -Filter "Overseer.dll" `
    -ErrorAction Stop |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $Dll) {
    throw "Overseer.dll was not found under $BuildRoot"
}

$Hash = Get-FileHash `
    -Path $Dll.FullName `
    -Algorithm SHA256

$ApiBaseUrl = $ApiBaseUrl.TrimEnd("/")

$EncodedVersion = [uri]::EscapeDataString($Version)

$Uri = "$ApiBaseUrl/api/plugin/releases/$Channel/publish?version=$EncodedVersion"

Write-Host ""
Write-Host "Overseer Plugin Publish" -ForegroundColor Cyan
Write-Host "-----------------------"
Write-Host "Channel : $Channel"
Write-Host "Version : $Version"
Write-Host "DLL     : $($Dll.FullName)"
Write-Host "Size    : $($Dll.Length) bytes"
Write-Host "SHA256  : $($Hash.Hash.ToLowerInvariant())"
Write-Host "Endpoint: $Uri"
Write-Host ""

$Headers = @{
    Authorization = "Bearer $Token"
}

try {
    $Response = Invoke-RestMethod `
        -Method Post `
        -Uri $Uri `
        -Headers $Headers `
        -ContentType "application/octet-stream" `
        -InFile $Dll.FullName
}
catch {
    Write-Host ""
    Write-Host "Publish failed." -ForegroundColor Red

    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
        Write-Host $_.ErrorDetails.Message
    }

    throw
}

Write-Host ""
Write-Host "Publish succeeded." -ForegroundColor Green
Write-Host ""

$Response | Format-List