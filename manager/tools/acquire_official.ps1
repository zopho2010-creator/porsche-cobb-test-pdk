[CmdletBinding(SupportsShouldProcess)]
param([string]$BandizipPath = "$env:ProgramFiles\Bandizip\bz.exe")

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sampleRoot = Join-Path $projectRoot 'samples'
$url = 'https://s3.us-west-2.amazonaws.com/software.cobbtuning.com/Update/AccessportManager/3.2.0/APManagerSetup.exe'
$expectedHash = '33e5e1182d0ef770142af45380ec4d8202301d642c05f6a2289f2b0909aeaa19'
$installer = Join-Path $sampleRoot 'downloads\APManagerSetup.exe'

function Assert-LocalPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($sampleRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the local sample tree: $Path"
    }
    for ($itemPath = $full; $itemPath -and $itemPath -ne $projectRoot; $itemPath = Split-Path -Parent $itemPath) {
        if ((Test-Path -LiteralPath $itemPath) -and
            ((Get-Item -LiteralPath $itemPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Refusing a reparse point in the sample path: $itemPath"
        }
    }
}

function Assert-Hash([string]$Path, [string]$Expected) {
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Expected) {
        throw "SHA-256 mismatch; existing file will not be overwritten: $Path"
    }
}

function Extract-Verified([string]$Archive, [string]$Destination, [string]$Stage) {
    Assert-LocalPath $Destination
    Assert-LocalPath $Stage
    New-Item -ItemType Directory -Path $Stage -Force | Out-Null
    & $BandizipPath x '-y' "-o:$Stage" $Archive | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Bandizip extraction failed: $Archive" }
    $files = @(Get-ChildItem -LiteralPath $Stage -File -Recurse -Force)
    if (-not $files.Count) { throw "Archive produced no files: $Archive" }
    # Check all existing files before copying any missing members.
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($Stage.Length + 1)
        $destinationFile = Join-Path $Destination $relative
        Assert-LocalPath $destinationFile
        if (Test-Path -LiteralPath $destinationFile) {
            Assert-Hash $destinationFile (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        }
    }
    foreach ($file in $files) {
        $destinationFile = Join-Path $Destination $file.FullName.Substring($Stage.Length + 1)
        if (-not (Test-Path -LiteralPath $destinationFile)) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $destinationFile) -Force | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $destinationFile
        }
    }
}

if (-not $PSCmdlet.ShouldProcess($sampleRoot, 'Acquire pinned official installer and extract archives without execution')) { return }
if (-not (Test-Path -LiteralPath $BandizipPath -PathType Leaf)) { throw "Bandizip console tool not found: $BandizipPath" }
Assert-LocalPath $installer
New-Item -ItemType Directory -Path (Split-Path -Parent $installer) -Force | Out-Null
if (Test-Path -LiteralPath $installer) {
    Assert-Hash $installer $expectedHash
} else {
    $download = "$installer.$([Guid]::NewGuid().ToString('N')).part"
    Invoke-WebRequest -Uri $url -OutFile $download
    Assert-Hash $download $expectedHash
    Move-Item -LiteralPath $download -Destination $installer
}
$headers = (Invoke-WebRequest -Uri $url -Method Head).Headers
$signature = Get-AuthenticodeSignature -LiteralPath $installer
$stageRoot = Join-Path $sampleRoot ('.extract-' + [Guid]::NewGuid().ToString('N'))
try {
    $manager = Join-Path $sampleRoot 'extracted\manager'
    Extract-Verified $installer $manager (Join-Path $stageRoot 'manager')
    Extract-Verified (Join-Path $manager 'APDriverInstall.exe') (Join-Path $sampleRoot 'extracted\drivers') (Join-Path $stageRoot 'drivers')
} finally {
    Assert-LocalPath $stageRoot
    if (Test-Path -LiteralPath $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }
}
$manifest = [ordered]@{
    observed_utc = [DateTime]::UtcNow.ToString('o')
    official_page = 'https://www.cobbtuning.com/products/accessport-manager'
    download_url = $url
    version = '3.2.0'
    bytes = (Get-Item -LiteralPath $installer).Length
    sha256 = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    response_last_modified = ($headers['Last-Modified'] -join ', ')
    release_date = $null
    last_modified_note = 'HTTP object metadata, not a verified release date'
    authenticode = [ordered]@{
        status = [string]$signature.Status
        message = $signature.StatusMessage
        signer = $signature.SignerCertificate.Subject
        signer_thumbprint = $signature.SignerCertificate.Thumbprint
        timestamp_signer = $signature.TimeStamperCertificate.Subject
    }
}
$manifestPath = Join-Path $projectRoot 'analysis\sources\acquisition_manifest.json'
New-Item -ItemType Directory -Path (Split-Path -Parent $manifestPath) -Force | Out-Null
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Output $manifestPath
