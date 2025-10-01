#Requires -Version 5.1
<#
.SYNOPSIS
    Generates OpenPGP certificates in bulk with Curve25519 keys.

.DESCRIPTION
    This script generates multiple OpenPGP certificates with:
    - Configurable key types (default: Ed25519 + Cv25519)
    - Configurable expiration (default: 5 years)
    - Support for primary and additional user IDs
    - Automatic revocation certificate generation
    - Exports public and private keys

.PARAMETER ConfigFile
    Path to JSON configuration file. Default: certificates.json

.PARAMETER DefaultKeyType
    Default primary key type. Default: EDDSA

.PARAMETER DefaultKeyCurve
    Default primary key curve. Default: Ed25519

.PARAMETER DefaultSubkeyType
    Default subkey type. Default: ECDH

.PARAMETER DefaultSubkeyCurve
    Default subkey curve. Default: Cv25519

.PARAMETER DefaultExpirationYears
    Default years until expiration. Default: 5

.EXAMPLE
    .\Generate-PGPCertificates.ps1
    
.EXAMPLE
    .\Generate-PGPCertificates.ps1 -ConfigFile "custom.json" -DefaultExpirationYears 10
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigFile = (Join-Path $PSScriptRoot "certificates.json"),
    
    [Parameter()]
    [string]$DefaultKeyType = "EDDSA",
    
    [Parameter()]
    [string]$DefaultKeyCurve = "Ed25519",
    
    [Parameter()]
    [string]$DefaultSubkeyType = "ECDH",
    
    [Parameter()]
    [string]$DefaultSubkeyCurve = "Cv25519",
    
    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$DefaultExpirationYears = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Helper function to write UTF8 without BOM (PS 5.1 compatible)
function Write-UTF8File {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding $false))
}

# Helper function to create temp passphrase file
function New-PassphraseFile {
    param([string]$Passphrase)
    $tempFile = Join-Path $env:TEMP "gpg_pass_$([guid]::NewGuid().ToString('N')).txt"
    Write-UTF8File -Path $tempFile -Content $Passphrase
    return $tempFile
}

# Helper function to run GPG command with error handling
function Invoke-GpgCommand {
    param(
        [string[]]$Arguments,
        [string]$ErrorMessage,
        [switch]$IgnoreStderr
    )
    $output = & gpg $Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$ErrorMessage : $output"
    }
    return $output
}

# Validate config file exists
if (-not (Test-Path $ConfigFile)) {
    Write-Host "Error: Configuration file not found: $ConfigFile" -ForegroundColor Red
    Write-Host "`nExpected JSON format:" -ForegroundColor Yellow
    Write-Host @'
[
  {
    "name": "John Doe",
    "primaryEmail": "john.doe@example.com",
    "passphrase": "SecurePass123!",
    "additionalEmails": ["j.doe@example.com"]
  }
]
'@
    exit 1
}

# Load and parse JSON configuration
try {
    $certificates = Get-Content -Path $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
}
catch {
    Write-Host "Error: Failed to parse JSON configuration: $_" -ForegroundColor Red
    exit 1
}

# Verify GPG is installed
try {
    $gpgVersion = (& gpg --version 2>&1 | Select-Object -First 1)
}
catch {
    Write-Host "Error: GnuPG (gpg) not found in PATH!" -ForegroundColor Red
    Write-Host "Download from: https://gnupg.org/download/" -ForegroundColor Yellow
    exit 1
}

# Setup output directory
$outputDir = Join-Path $PSScriptRoot "pgp_certificates"
if (-not (Test-Path $outputDir)) {
    $null = New-Item -ItemType Directory -Path $outputDir
}

# Display header
Write-Host "`nOpenPGP Bulk Certificate Generator" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host "[OK] GnuPG: $gpgVersion" -ForegroundColor Green
Write-Host "`nDefaults:" -ForegroundColor Yellow
Write-Host "  Key Type: $DefaultKeyType/$DefaultKeyCurve + $DefaultSubkeyType/$DefaultSubkeyCurve"
Write-Host "  Expiration: $DefaultExpirationYears years from generation"
Write-Host "`nConfiguration:" -ForegroundColor Yellow
Write-Host "  Config: $(Resolve-Path $ConfigFile)"
Write-Host "  Certificates: $($certificates.Count)"
Write-Host "  Output: $outputDir`n"

$successCount = 0
$failCount = 0

# Process each certificate
foreach ($cert in $certificates) {
    $name = $cert.name
    $email = $cert.primaryEmail
    $passphrase = $cert.passphrase
    $additionalEmails = @($cert.additionalEmails)
    
    # Use per-certificate settings or defaults (using PSObject.Properties for safe access)
    $keyType = if ($cert.PSObject.Properties['keyType'] -and $cert.keyType) { $cert.keyType } else { $DefaultKeyType }
    $keyCurve = if ($cert.PSObject.Properties['keyCurve'] -and $cert.keyCurve) { $cert.keyCurve } else { $DefaultKeyCurve }
    $subkeyType = if ($cert.PSObject.Properties['subkeyType'] -and $cert.subkeyType) { $cert.subkeyType } else { $DefaultSubkeyType }
    $subkeyCurve = if ($cert.PSObject.Properties['subkeyCurve'] -and $cert.subkeyCurve) { $cert.subkeyCurve } else { $DefaultSubkeyCurve }
    $expirationYears = if ($cert.PSObject.Properties['expirationYears'] -and $cert.expirationYears) { $cert.expirationYears } else { $DefaultExpirationYears }
    $expirationDate = (Get-Date).AddYears($expirationYears).ToString("yyyy-MM-dd")
    
    Write-Host "Processing: $name <$email>" -ForegroundColor Cyan
    
    # Create sanitized filename
    $sanitizedEmail = $email -replace '[^a-zA-Z0-9@._-]', '_'
    $publicKeyFile = Join-Path $outputDir "$sanitizedEmail.public.asc"
    $privateKeyFile = Join-Path $outputDir "$sanitizedEmail.private.asc"
    $revocationFile = Join-Path $outputDir "$sanitizedEmail.revocation.asc"
    
    # Create GPG batch file
    $batchContent = @"
Key-Type: $keyType
Key-Curve: $keyCurve
Key-Usage: sign
Subkey-Type: $subkeyType
Subkey-Curve: $subkeyCurve
Subkey-Usage: encrypt
Name-Real: $name
Name-Email: $email
Expire-Date: $expirationDate
Passphrase: $passphrase
%commit
"@
    
    $batchFile = Join-Path $env:TEMP "gpg_batch_$sanitizedEmail.txt"
    $passphraseFile = $null
    
    try {
        Write-UTF8File -Path $batchFile -Content $batchContent
        
        # Generate key (GPG outputs info to stderr, don't treat as error)
        Write-Host "  Generating key..." -NoNewline
        $ErrorActionPreference = 'Continue'
        $null = & gpg --batch --gen-key $batchFile 2>&1
        $genExitCode = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        
        if ($genExitCode -ne 0) {
            throw "Key generation failed with exit code $genExitCode"
        }
        Write-Host " [OK]" -ForegroundColor Green
        
        # Get fingerprint
        $ErrorActionPreference = 'Continue'
        $keyInfo = & gpg --list-keys --with-colons $email 2>&1
        $ErrorActionPreference = 'Stop'
        
        $fingerprint = ($keyInfo | Where-Object { $_ -match '^fpr:+([0-9A-F]{40}):' } | 
                       ForEach-Object { if ($_ -match '^fpr:+([0-9A-F]{40}):') { $matches[1] } } | 
                       Select-Object -First 1)
        
        if (-not $fingerprint) {
            throw "Could not retrieve key fingerprint"
        }
        
        Write-Host "  Fingerprint: $fingerprint" -ForegroundColor Gray
        
        # Add additional user IDs
        if ($additionalEmails.Count -gt 0) {
            Write-Host "  Adding user IDs..." -NoNewline
            $passphraseFile = New-PassphraseFile -Passphrase $passphrase
            
            foreach ($addEmail in $additionalEmails) {
                $gpgArgs = @('--batch', '--yes', '--no-tty', '--pinentry-mode', 'loopback', 
                         '--passphrase-file', $passphraseFile, '--quick-add-uid', 
                         $fingerprint, "$name <$addEmail>")
                $ErrorActionPreference = 'Continue'
                $null = & gpg $gpgArgs 2>&1
                $uidExitCode = $LASTEXITCODE
                $ErrorActionPreference = 'Stop'
                
                if ($uidExitCode -ne 0) {
                    Write-Warning "Failed to add UID: $addEmail"
                }
            }
            Write-Host " [OK]" -ForegroundColor Green
        }
        
        # Export public key
        Write-Host "  Exporting public key..." -NoNewline
        if (Test-Path $publicKeyFile) { Remove-Item $publicKeyFile -Force }
        
        Invoke-GpgCommand -Arguments @('--batch', '--yes', '--armor', '--output', $publicKeyFile, '--export', $fingerprint) `
                         -ErrorMessage "Public key export failed"
        Write-Host " [OK]" -ForegroundColor Green
        
        # Export private key
        Write-Host "  Exporting private key..." -NoNewline
        if (Test-Path $privateKeyFile) { Remove-Item $privateKeyFile -Force }
        if (-not $passphraseFile) { $passphraseFile = New-PassphraseFile -Passphrase $passphrase }
        
        Invoke-GpgCommand -Arguments @('--batch', '--yes', '--no-tty', '--pinentry-mode', 'loopback', 
                                       '--passphrase-file', $passphraseFile, '--armor', '--output', 
                                       $privateKeyFile, '--export-secret-keys', $fingerprint) `
                         -ErrorMessage "Private key export failed"
        Write-Host " [OK]" -ForegroundColor Green
        
        # Copy auto-generated revocation certificate
        Write-Host "  Copying revocation cert..." -NoNewline
        $gnupgHome = if ($env:GNUPGHOME) { $env:GNUPGHOME } else { Join-Path $env:APPDATA "gnupg" }
        $autoRevFile = Join-Path $gnupgHome "openpgp-revocs.d\$fingerprint.rev"
        
        if (Test-Path $autoRevFile) {
            Copy-Item $autoRevFile $revocationFile -Force
            Write-Host " [OK]" -ForegroundColor Green
        } else {
            Write-Host " [WARN - not found]" -ForegroundColor Yellow
        }
        
        Write-Host "  Success!" -ForegroundColor Green
        Write-Host "    Public:     $publicKeyFile"
        Write-Host "    Private:    $privateKeyFile"
        Write-Host "    Revocation: $revocationFile"
        
        $successCount++
    }
    catch {
        Write-Host " [FAILED]" -ForegroundColor Red
        Write-Host "  Error: $_" -ForegroundColor Red
        $failCount++
    }
    finally {
        # Cleanup temp files
        Remove-Item $batchFile -Force -ErrorAction SilentlyContinue
        if ($passphraseFile) { Remove-Item $passphraseFile -Force -ErrorAction SilentlyContinue }
    }
    
    Write-Host ""
}

# Display summary
Write-Host "===================================" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Successful: $successCount" -ForegroundColor Green
if ($failCount -gt 0) {
    Write-Host "  Failed:     $failCount" -ForegroundColor Red
} else {
    Write-Host "  Failed:     $failCount" -ForegroundColor Gray
}
Write-Host "`nCertificates saved to: $outputDir" -ForegroundColor Yellow
Write-Host "`nImportant:" -ForegroundColor Yellow
Write-Host "  - Keep private keys and revocation certs secure"
Write-Host "  - Store passphrases in a password manager"
Write-Host "  - Backup revocation certificates separately"
Write-Host "  - Check individual expiration dates in each certificate`n"
