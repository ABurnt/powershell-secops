<#
.SYNOPSIS
    Generates a self-signed certificate for Microsoft Graph API certificate-based authentication.

.DESCRIPTION
    Creates a self-signed X.509 certificate in the current user's certificate store,
    exports the public key (.cer) for upload to an Entra ID app registration, and prints
    the environment variable commands needed to run the following script.

    Run this once per app registration. After completing the steps printed at the end,
    all scripts in this repository will authenticate without storing any secrets.

.PARAMETER CertName
    Common name (CN) for the certificate. Defaults to "GraphAPIAuth".

.PARAMETER ValidityYears
    Certificate validity period in years. Default is 1 year.

.PARAMETER OutputPath
    Folder where the .cer public key file is exported.
    Defaults to $env:USERPROFILE\SelfSignedCerts\.

.EXAMPLE
    .\New-GraphAuthCertificate.ps1

.EXAMPLE
    .\New-GraphAuthCertificate.ps1 -CertName "GraphAPIAuth" -ValidityYears 1

.NOTES
    Author   : Andrzej Berndt
    Requires : PowerShell 5.1+, no external modules
#>

param (
    [string]$CertName     = "GraphAPIAuth",
    [int]   $ValidityYears = 1,
    [string]$OutputPath   = "$env:USERPROFILE\SelfSignedCerts"
)

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory | Out-Null
}

# Generate certificate in the current user's personal store
$cert = New-SelfSignedCertificate `
    -Subject "CN=$CertName" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -NotAfter (Get-Date).AddYears($ValidityYears)

# Export the public key (.cer) for upload to Entra ID
$cerFile = Join-Path $OutputPath "$CertName.cer"
Export-Certificate -Cert $cert -FilePath $cerFile | Out-Null

Write-Host "`nCertificate created." -ForegroundColor Green
Write-Host "  Subject    : CN=$CertName"
Write-Host "  Thumbprint : $($cert.Thumbprint)" -ForegroundColor Cyan
Write-Host "  Valid until: $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  Public key : $cerFile" -ForegroundColor Cyan

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. In Entra ID, open your app registration"
Write-Host "     Certificates & secrets > Certificates > Upload certificate"
Write-Host "     Upload: $cerFile"
Write-Host ""
Write-Host "  2. Set these environment variables before running the scripts:"
Write-Host ""
Write-Host "     `$env:TENANT_ID       = `"<your-tenant-id>`"" -ForegroundColor DarkCyan
Write-Host "     `$env:CLIENT_ID       = `"<your-app-registration-client-id>`"" -ForegroundColor DarkCyan
Write-Host "     `$env:CERT_THUMBPRINT = `"$($cert.Thumbprint)`"" -ForegroundColor DarkCyan
