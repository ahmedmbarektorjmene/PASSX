param (
    [string]$FilePath
)

if (-not $FilePath) {
    Write-Error "Please provide a file path to sign."
    exit 1
}

if (-not (Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath"
    exit 1
}

$CertName = "PassX Dev Cert"
$Cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -match $CertName } | Select-Object -First 1

if (-not $Cert) {
    Write-Host "Creating self-signed certificate '$CertName'..."
    $Cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" -CertStoreLocation Cert:\CurrentUser\My
    Write-Host "Certificate created."
} else {
    Write-Host "Using existing certificate '$CertName'."
}

Write-Host "Signing $FilePath..."
Set-AuthenticodeSignature -FilePath $FilePath -Certificate $Cert -TimestampServer "http://timestamp.digicert.com"

if ($?) {
    Write-Host "Successfully signed $FilePath"
} else {
    Write-Error "Signing failed."
    exit 1
}
