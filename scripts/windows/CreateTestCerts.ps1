#Requires -RunAsAdministrator

# This script generates test certificates for use with Secure Boot testing.

param (
    [string]$Action
)

Write-Warning @"
================================================================================
WARNING: This script is for validation and testing purposes only.
DO NOT use the generated certificates or keys in production environments.
Keys are stored in software and are not protected by a Hardware Security Module (HSM).
For production, always use an HSM or other secure key storage solution.
================================================================================
"@

# =============================================================================
# Script Variables - Do not change
# =============================================================================
# Change these variables to your own values if required

# This is the text that will be appended to the end of the certificate's OU field
$AdditionalText = "TESTING ONLY - DO NOT USE FOR PRODUCTION"



if (-not $Env:TestSecureBootDefaults) {
    $Env:TestSecureBootDefaults = (Get-Location).Path + "\SecureBootDefaults"
}

$DbOutputDir = "$($Env:TestSecureBootDefaults)\DB"
$KEKOutputDir = "$($Env:TestSecureBootDefaults)\KEK"
$PKOutputDir = "$($Env:TestSecureBootDefaults)\PK"

# This is the directory where the certificates will be created
$SigningCerts = "$($Env:TestSecureBootDefaults)\SigningCerts"

$TestPKName = "TestPK"
$TestKEKName = "TestKEK"
$TestDBName = "TestDB"

# Create a list of the certificates to create
$CertsToCreate = @(
    # The PK certificate
    @{
        Subject = "CN=$TestPKName OU=$AdditionalText"
        Name = $TestPKName
        CrtPath = "$PKOutputDir\$TestPKName.crt" # The CRT file is the public key used by the UEFI firmware (in DER format)
        PfxPath = "$SigningCerts\$TestPKName.pfx" # The PFX file is the private key used by the signing tools
        P7bPath = "$SigningCerts\$TestPKName.p7b" # The P7B file is the PKCS#7 file that contains the certificate chain used by commands to verify the signature
        OutputDir = $PKOutputDir
    },
    # The KEK certificate
    @{
        Subject = "CN=$TestKEKName OU=$AdditionalText"
        Name = $TestKEKName
        CrtPath = "$KEKOutputDir\$TestKEKName.crt"
        PfxPath = "$SigningCerts\$TestKEKName.pfx"
        P7bPath = "$SigningCerts\$TestKEKName.p7b"
        OutputDir = $KEKOutputDir
    },
    # The DB certificate
    @{
        Subject = "CN=$TestDBName OU=$AdditionalText"
        Name = $TestDBName
        CrtPath = "$DbOutputDir\$TestDBName.crt"
        PfxPath = "$SigningCerts\$TestDBName.pfx"
        P7bPath = "$SigningCerts\$TestDBName.p7b"
        OutputDir = $DbOutputDir
    }
)

$CertStore = "Cert:\LocalMachine\My"

# These are the common parameters that will be used to create the certificates
$CommonParams = @{
    Type = "Custom"
    KeyUsage = "DigitalSignature"
    KeyAlgorithm = "RSA"
    KeyLength = 2048 # 2048 is the minimum key length for Secure Boot 
    KeyExportPolicy = "Exportable"
    CertStoreLocation = $CertStore
    NotAfter = (Get-Date).AddYears(1)
}

# =============================================================================
# Script Functions
# =============================================================================

function Test-Action {
    param (
        [string]$Action,
        [array]$ValidActions
    )

    if (-not $Action) {
        Write-Host "Please provide an action ($ValidActions) using the -Action parameter." -ForegroundColor Yellow
        return $false
    }

    if ($ValidActions -notcontains $Action) {
        Write-Host "Invalid action. Supported actions are $ValidActions." -ForegroundColor Red
        return $false
    }

    return $true
}

# Create a function to generate a new certificate
function New-Certificate
{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Subject,
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$CrtPath,
        [Parameter(Mandatory=$true)]
        [string]$PfxPath,
        [Parameter(Mandatory=$true)]
        [string]$P7bPath
    )
    write-host $CrtPath

    $Cert = New-SelfSignedCertificate -Subject $Subject @CommonParams
    $Cert | Export-Certificate -FilePath $CrtPath -Type CERT
    $Cert | Export-Certificate -FilePath $P7bPath -Type p7b


    Export-PfxCertificate -Cert "$CertStore\$($Cert.Thumbprint)" -FilePath $PfxPath -Password $CertPassword
}

# create a function that deletes the certificates from the local machine
function Delete-Certificate
{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Subject
    )

    # Loop over Cert:\LocalMachine\My and delete any certificate with "Test" in the common name

    $certStore = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -match "CN=.*$Subject" }

    if ($certStore.Count -eq 0) {
        Write-Host "No certificates with 'Test' in the common name found."
        return
    }

    foreach ($cert in $certStore) {
        $commonName = $cert.Subject -replace '^.*?CN=([^,]*).*$', '$1'
        Write-Host "Removing certificate with common name: $commonName"
        Remove-Item $cert.PSPath -Force
    }

    Write-Host "Certificates with '$Subject' in the common name removed successfully."
}

function New-OutputDirIfNotExists {
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputDir
    )

    if (-not (Test-Path $OutputDir)) {
        New-Item -Path $OutputDir -ItemType Directory
    }
}

function Remove-OutputDirIfExists {
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputDir
    )

    if (Test-Path $OutputDir) {
        Remove-Item -Path $OutputDir -Recurse -Force
    }
}

# =============================================================================
# Script Execution
# =============================================================================

if (-not (Test-Action -Action $Action -ValidActions @("create", "delete"))) {
    return
}

if ($Action.equals("create")) {
    
    # Create the output directories for the signing certificates
    New-OutputDirIfNotExists $SigningCerts
    # Prompt the user to enter a password for the certificates
    $CertPassword = Read-Host -AsSecureString -Prompt "Enter a password to protect the certificate private keys"
    Set-Variable -Name CertPassword -Value $CertPassword -Scope Global

    # for each of the certificates to create, call New-Certificate
    foreach ($cert in $CertsToCreate) {
        if (Test-Path $cert.CrtPath) {
            Write-Host "Test certificate $($cert.Name) already exists. Delete it first using the -Action delete parameter." -ForegroundColor Yellow
            return
        }

        New-OutputDirIfNotExists $cert.OutputDir

        Write-Host "Creating test certificate $($cert.Name): $($cert.CrtPath)"

        New-Certificate -Subject $cert.Subject -Name $cert.Name -CrtPath $cert.CrtPath -PfxPath $cert.PfxPath -P7bPath $cert.P7bPath

    }

    write-host "Use the *.crt files for the UEFI Secure Boot Setup"



} elseif ($Action.Equals("delete")) {

    # for each certificate created
    foreach ($cert in $CertsToCreate) {

        # test if the OutputDir exists
        If (Test-Path $cert.OutputDir) {

            # if it does, delete it
            Remove-OutputDirIfExists $cert.OutputDir
        }

        # test if the certificate exists
        If (Test-Path $cert.CrtPath) {

            # if it does, delete it
            Remove-Item -Path $cert.CrtPath -Force
        }

        # test if the pfx file exists
        If (Test-Path $cert.PfxPath) {

            # if it does, delete it
            Remove-Item -Path $cert.PfxPath -Force
        }

        Delete-Certificate -Subject $cert.Name

    }

    write-host "Deleted test certificates"
}
