#Requires -RunAsAdministrator

<#
.DESCRIPTION
This script installs and enables Secure Boot certificates at runtime (from the operating system).

.PARAMETER PresignedObjectsPath
A path to the directory containing the pre-signed Secure Boot objects.

.PARAMETER PathToPkP7b
(Optional) A path to the PKCS7 signature of the Platform Key (PK).

.NOTES
Author: Microsoft
Date: 4/2/25
Version: 1.1
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$PresignedObjectsPath,

    [Parameter(Mandatory=$false)]
    [string]$PathToPkP7b
)

function Validate-FileSize {
    param (
        [string]$FilePath,
        [int]$MinSizeBytes
    )
    if (-not (Test-Path -Path $FilePath)) {
        throw "File not found: $FilePath"
    }
    $fileInfo = Get-Item -Path $FilePath
    if ($fileInfo.Length -lt $MinSizeBytes) {
        throw "File $FilePath is smaller than the required minimum size of $MinSizeBytes bytes."
    }
}

function Log-Message {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

try {
    # Check if Secure Boot is already enabled
    $SecurebootEnabled = Confirm-SecureBootUEFI
    if ($SecurebootEnabled) {
        Log-Message "Secure Boot is already enabled. Please disable Secure Boot and try again." "Red"
        return
    }

    Log-Message "Enrolling certificates for Secure Boot..." "Green"

    # Validate the presence of required pre-signed objects
    $RequiredFiles = @("PK.bin", "KEK.bin", "DB.bin", "DBX.bin")
    foreach ($RequiredFile in $RequiredFiles) {
        $FilePath = Join-Path -Path $PresignedObjectsPath -ChildPath $RequiredFile
        if (-not (Test-Path -Path $FilePath)) {
            Log-Message "Required file $RequiredFile is missing. Please download the latest release and try again." "Yellow"
            Log-Message "https://github.com/microsoft/secureboot_objects/releases" "Yellow"
            return
        }
    }

    # Validate the size of the DBX file (minimum 28 bytes - EFI_SIGNATURE_LIST minimum size assuming 0 entries)
    $DbxFilePath = Join-Path -Path $PresignedObjectsPath -ChildPath "DBX.bin"
    Validate-FileSize -FilePath $DbxFilePath -MinSizeBytes 28

    # Timestamp for Secure Boot enrollment
    $time = "2015-08-28T00:00:00Z"

    # Enroll certificates in reverse order
    Log-Message "Enrolling DB..." "Green"
    $Result = Set-SecureBootUEFI -Time $time -ContentFilePath (Join-Path $PresignedObjectsPath "DB.bin") -Name db
    if ($null -ne $Result) {
        Log-Message "DB enrolled successfully." "Green"
    } else {
        Log-Message "Failed to enroll DB." "Red"
        throw "Failed to enroll DB. Please check the file and try again."
    }

    Log-Message "Enrolling DBX..." "Green"
    $esult = Set-SecureBootUEFI -Time $time -ContentFilePath $DbxFilePath -Name dbx
    if ($null -ne $Result) {
        Log-Message "DBX enrolled successfully." "Green"
    } else {
        Log-Message "Failed to enroll DBX." "Red"
        throw "Failed to enroll DBX. Please check the file and try again."
    }

    Log-Message "Enrolling KEK..." "Green"
    $Result = Set-SecureBootUEFI -Time $time -ContentFilePath (Join-Path $PresignedObjectsPath "KEK.bin") -Name KEK
    if ($null -ne $Result) {
        Log-Message "KEK enrolled successfully." "Green"
    } else {
        Log-Message "Failed to enroll KEK." "Red"
        throw "Failed to enroll KEK. Please check the file and try again."
    }

    Log-Message "Enrolling PK..." "Green"
    $PkFilePath = Join-Path -Path $PresignedObjectsPath -ChildPath "PK.bin"
    $Result = $null
    if (-not [string]::IsNullOrEmpty($PathToPkP7b)) {
        $Result = Set-SecureBootUEFI -Time $time -ContentFilePath $PkFilePath -Name PK -SignedFilePath $PathToPkP7b
    } else {
        # Note: This will work on Project MU-based firmware (e.g., Surface) but may not be supported industry-wide
        $Result = Set-SecureBootUEFI -Time $time -ContentFilePath $PkFilePath -Name PK
    }

    if ($null -ne $Result) {
        Log-Message "PK enrolled successfully." "Green"
    } else {
        Log-Message "Failed to enroll PK." "Red"
        throw "Failed to enroll PK. Please check the file and try again."
    }

    Log-Message "Enrollment complete." "Green"
} catch {
    Log-Message "An error occurred: $_" "Red"
}
finally {
    Log-Message "Script execution finished." "White"
}
