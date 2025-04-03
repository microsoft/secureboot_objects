#Requires -RunAsAdministrator

<#
.DESCRIPTION
The script is designed to install and enable secure boot at runtime (from the operating system).

.PARAMETER <PresignedObjectsPath>
A path to the Objects that are not signed

.PARAMETER <PathToPkP7b>
(Optional) A path to the pk7b signature of the Platform key

.NOTES
Author: Microsoft
Date: 4/2/25
Version: 1
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$PresignedObjectsPath,
    [Parameter(Mandatory=$false)]
    [string]$PathToPkP7b
)

$SecurebootEnabled = Confirm-SecureBootUEFI
if ($SecurebootEnabled) {
    Write-Host "Secureboot is enabled. Please disable Secureboot and try again." -ForegroundColor Red
    # return
}

write-host "Enrolling certificates for Secureboot" -ForegroundColor Green

# Check if the PreSignedObjects exist
$PreSignedObjects = Get-ChildItem -Path $PresignedObjectsPath -Filter *.bin
foreach ($PreSignedObject in @("DefaultPk.bin", "DefaultKek.bin", "DefaultDb.bin", "DefaultDbx.bin")) {
    if ($PreSignedObjects.Name -notcontains $PreSignedObject) {
        Write-Host "PreSignedObject $PreSignedObject does not exist. Please download the latest release and try again." -ForegroundColor Yellow
        Write-Host "https://github.com/microsoft/secureboot_objects/releases" -ForegroundColor Yellow
        return
    }
}

write-host "Enrolling the certificates in reverse order" -ForegroundColor Green

# We need a timestamp
$time = "2015-08-28T00:00:00Z"


write-host "Enrolling DB" -ForegroundColor Green
Set-SecureBootUEFI -Time $time -ContentFilePath "$PresignedObjectsPath\DefaultDb.bin" -Name db

write-host "Enrolling DBX" -ForegroundColor Green
Set-SecureBootUEFI -Time $time -ContentFilePath "$PresignedObjectsPath\DefaultDbx.bin" -Name dbx

write-host "Enrolling KEK" -ForegroundColor Green
Set-SecureBootUEFI -Time $time -ContentFilePath "$PresignedObjectsPath\DefaultKek.bin" -Name KEK

write-host "Enrolling PK" -ForegroundColor Green

if (-not [string]::IsNullOrEmpty($PathToPkP7b)) {
    Set-SecureBootUEFI -Time $time -ContentFilePath "$PresignedObjectsPath\DefaultPk.bin" -Name PK -SignedFilePath $PathToPkP7b
} else {
    # Note this will work on Project MU based firmware (Ex. Surface) however this is not an industry wide feature
    Set-SecureBootUEFI -Time $time -ContentFilePath "$PresignedObjectsPath\DefaultPk.bin" -Name PK
}

Write-Host "Enrollment complete" -ForegroundColor Green
