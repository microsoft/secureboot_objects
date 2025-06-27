<#
.SYNOPSIS
    Microsoft 'Windows UEFI CA 2023' Media Update Script

.DESCRIPTION
    This script updates Windows media to use boot binaries signed with the 'Windows UEFI CA 2023' certificate.

.NOTES
    File Name  : Make2023BootableMedia.ps1
    Author     : Microsoft Corporation
    Version    : 1.0
    Date       : 2025-02-25

.LICENSE
    Licensed under the BSD License. See License.txt in the project root for full license information.

.COPYRIGHT
    Copyright (c) Microsoft Corporation. All rights reserved.
#>

param (

    [Parameter(Position=0,mandatory=$true)]
	[string] $MediaPath,

	[ValidateSet("ISO", "USB", "LOCAL", IgnoreCase=$true)]
	[Parameter(Position = 1, Mandatory=$false)]
	[string] $TargetType,

	[Parameter(Position = 2,mandatory=$false)]
	[string] $ISOPath,

	[Parameter(Position = 3,mandatory=$false)]
    [string] $USBDrive,

    [Parameter(Position = 4,mandatory=$false)]
    [string] $FileSystem,

    [Parameter(Position = 5, Mandatory=$false)]
    [string] $NewMediaPath,

    [Parameter(Position = 6, Mandatory=$false)]
    [string] $StagingDir
)

function Get-TS { return "{0:HH:mm:ss}" -f [DateTime]::Now }

function Show-Usage {
    $scriptName = $global:ScriptName
    Write-Host "Usage:`r`n$scriptName -MediaPath <path> -TargetType <type> -ISOPath <path> -USBDrive <drive:> -FileSystem <type> -NewMediaPath <path> -StagingDir <path>" -ForegroundColor Blue
    Write-Host "  -MediaPath <path> The path to the media folder or ISO file to be used as baseline."
    Write-Host "  -TargetType <type> The type of media to be created (ISO, USB, or LOCAL)."
    Write-Host "        ISO: Convert media specified in -MediaPath to 2023 bootable ISO file. Targets -ISOPath."
    Write-Host "        USB: Convert media specified in -MediaPath to 2023 bootable image and writes it to -USBDrive."
    Write-Host "        LOCAL: Convert media specified in -MediaPath to 2023 bootable image copied to -NewMediaPath."
    Write-Host "  -ISOPath <path> The path to the new ISO file to be created from -MediaPath."
    Write-Host "  -USBDrive <drive:> The drive letter to a target USB drive (example E:)."
    Write-Host "  -FileSystem <type> Optional. The file system to format the USB drive with (FAT32 or ExFAT). Default is FAT32."
    Write-Host "  -NewMediaPath <path> Required for LOCAL TargetType. -MediaPath content is duplicated here and then updated."
    Write-Host "  -StagingDir (optional) <path> Overrides default temp staging path used by this script. System %TEMP% used by default with random subfolder."
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "$scriptName -MediaPath C:\Media\Win10Media -TargetType ISO -ISOPath C:\Media\Win10_Updated.iso"
    Write-Host "$scriptName -MediaPath C:\Media\Win11.iso -TargetType ISO -ISOPath C:\Media\Win11_Updated.iso"
    Write-Host "$scriptName -MediaPath \\server\share\Win11_Media -TargetType ISO -ISOPath C:\Media\Win11_Updated.iso"
    Write-Host "$scriptName -MediaPath \\server\share\Win11.iso -TargetType ISO -ISOPath C:\Media\Win11_Updated.iso"
    Write-Host "$scriptName -MediaPath C:\Media\Win1124H2 -TargetType USB -USBDrive H:"
    Write-Host "$scriptName -MediaPath C:\Media\Win11.iso -TargetType USB -USBDrive E:"
    Write-Host "$scriptName -MediaPath C:\Media\Win1124H2 -TargetType LOCAL -NewMediaPath C:\Media\Win1124H2_Updated"
    Write-Host "$scriptName -MediaPath H:\Media\Win11.iso -TargetType LOCAL -NewMediaPath R:\Win11_Updated"
    Write-Host "$scriptName -MediaPath C:\Media\Win1124H2 -TargetType ISO -ISOPath C:\Media\Win1124H2_Updated.iso -StagingDir C:\Temp\Win1124H2"
    Write-Host "`r`nIMPORTANT! You must provide this script with a media source (-MediaPath) which has the latest 2024-4B (or later) updates included!`r`n" -ForegroundColor Red
}

function Show-ADK-Req {
    Write-Host "This script requires the Windows ADK be installed on the system. Available at http://aka.ms/adk" -ForegroundColor Red
    Write-Host "After install, open an admin-elevated 'Deploy and Imaging Tools Environment' command prompt provided with the ADK." -ForegroundColor Red
    Write-Host "Then run PowerShell from this command prompt and you should be good to go.`r`n" -ForegroundColor Red
}

function Debug-Pause {

    if ($global:Dbg_Pause) {
        Write-Host "Press any key to continue"
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    return
}

# Routine to help with script debugging
function Write-Dbg-Host {
    if ($global:Dbg_Ouput) {
        Write-Host "$(Get-TS): [DBG] $args" -ForegroundColor DarkMagenta
    }
}

function Execute-Cleanup {

    # Pause here to allow the user to see the mounted WIM
    Debug-Pause

    Write-Dbg-Host "Cleaning up"

    if ($global:WIM_Mount_Path) {
        Write-Dbg-Host "`r`nDismounting $global:WIM_Mount_Path"
        try {
            Dismount-WindowsImage -Path $global:WIM_Mount_Path -Discard -ErrorAction stop | Out-Null
        } catch {
            Write-Host "Failed to dismount WIM [$global:WIM_Mount_Path]" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }

    if ($global:ISO_Mount_Path) {
        Write-Dbg-Host "Dismounting $global:ISO_Mount_Path"

        try {
            Dismount-DiskImage -ImagePath $global:ISO_Mount_Path -ErrorAction stop | Out-Null
        } catch {
            Write-Host "Failed to dismount ISO [$global:ISO_Mount_Path]" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }

    }

    if ($global:StagingDir_Created -eq $true) {
        Write-Dbg-Host "Removing staging directory final: $global:Staging_Directory_Path"
        try {
            Remove-Item -Path $global:Staging_Directory_Path -Recurse -Force -ErrorAction stop | Out-Null
        } catch {
            Write-Host "Failed to remove $global:Staging_Directory_Path" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }
}

function Validate-Requirements {

    Write-Host "Checking for required support tools" -ForegroundColor Blue
    # Check if the script is running with administrative privileges
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "You do not have Administrator rights to run this script.`nPlease re-run this script as an Administrator." -ForegroundColor Red
        exit
    }
    # Look for the oscdimg.exe tool in the commonly used install path for the ADK.
    $adkOsCdImgPath = "\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
    $progFilesPath = Get-ChildItem "Env:ProgramFiles(x86)"
    if ($progFilesPath -ne $null) {
        $executablePath = Join-Path -Path $progFilesPath.Value -ChildPath $adkOsCdImgPath
        if (Test-Path -Path $executablePath) {
            Write-Dbg-Host "Found oscdimg.exe in: $executablePath"
            $global:oscdimg_exe = $executablePath
            return $true
        }
        Write-Dbg-Host "oscdimg.exe not found in $executablePath"
    }
    # Final attempt to find oscdimg.exe in the system PATH
    $executablePath = (where.exe oscdimg.exe 2>$null)
    if ($null -eq $executablePath) {
        # See if oscdimg.exe exists in the current working directory
        $executablePath = Join-Path -Path $PWD.Path -ChildPath "oscdimg.exe"
        if (-not (Test-Path -Path $executablePath)) {
            Write-Host "`r`nRequired support tools not found!" -ForegroundColor Red
            Write-Dbg-Host "oscdimg.exe not found in $PWD or in the system PATH!"
            Show-ADK-Req
            return $false
        }
    }

    Write-Dbg-Host "oscdimg.exe found in: $executablePath"
    $global:oscdimg_exe = $executablePath
    return $true
}

function Initialize-MediaPaths {
    param (
         [string] $MediaPath,
         [string] $NewMediaPath
     )

    $isUNCPath = $false
    $localMediaPath = $MediaPath
    $mountResult = $null

    Write-Host "Staging media" -ForegroundColor Blue
    $global:Src_Media_Path = $MediaPath
    # See if MediaPath is a UNC path
    if ($MediaPath -match "^\\\\") {
        Write-Dbg-Host "[$MediaPath] is a UNC path"
        $isUNCPath = $true
    }

    # Now determine if this is an ISO
    if ($MediaPath -match "\.iso$") {

        Write-Dbg-Host "$MediaPath is an ISO file"
        if ($isUNCPath) {

            $localIsoPath = $global:Staging_Directory_Path + "\$((Get-Item -Path $global:Src_Media_Path).Name)"
            Write-Host "Copying [$global:Src_Media_Path] to staging directory"
            Write-Dbg-Host "Copying [$global:Src_Media_Path] --> [$localIsoPath]"
            try {
                Copy-LargeFileWithProgres -SourcePath $global:Src_Media_Path -Destination $localIsoPath -Force -ErrorAction stop | Out-Null
            } catch {
                Write-Host $_.Exception.Message -ForegroundColor Red
                return $false
            }
        } else{
            # Get full path for the ISO
            $global:Src_Media_Path = (Get-Item -Path $MediaPath).FullName
            if ($global:Src_Media_Path -eq $null) {
                Write-Host "Failed to get full path for [$MediaPath]" -ForegroundColor Red
                return $false
            }
            $localIsoPath = $global:Src_Media_Path
        }

        Write-Host "--->Mounting ISO from staged media"
        Write-Dbg-Host "Mounting ISO: $localIsoPath"
        $mountResult = Mount-DiskImage -ImagePath $localIsoPath -PassThru -ErrorAction stop
        if ($mountResult -eq $null) {
            Write-Host "Failed to mount $localIsoPath" -ForegroundColor Red
            return $false
        }

        $global:ISO_Mount_Path = $localIsoPath
        $localMediaPath = ($mountResult | Get-Volume).DriveLetter + ":"

        # Retrieve the volume label from the mounted ISO to be used later if a new ISO is created
        $global:ISO_Lable = (Get-Volume -DriveLetter ($mountResult | Get-Volume).DriveLetter).FileSystemLabel

    } else {

        Write-Dbg-Host "[$MediaPath] is a folder"
        $tmpPath = $MediaPath
        if ($MediaPath[-1] -eq "\") {
            $tmpPath = $MediaPath.Substring(0, $MediaPath.Length - 1)
            Write-Dbg-Host "tmpPath: $tmpPath"
        }

        $global:Src_Media_Path = $tmpPath
        $localMediaPath = $tmpPath
    }

    $bootWimPath = $localMediaPath + "\sources\boot.wim"
    Write-Dbg-Host "Making sure [$bootWimPath] exists"
    if (-not (Test-Path -Path $bootWimPath)) {
        Write-Host "[$localMediaPath\] does not appear to point to valid Windows media!" -ForegroundColor Red
        return $false
    }

    # Get the current working directory and add "WimMount" to it
    $global:WIM_Mount_Path = $global:Staging_Directory_Path + "\WimMount"

    # If the WIM MOUNT directory does not exist, create it
    if (-not (Test-Path -Path $global:WIM_Mount_Path)) {
        New-Item -ItemType Directory -Path $global:WIM_Mount_Path -Force | Out-Null
        Write-Dbg-Host "Creating $global:WIM_Mount_Path"
    }else{
        Write-Dbg-Host "$global:WIM_Mount_Path already exists"
    }

    # Create a new folder to stage the updated media content
    if ($NewMediaPath){
        Write-Dbg-Host "[$NewMediaPath] provided"
        $tmpPath = $NewMediaPath

        if ($NewMediaPath -match "^[a-zA-Z]:$") {
            $tmpPath = "$NewMediaPath\"
        } else {
            if ($NewMediaPath[-1] -eq "\") {
                $tmpPath = $NewMediaPath.Substring(0, $tmpPath.Length - 1)
            }
        }
        Write-Dbg-Host "tmpPath: $tmpPath"
        $global:Temp_Media_To_Update_Path = $tmpPath
    } else{
        $global:Temp_Media_To_Update_Path = $global:Staging_Directory_Path + "\MediaToUpdate"
    }

    if (-not (Test-Path -Path $global:Temp_Media_To_Update_Path)) {
        try {
            New-Item -ItemType Directory -Path $global:Temp_Media_To_Update_Path  -Force | Out-Null
            Write-Dbg-Host "[$global:Temp_Media_To_Update_Path] created"
        } catch {
            Write-Host $_.Exception.Message -ForegroundColor Red
            return $false
        }
    }

    Write-Dbg-Host "Copying [$localMediaPath] --> [$global:Temp_Media_To_Update_Path]"
    try {
        Copy-FilesWithProgress -SourcePath $localMediaPath -DestinationPath $global:Temp_Media_To_Update_Path
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $false
    }

    if ($mountResult -ne $null) {
        Write-Dbg-Host "Unmounting [$global:ISO_Mount_Path]"
        try {
            Dismount-DiskImage -ImagePath $global:ISO_Mount_Path -ErrorAction stop | Out-Null
        } catch {
            Write-Host "Failed to dismount ISO [$global:ISO_Mount_Path]" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            return $false
        }
    }

    Write-Dbg-Host "Media [$global:Temp_Media_To_Update_Path] ready for update!"

    return $true
}

function Initialize-StagingDirectory {
     param (
         [string] $StagingDir
     )

    # If $StagingDir does not exist, set it to the system %TEMP%\%randomdir% directory
    Write-Host "Initializing staging directory" -ForegroundColor Blue

    if (-not $StagingDir) {
        $global:Staging_Directory_Path = [System.IO.Path]::GetTempPath() + ([System.IO.Path]::GetRandomFileName()).Replace(".", "")
        Write-Dbg-Host "Using default staging directory: $global:Staging_Directory_Path"
        New-Item -ItemType Directory -Path $global:Staging_Directory_Path -Force | Out-Null
        $global:StagingDir_Created = $true
    } else {
        Write-Dbg-Host "Using provided staging directory: $StagingDir"

        $global:Staging_Directory_Path = $StagingDir
        if ($StagingDir[-1] -eq "\") {
            $global:Staging_Directory_Path = $StagingDir.Substring(0, $StagingDir.Length - 1)
        }

        # If the provided staging directory is the root of a drive, and in the format of "D:" or "D:\", append a random subfolder to it
        if ($global:Staging_Directory_Path -match "^[a-zA-Z]:$") {
            $global:Staging_Directory_Path = "$global:Staging_Directory_Path\" + ([System.IO.Path]::GetRandomFileName()).Replace(".", "")
            Write-Dbg-Host "Appending random subfolder to staging directory: $global:Staging_Directory_Path"
            New-Item -ItemType Directory -Path $global:Staging_Directory_Path -Force | Out-Null
            $global:StagingDir_Created = $true
        } elseif (-not (Test-Path -Path $global:Staging_Directory_Path)) {
            # Provided staging directory does not exist, ask the user if they want to create it
            Write-Host "Staging directory [$global:Staging_Directory_Path] does not exist. Do you want to create it? (Y/N)" -ForegroundColor Yellow
            $response = Read-Host
            if ($response -ne "Y") {
                Write-Host "Aborting execution`r`n" -ForegroundColor Red
                return $false
            } else {
                New-Item -ItemType Directory -Path $global:Staging_Directory_Path -Force | Out-Null
                $global:StagingDir_Created = $true
                Write-Dbg-Host "[$global:Staging_Directory_Path] created"
            }
        }
    }
    $drive = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -eq $global:Staging_Directory_Path.Substring(0, 3) }
    Write-Dbg-Host "Drive [$drive] free disk space: $($drive.Free / 1GB)GB"
    if ($drive.Free -lt 10GB) {
        Write-Host "Drive [$drive] used for temp file staging does not not have enough free disk space! (10GB required)" -ForegroundColor Red
        return $false
    }

    return $true
}
function Validate-Parameters {
    param (
        [string] $TargetType,
        [string] $ISOPath,
        [string] $USBDrive,
        [string] $NewMediaPath,
        [string] $FileSystem,
        [string] $StagingDir
     )


    if ($StagingDir){
        $driveLetter = $StagingDir.SubString(0,1)
        $fs = (Get-Volume -DriveLetter $driveLetter).FileSystem

        if ($fs -ne "NTFS" -and $fs -ne "ReFS") {
            Write-Host "`r`n-StagingDir [$StagingDir] must target an NTFS or ReFS based file system`r`n" -ForegroundColor Red
            return $false
        }
    }

    if (-not $TargetType) {
        Write-Host "`r`n-TargetType parameter required`r`n" -ForegroundColor Red
        return $false
    }

    switch ($TargetType) {
        "ISO" {

            if ($NewMediaPath){
                Write-Host "`r`n-NewMediaPath parameter invalid for TargetType ISO.`r`n" -ForegroundColor Red
                return $false
            }

            if ($USBDrive) {
                Write-Host "`r`n-USBDrive parameter invalid for TargetType ISO.`r`n" -ForegroundColor Red
                return $false
            }

            if ($FileSystem) {
                Write-Host "`r`n-FileSystem parameter invalid for TargetType ISO.`r`n" -ForegroundColor Red
                return $false
            }

            if (-not $ISOPath) {
                Write-Host "`r`n-ISOPath parameter required for TargetType ISO.`r`n" -ForegroundColor Red
                return $false
            }

            if (-not ($ISOPath -match "\.iso$")) {
                Write-Host "`r`n-ISOPath must specify a *.ISO file.`r`n" -ForegroundColor Red
                Write-Dbg-Host "Invalid ISOPath: $ISOPath"
                return $false
            }
            # if $ISOPath exists, ask the user if they want to overwrite it, otherwise abort
            if (Test-Path -Path $ISOPath) {
                Write-Host "ISO [$ISOPath] already exists. Do you want to overwrite it? (Y/N)" -ForegroundColor Yellow
                $response = Read-Host
                if ($response -ne "Y") {
                    Write-Host "Aborting execution`r`n" -ForegroundColor Red
                    exit
                } else {
                    Write-Dbg-Host "Deleting [$ISOPath]"
                    Remove-Item -Path $ISOPath -Force
                }
            }

            Write-Dbg-Host "ISOPath: $ISOPath"
        }
        "USB" {

            if ($NewMediaPath){
                Write-Host "`r`n-NewMediaPath parameter invalid for TargetType USB.`r`n" -ForegroundColor Red
                return $false
            }

            if ($ISOPath) {
                Write-Host "`r`n-ISOPath parameter invalid for TargetType USB.`r`n" -ForegroundColor Red
                return $false
            }

            if ($FileSystem -and
               ($FileSystem -ne "FAT32" -and $FileSystem -ne "ExFAT" -and $FileSystem -ne "NTFS")) {
               Write-Host "`r`n-FileSystem must be FAT32, ExFAT, or NTFS to proceed." -ForegroundColor Red
               return $false
            }

            if ($FileSystem -eq "NTFS") {
                Write-Host "`r`n⚠️  WARNING: The NTFS format may not be supported by all UEFI firmware." -ForegroundColor Yellow
                Write-Host "       However, it is required for files larger than 4 GB (such as install.wim).\r\n" -ForegroundColor Yellow

            }


            if (-not $USBDrive) {
                Write-Host "`r`n-USBDrive parameter required for TargetType USB.`r`n" -ForegroundColor Red
                return $false
            }

            if (-not ($USBDrive -match "^[a-zA-Z]:$")) {
                Write-Host "`r`n-USBDrive must specify a valid drive letter. ($USBDrive invalid!)`r`n" -ForegroundColor Red
                return $false
            } else {
                Write-Host "`r`nWARNING: Contents on drive [$USBDrive] will be erased! Continue? (Y/N) " -ForegroundColor Yellow
                $response = Read-Host
                if ($response -ne "Y") {
                    Write-Host "Aborting execution`r`n" -ForegroundColor Red
                    exit
                }
            }
        }
        "LOCAL" {

            if ($USBDrive) {
                Write-Host "`r`n-USBDrive parameter invalid for TargetType LOCAL.`r`n" -ForegroundColor Red
                return $false
            }

            if ($ISOPath) {
                Write-Host "`r`n-ISOPath parameter invalid for TargetType LOCAL.`r`n" -ForegroundColor Red
                return $false
            }

            if ($FileSystem) {
                Write-Host "`r`n-FileSystem parameter invalid for TargetType LOCAL.`r`n" -ForegroundColor Red
                return $false
            }

            if (-not $NewMediaPath) {
                Write-Host "`r`n-NewMediaPath parameter required for TargetType LOCAL.`r`n" -ForegroundColor Red
                return $false
            }

            $tmpPath = $NewMediaPath
            if ($NewMediaPath -match "^[a-zA-Z]:$" -or $NewMediaPath -match "^[a-zA-Z]:\\$") {
                $isRoot = $true
                $tmpPath = "$($NewMediaPath.Substring(0, 2))\"
            }

            $driveLetter = $tmpPath.SubString(0,1)
            $fs = (Get-Volume -DriveLetter $driveLetter).FileSystem

            if ($fs -ne "NTFS" -and $fs -ne "ReFS") {
                Write-Host "`r`n-NewMediaPath [$tmpPath] must target an NTFS or ReFS based file system`r`n" -ForegroundColor Red
                return $false
            }

            $drive = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -eq $tmpPath.Substring(0, 3) }
            if ($drive.Free -lt 10GB) {
                Write-Host "$NewMediaPath does not have enough free space! (10GB required)" -ForegroundColor Red
                return $false
            }

            if ($isRoot){
                return $true
            }

            if (-not (Test-Path -Path $NewMediaPath)) {
                Write-Host "NewMediaPath [$NewMediaPath] does not exist! Create it? (Y/N)" -ForegroundColor Yellow
                $response = Read-Host
                if ($response -ne "Y") {
                    Write-Host "Aborting execution`r`n" -ForegroundColor Red
                    exit
                } else {
                    New-Item -ItemType Directory -Path $NewMediaPath -Force | Out-Null
                }
            } else {
                Write-Host "NewMediaPath [$NewMediaPath] already exists. Do you want to overwrite it? (Y/N)" -ForegroundColor Yellow
                $response = Read-Host
                if ($response -ne "Y") {
                    Write-Host "Aborting execution`r`n" -ForegroundColor Red
                    exit
                } else {
                    Write-Dbg-Host "Deleting [$NewMediaPath]"
                    Remove-Item -Path $NewMediaPath -Recurse -Force
                }
            }
        }
        default {
            Write-Host "Invalid TargetType: $TargetType" -ForegroundColor Red
            return $false
        }
    }

    return $true
}

function Copy-FilesWithProgress {
    param (
        [string] $SourcePath,
        [string] $DestinationPath
    )

    $files = Get-ChildItem -Path $SourcePath -Recurse
    $totalFiles = $files.Count
    $currentFile = 0

    foreach ($file in $files) {
        $currentFile++
        $percentComplete = [math]::Round(($currentFile / $totalFiles) * 100, 2)
        $destinationFile = $file.FullName -replace [regex]::Escape($SourcePath), $DestinationPath

        $destinationDir = [System.IO.Path]::GetDirectoryName($destinationFile)
        if (-not (Test-Path -Path $destinationDir)) {
            New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
        }

        # if the file is larger than 5MB, use the Copy-LargeFileWithProgres function
        if ($file.Length -gt 5MB) {
            Copy-LargeFileWithProgres -SourcePath $file.FullName -DestinationPath $destinationFile
            continue
        } else{
            Copy-Item -Path $file.FullName -Destination $destinationFile -Force
        }

        Write-Progress -Activity "Copying files" -Status "copying [$file]" -PercentComplete $percentComplete
    }
    Write-Progress -Activity "Copying files" -Completed
}

function Copy-LargeFileWithProgres {
    param (
        [string] $SourcePath,
        [string] $DestinationPath
    )

    # Define source and destination files
    $sourceFile = $SourcePath
    $destinationFile = $DestinationPath
    $fileName = [System.IO.Path]::GetFileName($sourceFile)

    # Get the total size of the source file
    $totalSize = (Get-Item $sourceFile).Length

    # Open file streams
    $sourceStream = [System.IO.File]::OpenRead($sourceFile)
    $destinationStream = [System.IO.File]::Create($destinationFile)

    # Define buffer size (e.g., 1 MB)
    $bufferSize = 10MB
    $buffer = New-Object byte[] $bufferSize
    $totalRead = 0

    # Copy in chunks
    try {
        while (($bytesRead = $sourceStream.Read($buffer, 0, $bufferSize)) -gt 0) {
            # Write to destination
            $destinationStream.Write($buffer, 0, $bytesRead)

            # Update total read
            $totalRead += $bytesRead

            # Calculate progress
            $percentComplete = [math]::Round(($totalRead / $totalSize) * 100, 2)

            # Display progress
            Write-Progress -Activity "Copying files" -Status "copying [$fileName] $percentComplete% complete" -PercentComplete $percentComplete
        }
        Write-Progress -Activity "Copying file" -Completed
    }
    finally {
        # Close streams
        $sourceStream.Close()
        $destinationStream.Close()
    }
}

function Copy-2023BootBins {

    $bootWimPath = $global:Temp_Media_To_Update_Path + "\sources\boot.wim"
    # Make sure we have a boot.wim file
    if (-not (Test-Path -Path $bootWimPath)) {
        Write-Host "[$global:Src_Media_Path] does not appear to point to valid Windows media!" -ForegroundColor Red
        return $false
    }
    $bootWimMount = $global:WIM_Mount_Path
    Write-Dbg-Host "Mounting [$bootWimPath]"
    Write-Host "--->Mounting boot.wim from staged media"
    try {
        $mountedImage = Mount-WindowsImage -ImagePath $bootWimPath -Index 1 -Path $bootWimMount -ReadOnly -ErrorAction stop | Out-Null
        Write-Dbg-Host "Mounted [$bootWimPath] --> [$bootWimMount]"
    } catch {
        Write-Host "Failed to mount boot.wim of the source media!`r`nMake sure -StagingDir and -NewMediaPath are targetting an NTFS or ReFS based filesystem." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $false
    }

    $ex_bins_path = $bootWimMount + "\Windows\Boot\EFI_EX"
    $ex_fonts_path = $bootWimMount + "\Windows\Boot\FONTS_EX"
    $ex_dvd_path = $bootWimMount + "\Windows\Boot\DVD_EX"

    # Make sure the directories exist
    if (-not (Test-Path -Path $ex_dvd_path) -or
        -not (Test-Path -Path $ex_fonts_path) -or
        -not (Test-Path -Path $ex_bins_path)) {
        Write-Host "-MediaPath [$((Get-Item -Path $global:Src_Media_Path).Name)] does not have required binaries." -ForegroundColor Red
        Write-Host "Make sure all required updates (2024-4B or later) have been applied." -ForegroundColor Red
        Write-Host "[$global:Temp_Media_To_Update_Path] staged but was not updated!" -ForegroundColor Red
        return $false
    }

    Write-Host "Updating staged media to use boot binaries signed with 'Windows UEFI CA 2023' certificate" -ForegroundColor Blue

    try {
        # Try to find and copy a valid boot manager
$bootmgrEx = Join-Path $ex_bins_path "bootmgr_EX.efi"
$bootmgfwEx = Join-Path $ex_bins_path "bootmgfw_EX.efi"

if (Test-Path $bootmgrEx) {
    Write-Dbg-Host "Copying $bootmgrEx to $global:Temp_Media_To_Update_Path\bootmgr.efi"
    Copy-Item -Path $bootmgrEx -Destination "$global:Temp_Media_To_Update_Path\bootmgr.efi" -Force -ErrorAction stop | Out-Null
} elseif (Test-Path $bootmgfwEx) {
    Write-Dbg-Host "Copying $bootmgfwEx to $global:Temp_Media_To_Update_Path\bootmgr.efi"
    Copy-Item -Path $bootmgfwEx -Destination "$global:Temp_Media_To_Update_Path\bootmgr.efi" -Force -ErrorAction stop | Out-Null
} else {
    Write-Warning "No *_EX.efi boot manager found in $ex_bins_path — skipping bootmgr.efi replacement."
}


        # Copy $ex_bins_path\bootmgrfw_EX.efi to $global:Temp_Media_To_Update_Path\efi\boot\bootx64.efi
        Write-Dbg-Host "Copying $ex_bins_path\bootmgfw_EX.efi to $global:Temp_Media_To_Update_Path\efi\boot\bootx64.efi"
        Copy-Item -Path $ex_bins_path"\bootmgfw_EX.efi" -Destination $global:Temp_Media_To_Update_Path"\efi\boot\bootx64.efi" -Force -ErrorAction stop | Out-Null

        # Copy $ex_dvd_path\EFI\en-US\efisys_EX.bin to $global:Temp_Media_To_Update_Path\efi\microsoft\boot\
        Write-Dbg-Host "Copying $ex_dvd_path\EFI\en-US\efisys_EX.bin to $global:Temp_Media_To_Update_Path\efi\microsoft\boot\efisys_ex.bin"
        Copy-Item -Path $ex_dvd_path"\EFI\en-US\efisys_EX.bin" -Destination $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\efisys_ex.bin" -Force -ErrorAction stop | Out-Null

        # Copy $ex_fonts_path\* to $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex
        Write-Dbg-Host "Copying $ex_fonts_path\* to $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex"
        New-Item -ItemType Directory -Path $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts_ex" -Force | Out-Null
        Copy-Item -Path $ex_fonts_path"\*" -Destination $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts_ex\" -Force -ErrorAction stop | Out-Null

        # rename $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex\*_EX.ttf to *.ttf
        Write-Dbg-Host "Renaming $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex\*_EX.ttf to *.ttf"
        Get-ChildItem -Path $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts_ex" -Filter "*_EX.ttf" | Rename-Item -NewName { $_.Name -replace '_EX', '' } -Force -ErrorAction stop

        # Copy $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex\* to $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts
        Write-Dbg-Host "Copying $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex\* to $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts"
        Copy-Item -Path $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts_ex\*" -Destination $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts" -Force -ErrorAction stop | Out-Null

        # remove $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex
        Write-Dbg-Host "Removing $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex"
        Remove-Item -Path $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts_ex" -Recurse -Force -ErrorAction stop | Out-Null

    } catch {
        Write-Host "$_" -ForegroundColor Red
        return $false
    }

    if ($global:WIM_Mount_Path) {
        Write-Dbg-Host "`r`nDismounting $global:WIM_Mount_Path"
        try {
            Dismount-WindowsImage -Path $global:WIM_Mount_Path -Discard -ErrorAction stop | Out-Null
            $global:WIM_Mount_Path = $null
        } catch {
            Write-Host "Failed to dismount WIM [$global:WIM_Mount_Path]" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }
    return $true
}

function Create-ISOMedia {
    param (
         [string] $ISOPath
     )

     Write-Host "Writing 'Windows UEFI CA 2023' bootable ISO media at location [$ISOPath]" -ForegroundColor Blue

     # If $ISOLable is not set, then defualt to "WINDOWS2023PCAISO"
    if (-not $global:ISO_Lable) {
        $global:ISO_Lable = "WINDOWS2023PCAISO"
    }

    # Generate a timestamp string in the following format: mm/dd/yyyy,hh:mm:ss
    $timestamp = Get-Date -Format "MM/dd/yyyy,HH:mm:ss"

    $runCommand = "-l$global:ISO_Lable -t$timestamp -bootdata:2#p0,e,b$global:Temp_Media_To_Update_Path\boot\etfsboot.com#pEF,e,b$global:Temp_Media_To_Update_Path\efi\microsoft\boot\efisys_ex.bin -u2 -udfver102 -o $global:Temp_Media_To_Update_Path $ISOPath"

    Write-Dbg-Host "Running: $global:oscdimg_exe $runCommand"
    try {

        # strip the file name from $ISOPath
        $isoDirPath = $ISOPath.Substring(0, $ISOPath.LastIndexOf("\"))

        # Make sure ISO path is valid or the call to oscdimg.exe will fail
        if (-not (Test-Path $isoDirPath)) {
            Write-Dbg-Host "ISOPath: $isoDirPath not valid, creating it" -ForegroundColor Red
            New-Item -ItemType Directory -Path $isoDirPath -Force | Out-Null
        }

        # $stdoutFile = "$Staging_Directory_Path\" + ([System.IO.Path]::GetRandomFileName()).Replace(".", "")
        # $stderrFile = "$Staging_Directory_Path\" + ([System.IO.Path]::GetRandomFileName()).Replace(".", "")
        Write-Dbg-Host "Writing [$ISOPath]"
        # Start-Process -FilePath $global:oscdimg_exe -ArgumentList $runCommand -Wait -NoNewWindow -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -ErrorAction Stop | Out-Null
        Start-Process -FilePath $global:oscdimg_exe -ArgumentList $runCommand -Wait -NoNewWindow -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "Failed to create ISO: $ISOPath" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $false
    }
    return $true
}

function Create-USBMedia {
    param (
         [string] $USBDrive,
         [string] $FileSystem
     )

    Write-Host "Creating 'Windows UEFI CA 2023' bootable USB media on drive [$USBDrive]" -ForegroundColor Blue

    $volume = Get-Volume -DriveLetter $USBDrive.TrimEnd(':')
    $currentLabel = $volume.FileSystemLabel

    if (-not $currentLabel) {
        $currentLabel = "BOOT2023PCA"
    }

    $fileSystem = $FileSystem
    if (-not $FileSystem) {
        $fileSystem = "NTFS"
    }

    # Format the drive using the existing label
    try {
        Format-Volume -DriveLetter $USBDrive.TrimEnd(':') -FileSystem $fileSystem -NewFileSystemLabel $currentLabel -Force
    } catch {
        Write-Host "Failed to format drive [$USBDrive] as $fileSystem" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $false
    }

    try {
        Write-Dbg-Host "Copying media to USB drive [$USBDrive\]"
        Copy-FilesWithProgress -SourcePath "$global:Temp_Media_To_Update_Path" -DestinationPath "$USBDrive\"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $false
    }

    return $true
}
function Update-LocalMedia {

    # Work here was already done during staging and CopyBins
    Write-Host "Creating 'Windows UEFI CA 2023' bootable local media at location [$global:Temp_Media_To_Update_Path]" -ForegroundColor Blue
    return $true
}

# Global variables
$global:ScriptName = Split-Path -Leaf $PSCommandPath
$global:Src_Media_Path = $null
$global:Staging_Directory_Path = $null
$global:StagingDir_Created = $false
$global:Temp_Media_To_Update_Path = $null
$global:WIM_Mount_Path = $null
$global:ISO_Mount_Path = $null
$global:ISO_Label = $null
$global:oscdimg_exe = $null
$global:Dbg_Pause = $false
$global:Dbg_Ouput = $false

Write-Host "`r`n`r`nMicrosoft 'Windows UEFI CA 2023' Media Update Script - Version 1.2`r`n" -ForegroundColor DarkYellow

# First validate that the required tools/environment exist
$result = Validate-Parameters -TargetType $TargetType -ISOPath $ISOPath -USBDrive $USBDrive -NewMediaPath $NewMediaPath -FileSystem $FileSystem -StagingDir $StagingDir
if (-not $result) {
    Write-Dbg-Host "Validate-Parameters failed"
    Show-Usage
    exit
}

# validate params
$result = Validate-Requirements
if (-not $result) {
    Write-Dbg-Host "Validate-Requirements failed"
    exit
}

# Now setup the staging infra
$result = Initialize-StagingDirectory -StagingDir $StagingDir
if (-not $result) {
    Write-Dbg-Host "Initialize-StagingDirectory failed"
    Execute-Cleanup
    exit
}

# Now initialize media path requirements
$result = Initialize-MediaPaths -MediaPath $MediaPath -NewMediaPath $NewMediaPath
if (-not $result) {
    Write-Dbg-Host "Initialize-MediaPath failed"
    Execute-Cleanup
    exit
}

$result = Copy-2023BootBins
if (-not $result) {
    Write-Dbg-Host "Copy-2023BootBins failed"
    Execute-Cleanup
    exit
}

switch ($TargetType) {
    "ISO" {
        $result = Create-ISOMedia -ISOPath $ISOPath
        if (-not $result) {
            Write-Host "ISO media creation failed" -ForegroundColor Red
        } else {
            if (Test-Path -Path $ISOPath){
                Write-Host "Successfully created ISO [$ISOPath]" -ForegroundColor Green
            }
        }
    }
    "USB" {
        $result = Create-USBMedia -USBDrive $USBDrive -FileSystem $FileSystem
        if (-not $result) {
            Write-Host "USB media creation failed!" -ForegroundColor Red
            break
        }
        Write-Host "Successfully created media on USB drive [$USBDrive]" -ForegroundColor Green
        break
    }
    "LOCAL" {

        $result = Update-LocalMedia
        if (-not $result) {
            Write-Host "Local media update failed!" -ForegroundColor Red
            break
        }
        Write-Host "Local media updated successfully at location [$global:Temp_Media_To_Update_Path]" -ForegroundColor Green
        break
    }
    default {
        Write-Host "Invalid TargetType: $TargetType" -ForegroundColor Red
        Show-Usage
        break
    }
}

Execute-Cleanup
exit
