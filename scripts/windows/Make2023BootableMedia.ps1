<#
.SYNOPSIS
    Microsoft 'Windows UEFI CA 2023' Media Update Script

.DESCRIPTION
    This script updates Windows media to use boot binaries signed with the 'Windows UEFI CA 2023' certificate.

.NOTES
    File Name  : Make2023BootableMedia.ps1
    Author     : Microsoft Corporation
    Version    : 1.3
    Date       : 2025-11-07

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
    [string] $StagingDir,

    [Parameter(Position = 7, Mandatory=$false)]
    [bool] $DebugOn = $false
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
    Write-Host "The Windows ADK must be installed on the system if trying to create ISO media. Available at http://aka.ms/adk" -ForegroundColor Red
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
    if ($global:Dbg_Output) {
        Write-Host "$(Get-TS): [DBG] $args" -ForegroundColor DarkMagenta
    }
}

function Execute-Cleanup {

    # Pause here to allow the user to see the mounted WIM
    Debug-Pause

    Write-Dbg-Host "Cleaning up"

    if ($global:WIM_Mount_Path) {
        Write-Dbg-Host "Dismounting [$global:WIM_Mount_Path]"
        try {
            Dismount-WindowsImage -Path $global:WIM_Mount_Path -Discard -ErrorAction stop | Out-Null
            try {
                Write-Dbg-Host "Removing WIM mount path [$global:WIM_Mount_Path]"
                Remove-Item -Path $global:WIM_Mount_Path -Recurse -Force -ErrorAction stop | Out-Null
            } catch {
                Write-Host "Failed to remove WIM mount path [$global:WIM_Mount_Path]" -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
            }
        } catch {
            Write-Host "Failed to dismount WIM [$global:WIM_Mount_Path]" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }

    if ($global:ISO_Mount_Path) {
        Write-Dbg-Host "Dismounting [$global:ISO_Mount_Path]"

        try {
            Dismount-DiskImage -ImagePath $global:ISO_Mount_Path -ErrorAction stop | Out-Null
        } catch {
            Write-Host "Failed to dismount ISO [$global:ISO_Mount_Path]" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }

    if ($global:StagingDir_Created -eq $true) {
        Write-Dbg-Host "Removing staging directory [$global:Staging_Directory_Path]"
        try {
            Remove-Item -Path $global:Staging_Directory_Path -Recurse -Force -ErrorAction stop | Out-Null
        } catch {
            Write-Host "Failed to remove [$global:Staging_Directory_Path]" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }
}

function Validate-Requirements {
    param (
        [string] $TargetType
    )

    # If the target type is ISO, check for the required support tools from the ADK
    if ($TargetType -eq "ISO") {

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
                Write-Dbg-Host "Found [oscdimg.exe] in [$executablePath]"
                $global:oscdimg_exe = $executablePath
                return $true
            }
            Write-Dbg-Host "[oscdimg.exe] not found in [$executablePath]"
        }
        # Final attempt to find oscdimg.exe in the system PATH
        $executablePath = (where.exe oscdimg.exe 2>$null)
        if ($null -eq $executablePath) {
            # See if oscdimg.exe exists in the current working directory
            $executablePath = Join-Path -Path $PWD.Path -ChildPath "oscdimg.exe"
            if (-not (Test-Path -Path $executablePath)) {
                Write-Host "`r`nRequired support tools not found!" -ForegroundColor Red
                Write-Dbg-Host "[oscdimg.exe] not found in [$PWD] or in the system PATH!"
                Show-ADK-Req
                return $false
            }
        }

        Write-Dbg-Host "[oscdimg.exe] found in [$executablePath]"
        $global:oscdimg_exe = $executablePath
    }
    return $true
}

function Initialize-MediaPaths {
    param (
         [string] $MediaPath,
         [string] $NewMediaPath,
         [string] $StagingDir
     )

    $isUNCPath = $false
    $localMediaPath = $MediaPath
    $mountResult = $null

    # If NewMediaPath is provided, use it as the staging directory
    if ($NewMediaPath) {
        try {
            $tmpPath = ConvertTo-AbsolutePath -Path $NewMediaPath
        }
        catch {
            Write-Host "Error processing [$NewMediaPath] -> Error: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }

        if ($NewMediaPath -match "^[a-zA-Z]:$") {
            $tmpPath = "$NewMediaPath\"
        }

        $global:Temp_Media_To_Update_Path = $tmpPath
        $global:Staging_Directory_Path = $tmpPath

    } else {

        # If NewMediaPath is not provided, use the StagingDir as the staging directory
        $result = Initialize-StagingDirectory $StagingDir
        if ($result -eq $false) {
            return $false
        }
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

    Write-Host "Staging media" -ForegroundColor Blue
    $global:Src_Media_Path = $MediaPath
    # See if MediaPath is a UNC path
    if ($MediaPath -match "^\\\\") {
        Write-Dbg-Host "[$MediaPath] is a UNC path"
        $isUNCPath = $true
    }

    # Now determine if this is an ISO
    if ($MediaPath -match "\.iso$") {

        Write-Dbg-Host "[$MediaPath] is an ISO file"
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

        Write-Host "Mounting ISO from staged media" -ForegroundColor Blue
        Write-Dbg-Host "Mounting ISO [$localIsoPath]"
        $mountResult = Mount-DiskImage -ImagePath $localIsoPath -PassThru -ErrorAction stop
        if ($mountResult -eq $null) {
            Write-Host "Failed to mount $localIsoPath" -ForegroundColor Red
            return $false
        }

        $global:ISO_Mount_Path = $localIsoPath
        $localMediaPath = ($mountResult | Get-Volume).DriveLetter + ":"

        # Retrieve the volume label from the mounted ISO to be used later if a new ISO is created
        $global:ISO_Label = (Get-Volume -DriveLetter ($mountResult | Get-Volume).DriveLetter).FileSystemLabel

    } else {

        Write-Dbg-Host "[$MediaPath] is a directory"
        try {
            $tmpPath = ConvertTo-AbsolutePath -Path $MediaPath -AllowUNC $true
        }
        catch {
            Write-Host "Error processing [$MediaPath] -> Error: $($_.Exception.Message)" -ForegroundColor Red
            return $false
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
        Write-Dbg-Host "Creating mount path [$global:WIM_Mount_Path]"
    }else{
        Write-Dbg-Host "Mount path [$global:WIM_Mount_Path] already exists"
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
        Write-Dbg-Host "Using default staging directory [$global:Staging_Directory_Path]"
        New-Item -ItemType Directory -Path $global:Staging_Directory_Path -Force | Out-Null
        $global:StagingDir_Created = $true
    } else {
        Write-Dbg-Host "Using provided staging directory [$StagingDir]"

        try {
            $tmpPath = ConvertTo-AbsolutePath -Path $StagingDir
            Write-Dbg-Host "StagingDir [$StagingDir] -> [$tmpPath]"
        }
        catch {
            Write-Host "Staging failure -> Error: $($_.Exception.Message) [$StagingDir]" -ForegroundColor Red
            return $false
        }

        $global:Staging_Directory_Path = $tmpPath

        $driveLetter = $global:Staging_Directory_Path.Substring(0, 1)
        try {
            $fs = (Get-Volume -DriveLetter $driveLetter -ErrorAction Stop).FileSystem
        } catch {
            Write-Host "Drive [$driveLetter`:] does not exist or is not accessible." -ForegroundColor Red
            return $false
        }

        # Make sure the staging directory is on an NTFS or ReFS formatted file system. This is required for the WIM mounting process.
        if ($fs -ne "NTFS" -and $fs -ne "ReFS") {
            Write-Host "`r`nStagingDir [$global:Staging_Directory_Path] must target an NTFS or ReFS formatted file system.`r`n" -ForegroundColor Red

            if ($global:StagingDir_Created -eq $true) {
                Write-Dbg-Host "Removing staging directory [$global:Staging_Directory_Path]"
                Remove-Item -Path $global:Staging_Directory_Path -Recurse -Force | Out-Null
                $global:StagingDir_Created = $false
            }
            return $false
        }

        $drive = Get-PSDrive -Name $driveLetter -PSProvider FileSystem
        if ($drive.Free -lt 10GB) {
            Write-Host "Drive [$drive] used for temp file staging does not not have enough free disk space! (10GB required)" -ForegroundColor Red
            Write-Dbg-Host "Drive [$drive] free disk space: $($drive.Free / 1GB)GB"

            if ($global:StagingDir_Created -eq $true) {
                Write-Dbg-Host "Removing staging directory [$global:Staging_Directory_Path]"
                Remove-Item -Path $global:Staging_Directory_Path -Recurse -Force | Out-Null
            }
            return $false
        }

        if (Test-Path -Path "$global:Staging_Directory_Path\") {
            # Provided staging directory already exists, ask the user if they want to overwrite it
            Write-Dbg-Host "Staging directory [$global:Staging_Directory_Path] already exists."
            Write-Dbg-Host "Appending random subfolder to staging directory [$global:Staging_Directory_Path]"
            $global:Staging_Directory_Path = "$global:Staging_Directory_Path\" + ([System.IO.Path]::GetRandomFileName()).Replace(".", "")

            try {
                New-Item -ItemType Directory -Path $global:Staging_Directory_Path -Force | Out-Null
                $global:StagingDir_Created = $true
            } catch {
                Write-Host "Failed to create staging directory [$global:Staging_Directory_Path]" -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                return $false
            }
        } else {
            # Provided staging directory does not exist, create it
            try {
                New-Item -ItemType Directory -Path $global:Staging_Directory_Path -Force | Out-Null
                $global:StagingDir_Created = $true
                Write-Dbg-Host "[$global:Staging_Directory_Path] created"
            }
            catch {
                Write-Host "Failed to create staging directory [$global:Staging_Directory_Path]" -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                return $false
            }
        }
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
                Write-Dbg-Host "Invalid ISOPath [$ISOPath]"
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

            Write-Dbg-Host "ISOPath [$ISOPath]"
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
                ($FileSystem -ne "FAT32" -and $FileSystem -ne "ExFAT")) {
                Write-Host "`r`n-FileSystem must be FAT32 to boot on most UEFI systems." -ForegroundColor Red
                return $false
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
                # Make sure the drive can support FAT32 if that is the target/default file system.
                Write-Dbg-Host "Checking drive [$USBDrive] file system"
                if (-not $FileSystem -or $FileSystem -ne "ExFAT") {
                    $partition = Get-Partition -DriveLetter $USBDrive.TrimEnd(':')
                    Write-Dbg-Host "Partition: $partition"
                    Write-Dbg-Host "Partition size: $($partition.Size / 1GB)GB"
                    if ($partition.Size -gt 32GB) {
                        Write-Host "Target drive partition is larger than 32GB and cannot be formatted as FAT32. " -ForegroundColor Red
                        Write-Host "Create a partition smaller than 32GB and try again (or use ExFAT)." -ForegroundColor Red
                        return $false
                    }
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

            if ($StagingDir) {
                Write-Host "`r`n-StagingDir parameter ignored for TargetType LOCAL.`r`n" -ForegroundColor Yellow
            }

            try {
                $tmpPath = ConvertTo-AbsolutePath -Path $NewMediaPath
                Write-Dbg-Host "NewMediaPath: [$NewMediaPath] -> [$tmpPath]"
            }
            catch {
                Write-Host "-$NewMediaPath' -> Error: $($_.Exception.Message)" -ForegroundColor Red
                return $false
            }

            $driveLetter = $tmpPath.Substring(0,1)
            $fs = (Get-Volume -DriveLetter $driveLetter).FileSystem
            try {
                $fs = (Get-Volume -DriveLetter $driveLetter -ErrorAction Stop).FileSystem
            } catch {
                Write-Host "Drive [$driveLetter`:] does not exist or is not accessible." -ForegroundColor Red
                return $false
            }

            # Make sure the target drive is NTFS or ReFS. This is required for the WIM mount operations.
            if ($fs -ne "NTFS" -and $fs -ne "ReFS") {
                Write-Host "`r`n-NewMediaPath [$tmpPath] must target an NTFS or ReFS file system.`r`n" -ForegroundColor Red
                return $false
            }

            $drive = Get-PSDrive -Name $driveLetter -PSProvider FileSystem
            if ($drive.Free -lt 10GB) {
                Write-Host "[$tmpPath] does not have enough free space! (10GB required)" -ForegroundColor Red
                Write-Dbg-Host "Drive [$drive] free disk space: $($drive.Free / 1GB)GB"
                return $false
            }
        }
        default {
            Write-Host "Invalid TargetType: $TargetType" -ForegroundColor Red
            return $false
        }
    }

    return $true
}

function ConvertTo-AbsolutePath {
    param(
        [string]$Path,
        [bool] $AllowUNC = $false
        )

    # Reject UNC paths
    if (-not $AllowUNC) {
        if ($Path -match "^\\\\") {
            throw "Network (UNC) path not allowed"
        }
    }

    $tmpPath = $Path
    if ($Path[-1] -eq "\") {
        $tmpPath = $Path.Substring(0, $Path.Length - 1)
    }

    # If a root drive path (C:\), return as-is
    if ($tmpPath -match "^[a-zA-Z]:") {
        return $tmpPath
    }

    # Handle rooted but not fully qualified paths (\rootdir)
    if ($tmpPath -match "^\\[^\\]") {
        # Combine with current drive
        $currentDrive = (Get-Location).Drive.Name + ":"
        return [System.IO.Path]::GetFullPath($currentDrive + $tmpPath)
    }

    # Handle relative paths (.\subdir, ..\parent, subdir)
    if (-not [System.IO.Path]::IsPathRooted($tmpPath)) {
        return [System.IO.Path]::GetFullPath((Join-Path -Path $PWD.Path -ChildPath $tmpPath))
    }

    # For any other case, try to get full path
    return [System.IO.Path]::GetFullPath($tmpPath)
}

function Copy-FilesWithProgress {
    param (
        [string] $SourcePath,
        [string] $DestinationPath
    )

    $files = Get-ChildItem -Path $SourcePath -Recurse -File
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
    Write-Host "Mounting boot.wim from staged media" -ForegroundColor Blue
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
        # Special case the architecture specific binary name
        $bootmgr_archver = "bootx64.efi"
        if (Test-Path -Path $global:Temp_Media_To_Update_Path\efi\boot\bootaa64.efi) {
            $bootmgr_archver = "bootaa64.efi" # ARM64
        }

        # Copy $ex_bins_path\bootmgrfw_EX.efi to $global:Temp_Media_To_Update_Path\efi\boot\bootx64.efi
        Write-Dbg-Host "Copying [$ex_bins_path\bootmgfw_EX.efi] to [$global:Temp_Media_To_Update_Path\efi\boot\$bootmgr_archver]"
        Copy-Item -Path $ex_bins_path"\bootmgfw_EX.efi" -Destination $global:Temp_Media_To_Update_Path"\efi\boot\"$bootmgr_archver -Force -ErrorAction stop | Out-Null

        # Copy $ex_bins_path\bootmgr_EX.efi to $global:Temp_Media_To_Update_Path\bootmgr.efi (but only if it exists)
        # Note that this file technically is not signed with the 'Windows UEFI CA 2023' certificate, but if present in the update, it should be copied.
        if ((Test-Path -Path $ex_bins_path"\bootmgr_EX.efi")) {
             # Copy  $ex_bins_path\bootmgr_EX.efi to $global:Temp_Media_To_Update_Path\bootmgr.efi
            Write-Dbg-Host "Copying [$ex_bins_path\bootmgr_EX.efi] to [$global:Temp_Media_To_Update_Path\bootmgr.efi]"
            Copy-Item -Path $ex_bins_path"\bootmgr_EX.efi" -Destination $global:Temp_Media_To_Update_Path"\bootmgr.efi" -Force -ErrorAction stop | Out-Null
        } else {
            Write-Dbg-Host "[$ex_bins_path\bootmgr_EX.efi] does not exist. Skipping."
        }

        # Copy $ex_dvd_path\EFI\en-US\efisys_EX.bin to $global:Temp_Media_To_Update_Path\efi\microsoft\boot\
        Write-Dbg-Host "Copying [$ex_dvd_path\EFI\en-US\efisys_EX.bin] to [$global:Temp_Media_To_Update_Path\efi\microsoft\boot\efisys_ex.bin]"
        Copy-Item -Path $ex_dvd_path"\EFI\en-US\efisys_EX.bin" -Destination $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\efisys_ex.bin" -Force -ErrorAction stop | Out-Null

        # Copy $ex_fonts_path\* to $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex
        Write-Dbg-Host "Copying [$ex_fonts_path\*] to [$global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex]"
        New-Item -ItemType Directory -Path $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts_ex" -Force | Out-Null
        Copy-Item -Path $ex_fonts_path"\*" -Destination $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts_ex\" -Force -ErrorAction stop | Out-Null

        # Rename $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex\*_EX.ttf to *.ttf
        Write-Dbg-Host "Renaming [$global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex\*_EX.ttf] to [*.ttf]"
        Get-ChildItem -Path $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts_ex" -Filter "*_EX.ttf" | Rename-Item -NewName { $_.Name -replace '_EX', '' } -Force -ErrorAction stop

        # Copy $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex\* to $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts
        Write-Dbg-Host "Copying [$global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex\*] to [$global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts]"
        Copy-Item -Path $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts_ex\*" -Destination $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts" -Force -ErrorAction stop | Out-Null

        # Remove $global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex
        Write-Dbg-Host "Removing [$global:Temp_Media_To_Update_Path\efi\microsoft\boot\fonts_ex]"
        Remove-Item -Path $global:Temp_Media_To_Update_Path"\efi\microsoft\boot\fonts_ex" -Recurse -Force -ErrorAction stop | Out-Null

    } catch {
        Write-Host "$_" -ForegroundColor Red
        return $false
    }

    if ($global:WIM_Mount_Path) {
        Write-Dbg-Host "Dismounting [$global:WIM_Mount_Path]"
        try {
            Dismount-WindowsImage -Path $global:WIM_Mount_Path -Discard -ErrorAction stop | Out-Null
            try {
                Write-Dbg-Host "Removing WIM mount path [$global:WIM_Mount_Path]"
                Remove-Item -Path $global:WIM_Mount_Path -Recurse -Force -ErrorAction stop | Out-Null
                $global:WIM_Mount_Path = $null
            } catch {
                Write-Host "Failed to remove WIM mount path [$global:WIM_Mount_Path]" -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
            }
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

     # If $ISOLabel is not set, then default to "WINDOWS2023PCAISO"
    if (-not $global:ISO_Label) {
        $global:ISO_Label = "WIN2023PCAISO"
    }

    # Generate a timestamp string in the following format: mm/dd/yyyy,hh:mm:ss
    $timestamp = Get-Date -Format "MM/dd/yyyy,HH:mm:ss"

    $runCommand = "-l$global:ISO_Label -t$timestamp -bootdata:2#p0,e,b$global:Temp_Media_To_Update_Path\boot\etfsboot.com#pEF,e,b$global:Temp_Media_To_Update_Path\efi\microsoft\boot\efisys_ex.bin -u2 -udfver102 -o $global:Temp_Media_To_Update_Path `"$($ISOPath)`""

    Write-Dbg-Host "Running [$global:oscdimg_exe $runCommand]"
    try {

        # strip the file name from $ISOPath
        $isoDirPath = $ISOPath.Substring(0, $ISOPath.LastIndexOf("\"))

        # Make sure ISO path is valid or the call to oscdimg.exe will fail
        if (-not (Test-Path $isoDirPath)) {
            Write-Dbg-Host "ISOPath [$isoDirPath] not valid. Creating it."
            New-Item -ItemType Directory -Path $isoDirPath -Force | Out-Null
        }

        Write-Dbg-Host "Writing [$ISOPath]"
        Start-Process -FilePath $global:oscdimg_exe -ArgumentList $runCommand -Wait -NoNewWindow -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "Failed to create ISO [$ISOPath]" -ForegroundColor Red
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
        $fileSystem = "FAT32"
    }

    # Format the drive using the existing label
    try {
        Write-Dbg-Host "Formatting drive [$USBDrive] as $fileSystem"
        Format-Volume -DriveLetter $USBDrive.TrimEnd(':') -FileSystem $fileSystem -NewFileSystemLabel $currentLabel -Force -ErrorAction stop | Out-Null
    } catch {
        Write-Host "Failed to format drive [$USBDrive] as $fileSystem" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $false
    }

    try {
        # If FAT32 and install.wim is larger than 4GB then split it
        if ($fileSystem -eq "FAT32") {
            $installWimPath = $global:Temp_Media_To_Update_Path + "\sources\install.wim"
            if ((Test-Path -Path $installWimPath) -and ((Get-Item -Path $installWimPath).Length -gt 4GB)) {

                Write-Dbg-Host "[$installWimPath] is larger than 4GB, splitting it"
                $installSwmPath = $global:Temp_Media_To_Update_Path + "\sources\install.swm"
                $installSwmSize = 4000
                Write-Host "Updating Media to be FAT32 compatible" -ForegroundColor Blue
                Split-WindowsImage -ImagePath $installWimPath -SplitImagePath $installSwmPath -FileSize $installSwmSize -ErrorAction stop | Out-Null

                # Remove the original install.wim
                Remove-Item -Path $installWimPath -Force -ErrorAction stop | Out-Null
            }
        }

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

Set-StrictMode -Version Latest

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
$global:Dbg_Output = $DebugOn

try {
    Write-Host "`r`n`r`nMicrosoft 'Windows UEFI CA 2023' Media Update Script - Version 1.3`r`n" -ForegroundColor DarkYellow

    # First validate that the required tools/environment exist
    $result = Validate-Parameters -TargetType $TargetType -ISOPath $ISOPath -USBDrive $USBDrive -NewMediaPath $NewMediaPath -FileSystem $FileSystem -StagingDir $StagingDir
    if (-not $result) {
        Write-Dbg-Host "Validate-Parameters failed"
        Show-Usage
        exit
    }

    # validate params
    $result = Validate-Requirements -TargetType $TargetType
    if (-not $result) {
        Write-Dbg-Host "Validate-Requirements failed"
        exit
    }

    # Now initialize media path requirements
    $result = Initialize-MediaPaths -MediaPath $MediaPath -NewMediaPath $NewMediaPath -StagingDir $StagingDir
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
            Write-Host "Successfully created media on drive [$USBDrive]" -ForegroundColor Green
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
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}

Execute-Cleanup
exit
