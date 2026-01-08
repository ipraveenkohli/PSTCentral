# Outlook Data Files Network Backup Script - Workgroup Edition with Individual Credentials
# Run this script with Administrator privileges

#region Configuration
$computerCredFile = "C:\BackupScript\computers_credentials.csv"  # CSV with computer names and credentials
$backupDestination = "C:\BackupScript\OutlookBackups"  # Local backup location
$logFile = "C:\BackupScript\backup_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$maxConcurrent = 3  # Number of concurrent backups
$closeOutlookForBackup = $true  # Set to $true to request Outlook close, $false to skip locked files
$waitAfterOutlookClose = 5  # Seconds to wait after closing Outlook
$restartOutlookAfterBackup = $false  # Set to $true to restart Outlook, $false to let user open it manually
$userWaitTimeoutMinutes = 5  # How long to wait for user to close Outlook before skipping (in minutes)
$notificationDisplaySeconds = 30  # How long to show the notification popup
#endregion

#region Functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    
    Write-Host $logMessage -ForegroundColor $color
    Add-Content -Path $logFile -Value $logMessage
}

function Get-RemoteCredential {
    param([string]$Username, [string]$Password)
    
    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($Username, $securePassword)
}

function Enable-RemoteAccess {
    param([string]$ComputerName, [PSCredential]$Credential)
    
    try {
        # Test WMI access first
        $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
        Write-Log "Connected to $ComputerName (OS: $($os.Caption))" "INFO"
        return $true
    }
    catch {
        Write-Log "Cannot connect to $ComputerName : $_" "ERROR"
        return $false
    }
}

function Get-OutlookDataFilesWorkgroup {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $dataPaths = @()
    
    try {
        Write-Log "Discovering drives on $ComputerName..." "INFO"
        
        # Get all logical drives on the remote computer using WMI
        $drives = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $ComputerName -Credential $Credential -Filter "DriveType=3" -ErrorAction SilentlyContinue
        
        if (-not $drives) {
            Write-Log "Could not detect drives on $ComputerName" "ERROR"
            return $dataPaths
        }
        
        $driveLetters = $drives | Select-Object -ExpandProperty DeviceID
        Write-Log "Found drives on $ComputerName : $($driveLetters -join ', ')" "SUCCESS"
        
        foreach ($remoteDrive in $driveLetters) {
            $driveLetter = $remoteDrive -replace ':', ''
            Write-Log "Scanning drive $remoteDrive on $ComputerName..." "INFO"
            
            # Create UNC path for the drive
            $uncDrivePath = "\\$ComputerName\$($driveLetter)$"
            
            # Check if drive is accessible
            if (-not (Test-Path $uncDrivePath)) {
                Write-Log "  Drive $remoteDrive is not accessible via network share" "WARNING"
                continue
            }
            
            # Create a network drive mapping temporarily
            $localDriveLetter = Get-AvailableDriveLetter
            
            if (-not $localDriveLetter) {
                Write-Log "  No available drive letters for mapping" "ERROR"
                continue
            }
            
            try {
                $null = New-PSDrive -Name $localDriveLetter -PSProvider FileSystem -Root $uncDrivePath -Credential $Credential -ErrorAction Stop
                Write-Log "  Mapped $uncDrivePath to $($localDriveLetter):" "INFO"
                
                # Search for PST/OST files on this drive
                Write-Log "  Searching for Outlook data files on $remoteDrive..." "INFO"
                
                # Get all user profiles on this drive (if Users folder exists)
                $usersPath = "$($localDriveLetter):\Users"
                if (Test-Path $usersPath) {
                    Write-Log "  Found Users folder, scanning user profiles..." "INFO"
                    
                    $profiles = Get-ChildItem $usersPath -Directory -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
                    
                    foreach ($profile in $profiles) {
                        Write-Log "    Scanning profile: $($profile.Name)" "INFO"
                        
                        # Standard Outlook locations
                        $profileSearchPaths = @(
                            "$($localDriveLetter):\Users\$($profile.Name)\Documents\Outlook Files",
                            "$($localDriveLetter):\Users\$($profile.Name)\AppData\Local\Microsoft\Outlook",
                            "$($localDriveLetter):\Users\$($profile.Name)\AppData\Roaming\Microsoft\Outlook",
                            "$($localDriveLetter):\Users\$($profile.Name)\Documents",
                            "$($localDriveLetter):\Users\$($profile.Name)\Desktop"
                        )
                        
                        foreach ($path in $profileSearchPaths) {
                            if (Test-Path $path) {
                                $files = Get-ChildItem -Path $path -Include "*.pst", "*.ost" -Recurse -Depth 3 -File -ErrorAction SilentlyContinue
                                
                                foreach ($file in $files) {
                                    # Convert to UNC path
                                    $uncPath = $file.FullName -replace "^$($localDriveLetter):", $uncDrivePath
                                    
                                    # Check if already added
                                    $alreadyExists = $dataPaths | Where-Object { $_.FilePath -eq $uncPath }
                                    if (-not $alreadyExists) {
                                        Write-Log "      Found: $($file.Name) ($([math]::Round($file.Length/1MB, 2)) MB) in $($file.DirectoryName)" "SUCCESS"
                                        $dataPaths += [PSCustomObject]@{
                                            ComputerName = $ComputerName
                                            Drive = $remoteDrive
                                            UserProfile = $profile.Name
                                            FilePath = $uncPath
                                            FileName = $file.Name
                                            SizeMB = [math]::Round($file.Length / 1MB, 2)
                                            LastModified = $file.LastWriteTime
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                # Also search root of drive and common folders (Data, Backup, etc.)
                Write-Log "  Searching common folders on $remoteDrive root..." "INFO"
                $rootSearchPaths = @(
                    "$($localDriveLetter):\Data",
                    "$($localDriveLetter):\Backup",
                    "$($localDriveLetter):\Outlook",
                    "$($localDriveLetter):\Email"
                )
                
                foreach ($path in $rootSearchPaths) {
                    if (Test-Path $path) {
                        Write-Log "    Checking: $path" "INFO"
                        $files = Get-ChildItem -Path $path -Include "*.pst", "*.ost" -Recurse -Depth 3 -File -ErrorAction SilentlyContinue
                        
                        foreach ($file in $files) {
                            # Convert to UNC path
                            $uncPath = $file.FullName -replace "^$($localDriveLetter):", $uncDrivePath
                            
                            # Check if already added
                            $alreadyExists = $dataPaths | Where-Object { $_.FilePath -eq $uncPath }
                            if (-not $alreadyExists) {
                                Write-Log "      Found: $($file.Name) ($([math]::Round($file.Length/1MB, 2)) MB)" "SUCCESS"
                                $dataPaths += [PSCustomObject]@{
                                    ComputerName = $ComputerName
                                    Drive = $remoteDrive
                                    UserProfile = "Root"
                                    FilePath = $uncPath
                                    FileName = $file.Name
                                    SizeMB = [math]::Round($file.Length / 1MB, 2)
                                    LastModified = $file.LastWriteTime
                                }
                            }
                        }
                    }
                }
                
                # Remove temporary drive mapping
                Remove-PSDrive -Name $localDriveLetter -Force -ErrorAction SilentlyContinue
                Write-Log "  Completed scanning drive $remoteDrive" "INFO"
            }
            catch {
                Write-Log "  Error scanning drive $remoteDrive : $_" "ERROR"
                Remove-PSDrive -Name $localDriveLetter -Force -ErrorAction SilentlyContinue
            }
        }
        
        Write-Log "Completed scanning all drives on $ComputerName" "INFO"
    }
    catch {
        Write-Log "Error discovering drives on $ComputerName : $_" "ERROR"
    }
    
    return $dataPaths
}

function Get-AvailableDriveLetter {
    $used = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
    foreach ($letter in 90..65) {  # Z to A
        $drive = [char]$letter
        if ($drive -notin $used) {
            return $drive
        }
    }
    return $null
}

function Test-FileLocked {
    param([string]$FilePath, [PSCredential]$Credential)
    
    try {
        # Try to open file for reading
        $stream = [System.IO.File]::Open($FilePath, 'Open', 'Read', 'None')
        $stream.Close()
        $stream.Dispose()
        return $false
    }
    catch {
        return $true
    }
}

function Show-RemoteNotification {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [string]$Title,
        [string]$Message,
        [int]$DisplaySeconds = 30
    )
    
    try {
        Write-Log "Sending notification to user on $ComputerName..." "INFO"
        
        # Method 1: Use msg.exe (simplest, no DCOM needed)
        try {
            Write-Host "`nAttempting to send message using msg.exe..." -ForegroundColor Yellow
            
            # Send message to all sessions (*)
            $msgCommand = "msg * /TIME:300 `"$Title - $Message`""
            
            # Execute via WMI
            $processClass = Get-WmiObject -List -ComputerName $ComputerName -Credential $Credential | Where-Object { $_.Name -eq "Win32_Process" }
            $result = $processClass.Create($msgCommand)
            
            if ($result.ReturnValue -eq 0) {
                Write-Log "Message sent successfully using msg.exe to all sessions" "SUCCESS"
                return $true
            } else {
                Write-Log "msg.exe failed with return code: $($result.ReturnValue)" "WARNING"
            }
        }
        catch {
            Write-Log "msg.exe method error: $_" "WARNING"
        }
        
        # Method 2: Create a simple notification file on desktop
        try {
            Write-Log "Creating desktop notification file..." "INFO"
            
            # Get all user profiles
            $profiles = Get-ChildItem "\\$ComputerName\C$\Users" -Directory | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User') }
            
            $notificationContent = @"
================================================
$Title
================================================

$Message

Time: $(Get-Date -Format 'HH:mm:ss')

Please close Outlook and this window will 
automatically disappear once backup is complete.
For disappear popup

================================================
"@
            
            foreach ($profile in $profiles) {
                $desktopPath = "\\$ComputerName\C$\Users\$($profile.Name)\Desktop\OUTLOOK_BACKUP_NOTICE.txt"
                $notificationContent | Out-File -FilePath $desktopPath -Encoding UTF8 -Force
                
                # Open the file automatically using notepad
                $processClass = Get-WmiObject -List -ComputerName $ComputerName -Credential $Credential | Where-Object { $_.Name -eq "Win32_Process" }
                $result = $processClass.Create("notepad.exe C:\Users\$($profile.Name)\Desktop\OUTLOOK_BACKUP_NOTICE.txt")
                
                if ($result.ReturnValue -eq 0) {
                    Write-Log "Desktop notification created and opened for $($profile.Name)" "SUCCESS"
                }
            }
            
            return $true
        }
        catch {
            Write-Log "Desktop notification method error: $_" "WARNING"
        }
        
        Write-Log "All notification methods attempted" "WARNING"
        return $false
    }
    catch {
        Write-Log "Error showing notification: $_" "WARNING"
        return $false
    }
}

function Remove-RemoteNotificationFiles {
    param(
        [string]$ComputerName
    )
    
    try {
        # Remove notification files from all user desktops
        $profiles = Get-ChildItem "\\$ComputerName\C$\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User') }
        
        foreach ($profile in $profiles) {
            $desktopFile = "\\$ComputerName\C$\Users\$($profile.Name)\Desktop\OUTLOOK_BACKUP_NOTICE.txt"
            if (Test-Path $desktopFile) {
                Remove-Item -Path $desktopFile -Force -ErrorAction SilentlyContinue
            }
        }
        
        Write-Log "Notification files cleaned up on $ComputerName" "INFO"
    }
    catch {
        # Silently ignore cleanup errors
    }
}

function Wait-ForOutlookClose {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [int]$TimeoutMinutes = 5
    )
    
    try {
        $timeoutSeconds = $TimeoutMinutes * 60
        $elapsed = 0
        $checkInterval = 10  # Check every 10 seconds
        
        Write-Log "Waiting for user to close Outlook (timeout: $TimeoutMinutes minutes)..." "INFO"
        
        while ($elapsed -lt $timeoutSeconds) {
            # Check if Outlook is still running
            $outlookRunning = Get-WmiObject -Class Win32_Process -ComputerName $ComputerName -Credential $Credential -Filter "Name='OUTLOOK.EXE'" -ErrorAction SilentlyContinue
            
            if (-not $outlookRunning) {
                Write-Log "Outlook closed by user on $ComputerName" "SUCCESS"
                return $true
            }
            
            # Show countdown in log every 30 seconds
            if ($elapsed % 30 -eq 0) {
                $remainingMinutes = [math]::Round(($timeoutSeconds - $elapsed) / 60, 1)
                Write-Log "Still waiting for Outlook to close... ($remainingMinutes minutes remaining)" "INFO"
            }
            
            Start-Sleep -Seconds $checkInterval
            $elapsed += $checkInterval
        }
        
        Write-Log "Timeout reached. User did not close Outlook within $TimeoutMinutes minutes" "WARNING"
        return $false
    }
    catch {
        Write-Log "Error waiting for Outlook close: $_" "ERROR"
        return $false
    }
}

function Close-RemoteOutlook {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    try {
        Write-Log "Checking if Outlook is running on $ComputerName..." "INFO"
        
        # Check if Outlook is running using WMI
        $outlookProcesses = Get-WmiObject -Class Win32_Process -ComputerName $ComputerName -Credential $Credential -Filter "Name='OUTLOOK.EXE'" -ErrorAction SilentlyContinue
        
        if ($outlookProcesses) {
            Write-Log "Outlook is running on $ComputerName (PID: $($outlookProcesses.ProcessId))" "WARNING"
            
            # Show notification to user
            $notificationTitle = "Action Required"
            $notificationMessage = "Monika.`n`nShutup n Do your work.`n`nThank you!"
            
            Show-RemoteNotification -ComputerName $ComputerName -Credential $Credential -Title $notificationTitle -Message $notificationMessage -DisplaySeconds $script:notificationDisplaySeconds
            
            Write-Log "Notification sent to user. Waiting for them to close Outlook..." "INFO"
            
            # Wait for user to close Outlook
            $userClosed = Wait-ForOutlookClose -ComputerName $ComputerName -Credential $Credential -TimeoutMinutes $script:userWaitTimeoutMinutes
            
            if ($userClosed) {
                Write-Log "User successfully closed Outlook on $ComputerName" "SUCCESS"
                Start-Sleep -Seconds $script:waitAfterOutlookClose
                return $true
            } else {
                Write-Log "User did not close Outlook within timeout period" "WARNING"
                
                # Ask if we should force close or skip
                Write-Log "Skipping backup for $ComputerName - Outlook still running" "WARNING"
                return $false
            }
        }
        
        Write-Log "Outlook is not running on $ComputerName" "INFO"
        return $true
    }
    catch {
        Write-Log "Error checking/closing Outlook on $ComputerName : $_" "ERROR"
        return $false
    }
}

function Start-RemoteOutlook {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [string]$UserProfile
    )
    
    try {
        Write-Log "Attempting to restart Outlook on $ComputerName..." "INFO"
        
        # Common Outlook paths to try
        $outlookPaths = @(
            "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            "C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE",
            "C:\Program Files\Microsoft Office\Office16\OUTLOOK.EXE",
            "C:\Program Files (x86)\Microsoft Office\Office16\OUTLOOK.EXE",
            "C:\Program Files\Microsoft Office\root\Office15\OUTLOOK.EXE",
            "C:\Program Files (x86)\Microsoft Office\root\Office15\OUTLOOK.EXE"
        )
        
        # Try to find and start Outlook using WMI
        foreach ($outlookPath in $outlookPaths) {
            # Check if file exists on remote computer
            $uncPath = "\\$ComputerName\" + ($outlookPath -replace ":", "$")
            
            if (Test-Path $uncPath) {
                Write-Log "Found Outlook at: $outlookPath" "INFO"
                
                # Start process using WMI
                $processStartup = ([WMICLASS]"\\$ComputerName\root\cimv2:Win32_ProcessStartup").CreateInstance()
                $processStartup.ShowWindow = 0  # Hidden/minimized
                
                $process = ([WMICLASS]"\\$ComputerName\root\cimv2:Win32_Process")
                $result = $process.Create($outlookPath, $null, $processStartup)
                
                if ($result.ReturnValue -eq 0) {
                    Write-Log "Outlook restarted successfully on $ComputerName (PID: $($result.ProcessId))" "SUCCESS"
                    return $true
                } else {
                    Write-Log "Failed to start Outlook, Return Code: $($result.ReturnValue)" "WARNING"
                }
            }
        }
        
        Write-Log "Could not find or start Outlook on $ComputerName" "WARNING"
        return $false
    }
    catch {
        Write-Log "Error restarting Outlook on $ComputerName : $_" "WARNING"
        return $false
    }
}

function Backup-OutlookFile {
    param(
        [PSCustomObject]$FileInfo,
        [string]$Destination,
        [PSCredential]$Credential,
        [bool]$OutlookWasClosed
    )
    
    try {
        # Create destination folder structure
        $computerFolder = Join-Path $Destination $FileInfo.ComputerName
        $userFolder = Join-Path $computerFolder $FileInfo.UserProfile
        $dateFolder = Join-Path $userFolder (Get-Date -Format "yyyyMMdd")
        
        if (-not (Test-Path $dateFolder)) {
            New-Item -Path $dateFolder -ItemType Directory -Force | Out-Null
        }
        
        $destFile = Join-Path $dateFolder $FileInfo.FileName
        
        # Check if file is locked
        $isLocked = Test-FileLocked -FilePath $FileInfo.FilePath -Credential $Credential
        
        if ($isLocked) {
            Write-Log "File is locked: $($FileInfo.FileName). Attempting backup with special methods..." "WARNING"
            
            # Try Robocopy with backup mode
            $sourceDir = Split-Path $FileInfo.FilePath -Parent
            $destDir = Split-Path $destFile -Parent
            $fileName = $FileInfo.FileName
            
            Write-Log "Using Robocopy backup mode for locked file..." "INFO"
            $null = robocopy $sourceDir $destDir $fileName /B /Z /R:3 /W:2 /NP /NFL /NDL 2>&1
            
            if (Test-Path $destFile) {
                $backupSize = (Get-Item $destFile).Length
                if ($backupSize -gt 0) {
                    Write-Log "Successfully backed up locked file: $fileName using Robocopy" "SUCCESS"
                    return $true
                }
            }
            
            # If robocopy failed, try FileStream
            Write-Log "Robocopy failed, trying FileStream with ReadWrite sharing..." "WARNING"
            
            try {
                $buffer = New-Object byte[] 1048576
                $sourceStream = [System.IO.File]::Open($FileInfo.FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $destStream = [System.IO.File]::Create($destFile)
                
                $totalRead = 0
                while (($read = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $destStream.Write($buffer, 0, $read)
                    $totalRead += $read
                }
                
                $sourceStream.Close()
                $destStream.Close()
                $sourceStream.Dispose()
                $destStream.Dispose()
                
                if ($totalRead -gt 0) {
                    Write-Log "Successfully backed up locked file using FileStream ($([math]::Round($totalRead/1MB, 2)) MB)" "SUCCESS"
                    return $true
                }
            }
            catch {
                Write-Log "FileStream method also failed: $_" "ERROR"
            }
            
            Write-Log "All methods failed to backup locked file: $($FileInfo.FileName)" "ERROR"
            return $false
        }
        
        # File is not locked - normal copy
        Write-Log "Backing up: $($FileInfo.FileName) ($($FileInfo.SizeMB) MB) from $($FileInfo.ComputerName)" "INFO"
        
        # Try normal copy first
        try {
            Copy-Item -Path $FileInfo.FilePath -Destination $destFile -Force -ErrorAction Stop
        }
        catch {
            # If copy fails, try robocopy
            Write-Log "Normal copy failed, trying Robocopy..." "WARNING"
            $sourceDir = Split-Path $FileInfo.FilePath -Parent
            $destDir = Split-Path $destFile -Parent
            $fileName = $FileInfo.FileName
            
            $null = robocopy $sourceDir $destDir $fileName /R:2 /W:2 /NP /NFL /NDL 2>&1
        }
        
        # Verify backup
        if (Test-Path $destFile) {
            $backupSize = (Get-Item $destFile).Length
            
            if ($backupSize -gt 0) {
                Write-Log "Successfully backed up $($FileInfo.FileName) from $($FileInfo.ComputerName)" "SUCCESS"
                return $true
            }
        }
        
        Write-Log "Backup verification failed for $($FileInfo.FileName)" "ERROR"
        return $false
    }
    catch {
        Write-Log "Error backing up $($FileInfo.FilePath): $_" "ERROR"
        return $false
    }
}

function Backup-LockedFile {
    param(
        [PSCustomObject]$FileInfo,
        [string]$DestinationFile,
        [PSCredential]$Credential
    )
    
    # This function is kept for backward compatibility but not used anymore
    # Outlook closing method is now the primary approach
    return $false
}

function Create-SampleCredentialFile {
    param([string]$FilePath)
    
    $sampleContent = @"
ComputerName,Username,Password
192.168.1.101,Administrator,Pass123!
192.168.1.102,Admin,SecurePass456
OFFICE-PC-01,administrator,Office@789
RECEPTION-PC,receptionist,Recep@2024
LAPTOP-HR,hr_admin,HrPass!123
"@
    
    Set-Content -Path $FilePath -Value $sampleContent
    Write-Log "Sample credential file created at: $FilePath" "INFO"
    Write-Log "Please edit this file with your actual computer names and credentials" "WARNING"
}
#endregion

#region Main Script
Write-Log "===== Outlook Backup Script Started (Individual Credentials) =====" "INFO"

# Display important note about remote notifications
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "IMPORTANT: Remote Notifications Setup" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "For popup notifications to work on remote computers, you need to:" -ForegroundColor White
Write-Host "1. Enable DCOM on each remote PC (one-time setup)" -ForegroundColor White
Write-Host "`nRun this on EACH remote PC as Administrator:" -ForegroundColor Green
Write-Host "   dcomcnfg" -ForegroundColor Cyan
Write-Host "   → Component Services → Computers → My Computer → Properties" -ForegroundColor Gray
Write-Host "   → Default Properties → Enable DCOM: YES" -ForegroundColor Gray
Write-Host "`nOR simply run this command on each remote PC:" -ForegroundColor Green
Write-Host "   reg add HKLM\Software\Microsoft\Ole /v EnableDCOM /t REG_SZ /d Y /f" -ForegroundColor Cyan
Write-Host "`nAlternatively, the script will still work - it just won't show popups." -ForegroundColor Yellow
Write-Host "Users can manually close Outlook when they see it in the backup log." -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

Start-Sleep -Seconds 3

# Check if credential file exists
if (-not (Test-Path $computerCredFile)) {
    Write-Log "Credential file not found: $computerCredFile" "ERROR"
    Write-Log "Creating sample credential file..." "INFO"
    
    # Create directory if needed
    $credDir = Split-Path $computerCredFile
    if (-not (Test-Path $credDir)) {
        New-Item -Path $credDir -ItemType Directory -Force | Out-Null
    }
    
    Create-SampleCredentialFile -FilePath $computerCredFile
    
    Write-Log "IMPORTANT: Edit $computerCredFile with your actual credentials and run again." "WARNING"
    Write-Log "Format: ComputerName,Username,Password" "INFO"
    
    # Open the file for editing
    if ([Environment]::UserInteractive) {
        Start-Process notepad $computerCredFile
    }
    exit
}

# Create backup destination
if (-not (Test-Path $backupDestination)) {
    New-Item -Path $backupDestination -ItemType Directory -Force | Out-Null
}

# Read computer credentials from CSV
try {
    $computerList = Import-Csv -Path $computerCredFile
    
    # Validate CSV format
    if (-not ($computerList[0].PSObject.Properties.Name -contains "ComputerName" -and 
              $computerList[0].PSObject.Properties.Name -contains "Username" -and 
              $computerList[0].PSObject.Properties.Name -contains "Password")) {
        Write-Log "Invalid CSV format. Required columns: ComputerName, Username, Password" "ERROR"
        exit
    }
}
catch {
    Write-Log "Error reading credential file: $_" "ERROR"
    exit
}

if ($computerList.Count -eq 0) {
    Write-Log "No computers found in $computerCredFile" "ERROR"
    exit
}

Write-Log "Found $($computerList.Count) computers to scan" "INFO"

# Statistics
$totalFiles = 0
$successCount = 0
$failCount = 0
$skippedComputers = 0
$processedComputers = 0

# Process each computer
foreach ($comp in $computerList) {
    $computerName = $comp.ComputerName.Trim()
    $username = $comp.Username.Trim()
    $password = $comp.Password.Trim()
    
    # Skip empty rows
    if ([string]::IsNullOrWhiteSpace($computerName)) {
        continue
    }
    
    Write-Log "========================================" "INFO"
    Write-Log "Processing computer: $computerName" "INFO"
    
    # Test connectivity
    if (-not (Test-Connection -ComputerName $computerName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Log "Cannot reach $computerName - skipping" "WARNING"
        $skippedComputers++
        continue
    }
    
    # Create credential for this computer
    $credential = Get-RemoteCredential -Username $username -Password $password
    
    # Test remote access
    if (-not (Enable-RemoteAccess -ComputerName $computerName -Credential $credential)) {
        Write-Log "Cannot access $computerName with provided credentials (User: $username) - skipping" "WARNING"
        $skippedComputers++
        continue
    }
    
    $processedComputers++
    
    # Close Outlook if enabled
    $outlookWasClosed = $false
    if ($closeOutlookForBackup) {
        $closeResult = Close-RemoteOutlook -ComputerName $computerName -Credential $credential
        $outlookWasClosed = [bool]$closeResult
    }
    
    # Get Outlook data files
    $dataFiles = Get-OutlookDataFilesWorkgroup -ComputerName $computerName -Credential $credential
    
    if ($dataFiles.Count -eq 0) {
        Write-Log "No Outlook data files found on $computerName" "INFO"
        
        # Restart Outlook if we closed it AND restart is enabled
        if ($outlookWasClosed -and $restartOutlookAfterBackup) {
            Start-RemoteOutlook -ComputerName $computerName -Credential $credential -UserProfile "Unknown"
        }
        continue
    }
    
    $fileCount = @($dataFiles).Count
    Write-Log "Found $fileCount Outlook data file(s) on $computerName" "INFO"
    $totalFiles += $fileCount
    
    # Backup each file
    foreach ($file in $dataFiles) {
        $result = Backup-OutlookFile -FileInfo $file -Destination $backupDestination -Credential $credential -OutlookWasClosed $outlookWasClosed
        if ($result) {
            $successCount++
        } else {
            $failCount++
        }
    }
    
    # Clean up notification files
    Remove-RemoteNotificationFiles -ComputerName $computerName
    
    # Restart Outlook ONLY if enabled and we closed it
    if ($restartOutlookAfterBackup -and $outlookWasClosed -and $dataFiles.Count -gt 0) {
        Start-RemoteOutlook -ComputerName $computerName -Credential $credential -UserProfile $dataFiles[0].UserProfile
    } elseif ($outlookWasClosed) {
        Write-Log "Outlook was closed. User will need to open it manually." "INFO"
    }
}

# Summary
Write-Log "========================================" "INFO"
Write-Log "===== Backup Summary =====" "INFO"
Write-Log "Total computers in list: $($computerList.Count)" "INFO"
Write-Log "Computers processed: $processedComputers" "INFO"
Write-Log "Computers skipped: $skippedComputers" "WARNING"
Write-Log "Total Outlook files found: $totalFiles" "INFO"
Write-Log "Successfully backed up: $successCount" "SUCCESS"
Write-Log "Failed backups: $failCount" $(if ($failCount -gt 0) { "ERROR" } else { "INFO" })
Write-Log "Backup location: $backupDestination" "INFO"
Write-Log "Log file: $logFile" "INFO"
Write-Log "===== Backup Script Completed =====" "INFO"

# Open log file (only if running interactively)
if ([Environment]::UserInteractive) {
    Write-Host "`nPress any key to open log file..." -ForegroundColor Cyan
    try {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Start-Process notepad $logFile
    }
    catch {
        # If ReadKey fails, just open the log
        Start-Process notepad $logFile
    }
}
#endregion

