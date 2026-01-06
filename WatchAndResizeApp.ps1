Start-Sleep -Seconds 20

# WatchAndResizeApp.ps1  (WMI-based)

# === CONFIG ===
$processName = "mpv"    # process name without .exe
$x      = 100
$y      = 100
$width  = 660
$height = 400
# ===============

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool SetWindowPos(
        IntPtr hWnd,
        IntPtr hWndInsertAfter,
        int X,
        int Y,
        int cx,
        int cy,
        uint uFlags
    );
}
"@

$SWP_NOZORDER   = 0x0004
$SWP_NOACTIVATE = 0x0010
$SWP_SHOWWINDOW = 0x0040
$flags = $SWP_NOZORDER -bor $SWP_NOACTIVATE -bor $SWP_SHOWWINDOW

# --- Clean up old subscription with same SourceIdentifier (if any) ---
$existing = Get-EventSubscriber -SourceIdentifier "AppStartWatcher" -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-Event -SourceIdentifier "AppStartWatcher"
    Remove-Event    -SourceIdentifier "AppStartWatcher" -ErrorAction SilentlyContinue
}

# --- Subscribe to process start events ---
$wql = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = '$processName.exe'"
Register-WmiEvent -Query $wql -SourceIdentifier "AppStartWatcher" | Out-Null

Write-Host "Watching for $processName.exe launches. Press Ctrl+C to stop."

while ($true) {
    $event = Wait-Event -SourceIdentifier "AppStartWatcher"

    # don't use $PID (special var) – use our own
    $procId = $event.SourceEventArgs.NewEvent.ProcessID

    # Get the process object
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $proc) { 
        Remove-Event -EventIdentifier $event.EventIdentifier
        continue 
    }

    # Wait for its main window
    $hWnd = [IntPtr]::Zero
    $timeoutSec = 10
    $elapsed = 0

    while ($hWnd -eq [IntPtr]::Zero -and -not $proc.HasExited -and $elapsed -lt $timeoutSec) {
        Start-Sleep -Milliseconds 200
        $elapsed += 0.2
        $proc.Refresh()
        $hWnd = $proc.MainWindowHandle
    }

    if ($hWnd -ne [IntPtr]::Zero) {
        [Win32]::SetWindowPos($hWnd, [IntPtr]::Zero, $x, $y, $width, $height, $flags) | Out-Null
        Write-Host "Resized new $processName.exe (PID $procId) to $width x $height at ($x, $y)."
    } else {
        Write-Host "Could not get window handle for PID $procId."
    }

    Remove-Event -EventIdentifier $event.EventIdentifier
}
