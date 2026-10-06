# PolinRider Monitor (Fork) - uninstaller
# Removes the Desktop shortcut shortcut. Does NOT delete the
# app files or your scan history.

$ErrorActionPreference = 'Continue'

Write-Host ""
Write-Host "PolinRider Monitor (Fork) - uninstall" -ForegroundColor Cyan
Write-Host ""

# 1. Remove Desktop shortcut
$desktop = [Environment]::GetFolderPath('Desktop')
$lnkPath = Join-Path $desktop 'PolinRider Monitor (Fork).lnk'
if (Test-Path $lnkPath) {
    Remove-Item -LiteralPath $lnkPath -Force
    Write-Host "  Removed Desktop shortcut" -ForegroundColor Green
} else {
    Write-Host "  No Desktop shortcut found" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
Write-Host "Fork app files, config.json, monitor.log, and history.json are left in place." -ForegroundColor Gray
Write-Host "Delete the folder manually if you also want those gone." -ForegroundColor Gray
Write-Host ""
