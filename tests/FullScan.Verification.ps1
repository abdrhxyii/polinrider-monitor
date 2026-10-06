# Read-only acceptance run. Does not save application history or perform cleanup.
param([string]$ConfigPath=(Join-Path (Split-Path $PSScriptRoot) 'config.json'))
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot
. (Join-Path $repo 'Scanner.ps1')
$config=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$log=[System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$state=[hashtable]::Synchronized(@{Files=0;Folder='';Cancelled=$false})
$ps=[powershell]::Create()
try {
    [void]$ps.AddScript({param($module,$config,$log,$state)
        . $module
        Invoke-PolinRiderScanWorker -ScanPaths $config.ScanPaths -MaxFileSize $config.MaxFileSize -IncludeDependencies ([bool]$config.IncludeDependencies) -ScanLog $log -ScanState $state
    })
    [void]$ps.AddArgument((Join-Path $repo 'Scanner.ps1')); [void]$ps.AddArgument($config)
    [void]$ps.AddArgument($log); [void]$ps.AddArgument($state)
    $handle=$ps.BeginInvoke(); $last=0
    while (-not $handle.IsCompleted) {
        Start-Sleep -Seconds 2
        while ($last -lt $log.Count) {
            $line=[string]$log[$last]; $last++
            # Compact console output; report retains every finding and coverage gap.
            if ($line -match '>> |=== |scanned \d*000 files|coverage summary') { Write-Output $line }
        }
    }
    $result=$ps.EndInvoke($handle)
    if ($ps.Streams.Error.Count -or $result.Count -ne 1) { throw 'Shared background worker failed.' }
    $report=$result[0]
} finally { $ps.Dispose() }

# Independent .NET inventory, matching the documented extension/scope policy.
# Count each root separately so overlap matches the original progress semantics.
$inventory=0; $inventoryErrors=0
foreach($rootPath in $report.Coverage.Roots) {
    Write-Output ('Inventory: '+$rootPath)
    $pending=New-Object 'System.Collections.Generic.Stack[string]'; $pending.Push($rootPath)
    while($pending.Count) {
        $dir=$pending.Pop()
        try { $entries=[IO.Directory]::GetFileSystemEntries($dir) } catch { $inventoryErrors++; continue }
        foreach($path in $entries) {
            try {
                $attrs=[IO.File]::GetAttributes($path)
                if ($attrs -band [IO.FileAttributes]::ReparsePoint) { continue }
                $name=[IO.Path]::GetFileName($path)
                if ($attrs -band [IO.FileAttributes]::Directory) {
                    if ($name -eq '.git' -or ($name -eq 'node_modules' -and -not $config.IncludeDependencies)) { continue }
                    $pending.Push($path); continue
                }
                $extension=[IO.Path]::GetExtension($path).ToLowerInvariant()
                $eligible=$extension -in @('.js','.mjs','.cjs','.jsx','.ts','.tsx','.php','.woff','.woff2','.ttf','.otf','.llf','.bat','.cmd','.ps1','.code-workspace','.dict') -or
                    $name -in @('package.json','package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml','composer.json','composer.lock') -or
                    ([IO.Path]::GetFileName($dir) -eq '.vscode' -and $extension -eq '.json')
                if ($eligible -and ([IO.FileInfo]$path).Length -lt $config.MaxFileSize) { $inventory++ }
            } catch { $inventoryErrors++ }
        }
    }
}
$verification=[pscustomobject]@{
    InventoryFileVisits=$inventory; ScannerDiscoveredFileVisits=$report.Coverage.DiscoveredFileVisits
    InventoryMatches=($inventory -eq $report.Coverage.DiscoveredFileVisits)
    InventoryErrors=$inventoryErrors; Report=$report
}
$output=Join-Path ([IO.Path]::GetTempPath()) ('polinrider-verification-'+[guid]::NewGuid()+'.json')
$verification | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $output -Encoding UTF8
Write-Output ('Verification report: '+$output)
Write-Output ('Result: '+$report.Result+'; Files: '+$report.Files+'; Complete: '+$report.Complete+'; Coverage issues: '+$report.CoverageIssues.Count+'; Inventory matches: '+$verification.InventoryMatches)
if (-not $verification.InventoryMatches) { throw 'Inventory differs: inspect the report for live filesystem changes or enumeration gaps.' }
