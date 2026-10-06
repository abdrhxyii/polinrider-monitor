# Exercises discovery beyond the former 100,000-entry ceiling with inert files.
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path $PSScriptRoot) 'Scanner.ps1')
# The full-machine default scan excludes node_modules, including these temporary fixtures.
$scaleRoot=Join-Path ([IO.Path]::GetTempPath()) ('node_modules\polinrider-scale-'+[guid]::NewGuid())
[IO.Directory]::CreateDirectory($scaleRoot) | Out-Null
try {
    $bytes=New-Object byte[] 0
    for($bucket=0;$bucket -lt 101;$bucket++) {
        $dir=Join-Path $scaleRoot ('bucket'+$bucket)
        [IO.Directory]::CreateDirectory($dir) | Out-Null
        for($entry=0;$entry -lt 1000;$entry++) { [IO.File]::WriteAllBytes((Join-Path $dir ($entry.ToString()+'.txt')),$bytes) }
        if($bucket % 25 -eq 0) { Write-Output ('Prepared '+(($bucket+1)*1000)+' inert inventory entries') }
    }
    [IO.File]::WriteAllText((Join-Path $scaleRoot 'normal.js'),'INERT normal text')
    $report=Invoke-PolinRiderScan -ScanPaths $scaleRoot -IncludeDependencies $true
    if (-not $report.Complete -or $report.Files -ne 1 -or $report.Coverage.MaxFiles -ne 0 -or $report.Coverage.MaxSeconds -ne 0) { throw 'Unbounded discovery failed beyond 100,000 entries.' }
    Write-Output 'PASS: 101,000 inert entries traversed without the former discovery/time caps.'
} finally {
    $checked=[IO.Path]::GetFullPath($scaleRoot)
    $expected=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) 'node_modules'))+[IO.Path]::DirectorySeparatorChar
    if($checked.StartsWith($expected,[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($checked).StartsWith('polinrider-scale-')) { Remove-Item -LiteralPath $checked -Recurse -Force }
}
