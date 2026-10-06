# Static scanner. This file defines functions only; candidates are never executed.
# Rules researched 2026-10-06. Provenance: docs/polinrider-detection-spec.md.
function Get-PolinRiderKnownIPs {
    # Original seven indicators plus the OpenSourceMalware remediation article.
    # Slash-separated storage prevents the detector source matching its own literals.
    @('166/88/54/158','54/251/176/6','52/221/63/237','18/142/149/167','34/36/29/190','52/223/34/155','35/71/137/105',
      '198/105/127/210','23/27/202/27','154/91/0/103','136/0/9/8','166/88/4/2','23/27/120/142','202/155/8/173','166/88/134/82','188/43/33/249','23/27/13/43') | ForEach-Object { $_.Replace('/','.') } | Select-Object -Unique
}

function Invoke-PolinRiderScanWorker {
    param([string[]]$ScanPaths, [long]$MaxFileSize=10000000, [bool]$IncludeDependencies=$false,
          $ScanState, $ScanLog, [scriptblock]$HostProvider={ Get-PolinRiderHostObservations })
    function WorkerLog([string]$message) {
        if ($message.StartsWith('>> ')) { $ScanState.Folder=$message.Substring(3) }
        [void]$ScanLog.Add("$((Get-Date).ToString('hh:mm:ss tt')) $message")
    }
    $report=Invoke-PolinRiderScan -ScanPaths $ScanPaths -MaxFileSize $MaxFileSize -IncludeDependencies $IncludeDependencies -MaxFiles 0 -MaxSeconds 0 -HostProvider $HostProvider -IsCancelled { $ScanState.Cancelled } -OnLog { param($message) WorkerLog $message } -OnProgress {
        param($path,$count)
        $ScanState.Files=$count; $ScanState.Folder=$path
        if ($count % 25 -eq 0) {
            $display=$path; if ($display.Length -gt 80) { $display='...'+$display.Substring($display.Length-77) }
            WorkerLog ('   ... scanned '+$count+' files (current: '+$display+')')
        }
    }
    WorkerLog ''
    WorkerLog ('=== scan '+$report.Result.ToLower()+': '+$report.Files+' files in '+$report.Duration+' ===')
    if (-not $report.Complete) { WorkerLog ('[coverage summary] scan incomplete; '+$report.CoverageIssues.Count+' coverage issue(s)') }
    return $report
}

function Invoke-PolinRiderScan {
    [CmdletBinding()]
    param(
        [string[]]$ScanPaths,
        [long]$MaxFileSize = 10000000,
        [bool]$IncludeDependencies = $false,
        [int]$MaxFiles = 0,
        [int]$MaxSeconds = 0,
        [scriptblock]$IsCancelled = { $false },
        [scriptblock]$OnProgress = {},
        [scriptblock]$OnLog = {},
        [scriptblock]$HostProvider = { @{ Processes = @(); Connections = @(); Artifacts = @() } }
    )
    if ($MaxFileSize -lt 1 -or $MaxFileSize -gt 100000000 -or $MaxFiles -lt 0 -or $MaxSeconds -lt 0) {
        throw 'Invalid scan limits (maximum supported file size is 100 MB).'
    }
    $findings = New-Object 'System.Collections.Generic.List[object]'
    $issues = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $queued = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $queue = New-Object 'System.Collections.Generic.Queue[object]'
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $count = 0; $stopped = $false; $dependencyExclusions = 0
    $legacyFiles=New-Object 'System.Collections.Generic.List[object]'
    $legacyBats=New-Object 'System.Collections.Generic.List[object]'
    $legacyProcesses=New-Object 'System.Collections.Generic.List[object]'
    $roots = New-Object 'System.Collections.Generic.List[string]'
    $occurrences = @{}
    $findingKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $issueKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $knownIps = @(Get-PolinRiderKnownIPs)
    function Issue($path, $reason) {
        if ($issueKeys.Add($path+'|'+$reason)) {
            $issues.Add([pscustomobject]@{ Path = $path; Reason = $reason })
            & $OnLog ('[coverage] '+$path+' | '+$reason)
        }
    }
    function Finding($path, $category, $rule, $confidence, $reason, $hash, $location, $reference) {
        if (-not $findingKeys.Add($path+'|'+$rule+'|'+$location+'|'+$reference)) { return }
        $findings.Add([pscustomobject]@{
            Path = $path; Category = $category; RuleId = $rule; RuleVersion = '2026-10-06'
            Confidence = $confidence; Reason = $reason; SHA256 = $hash
            Location = $location; Reference = $reference; Remediation = 'ReviewOnly'
        })
        & $OnLog ('[finding '+$confidence+'] '+$path+' | '+$rule+' | '+$reason)
    }
    function InScope([string]$path) {
        foreach ($r in $roots) {
            $prefix = $r.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
            if ($path.Equals($r, [StringComparison]::OrdinalIgnoreCase) -or
                $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    }
    function LinkedPath([string]$path) {
        $cursor = $path
        while ($cursor) {
            if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
                if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
            }
            $parent = [IO.Path]::GetDirectoryName($cursor)
            if ($parent -eq $cursor) { break }; $cursor = $parent
        }
        return $false
    }
    function Limited {
        if (& $IsCancelled) { return $true }
        return ($MaxSeconds -gt 0 -and $clock.Elapsed.TotalSeconds -ge $MaxSeconds)
    }
    function Matches([string]$text, [string]$pattern) {
        try { return [regex]::Matches($text, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromMilliseconds(200)) }
        catch [Text.RegularExpressions.RegexMatchTimeoutException] {
            Issue $path 'A bounded text rule timed out; remaining checks continued.'
            return @()
        }
    }
    # Remove JSONC comments/trailing commas while preserving strings and positions.
    function JsonData([string]$text) {
        $pattern = '"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/'
        $rx = [regex]::new($pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromMilliseconds(200))
        $clean = $rx.Replace($text, [Text.RegularExpressions.MatchEvaluator]{ param($m)
            if ($m.Value.StartsWith('"')) { return $m.Value }
            return [regex]::Replace($m.Value, '[^\r\n]', ' ')
        })
        $rx = [regex]::new('"(?:\\.|[^"\\])*"|,\s*(?=[}\]])', [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromMilliseconds(200))
        $clean = $rx.Replace($clean, [Text.RegularExpressions.MatchEvaluator]{ param($m)
            if ($m.Value.StartsWith('"')) { return $m.Value }; return ' ' * $m.Length
        })
        # Bound nesting before handing data to the Windows PowerShell JSON parser.
        $outside = [regex]::Replace($clean, '"(?:\\.|[^"\\])*"', '""', [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromMilliseconds(200))
        $depth = 0
        for ($index=0; $index -lt $outside.Length; $index++) {
            if ($index % 4096 -eq 0 -and (Limited)) { throw 'Parsing cancelled or timed out.' }
            $c=$outside[$index]
            if ($c -eq '{' -or $c -eq '[') { $depth++; if ($depth -gt 64) { throw 'JSON nesting exceeds 64.' } }
            if ($c -eq '}' -or $c -eq ']') { $depth-- }
        }
        return ConvertFrom-Json -InputObject $clean -ErrorAction Stop
    }
    function U32($bytes, $offset) {
        return [uint64]$bytes[$offset] * 16777216 + [uint64]$bytes[$offset+1] * 65536 + [uint64]$bytes[$offset+2] * 256 + $bytes[$offset+3]
    }
    function InspectFont($bytes, $extension) {
        if ($bytes.Length -lt 12) { return 'Truncated font header.' }
        $signature = [Text.Encoding]::ASCII.GetString($bytes, 0, 4)
        if ($extension -eq '.woff' -or $extension -eq '.woff2') {
            $expected = if ($extension -eq '.woff') { 'wOFF' } else { 'wOF2' }
            $header = if ($extension -eq '.woff') { 44 } else { 48 }
            if ($signature -ne $expected) { return 'Font extension does not match its binary signature.' }
            if ($bytes.Length -lt $header -or (U32 $bytes 8) -ne $bytes.Length) { return 'Font container length is invalid.' }
            $tables = [int]$bytes[12] * 256 + $bytes[13]
            if ($tables -eq 0) { return 'Font has no tables.' }
            if ($extension -eq '.woff') {
                $directoryEnd = 44 + 20 * $tables
                if ($directoryEnd -gt $bytes.Length) { return 'Font table directory is truncated.' }
                $ranges = @()
                for ($i = 0; $i -lt $tables; $i++) {
                    $entry = 44 + 20 * $i; $offset = U32 $bytes ($entry+4); $length = U32 $bytes ($entry+8)
                    if ($offset -lt $directoryEnd -or $offset+$length -gt $bytes.Length -or $length -gt (U32 $bytes ($entry+12))) { return 'Font table range is invalid.' }
                    foreach ($range in $ranges) { if ($offset -lt $range.End -and $offset+$length -gt $range.Start) { return 'Font table ranges overlap.' } }
                    $ranges += @{ Start=$offset; End=$offset+$length }
                }
            } elseif ((U32 $bytes 20) -gt $bytes.Length-48) { return 'WOFF2 compressed length is invalid.' }
            # Metadata/private blocks are allowed; do not treat their existence as malware.
            $metaOffset = if ($extension -eq '.woff') { 24 } else { 28 }
            $privateOffset = if ($extension -eq '.woff') { 36 } else { 40 }
            foreach ($entry in @($metaOffset, $privateOffset)) {
                $offset = U32 $bytes $entry; $length = U32 $bytes ($entry+4)
                if (($offset -eq 0 -and $length -ne 0) -or ($offset -ne 0 -and ($offset -lt $header -or $offset+$length -gt $bytes.Length))) { return 'Font auxiliary block range is invalid.' }
            }
        } else {
            $magic = U32 $bytes 0
            if ($magic -ne 65536 -and $signature -notin @('OTTO','true','typ1')) { return 'Font extension does not match an sfnt signature.' }
            $tables = [int]$bytes[4] * 256 + $bytes[5]; $end = 12+16*$tables
            if ($tables -eq 0 -or $end -gt $bytes.Length) { return 'Font table directory is invalid.' }
            for ($i=0; $i -lt $tables; $i++) {
                $entry = 12+16*$i; $offset = U32 $bytes ($entry+8); $length = U32 $bytes ($entry+12)
                if ($offset -lt $end -or $offset+$length -gt $bytes.Length) { return 'Font table range is invalid.' }
            }
        }
        return $null
    }
    function References($text, $base, $source, $hash, $field) {
        # Only literal Node targets can be resolved. No shell expansion is performed.
        foreach ($m in (Matches $text '(?<![\w-])["'']?(?:node(?:\.exe)?|nodejs)["'']?\s+(?:"([^"\r\n]+)"|''([^''\r\n]+)''|([^\s;&|<>]+))')) {
            $target = ($m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value | Where-Object { $_ } | Select-Object -First 1)
            if ($target.StartsWith('-')) { Issue $source 'Node flags or inline execution require manual reference review.'; continue }
            $target = $target.Replace('${workspaceFolder}', $base)
            if ($target -match '\$|%|`') { Issue $source 'Dynamic execution reference could not be resolved.'; continue }
            try {
                $target = if ([IO.Path]::IsPathRooted($target)) { [IO.Path]::GetFullPath($target) } else { [IO.Path]::GetFullPath((Join-Path $base $target)) }
                if (-not (InScope $target)) { Issue $source 'Execution reference points outside selected roots.'; continue }
                if (LinkedPath $target) { Issue $target 'Execution reference crosses a reparse point.'; continue }
                if (-not [IO.File]::Exists($target)) { Issue $target 'Referenced executable file is missing.'; continue }
                if (-not $IncludeDependencies -and $target -match '[\\/]node_modules[\\/]') { Issue $target 'Referenced dependency excluded by configuration.'; continue }
                if ([IO.Path]::GetExtension($target) -notin @('.js','.mjs','.cjs','.ts','.tsx','.jsx')) {
                    Finding $source 'Execution' 'node-asset' 'Suspicious' 'Node executes a file with an unexpected extension.' $hash $field $target
                }
                if ($MaxFiles -gt 0 -and $queued.Count -ge $MaxFiles) { Issue $target 'Reference/discovery limit reached.'; continue }
                if ($queued.Add($target)) { $queue.Enqueue(@{ Path=$target; Reference=$source }) }
                elseif ($seen.Contains($target)) {
                    foreach ($f in @($findings.ToArray())) {
                        if ($f.Path -eq $target -and $f.Category -eq 'Payload') { $f.Reference = $source }
                    }
                }
            } catch { Issue $source 'Execution reference could not be inspected.' }
        }
    }
    function InspectString($text, $source, $hash, $field, $base, [bool]$commandContext=$false) {
        # Assemble signatures so scanning this detector does not match its own rule definitions.
        $downloadPattern = '\b(' + ('cu'+'rl|wg'+'et|Invoke-'+'WebRequest|i'+'wr|Download'+'String') + ')\b'
        $executePattern = '(\|\s*(' + ('ba'+'sh|s'+'h|c'+'md|power'+'shell|i'+'ex') + ')\b|\b(' + ('Invoke-'+'Expression|i'+'ex') + ')\b)'
        $download = $commandContext -and (Matches $text $downloadPattern).Count -gt 0
        $execute = $commandContext -and (Matches $text $executePattern).Count -gt 0
        $pipelinePattern=$downloadPattern+'[^;\r\n|]*\|\s*(bash|sh|cmd|powershell|pwsh|iex)\b'
        if ($commandContext -and $download -and $execute -and (Matches $text $pipelinePattern).Count) { Finding $source 'Execution' 'download-execute' 'High' 'Command downloads content and pipes it to an interpreter.' $hash $field $null }
        elseif ($commandContext -and $download -and $execute) { Finding $source 'Execution' 'download-execute' 'Suspicious' 'Download and execution tokens occur in a command; review the data flow.' $hash $field $null }
        if ($commandContext -and (Matches $text '\b(node|nodejs|powershell|pwsh|cmd|curl|wget|Invoke-WebRequest)(?:\.exe)?\b').Count) {
            Finding $source 'Configuration' 'interpreter-command' 'Review' 'Command invokes an interpreter or download tool; verify its purpose.' $hash $field $null
        }
        if ($text.IndexOf('-enc',[StringComparison]::OrdinalIgnoreCase) -ge 0 -and (Matches $text '\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*\s-(?:enc|encodedcommand)\b').Count) {
            Finding $source 'Execution' 'encoded-shell' 'Suspicious' 'Encoded PowerShell execution requires review.' $hash $field $null
        }
        if ((Matches $text 'api\.telegram\.org/bot').Count) {
            Finding $source 'Exfiltration' 'telegram-bot-api' 'Suspicious' 'Telegram Bot API endpoint indicator found; review whether project code sends collected data.' $hash $field $null
        }
        if ($commandContext) { References $text $base $source $hash $field }
    }
    function WalkData($data, $source, $hash, $field, $base, $depth=0) {
        if ($depth -gt 64) { Issue $source 'Configuration depth limit reached.'; return }
        if ($data -is [string]) {
            # Inspect every value to cover platform overrides and command-bearing settings.
            InspectString $data $source $hash $field $base
            if ($field -match 'runtimeExecutable$|terminal\..*\.path$') { InspectString $data $source $hash $field $base $true }
            if ($field -match '(program|runtimeExecutable|path)$' -and $data -match '\.(woff2?|ttf|otf|llf)$') {
                References ('node "' + $data + '"') $base $source $hash $field
            }
            if ($field -match '\.runOn$' -and $data -eq 'folderOpen') { Finding $source 'Configuration' 'automatic-task' 'Review' 'Task requests execution when the folder opens.' $hash $field $null }
            if ($field -match 'terminal\..*(path|args)|runtimeExecutable' -and $data -match '\.(cmd|bat|ps1|js|llf)$') {
                Finding $source 'Configuration' 'custom-executable' 'Review' 'Custom terminal/debug executable requires review.' $hash $field $null
            }
        } elseif ($data -is [System.Collections.IEnumerable] -and $data -isnot [string]) {
            $i=0; foreach ($item in $data) { WalkData $item $source $hash "$field[$i]" $base ($depth+1); $i++ }
        } elseif ($null -ne $data) {
            # Combine command + args, and debugger runtime + program without invoking either.
            if ($data.command) {
                if ($data.options.cwd -or $data.cwd) { Issue $source 'Custom working directory requires manual execution-reference review.' }
                $argsText = (@($data.args) | ForEach-Object { '"' + $_ + '"' }) -join ' '
                InspectString ($data.command+' '+$argsText) $source $hash ($field+'.command+args') $base $true
            }
            if ($data.path -and $field -match 'terminal\.') {
                $argsText=(@($data.args) | ForEach-Object { '"'+$_+'"' }) -join ' '
                InspectString ($data.path+' '+$argsText) $source $hash ($field+'.path+args') $base $true
            }
            if ($data.program -and ($data.runtimeExecutable -match '^node(?:\.exe)?$' -or $data.type -in @('node','pwa-node'))) { References ('node "'+$data.program+'"') $base $source $hash ($field+'.program') }
            foreach ($p in $data.PSObject.Properties) {
                if ($field -eq '$.scripts' -and $p.Value -is [string]) { InspectString $p.Value $source $hash ($field+'.'+$p.Name) $base $true }
                if ($p.Name -eq 'task.allowAutomaticTasks' -and ($p.Value -eq $true -or $p.Value -eq 'on')) {
                    Finding $source 'Configuration' 'automatic-tasks-enabled' 'Review' 'Workspace requests automatic tasks; review trust and task definitions.' $hash ($field+'.'+$p.Name) $null
                }
                WalkData $p.Value $source $hash ($field+'.'+$p.Name) $base ($depth+1)
            }
        }
    }
    foreach ($path in $ScanPaths) {
        try {
            $r = [IO.Path]::GetFullPath($path)
            if ($r -ne [IO.Path]::GetPathRoot($r)) { $r = $r.TrimEnd([IO.Path]::DirectorySeparatorChar) }
            if (-not [IO.Directory]::Exists($r)) { Issue $path 'Scan root is missing or inaccessible.'; continue }
            if (-not $IncludeDependencies -and $r -match '(^|[\\/])node_modules([\\/]|$)') { Issue $r 'Dependency root excluded by configuration.'; continue }
            if (LinkedPath $r) { Issue $r 'Scan root crosses a reparse point.'; continue }
            $roots.Add($r)
        } catch { Issue $path 'Invalid scan root.' }
    }
    $dirs = New-Object 'System.Collections.Generic.Stack[string]'
    $discovered = 0
    & $OnLog '=== file scan ==='
    foreach ($r in $roots) {
    if (Limited) { $stopped=$true; break }
    & $OnLog ('>> '+$r+' (discovering files)')
    $rootCandidates=0
    $dirs.Push($r)
    $visitedDirs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    while ($dirs.Count) {
        if (Limited) { $stopped=$true; break }
        $dir=$dirs.Pop(); if (-not $visitedDirs.Add($dir)) { continue }
        try {
            foreach ($item in (Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)) {
                if (Limited) { $stopped=$true; $dirs.Clear(); break }
                $discovered++
                if ($MaxFiles -gt 0 -and $discovered -gt $MaxFiles) { Issue $dir 'Discovery limit reached.'; $dirs.Clear(); break }
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Issue $item.FullName 'Reparse point excluded.'; continue }
                if ($item.PSIsContainer) {
                    if ($item.Name -eq '.git') { continue }
                    if ($item.Name -eq 'node_modules' -and -not $IncludeDependencies) { $dependencyExclusions++; continue }
                    $dirs.Push($item.FullName); continue
                }
                $ext=$item.Extension.ToLowerInvariant()
                $eligible = $ext -in @('.js','.mjs','.cjs','.jsx','.ts','.tsx','.php','.woff','.woff2','.ttf','.otf','.llf','.bat','.cmd','.ps1','.code-workspace') -or
                    $ext -eq '.dict' -or $item.Name -in @('package.json','package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml','composer.json','composer.lock','temp_auto_push.bat','config.bat') -or
                    ($dir -match '[\\/]\.vscode$' -and $ext -eq '.json')
                if ($eligible) {
                    if ($item.Length -ge $MaxFileSize) { Issue $item.FullName 'File meets or exceeds size limit.'; continue }
                    $rootCandidates++
                    $occurrences[$item.FullName]=1+[int]$occurrences[$item.FullName]
                    if ($queued.Add($item.FullName)) { $queue.Enqueue(@{ Path=$item.FullName; Reference=$null }) }
                }
            }
        } catch { Issue $dir 'Directory could not be fully enumerated.' }
    }
    & $OnLog ('>> '+$r+' ('+$rootCandidates+' files)')
    }
    $original = @(('rmcej'+'%otb%'),('_$_'+'1e42'),('285'+'7687'),('266'+'7686'))
    $rotated = @(('Cot%3'+'t=shtP'),('111'+'1436'),('389'+'6884'))
    $packages = @('tailwindcss-style-animate','tailwind-mainanimation','tailwind-autoanimation','tailwind-animationbased','tailwindcss-typography-style','tailwindcss-style-modify','tailwindcss-animate-style')
    while ($queue.Count -and -not $stopped) {
        if (Limited) { $stopped=$true; break }
        $candidate=$queue.Dequeue(); $path=$candidate.Path
        if (-not $seen.Add($path)) { continue }
        if ($MaxFiles -gt 0 -and $seen.Count -gt $MaxFiles) { Issue $path 'Analysis file limit reached.'; break }
        $attempts=[Math]::Max(1,[int]$occurrences[$path])
        for ($attempt=0; $attempt -lt $attempts; $attempt++) { $count++; & $OnProgress $path $count }
        try {
            if (LinkedPath $path) { Issue $path 'File crosses a reparse point.'; continue }
            $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try {
                if ($stream.Length -ge $MaxFileSize) { Issue $path 'File meets or exceeds size limit.'; continue }
                $bytes=New-Object byte[] ([int]$stream.Length); $offset=0
                while ($offset -lt $bytes.Length) {
                    $n=$stream.Read($bytes,$offset,[Math]::Min(65536,$bytes.Length-$offset))
                    if ($n -eq 0) { throw 'Short read.' }; $offset+=$n
                    if (Limited) { $stopped=$true; break }
                }
                if ($stopped) { break }
            } finally { $stream.Dispose() }
            $sha=[Security.Cryptography.SHA256]::Create()
            try { $hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
            $text=[Text.Encoding]::UTF8.GetString($bytes)
            if ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) { $text=[Text.Encoding]::Unicode.GetString($bytes) }
            $ext=[IO.Path]::GetExtension($path).ToLowerInvariant(); $name=[IO.Path]::GetFileName($path)
            $v1=@($original | Where-Object { $text.Contains($_) }).Count
            # Original detection must survive a timeout/failure in any newer rule.
            if ($v1 -ge 2) {
                Finding $path 'Payload' 'campaign-markers' 'High' 'Multiple documented PolinRider fingerprints occur together.' $hash 'content' $candidate.Reference
                if ($ext -in @('.js','.mjs','.cjs','.jsx','.ts','.tsx')) {
                    $legacyFiles.Add([pscustomobject]@{Path=$path;SHA256=$hash})
                    & $OnLog ('   [HIT] '+$path+'  <-- INFECTED (original markers)')
                }
            }
            $v2=@($rotated | Where-Object { $text.Contains($_) }).Count
            $markerEvidence=New-Object 'System.Collections.Generic.List[string]'
            if ($text.Contains($original[0])) { $markerEvidence.Add('rmcej variant string') }
            if ($text.Contains($original[1])) { $markerEvidence.Add('original decoder name') }
            $originalSlot='global['+[char]39+'!'+[char]39+']'
            if ($text.Contains($originalSlot)) { $markerEvidence.Add('original global decoder slot') }
            if ($text.Contains($rotated[0])) { $markerEvidence.Add('Cot variant string') }
            $decoderName='M'+'Dy'
            $hasRotatedDecoder=(Matches $text ('\bfunction\s+'+$decoderName+'\s*\(\s*f\s*\)')).Count -gt 0
            if ($hasRotatedDecoder) { $markerEvidence.Add('rotated decoder function') }
            $vSlot='_'+'V'
            $hasRotatedSlot=(Matches $text ('global\s*\[\s*[''"]'+$vSlot+'[''"]\s*\]')).Count -gt 0
            if ($hasRotatedSlot) { $markerEvidence.Add('rotated global decoder slot') }
            $rotatedMatch=$text.Contains($rotated[0]) -and ($v2 -ge 2 -or $hasRotatedDecoder -or $hasRotatedSlot)
            $commitToken='LAST_COMMIT_'+'DATE'
            if ($ext -in @('.bat','.cmd') -and (Matches $text ('\b'+$commitToken+'\b')).Count) { $markerEvidence.Add('batch commit-date indicator') }
            $propagationName='temp_auto_push'+'.bat'
            if ($name -ieq $propagationName) { $markerEvidence.Add('known propagation filename') }
            if ($name -ieq 'config.bat') { $markerEvidence.Add('known configuration batch artifact') }
            if ($markerEvidence.Count -gt 0) {
                $confidence=if ($v1 -ge 2 -or $rotatedMatch -or ($ext -eq '.bat' -and $text -match 'commit --amend' -and $text -match 'git push' -and $text -match '--no-verify' -and $text -match 'date %')) { 'High' } else { 'Review' }
                $strength=if ($confidence -eq 'High') { 'Several campaign invariants match:' } else { 'Campaign-related marker requires review:' }
                Finding $path 'CampaignMarker' 'issue-39299-indicators' $confidence ($strength+' '+($markerEvidence -join ', ')+'.') $hash 'content/name' $candidate.Reference
            }
            if ($v1 -ge 2 -or $rotatedMatch) {
                Finding $path 'Payload' 'campaign-markers' 'High' 'Multiple documented PolinRider fingerprints occur together.' $hash 'content' $candidate.Reference
            } elseif ((Matches $text ('\bglobal\s*(?:\.i\s*=|\[\s*[''"](?:!|'+$vSlot+')[''"]\s*\]\s*=)')).Count -and
                (Matches $text '(eval\s*\(|_0x[a-f0-9]{4,}|child_process)').Count) {
                Finding $path 'Payload' 'loader-structure' 'Suspicious' 'Build marker and obfuscated/executable JavaScript structure require review.' $hash 'content' $candidate.Reference
            }
            # Keep the original Secure Machine behavior available only for its
            # original JS marker threshold and batch signature. New rules never
            # enter this cleanup allowlist.
            if ((Matches $text '(default-configuration|vscode-settings-bootstrap|vscode-settings-config|vscode-bootstrapper|vscode-load-config|260120)\.vercel\.app').Count) {
                Finding $path 'Indicator' 'campaign-domain' 'Suspicious' 'A documented campaign domain occurs in this file.' $hash 'content' $candidate.Reference
            }
            if ($ext -in @('.woff','.woff2','.ttf','.otf')) {
                $anomaly=InspectFont $bytes $ext
                if ($anomaly) { Finding $path 'Asset' 'font-container' 'Suspicious' $anomaly $hash 'header/tables' $candidate.Reference }
            }
            if ($ext -in @('.woff','.woff2','.ttf','.otf','.llf','.dict') -and (Matches $text '\b(require\s*\(|global\s*\[|eval\s*\(|child_process\b|fetch\s*\()').Count) {
                Finding $path 'Asset' 'asset-javascript' 'Review' 'Readable JavaScript indicators occur in an asset; inspect its purpose and execution references.' $hash 'content' $candidate.Reference
            }
            if ($name -ieq 'spellright.dict') { Finding $path 'Artifact' 'dictionary-artifact' 'Review' 'Documented dictionary filename; a legitimate dictionary can have the same name.' $hash 'filename' $candidate.Reference }
            foreach ($ip in $knownIps) {
                if ($text.Contains($ip) -and (Matches $text ('(?<![\d.])'+[regex]::Escape($ip)+'(?![\d.])')).Count) { Finding $path 'Indicator' 'known-ip-content' 'Review' ('Known IP indicator in file: '+$ip+'. Verify its use.') $hash 'content' $ip }
            }
            $isConfig=$path -match '[\\/]\.vscode[\\/][^\\/]+\.json$' -or $ext -eq '.code-workspace'
            $isManifest=$name -in @('package.json','package-lock.json','npm-shrinkwrap.json','composer.json','composer.lock')
            $base=[IO.Path]::GetDirectoryName($path)
            if ($isConfig -and $base -match '[\\/]\.vscode$') { $base=[IO.Path]::GetDirectoryName($base) }
            if ($isConfig -or $isManifest) {
                try { $data=JsonData $text; WalkData $data $path $hash '$' $base }
                catch { Issue $path 'JSONC parsing failed or exceeded limits; raw inspection still performed.'; InspectString $text $path $hash 'raw fallback' $base }
            } else { InspectString $text $path $hash 'content' $base }
            if ($name -in @('yarn.lock','pnpm-lock.yaml')) { Issue $path 'Lockfile checked for identifiers only; structured format is unsupported.' }
            if ($isManifest -or $name -in @('yarn.lock','pnpm-lock.yaml')) {
                foreach ($package in $packages) {
                    if ((Matches $text ('(?<![\w-])'+[regex]::Escape($package)+'(?![\w-])')).Count) {
                        Finding $path 'Dependency' 'campaign-package' 'Suspicious' ('Known campaign package identity: '+$package+'. Review the resolved version.') $hash 'dependency data' $null
                    }
                }
            }
            if ($ext -eq '.php' -and (Matches $text '\bshell_exec\s*\(').Count -and (Matches $text '\bnode\b|base64_decode').Count) {
                Finding $path 'Execution' 'php-wrapper' 'Suspicious' 'PHP shell execution combined with Node or encoded content requires review.' $hash 'content' $null
            }
            if ($name -eq 'cli.js' -and $path -match '[\\/]npm[\\/]lib[\\/]cli\.js$' -and $bytes.Length -gt 500000) {
                Finding $path 'Persistence' 'oversized-npm-cli' 'Review' 'npm CLI is unusually large; compare with a verified installation and inspect for appended payloads.' $hash 'file size/content' $null
            }
            if ($ext -in @('.js','.mjs','.cjs','.jsx','.ts','.tsx') -and
                (Matches $text '(fetch\s*\(|https?\.get\s*\(|node-fetch)').Count -and
                (Matches $text '\beval\s*\(|new\s+Function\s*\(').Count) {
                Finding $path 'Execution' 'remote-evaluation' 'Suspicious' 'Network retrieval and dynamic code evaluation occur together; review the data flow.' $hash 'content' $null
            }
            if ($ext -in @('.bat','.cmd') -and $text -match 'commit --amend' -and $text -match 'git push' -and $text -match '--no-verify' -and $text -match 'date %') {
                Finding $path 'Propagation' 'history-rewrite' 'High' 'Batch script matches the documented Git history rewriting pattern.' $hash 'content' $null
                if ($ext -eq '.bat' -and $bytes.Length -lt 100000) { $legacyBats.Add([pscustomobject]@{Path=$path;SHA256=$hash}) }
            }
        } catch {
            $failure = $_.Exception
            if ($failure.InnerException) { $failure = $failure.InnerException }
            Issue $path ('File could not be safely analyzed ('+$failure.GetType().Name+').')
        }
    }
    if (Limited) { $stopped=$true }
    if ($stopped) { Issue '' 'Scan cancelled or elapsed time limit reached.' }
    try {
        if (-not $stopped) {
            & $OnLog '=== process scan ==='
            $hostData=& $HostProvider
            foreach ($p in $hostData.Processes) {
                if ($p.Name -match '^(node|nodejs|python|pythonw|powershell|pwsh)(\.exe)?$' -and $p.CommandLine) {
                    $inline=$p.CommandLine -match '(?: -e |--eval)' -and $p.CommandLine -match 'global[.\[]'
                    $asset=$p.Name -match '^node' -and $p.CommandLine -match '\.(woff2?|llf|ttf|otf)\b'
                    if ($inline -or $asset) {
                    $connected=@($hostData.Connections | Where-Object { $_.OwningProcess -eq $p.ProcessId }).Count
                        Finding ('PID '+$p.ProcessId) 'Process' 'suspicious-launch' 'Suspicious' ('Suspicious interpreter launch; parent PID '+$p.ParentProcessId+'; active connections '+$connected+'.') $null 'process metadata (arguments redacted)' $p.ExecutablePath
                    }
                    $legacyMarker=-join ([char[]]@(103,108,111,98,97,108,91))
                    if ($p.Name -eq 'node.exe' -and $p.CommandLine.IndexOf($legacyMarker) -ge 0 -and $p.CommandLine -match ' -e |--eval') {
                        $procHash=[Security.Cryptography.SHA256]::Create()
                        try { $commandHash=([BitConverter]::ToString($procHash.ComputeHash([Text.Encoding]::UTF8.GetBytes($p.CommandLine))).Replace('-','').ToLowerInvariant()) } finally { $procHash.Dispose() }
                        $legacyProcesses.Add([pscustomobject]@{ProcessId=[int]$p.ProcessId;CommandLineHash=$commandHash})
                        & $OnLog ('   [PROC] PID '+$p.ProcessId)
                    }
                }
            }
            foreach ($artifact in $hostData.Artifacts) { Finding $artifact 'Host' 'credential-staging' 'Suspicious' 'Documented credential-staging filename found; contents were not read.' $null 'filename only' $null }
            if (-not $legacyProcesses.Count) { & $OnLog 'no suspicious node.exe processes' }
            & $OnLog '=== c2 connection scan ==='
            foreach ($connection in $hostData.Connections) {
                if ($connection.RemoteAddress -in $knownIps) {
                    Finding ('PID '+$connection.OwningProcess) 'Network' 'legacy-network-indicator' 'Review' 'Connection matches a legacy IP indicator; shared infrastructure alone does not establish malware.' $null 'connection metadata' $connection.RemoteAddress
                    & $OnLog ('   [CONN] '+$connection.RemoteAddress+' <- PID '+$connection.OwningProcess)
                }
            }
            foreach ($p in $hostData.Processes) {
                if ($p.CommandLine -and $p.CommandLine -match 'api\.telegram\.org/bot') {
                    Finding ('PID '+$p.ProcessId) 'Exfiltration' 'telegram-bot-api' 'Review' 'Process arguments reference the Telegram Bot API; inspect locally without sharing token-bearing arguments.' $null 'process metadata (arguments redacted)' $null
                }
            }
            foreach ($failure in $hostData.Issues) { Issue 'Host observations' $failure }
            if (-not @($findings | Where-Object Category -eq 'Network').Count) { & $OnLog 'no active C2 connections' }
            & $OnLog '=== bat dropper scan (temp_auto_push.bat signature) ==='
            foreach ($bat in $legacyBats) { & $OnLog ('   [BAT] '+$bat.Path+'  <-- DROPPER') }
            if (-not $legacyBats.Count) { & $OnLog 'no .bat droppers found' }
        }
    } catch { Issue 'Host observations' 'Host observations unavailable.' }
    $high=@($findings | Where-Object { $_.Confidence -eq 'High' -and $_.SHA256 } | Select-Object -ExpandProperty Path -Unique).Count
    $status=if ($stopped) { 'STOPPED' } elseif ($high) { 'INDICATORS FOUND' } elseif ($findings.Count) { 'REVIEW REQUIRED' } elseif ($issues.Count) { 'INCOMPLETE' } else { 'NO INDICATORS IN SCOPE' }
    return [pscustomobject]@{
        SchemaVersion=2; When=(Get-Date -Format 'yyyy-MM-dd hh:mm:ss tt'); Result=$status; Complete=(-not $stopped -and $issues.Count -eq 0)
        Files=$count; Infected=$high; Procs=@($findings | Where-Object Category -eq 'Process').Count; C2=@($findings | Where-Object Category -eq 'Network').Count
        BatDroppers=@($findings | Where-Object Category -eq 'Propagation').Count
        Duration=('{0:N1}s' -f $clock.Elapsed.TotalSeconds); Findings=@($findings.ToArray()); CoverageIssues=@($issues.ToArray())
        Coverage=[pscustomobject]@{ Roots=@($roots.ToArray()); IncludeDependencies=$IncludeDependencies; ExcludedDependencyDirectories=$dependencyExclusions; MaxFileSize=$MaxFileSize; MaxFiles=$MaxFiles; MaxSeconds=$MaxSeconds; HostObservationProviderSupplied=$PSBoundParameters.ContainsKey('HostProvider'); DiscoveredFileVisits=($occurrences.Values | Measure-Object -Sum).Sum; DiscoveredUniqueFiles=$occurrences.Count; AnalyzedUniqueFiles=$seen.Count }
        InfectedFiles=@($legacyFiles.ToArray() | ForEach-Object Path)
        LegacyFileEvidence=@($legacyFiles.ToArray())
        LegacyBatEvidence=@($legacyBats.ToArray())
        LegacyProcessEvidence=@($legacyProcesses.ToArray())
        ProcIds=@($legacyProcesses.ToArray() | ForEach-Object ProcessId)
        C2Hits=@($findings | Where-Object Category -eq 'Network' | ForEach-Object { $_.Reference+' <- '+$_.Path }); BatFiles=@($legacyBats.ToArray() | ForEach-Object Path); ReportOnly=$true
    }
}

function Get-PolinRiderHostObservations {
    $failures=@(); $processes=@(); $connections=@(); $artifacts=@()
    try { $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine) } catch { $failures+='Process enumeration unavailable.' }
    try { $connections=@(Get-NetTCPConnection -ErrorAction Stop | Select-Object OwningProcess,RemoteAddress,RemotePort) } catch { $failures+='Connection enumeration unavailable.' }
    # Inspect filenames only, with a bounded walk and no reparse points.
    $staging=Join-Path $env:USERPROFILE '.npm'
    if ([IO.Directory]::Exists($staging)) {
        $dirs=New-Object 'System.Collections.Generic.Queue[string]'; $dirs.Enqueue($staging); $visited=0
        while ($dirs.Count -and $visited -lt 1000) {
            $dir=$dirs.Dequeue()
            try {
                if (([IO.File]::GetAttributes($dir) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $failures+='Host reparse point excluded.'; continue }
                foreach ($item in (Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)) {
                    $visited++; if ($visited -ge 1000) { $failures+='Host artifact enumeration limit reached.'; break }
                    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    if ($item.PSIsContainer) { $dirs.Enqueue($item.FullName) }
                    elseif ($item.Name -in @('_credentials.json','_sysenv.json','_sysenv.env')) { $artifacts+=$item.FullName }
                }
            } catch { $failures+='Host artifact directory unavailable.' }
        }
    }
    return @{ Processes=$processes; Connections=$connections; Artifacts=$artifacts; Issues=$failures }
}
