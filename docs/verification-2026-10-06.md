# Combined scanner verification — 6 October 2026

## Implementation

The GUI calls `Invoke-PolinRiderScanWorker` from `Scanner.ps1`. The same worker runs in integration tests. Original checks and newer rules share the existing progress, logs, dashboard and history. GUI scans have no discovery/file/time cap; size limits, dependency exclusions and reparse exclusions remain explicit. Original cleanup still requires supported signatures, unchanged evidence and the expected payload boundary.

## Passed checks

- Windows PowerShell 5.1 fixture suite, application parsing and real WPF dashboard instantiation without showing a window.
- Actual worker from the separately installed original application, executed on harmless fixtures with mocked host APIs: original detections, original file count and batch detections agree.
- Original payload trimming, matching batch deletion, `.gitignore` update and mocked process termination. Changed files and newer asset findings remain untouched.
- JSONC, platform overrides, quoted and parenthesized paths, renamed Node targets, all requested file categories, campaign markers, valid/malformed font containers and asset text inspection.
- Original/new IP union, connection observations, Telegram token redaction, dependency settings, overlapping roots, missing/locked files, cancellation, host failures and history compatibility.
- Original marker detection remains available when a newer bounded text rule times out; other checks continue and the coverage warning remains visible.
- Separate large-discovery test traversed 101,000 inert entries without the former 100,000-entry cap.
- `git diff --check`.

## Read-only configured-root acceptance run

The full background-worker run took 965.9 seconds, exceeding the former ten-minute limit. It discovered and analyzed 56,315 unique eligible files and recorded 59,487 visits including overlapping roots. It observed zero high-confidence file findings, zero suspicious processes, zero matching connections and zero original batch droppers. Its result was **REVIEW REQUIRED**, with incomplete coverage; this does not establish that the machine is clean.

The initial independent inventory counted 59,489 visits. The two extra visits were the new `tests/LargeDiscovery.Tests.ps1`, created after discovery of the two overlapping project roots. Rechecking those roots produced 3,174 visits (1,587 unique files), versus the earlier 3,172 visits. The remaining independent drive inventory is therefore 56,315, matching the original drive discovery exactly. No unexplained count difference remains. The raw verification report intentionally retains its initial mismatch rather than rewriting historical observations.

The run recorded 1,400 coverage issues: 810 excluded reparse points, 110 inaccessible directories, 18 oversized candidates, three missing roots, plus unresolved references, parser/format limitations and 13 text-rule timeouts. Those 13 timeout cases prompted a correction: a bounded text rule no longer aborts the remaining file checks or suppresses original detection. A subsequent 408-file scan of the affected directories completed; 12 large bundles retained explicit rule-level timeout warnings, and no high-confidence finding was observed in that targeted run.

Candidate files were only read. No real project/system cleanup, firewall changes, dependency installation or application-history updates were performed during verification. Temporary fixtures were removed; detailed full-run evidence remains in the uniquely named temporary verification report.

## Reproduce

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/Scanner.Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/LargeDiscovery.Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/FullScan.Verification.ps1
```

For inventory comparison, keep the filesystem stable during the run. Access failures, skipped links and bounded-rule warnings remain coverage limitations even when discovery totals match.
