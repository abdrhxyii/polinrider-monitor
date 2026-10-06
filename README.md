# PolinRider Monitor

A local Windows PowerShell/WPF tool for static PolinRider detection and recovery guidance.

**Version 1.1 uses static inspection and restores the original Secure Machine action for supported findings.** It never runs candidate scripts, renders fonts, installs dependencies, or contacts extracted URLs. A scan cannot establish that a compromised workstation has been eradicated.

## Coverage

- JavaScript/TypeScript, PHP, batch/shell launchers, VS Code JSONC configurations, workspace files, dependency manifests, fonts, and LLF assets.
- Original and April rotated campaign fingerprints, plus suspicious loader structures and remote code evaluation.
- Task commands and arguments, platform overrides, automatic tasks, terminal/debug configuration, and literal Node execution references.
- Referenced Node targets are inspected regardless of extension, within selected roots. Dynamic references, flags, custom working directories, missing targets, and out-of-scope targets require manual review and are reported as coverage issues.
- WOFF/WOFF2/TTF/OpenType signature and bounded container checks. No font decompression or rendering; these are partial format checks, not full font validation.
- Documented campaign package identities in manifests/lockfiles. Identities require version review; the scanner does not assert every version is malicious. Yarn and pnpm lockfiles receive identifier checks with an explicit unsupported-structure notice.
- Checks the Apache Superset issue's individual marker list: original and rotated strings/decoder markers, `LAST_COMMIT_DATE` in batch files, and the `temp_auto_push.bat` filename. One marker produces a review finding; combinations and the established batch signature can be high confidence. These new marker-only findings do not authorize the original cleanup action.
- Also includes recovery-guide pivots for `config.bat`, `spellright.dict`, and oversized `npm/lib/cli.js` files, which are review signals rather than automatic cleanup targets.
- Interpreter process observations correlated with active connections. Legacy IP matches are review evidence only, since infrastructure can be shared or change.
- Network review includes the seven earlier IP indicators and the eleven IPs in the OpenSourceMalware recovery guide. It also looks for the Telegram Bot API URL in scanned content/process metadata; process arguments are redacted. The monitor records matches and does not configure firewall blocks; these dated indicators are not proof of compromise.
- Documented credential-staging filenames below the user's `.npm` directory, without reading secret contents.

Rules carry a research date and confidence. Generic Node, eval, obfuscation, and automatic-task use alone do not establish infection. Read failures, cancellation, excluded junctions, size/time/file limits, and unresolved references remain visible.

Installed dependencies are excluded by default; enable **Inspect node_modules too** in Settings. Git object storage is excluded. Remote branches/history, arbitrary interpreter reference resolution, complete data-flow analysis, every package ecosystem, and full antivirus/EDR behavior are outside scope. Candidate reads are bounded to 10 MB by default, 100 MB maximum; discovery/analysis is capped at 100,000 entries/files and 600 seconds.

## Install and use

Keep `Scanner.ps1` beside `app.ps1`. No third-party scanner dependencies are required.

1. Run `install.ps1` to create the shortcut, or launch `PolinRiderMonitor.vbs` directly.
2. Choose folders and options in Settings, then select **Scan Now**.
3. Review findings and coverage messages in Logs. Detailed hashes, evidence fields, reference locations, scope, and confidence are retained in `history.json`; summaries are retained in `monitor.log`.
4. If the scan found original-pattern JavaScript, matching inline Node processes, or matching batch droppers, **Secure Machine** offers cleanup for those findings. It rechecks the marker/signature and selected scan scope before acting. JavaScript cleanup also requires the expected payload boundary; otherwise it skips the file. New config, font, renamed-payload, PHP, and review-only findings remain for manual remediation from verified originals.

Result meanings:

| Result | Meaning |
| --- | --- |
| NO INDICATORS IN SCOPE | No rules matched within recorded scope; not proof of a clean host |
| REVIEW REQUIRED | Suspicious or review-level evidence was found |
| INDICATORS FOUND | High-confidence indicators were found; review context and coverage |
| INCOMPLETE | No findings, but inspection could not cover all requested candidates |
| STOPPED | Cancelled or elapsed-time limit reached |

Findings and incomplete coverage can coexist. Inspect `CoverageIssues` even when the result is INDICATORS FOUND or REVIEW REQUIRED. Cancelled scans are saved. Older history remains readable, but its original CLEAN label retains only its old scope.

## Recovery

If files are contaminated but never executed, preserve their hashes/original bytes and replace both launchers and payloads from verified clean sources before opening or building the project. Never repair binary assets by trimming text. Do not assume deleting a fake font removes its task trigger.

If execution occurred, isolate and investigate the workstation with trusted security tooling. From a clean device, revoke exposed sessions and rotate relevant GitHub/npm/cloud credentials, SSH keys, and other secrets. Audit repositories, branches, workflows, package releases, CI systems, and other contributors who could reintroduce malware. Rebuild from trusted media when eradication cannot be confidently established. Source cleanup does not remove every later-stage component.

Use VS Code Restricted Mode for unfamiliar projects, keep automatic tasks disabled, and inspect execution paths before installation/builds. Blocking a fixed IP is insufficient for changing or blockchain-resolved infrastructure. This tool makes no firewall changes, remote writes, credential changes, or automatic deletions.

## Configuration

`config.json` beside the app contains `ScanPaths`, `MaxFileSize`, `AutoScanOnLaunch`, and `IncludeDependencies` (default false). Settings updates these values. Runtime files remain local; do not publish history/logs containing private paths.

## Verification

Run the harmless fixture suite:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests/Scanner.Tests.ps1
```

The execution-policy option applies only to this process running the repository's authored tests. It does not change machine policy or execute specimens. Tests exercise the scanner boundary, JSONC, platform overrides, renamed/nested references, fonts, campaign families, dependency exclusions, host metadata, scope/limits/cancellation, unchanged input bytes, and history compatibility.

## Research and limitations

Research baseline: 6 October 2026. Detection rules are reviewed local changes; the tool does not download rule updates or researcher scripts automatically.

- [OSM campaign dossier](https://github.com/OpenSourceMalware/PolinRider)
- [September 26 research, updated September 28](https://opensourcemalware.com/blog/polinrider-is-a-b-testing-its-way-past-your-detections)
- [Socket September 17 research](https://www.socket.dev/blog/polinrider-github-packagist)
- [Developer recovery guide](https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider)
- [Windows incident response](https://github.com/OpenSourceMalware/PolinRider/blob/main/polinrider-windows-incident-response.md)
- [VS Code Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust)
- [WOFF](https://www.w3.org/TR/WOFF/), [WOFF2](https://www.w3.org/TR/WOFF2/), [OpenType](https://learn.microsoft.com/en-us/typography/opentype/spec/otff)

False positives and missed variants remain possible. Review findings before taking action. Reviewed quarantine/restoration for newer file types is a subsequent delivery, not implemented here.

## Project

Fork of [Saif-Arshad/polinrider-monitor](https://github.com/Saif-Arshad/polinrider-monitor). PowerShell, WPF, background runspaces. MIT license; see LICENSE. Screenshots in `docs/screenshots` reflect the earlier UI.
