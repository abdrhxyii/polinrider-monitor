# Expand PolinRider detection and provide safe, reviewed remediation

Status: Testing boundaries confirmed by the user; awaiting issue-tracker setup for publication. Research baseline: 6 October 2026. No application changes authorized by this document alone.

## Problem Statement

The monitor checks selected JavaScript/TypeScript files for original PolinRider fingerprints, selected inline Node processes, fixed remote IPs, and one batch propagation pattern. Its current cleanup assumes text with a particular injection boundary. It excludes installed dependencies and can report CLEAN despite incomplete coverage.

Developers need to find documented newer infection paths without executing suspicious content, corrupting legitimate assets, or mistaking repository cleanup for eradication of a compromised workstation. Newer reporting documents renamed payloads, arbitrary extensions, nested locations, multiple obfuscators, settings changes, PHP launchers, and reinfection from other compromised contributors.

## Solution

Provide a local, bounded static scan that connects launch configurations and scripts to the files they execute, independently of names and extensions. Combine campaign signatures, structural indicators, format checks, and execution references in explainable findings. Distinguish high-confidence malware, suspicious content, and incomplete coverage.

Initially ship expanded detection without automatic cleanup for new finding types. A subsequent reviewed remediation phase preserves evidence, verifies file identity, quarantines confirmed payloads, and restores configurations or assets from verified originals. Explain that executed malware requires host investigation and credential recovery in addition to source repair.

## User Stories

1. As a developer, I want existing JS/TS detection preserved, so that broader coverage does not regress existing protection.
2. As a developer, I want documented original and newer payload families detected, so that rotated fingerprints do not defeat the scan.
3. As a developer, I want nested VS Code execution configurations inspected, so that malicious tasks are found throughout a monorepo.
4. As a developer, I want comments and trailing commas supported, so that valid JSONC is not silently skipped.
5. As a developer, I want platform overrides and task dependencies inspected, so that commands hidden in another platform or task are visible.
6. As a developer, I want dangerous terminal and debugger execution settings explained, so that I can identify launch paths beyond automatic tasks.
7. As a developer, I want referenced local payloads inspected regardless of extension, so that renamed files such as LLF payloads are covered.
8. As a developer, I want font files checked as bytes, so that disguised JavaScript is found without rendering or executing it.
9. As a developer, I want legitimate fonts and ordinary build tasks treated fairly, so that weak indicators do not automatically become infection verdicts.
10. As a developer, I want PHP and package execution wrappers checked, so that cross-ecosystem launch paths are covered.
11. As a developer, I want manifests and lockfiles checked for known malicious identities and versions, so that dependencies can be reviewed before installation.
12. As a developer, I want an optional installed-dependency scan, so that dependency exclusions are explicit and adjustable.
13. As a developer, I want process and network evidence correlated, so that the monitor can detect more than one inline Node command pattern.
14. As a developer, I want documented host artifacts reported without collecting secret contents, so that host investigation does not leak credentials into logs.
15. As a developer, I want findings to state reasons, confidence, evidence locations, and hashes, so that I can assess them before acting.
16. As a developer, I want skipped files, read failures, and cancellation reported, so that a partial scan never appears fully clean.
17. As a developer, I want scans to remain cancellable and bounded, so that large or malformed input cannot freeze the application.
18. As a developer, I want selected scan roots respected, so that references or junctions cannot expand access silently.
19. As a developer, I want suspicious content inspected without running it or contacting its URLs, so that scanning cannot activate an infection.
20. As a developer, I want evidence preserved before reviewed remediation, so that cleanup remains auditable and recoverable.
21. As a developer, I want assets replaced from verified originals, so that binary files are never damaged by JavaScript text cleanup.
22. As a developer, I want changed files and reused process IDs revalidated, so that remediation cannot act on stale scan results.
23. As a developer, I want recovery guidance covering credentials, workstations, repositories, contributors, and CI, so that infection is not reintroduced after source cleanup.
24. As a maintainer, I want detection rules versioned with sources, so that future research can be incorporated and reviewed.

## Implementation Decisions

- Retain the PowerShell/WPF application and background scan model. No runtime installation of dependencies during scans.
- Use one scanner orchestration boundary accepting scan options and a supplied host-observation provider; return structured findings and coverage. Keep remediation behind a separate explicit boundary because it mutates files and processes. The user confirmed these testing boundaries.
- Separate discovery, bounded static analysis, evidence correlation, and remediation responsibilities without exposing many test-only interfaces.
- Inspect workspace task, settings, launch, and multi-root configuration files as JSONC data. Cover commands, arguments, shell settings, environments, task dependencies, and platform overrides. Never execute substitutions or workspace commands to resolve references.
- Combine tolerant parsing with bounded raw-content inspection when parsing fails; preserve the parse failure as a coverage issue. Flag unsupported dynamic references as unresolved rather than safe.
- Inspect files referenced by executable tasks, package scripts, source loaders, and debugger configurations irrespective of extension. Normalize only statically resolvable paths, record the reference chain, and prevent cycles. Out-of-scope references remain reported without being followed.
- Inspect WOFF, WOFF2, and TTF/OpenType bytes for recognized headers, bounded lengths and table ranges, script indicators, and campaign rules. Initially avoid font decompression, installation, preview, and rendering. Bad headers alone produce suspicious findings; valid headers do not establish safety.
- Do not require a particular Font Awesome name, directory, whitespace padding, global marker, or visible wallet literal. Signature hits are one evidence source, with structural and launcher correlation providing additional coverage. Generic eval, Node, shell_exec, automatic-task, or obfuscation usage alone is not a confirmed campaign match.
- Extend source coverage to documented PHP launchers. Check package manifests and supported lockfiles for known malicious resolved identities/versions and execution scripts. Explicitly report unsupported lockfile formats. Installed dependency inspection is an opt-in scope with visible exclusions.
- Observe processes, executable paths, parent relationships, command lines, and connections without launching target executables. Shared blockchain infrastructure or a fixed-IP match alone must not trigger destructive actions.
- Host artifact inspection is read-only and evidence-based. Ordinary directories or installed Node/Python alone are insufficient evidence. Redact environment values, credentials, and tokens in findings and logs.
- Findings contain category, rule ID/version, confidence, explanation, artifact location, byte offset or field where practical, correlation references, and content hash for file artifacts. Keep coverage counts and failures separate from finding confidence.
- Replace an unqualified CLEAN verdict with no indicators found within stated scope; incomplete or stopped scans remain distinguishable. Extend history compatibly; old entries retain their original recorded scope and cannot authorize new remediation behavior.
- Apply explicit file-size, parsing-depth, traversal, reference-count, regex-time, and elapsed-time limits. Expose excluded or limited items. Use bounded/chunked reads where appropriate, including matches crossing chunk boundaries; revalidate files changed during reads.
- Expanded detectors are report-only in the first delivery. Do not route configs, fonts, arbitrary-extension assets, or uncertain newer JS variants into existing text trimming.
- Reviewed remediation preserves original bytes and hashes before changes, requires an explicit selected action, and checks current identity against scan evidence. Restore only verified originals; never fetch or trust restoration material from the suspect project's executable configuration. Revalidate process identity before termination.
- Quarantine uses an inert location outside watched project roots, prevents automatic execution, and retains reversible metadata. Source repair never automatically commits, pushes, rewrites history, or changes repository protections.
- Recovery guidance separates unexecuted source contamination from confirmed execution. For confirmed execution, recommend isolation, trusted host investigation, access revocation and credential rotation from a clean device, repository/CI review, contributor coordination, and trusted rebuild when eradication cannot be established.
- Detection rules carry cited provenance and a research date. Updates are reviewed data changes; no automatic download or execution of researcher scripts or samples.

## Testing Decisions

- Test externally visible scanner results using harmless temporary project trees and injected host observations. Assert findings, reasons, confidence, reference chains, coverage, cancellation, and unchanged input bytes rather than helper implementation details.
- Prefer the complete scan boundary; add a separate remediation boundary only for the subsequent mutation phase. No existing test suite or comparable testing convention was found in this repository.
- Include inert markers for documented payload families; JSONC comments/trailing commas; nested workspaces; platform overrides; dependencies; suspicious settings; unresolved variables; launch references; PHP wrappers; known package identity/version fixtures; unknown extensions; and renamed/deeply nested assets.
- Include legitimate tasks, terminal profiles, genuine font fixtures, malformed fonts, and benign eval/obfuscation examples to verify confidence distinctions and avoid destructive false positives.
- Verify byte signatures and container anomalies, signatures beyond whitespace padding and across read boundaries, valid-header files with suspicious appended data, and files modified mid-scan. Header validity must not suppress other evidence.
- Verify no candidate subprocess is launched, no extracted URL is contacted, no font is rendered, and no secret contents enter logs. All specimen fixtures are non-executable and contain no functional malicious stages.
- Verify permission failures, oversized files, unsupported formats, reference cycles, outside-root references, junctions, cancellation, and parser limits appear as coverage issues rather than clean results.
- Verify existing source and propagation detection remains functional and existing history loads safely.
- For later remediation, verify backup/quarantine integrity, verified restoration, stale-file and reused-PID refusal, selected-action enforcement, and exclusion of binary assets from text trimming. Merely finding an indicator never triggers remediation.

## Out of Scope

- Guaranteeing detection of all future variants or declaring a workstation eradicated from a file scan.
- Executing, importing, rendering, or dynamically deobfuscating suspicious payloads; contacting C2; installing project dependencies; running researcher scripts.
- Automatic credential rotation, OS reinstallation, firewall changes, remote repository writes, force-pushes, or messages to other people.
- Automatic font repair or arbitrary heuristic-based deletion.
- A full antivirus/EDR product, complete coverage of every package ecosystem, remote branch/history scanning, or live GitHub activity monitoring. Guidance covers these recovery needs; implementing dedicated integrations requires separate scope.
- Application implementation in this specification-writing task.

## Further Notes

- Current code review established coverage gaps; no workstation scan or confirmed infection assessment has been performed.
- First delivery: static configuration, referenced-payload, asset, source, and manifest detection with structured findings and coverage. Second delivery: host evidence correlation. Third delivery: reviewed remediation after detection behavior is validated. Host recovery can be necessary immediately and must not wait for these features.
- Publication target and tracker setup were not explicitly supplied. The local Git remote identifies the user's fork, but tracker conventions must be established before publication. The invoked skill requires the ready-for-agent label; testing boundaries are confirmed. Run /setup-matt-pocock-skills to supply missing tracker setup.

Primary research and documentation:

- [OSM campaign dossier and April update](https://github.com/OpenSourceMalware/PolinRider#april-1011-update): original/rotated families and documented config/task/font/dependency paths.
- [OSM September 26 report, updated September 28](https://opensourcemalware.com/blog/polinrider-is-a-b-testing-its-way-past-your-detections): changing names, extensions, paths, obfuscators, execution configurations, and reinfection.
- [Socket September 17 research](https://www.socket.dev/blog/polinrider-github-packagist): PHP launchers, development-version exposure, and distinction between source cleanup and host recovery.
- [OSM Windows response guide](https://github.com/OpenSourceMalware/PolinRider/blob/main/polinrider-windows-incident-response.md): documented later-stage credential targets and host artifacts; indicators are evidence, not blanket deletion rules.
- [VS Code tasks](https://code.visualstudio.com/docs/debugtest/tasks), [task schema](https://code.visualstudio.com/docs/reference/tasks-appendix), [terminal profiles](https://code.visualstudio.com/docs/terminal/profiles), and [Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust): legitimate configuration behavior and trust restrictions.
- [WOFF](https://www.w3.org/TR/WOFF/), [WOFF2](https://www.w3.org/TR/WOFF2/), and [OpenType](https://learn.microsoft.com/en-us/typography/opentype/spec/otff): binary format checks.
- [npm ignore-scripts behavior](https://docs.npmjs.com/cli/v11/commands/npm-ci/#ignore-scripts): lifecycle suppression does not prevent explicitly requested scripts from running.
