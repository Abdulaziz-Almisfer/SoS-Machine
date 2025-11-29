SoS Machine — Smart Offensive Simulation

SoS Machine is a focused, no-nonsense tool that scans PowerShell history across Windows users, detects offensive TTPs, and produces a single colorized HTML report that helps red teams, IR, and threat hunters find the real signals fast.

TL;DR (one-liner)

SoS Machine turns messy PowerShell history into actionable threat intelligence — fast, local, and read-only.

Quick pitch (short LinkedIn / tweet)

SoS Machine: fast post-exploitation intelligence from PowerShell history. Scans all users, detects C2/cradles/AD enumeration/persistence, and exports a colorized HTML report. No external deps — just run it and get the signal, not noise.

Why it exists

PowerShell is both attacker favorite and a rich forensic source. Humans can't comb through thousands of commands quickly; SoS Machine automates detection of meaningful TTPs (C2 frameworks, encoded payloads, AD tools, credential theft, persistence, AV tampering) and shows the results in one clear report. It’s designed for labs, red team post-checks, and first-pass triage during IR.

Key features

✔️ Scans PSReadLine history for all users on a Windows host (run as admin for full coverage).

✔️ Large, practical rule set for TTPs: encoded commands, IEX cradles, PowerView/SharpHound, Mimikatz indicators, persistence patterns, AV tampering, download/exfil patterns, and more.

✔️ Single HTML report with colorized severity (Critical / High / Medium / Low) and matched rule explanations.

✔️ Read-only: the tool does not change system config or install agents.

✔️ Zero external dependencies (pure Python) — portable and simple to run.

Example usage

Place SoS_Machine.py on the host (or on a management box that can reach the host).

Run PowerShell as Administrator (for full user coverage) and execute:

python SoS_Machine.py


Open the generated report:

pshistory_allusers_fullrules_report.html

What it detects (high-level)

Execution & obfuscation: IEX, -EncodedCommand, Invoke-Expression, Base64 decode patterns.

Download & staging: Invoke-WebRequest, certutil, bitsadmin, curl/wget, download+execute cradles.

AD enumeration & collection: Get-Net*, Get-AD*, PowerView.ps1, SharpHound.

Credential access: Get-Credential, Export-PfxCertificate, mimikatz, sekurlsa.

Lateral movement: Invoke-Command, psexec, wmic, Enter-PSSession.

Persistence & evasion: scheduled tasks, service creation, registry Run keys, Defender exclusions, event log clearing.

Shellcode & injection indicators and other suspicious API calls or patterns.

Output

Single HTML file with:

Summary (total commands, users, counts by severity)

Findings table (Critical / High / Medium) with matched regex and reason

Full commands table for context

Recommended workflow

Run SoS Machine immediately after an engagement or as a first step in IR to highlight suspicious commands.

Use findings to prioritize which hosts to image or which logs/events to pull next (Sysmon, EVTX).

Tune the ruleset to your environment: whitelist legitimate admin tooling and add organization-specific telemetry if needed.

Security & ethics

Designed for authorized use only. Run on systems you own, control, or have written permission to test.

The tool reads potentially sensitive data (transcripts / command contents). Treat outputs as sensitive and store securely.
