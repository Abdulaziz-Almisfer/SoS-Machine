## SoS Machine

SoS Machine — Smart Offensive Simulation
Turn raw PowerShell history into actionable threat intelligence. Fast, local, read-only, and built for red teams, IR, and threat hunters.

TL;DR

SoS Machine scans PowerShell PSReadLine history across Windows users, applies a broad TTP-focused ruleset, and produces a single colorized HTML triage report (Critical / High / Medium / Low). No agents, no changes to the host — just clear signals, not noise.

Key Features

Scans PSReadLine history for all users on a host (run as Administrator for full coverage).

Large practical ruleset covering common offensive TTPs:

execution & obfuscation, download cradles, AD enumeration, credential theft, persistence, AV tampering, lateral movement, shellcode indicators, and more.

Produces a single HTML report with:

summary, findings (colored by severity), and a full command list for context.

Read-only: does not change system configuration or install components.

Zero external dependencies (pure Python), portable and easy to run.

Why SoS Machine

PowerShell is both an attacker’s favorite and a rich forensic source. Humans can’t efficiently triage thousands of shell commands. SoS Machine automates that first-pass triage: it highlights the suspicious commands and explains why they matter so you can prioritize follow-up (Sysmon, memory capture, imaging).

Usage

Place the script on the target or a management box that can access the target.

Run PowerShell as Administrator (for full user coverage).

Execute:

python SoS_Machine.py


Open the generated report:

pshistory_allusers_fullrules_report.html

What it detects (high level)

Execution & obfuscation: IEX, -EncodedCommand, Invoke-Expression, Base64 decoding.

Download & staging: Invoke-WebRequest, certutil, bitsadmin, curl/wget, download+execute cradles.

AD enumeration & collection: Get-Net*, Get-AD*, PowerView.ps1, SharpHound.

Credential access: Get-Credential, certificate export, mimikatz, sekurlsa.

Lateral movement: Invoke-Command, psexec, wmic, Enter-PSSession.

Persistence & evasion: scheduled tasks, service creation, registry Run keys, Defender exclusions, event log clearing.

Shellcode & injection: reflective loading, memory APIs, injection primitives.

Network beacon/exfil patterns: HTTP POST/GET to external hosts, REST beacons.

Output

Single colorized HTML file: pshistory_allusers_fullrules_report.html

Summary (total commands, users, severity counts)

Findings table (Critical / High / Medium) with matched pattern and reason

Full commands table for context

Recommended workflow

Run SoS Machine as the first triage step after an engagement or suspected compromise.

Use findings to prioritize hosts for deeper collection (memory, sysmon, evtx).

Tune the ruleset to your environment: whitelist legitimate admin tools and add organization-specific telemetry.

Integrate outputs into your IR pipeline or SIEM as needed.

Security & Ethics

Authorized use only. Run SoS Machine on systems you own or have explicit permission to test.

The tool reads potentially sensitive command contents. Treat report outputs as sensitive data and store them securely.

SoS Machine is a triage tool — it does not replace dedicated EDR/forensics tooling.

Extending & Contributing

Rules are intentionally practical and editable. Add or tune regex patterns to match your environment.

Contributions welcome: add new detections, reduce false positives, or add integration hooks (CSV export, SIEM exporters, central aggregator).
