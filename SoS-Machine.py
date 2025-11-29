#!/usr/bin/env python3
# ps_history_allusers_fullrules.py
# Collect PSReadLine (all users), match against an extensive ruleset, output single HTML report.
# No external dependencies. Run as Administrator to read other users' histories.

import os
import re
import datetime
import html

# ---------------------------
# Extensive ruleset (pattern, level, reason)
# Levels: Critical, High, Medium, Low, Info
# ---------------------------
RULES = [
    # Critical / C2 / frameworks
    (r'Invoke-Obfuscation', 'Critical', 'Invoke-Obfuscation framework usage (obfuscation)'),
    (r'Invoke-Mimikatz|mimikatz|sekurlsa', 'Critical', 'Mimikatz / LSASS dumping indicators'),
    (r'\bEmpire\b|\bPoshC2\b|\bCovenant\b|\bSliver\b', 'Critical', 'Known C2 framework mention'),

    # Execution & obfuscation
    (r'\bIEX\b', 'High', 'Invoke-Expression (IEX) - dynamic execution'),
    (r'-EncodedCommand\b|-enc\b|\bEncodedCommand\b', 'High', 'EncodedCommand / -enc used (obfuscated payload)'),
    (r'\bInvoke-Expression\b', 'High', 'Invoke-Expression dynamic execution'),
    (r'FromBase64String|FromBase64|Convert::FromBase64String', 'High', 'Base64 decoding usage (possible deobfuscation)'),
    (r'PowerShell(?:\.exe)?\s+.*-enc\b', 'High', 'PowerShell encoded command executed'),
    (r'\\bInvoke-Obfuscation\\b', 'Critical', 'Invoke-Obfuscation explicit'),

    # Download / network
    (r'\bInvoke-WebRequest\b|\bInvoke-RestMethod\b|\bDownloadString\b|\bDownloadFile\b', 'High', 'PowerShell web download functions'),
    (r'\bcertutil\b.*(urlcache|decode|-decode)', 'High', 'certutil used for download or decode'),
    (r'\bbitsadmin\b', 'High', 'BITSAdmin download job'),
    (r'\bcurl\b|\bwget\b', 'Medium', 'curl/wget used (file retrieval)'),
    (r'New-Object\s+System\.Net\.WebClient|System\.Net\.WebClient', 'Medium', 'WebClient download usage'),
    (r'\bInvoke-RestMethod\b.*-Method\s+Post', 'High', 'REST POST requests (possible exfil / C2)'),

    # AD enumeration / BloodHound / PowerView / SharpHound
    (r'\bGet-AD(User|Computer|Group|Domain)\b', 'High', 'Active Directory enumeration (Get-AD*)'),
    (r'\bGet-Net(User|Computer|Group|Domain|DomainTrust|NetGroup|NetComputer)\b', 'High', 'PowerView / Get-Net* enumeration'),
    (r'\bPowerView\.ps1\b|\bSharpHound\b|\bSharpHound\b', 'High', 'PowerView / SharpHound / BloodHound collection'),
    (r'-SPN\b|Kerberoast|GetUserSPN|Get-NetUser\s+-SPN', 'High', 'SPN / Kerberoast enumeration'),

    # Credential access / theft
    (r'\bGet-Credential\b|\bcmdkey\b|\bvaultcmd\b', 'High', 'Credential prompt / storage usage'),
    (r'\bExport-PfxCertificate\b|\bExport-Certificate\b', 'High', 'Exporting certificates / secrets'),
    (r'\bsekurlsa\b', 'Critical', 'sekurlsa references - LSASS access'),
    (r'\bInvoke-Mimikatz\b', 'Critical', 'Invoke-Mimikatz invocation'),

    # Lateral movement / remote exec
    (r'\bInvoke-Command\b', 'High', 'Remote command execution (Invoke-Command)'),
    (r'\bpsexec\b|\bwmic\b|\bwinrm\b|\bEnter-PSSession\b|\bNew-PSSession\b', 'High', 'Remote exec / lateral movement tooling'),
    (r'\bWMI\b|\bGet-WmiObject\b|\bgwmi\b', 'Medium', 'WMI enumeration / remote execution'),

    # Persistence
    (r'\bschtasks\b|\bRegister-ScheduledTask\b', 'High', 'Scheduled task creation (persistence)'),
    (r'\bNew-Service\b|\bsc\s+create\b', 'High', 'Service creation (persistence)'),
    (r'Set-ItemProperty.*\\Run', 'High', 'Registry Run key persistence'),
    (r'Add-Content.*Startup|Copy-Item.*Startup|Move-Item.*Startup', 'High', 'Startup folder persistence'),

    # Defense evasion / AV tampering
    (r'Add-MpPreference|Set-MpPreference|Disable-WindowsDefender', 'High', 'Disabling Defender or setting exclusions'),
    (r'Set-ExecutionPolicy\s+Bypass', 'High', 'Execution policy bypass'),
    (r'\bwevtutil\s+cl\b|\bClear-EventLog\b', 'High', 'Event log clearing / log tampering'),
    (r'Registry::HKLM.*DisableAntiSpyware|DisableAntiSpyware', 'High', 'Disabling AV via registry keys'),

    # File staging / compression / exfil
    (r'Compress-Archive|Expand-Archive|Add-Type.*Compression', 'Medium', 'Compression for staging/exfil'),
    (r'Out-File.*\.zip|Out-File.*\.7z|Compress-Archive', 'Medium', 'Creating archive via Out-File/Compress-Archive'),
    (r'Copy-Item.*\\\\|Move-Item.*\\\\|New-PSDrive\s', 'Low', 'File movement or mapping network drive'),

    # Shellcode / injection patterns (indicators, not payloads)
    (r'Invoke-Shellcode|ReflectiveLoad|VirtualAlloc|WriteProcessMemory|CreateRemoteThread', 'Critical', 'Shellcode injection / reflective loading indicators'),
    (r'LoadLibraryA|LoadLibraryW|GetProcAddress', 'High', 'Native DLL load / API usage typical of injections'),

    # LOLBins & common tools
    (r'\bnet user\b|\bnet localgroup\b|\bnet group\b', 'Medium', 'net.exe user/group enumeration'),
    (r'\bwhoami\b|\bsysteminfo\b|\bhostname\b', 'Low', 'Basic host reconnaissance'),
    (r'\bnetstat\b|\bsc query\b|\btasklist\b', 'Low', 'System/network info gathering'),
    (r'\bnslookup\b|\bResolve-DnsName\b', 'Low', 'DNS reconnaissance'),

    # PowerShell stealthy flags
    (r'-NoProfile\b|-NonInteractive\b|-WindowStyle\s+Hidden|-EncodedCommand', 'Medium', 'Stealthy PowerShell invocation flags'),

    # Dynamic .NET / reflection abuse
    (r'Add-Type\b|Reflection\.Assembly::Load|Assembly.Load', 'Medium', 'Dynamic .NET type or assembly loading'),

    # JavaScript / WSH indicators inside scripts
    (r'WScript\.Shell|CreateObject\("Wscript\.Shell"\)', 'Medium', 'WSH usage (scripting host)'),

    # Exfil / network beacon patterns
    (r'Invoke-RestMethod.*-Uri|Invoke-WebRequest.*-Uri|wget\s+-O', 'High', 'HTTP beacon / exfil pattern'),
    (r'(POST|GET)\s+https?://', 'High', 'HTTP request to external host (possible C2/exfil)'),

    # Tools & frameworks names
    (r'\bPowerSploit\b|\bPowerUp\b|\bPowerView\b', 'High', 'PowerShell offensive toolkit mention'),
    (r'\bSharpHound\b|\bBloodHound\b', 'High', 'BloodHound/SharpHound usage'),

    # Credential dumping helpers
    (r'lsass|drsuapi|miniDump|dumpert', 'Critical', 'LSASS memory access / dumping'),

    # Kerberos / SPN enumeration
    (r'GetUserSPN|Kerberoast|RequestKerberos', 'High', 'SPN / Kerberoast related activity'),

    # Certificate / token handling
    (r'Invoke-AzureAD|Get-AzureADUser|Get-AzureADApplication', 'Medium', 'Azure AD enumeration / interaction'),
    (r'Export-PfxCertificate|ConvertTo-SecureString.*-AsPlainText', 'High', 'Exporting keys or insecure conversion'),

    # Process & service abuse
    (r'Start-Process\b|\bStart-Job\b|\bStart-ThreadJob\b', 'Medium', 'Background process/job creation'),
    (r'CreateObject\("WScript\.Shell"\)|ShellExecute', 'Medium', 'Script host process launch'),

    # Misc suspicious verbs
    (r'Invoke-Expression|IEX|iex', 'High', 'Dynamic code execution (generic)'),
    (r'Invoke-Item|Invoke-Command', 'High', 'Invocation of external items/commands'),

    # Common admin tools that when used by non-admins may be suspicious
    (r'psexec|wmic|schtasks|sc\s+create', 'High', 'Admin tools used for remote/privilege actions'),

    # Defender / Windows update tampering patterns
    (r'Add-MpPreference.*Exclusion|Set-MpPreference.*Exclusion', 'High', 'Adding Defender exclusion'),

    # Registry operations often used in persistence/evade
    (r'Reg.exe\s+add|New-ItemProperty|Set-ItemProperty', 'Medium', 'Registry modification commands'),

    # PowerShell download cradle patterns
    (r'iex\(New-Object\s+Net\.WebClient\)\.DownloadString', 'High', 'Download cradle (download+execute via IEX)'),

    # Binaries / installer invocation
    (r'Install-Package|msiexec|Start-Process.*msiexec', 'Medium', 'Installer/package execution'),

    # Encoding and obfuscation heuristics
    (r'FromBase64String|ToBase64String|Base64', 'Medium', 'Base64 encoding/decoding usage'),

    # Script block logging avoidance patterns
    (r'\$ExecutionContext\.InvokeCommand', 'Medium', 'Script block execution reflection'),

    # Potential credential harvesters
    (r'Get-Content.*(password|passwd|cred|secret|token|key)', 'High', 'Reading files that likely contain credentials'),

    # Extraction / archive helpers
    (r'Tar\.exe|7z\.exe|7za\.exe|Compact-Archive', 'Medium', 'Archiving tools usage'),

    # Networking libraries usage
    (r'System\.Net\.Sockets|TcpClient|UdpClient|Socket', 'High', 'Low-level socket network usage (possible C2)'),

    # PowerShell remoting & session configuration
    (r'Register-PSSessionConfiguration|Enable-PSRemoting|Disable-PSRemoting', 'High', 'PowerShell remoting configuration'),

    # WMI persistence patterns
    (r'Win32_Service|Create|Put', 'Medium', 'WMI service creation patterns'),

    # Known suspicious file patterns
    (r'\.exe$|\.dll$|\.ps1$|\.bat$|\.scr$', 'Low', 'Execution script/binary reference'),

    # Generic suspicious functions
    (r'Invoke-Assembly|LoadLibrary', 'High', 'Loading assemblies via Invoke-Assembly or native LoadLibrary'),

    # Network share manipulation
    (r'New-PSDrive.*\\\\|net use', 'Low', 'Mapping network shares (could be staging)'),

    # High-risk string operations (encoding/decoding)
    (r'ConvertFrom-SecureString|ConvertTo-SecureString.*-AsPlainText', 'High', 'SecureString conversion to plain text'),

    # Common scanning and fingerprinting
    (r'PortScan|nmap|Masscan', 'High', 'Network scanning tool mention'),

    # Offensive tooling indicators
    (r'Invoke-RedTeam|Invoke-RedTeamTool|Invoke-External', 'High', 'Red-team tool invocation patterns'),

    # Suspicious PowerShell arguments
    (r'-NonInteractive|-NoProfile|-ExecutionPolicy\s+Bypass', 'Medium', 'Stealthy invocation flags'),

    # Anything that references process memory or injection primitives
    (r'OpenProcess|ReadProcessMemory|NtReadVirtualMemory', 'Critical', 'Process memory access primitives'),

    # Potential persistence through scheduled tasks or services
    (r'\bRegister-ScheduledTask\b|\bScheduledTask\b', 'High', 'Registering scheduled tasks'),

    # Obvious phishing/download commands
    (r'Invoke-WebRequest.*-OutFile|Start-BitsTransfer', 'High', 'Download to file (possible payload staging)'),

    # Potential recon with AD tools
    (r'netstat -an|Get-NetTCPConnection', 'Low', 'Network socket inspection'),

    # Placeholder for many other heuristics (add more as needed)
]

# ---------------------------
# Severity ranking helper
# ---------------------------
SEVERITY_SCORE = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

# ---------------------------
# Collect PSReadLine from all users
# ---------------------------
def collect_all_psreadline():
    base = r"C:\Users"
    collected = []
    if not os.path.isdir(base):
        # fallback: current user only
        userprofile = os.environ.get("USERPROFILE")
        if not userprofile:
            return collected
        hist = os.path.join(userprofile, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
        if os.path.isfile(hist):
            try:
                with open(hist, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        cmd = line.rstrip("\n")
                        if cmd and cmd.strip():
                            collected.append({"user": os.path.basename(userprofile), "command": cmd})
            except Exception:
                pass
        return collected

    for user in os.listdir(base):
        # skip obvious profiles
        if user.lower() in ("public", "default", "defaultuser0", "all users", "desktopdefault"):
            continue
        hist = os.path.join(base, user, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
        if os.path.isfile(hist):
            try:
                with open(hist, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        cmd = line.rstrip("\n")
                        if cmd and cmd.strip():
                            collected.append({"user": user, "command": cmd})
            except Exception as e:
                # permission or read error
                print(f"[!] Could not read {hist}: {e}")
    return collected

# ---------------------------
# Score a single command by scanning rules; return best (highest-severity) match
# ---------------------------
def score_command(cmd_text):
    best_level = "Low"
    best_reason = ""
    best_score = SEVERITY_SCORE[best_level]
    for pat, level, reason in RULES:
        try:
            if re.search(pat, cmd_text, re.IGNORECASE):
                sc = SEVERITY_SCORE.get(level, 2)
                if sc > best_score:
                    best_score = sc
                    best_level = level
                    best_reason = reason + f" (matched: {pat})"
                    if best_score == SEVERITY_SCORE["Critical"]:
                        break
        except re.error:
            # invalid regex skip
            continue
    return best_level, best_reason

# ---------------------------
# Generate HTML report
# ---------------------------
def generate_html(scored_list, outname="pshistory_allusers_fullrules_report.html"):
    now = datetime.datetime.utcnow().isoformat() + "Z"
    total = len(scored_list)
    users = sorted(set(r["user"] for r in scored_list))
    crit = sum(1 for r in scored_list if r["level"] == "Critical")
    high = sum(1 for r in scored_list if r["level"] == "High")
    med = sum(1 for r in scored_list if r["level"] == "Medium")

    # header
    parts = []
    parts.append("<!doctype html><html><head><meta charset='utf-8'><title>PSReadLine All-Users Report</title>")
    parts.append("<style>")
    parts.append("body{font-family:Segoe UI,Arial;padding:18px;background:#fff}")
    parts.append("table{border-collapse:collapse;width:100%}")
    parts.append("th,td{border:1px solid #ddd;padding:8px;vertical-align:top}")
    parts.append("th{background:#222;color:#fff}")
    parts.append("pre{white-space:pre-wrap;font-family:Consolas,monospace}")
    parts.append(".c-Critical{background:#ffdddd}.c-High{background:#fff0e0}.c-Medium{background:#fffbe6}.c-Low{}")
    parts.append("</style></head><body>")
    parts.append(f"<h1>PowerShell PSReadLine Report — All Users</h1>")
    parts.append(f"<p><strong>Generated:</strong> {html.escape(now)}</p>")
    parts.append(f"<p><strong>Total commands:</strong> {total} &nbsp; | &nbsp; <strong>Users:</strong> {len(users)} &nbsp; | &nbsp; <strong>Critical/High/Medium:</strong> {crit}/{high}/{med}</p>")

    # Findings table
    parts.append("<h2>Findings (Critical / High / Medium)</h2>")
    parts.append("<table><thead><tr><th>#</th><th>User</th><th>Command</th><th>Level</th><th>Reason</th></tr></thead><tbody>")
    findings = [r for r in scored_list if r["level"] in ("Critical", "High", "Medium")]
    # sort by severity then user
    severity_order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    findings.sort(key=lambda x: (-severity_order.get(x["level"], 0), x["user"]))
    for i, r in enumerate(findings, start=1):
        parts.append("<tr class='c-{lvl}'><td>{i}</td><td>{user}</td><td><pre>{cmd}</pre></td><td>{lvl}</td><td>{reason}</td></tr>"
                     .format(i=i, user=html.escape(r["user"]), cmd=html.escape(r["command"]), lvl=html.escape(r["level"]), reason=html.escape(r.get("reason",""))))
    parts.append("</tbody></table>")

    # All commands table
    parts.append("<h2>All Commands</h2>")
    parts.append("<table><thead><tr><th>#</th><th>User</th><th>Command</th><th>Level</th></tr></thead><tbody>")
    for i, r in enumerate(scored_list, start=1):
        parts.append("<tr class='c-{lvl}'><td>{i}</td><td>{user}</td><td><pre>{cmd}</pre></td><td>{lvl}</td></tr>"
                     .format(i=i, user=html.escape(r["user"]), cmd=html.escape(r["command"]), lvl=html.escape(r["level"])))
    parts.append("</tbody></table>")

    parts.append("</body></html>")
    with open(outname, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
    print(f"[*] Report saved: {outname} (Total cmds: {total}, Users: {len(users)}, Critical/High/Medium: {crit}/{high}/{med})")

# ---------------------------
# Main
# ---------------------------
def main():
    print("[*] Collecting PSReadLine histories for all users...")
    rows = collect_all_psreadline()
    if not rows:
        print("[!] No PSReadLine histories found. Exiting.")
        return
    print(f"[*] Collected {len(rows)} commands. Scoring against {len(RULES)} rules...")
    scored = []
    for item in rows:
        user = item.get("user", "unknown")
        cmd = item.get("command", "")
        lvl, reason = score_command(cmd)
        scored.append({"user": user, "command": cmd, "level": lvl, "reason": reason})
    generate_html(scored)

if __name__ == "__main__":
    main()
