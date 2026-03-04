#requires -version 5.1
[CmdletBinding()]
param(
    [string]$OutDir = "$env:PUBLIC\SecurityAudit",
    [int]$PatchMaxAgeDays = 45,
    [int]$MaxFindingsPerCheck = 40
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:CountByCheck = @{}

function Add-Finding {
    param(
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,
        [string]$Check,
        [string]$Details,
        [string]$Evidence = ''
    )

    if (-not $script:CountByCheck.ContainsKey($Check)) { $script:CountByCheck[$Check] = 0 }
    if ($script:CountByCheck[$Check] -ge $MaxFindingsPerCheck) { return }
    $script:CountByCheck[$Check]++

    $script:Findings.Add([pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Severity  = $Severity
        Check     = $Check
        Details   = $Details
        Evidence  = $Evidence
    })
}

function Invoke-Check {
    param([string]$Name, [scriptblock]$Script)
    try { & $Script }
    catch { Add-Finding -Severity Low -Check "$Name Error" -Details $_.Exception.Message }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Expand-Text([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    [Environment]::ExpandEnvironmentVariables($Text.Trim())
}

function Get-ExePathFromCommand([string]$CommandLine) {
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $cmd = Expand-Text $CommandLine

    if ($cmd -match '^\s*"([^"]+)"') { return $matches[1] }
    if ($cmd -match '^\s*([^\s]+)') { return $matches[1] }
    return $null
}

function Test-SuspiciousPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = (Expand-Text $Path).ToLowerInvariant()
    (
        $p -match '\\users\\[^\\]+\\appdata\\' -or
        $p -match '\\users\\public\\' -or
        $p -match '\\windows\\temp\\' -or
        $p -match '\\temp\\' -or
        $p -match '\\recycle\.bin\\'
    )
}

function Test-FileUnsigned([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $expanded = Expand-Text $Path
    if (-not (Test-Path -LiteralPath $expanded)) { return $false }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $expanded
        ($sig.Status -ne 'Valid')
    } catch { $false }
}

if (-not (Test-IsAdmin)) {
    Write-Warning "Run this script as Administrator for full coverage."
}

if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

Invoke-Check "Defender" {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $mp = Get-MpComputerStatus
        if (-not $mp.AntivirusEnabled) { Add-Finding Critical "Defender" "Antivirus is disabled." }
        if (-not $mp.RealTimeProtectionEnabled) { Add-Finding Critical "Defender" "Real-time protection is disabled." }

        if ($mp.PSObject.Properties.Name -contains 'IsTamperProtected' -and -not $mp.IsTamperProtected) {
            Add-Finding High "Defender" "Tamper protection is disabled."
        }

        if ($mp.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-7)) {
            Add-Finding Medium "Defender" "Signatures are older than 7 days." "Last update: $($mp.AntivirusSignatureLastUpdated)"
        }
    } else {
        Add-Finding Info "Defender" "Defender cmdlets not available on this host."
    }
}

Invoke-Check "Firewall" {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $disabled = $profiles | Where-Object { -not $_.Enabled }
    foreach ($p in $disabled) {
        Add-Finding High "Firewall" "Firewall profile disabled." $p.Name
    }
}

Invoke-Check "SMBv1" {
    if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        foreach ($f in @('SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server')) {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue
            if ($feature -and $feature.State -eq 'Enabled') {
                Add-Finding High "SMBv1" "Legacy SMBv1 component is enabled." $f
            }
        }
    }
}

Invoke-Check "RDP/NLA" {
    $ts = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop
    if ($ts.fDenyTSConnections -eq 0) {
        $nla = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue
        if (-not $nla -or $nla.UserAuthentication -ne 1) {
            Add-Finding High "RDP/NLA" "RDP is enabled without NLA."
        }
    }
}

Invoke-Check "UAC" {
    $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
    if ($uac.EnableLUA -eq 0) {
        Add-Finding High "UAC" "UAC is disabled."
    }
}

Invoke-Check "WDigest" {
    $wd = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -ErrorAction SilentlyContinue
    if ($wd -and $wd.UseLogonCredential -eq 1) {
        Add-Finding High "WDigest" "UseLogonCredential is enabled (cleartext credential risk)."
    }
}

Invoke-Check "PowerShell Logging" {
    $sb = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue
    $ml = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -ErrorAction SilentlyContinue
    $tr = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -ErrorAction SilentlyContinue

    if (-not $sb -or $sb.EnableScriptBlockLogging -ne 1) { Add-Finding Medium "PowerShell Logging" "ScriptBlock logging is disabled." }
    if (-not $ml -or $ml.EnableModuleLogging -ne 1) { Add-Finding Medium "PowerShell Logging" "Module logging is disabled." }
    if (-not $tr -or $tr.EnableTranscripting -ne 1) { Add-Finding Medium "PowerShell Logging" "Transcription is disabled." }
}

Invoke-Check "Local Accounts" {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Add-Finding High "Local Accounts" "Guest account is enabled."
        }

        $weak = Get-LocalUser | Where-Object { $_.Enabled -and $_.PasswordNeverExpires -and $_.Name -notin @('Administrator','DefaultAccount','WDAGUtilityAccount') }
        foreach ($u in $weak) {
            Add-Finding Medium "Local Accounts" "Enabled account with non-expiring password." $u.Name
        }
    }
}

Invoke-Check "Administrators Group" {
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
        foreach ($a in $admins) {
            if ($a.ObjectClass -eq 'User' -and $a.Name -notmatch '\\Administrator$') {
                Add-Finding Low "Administrators Group" "Review local admin membership." $a.Name
            }
        }
    }
}

Invoke-Check "Autoruns (Registry)" {
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }
        $props = (Get-ItemProperty -Path $key).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
        foreach ($p in $props) {
            $cmd = [string]$p.Value
            $exe = Get-ExePathFromCommand $cmd
            if (Test-SuspiciousPath $cmd) {
                Add-Finding High "Autoruns (Registry)" "Suspicious autostart command." "$key -> $($p.Name) = $cmd"
            }
            if ($exe -and (Test-FileUnsigned $exe)) {
                Add-Finding Medium "Autoruns (Registry)" "Unsigned binary in autostart." "$key -> $exe"
            }
        }
    }
}

Invoke-Check "Scheduled Tasks" {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }
    foreach ($t in $tasks) {
        foreach ($a in $t.Actions) {
            $exec = Expand-Text ([string]$a.Execute)
            $args = [string]$a.Arguments
            $cmd = "$exec $args".Trim()

            if (Test-SuspiciousPath $cmd) {
                Add-Finding High "Scheduled Tasks" "Suspicious non-Microsoft scheduled task action." "$($t.TaskPath)$($t.TaskName) -> $cmd"
            }

            if ($exec -and (Test-FileUnsigned $exec)) {
                Add-Finding Medium "Scheduled Tasks" "Unsigned executable in scheduled task." "$($t.TaskPath)$($t.TaskName) -> $exec"
            }
        }
    }
}

Invoke-Check "Services" {
    $svcs = Get-CimInstance Win32_Service -ErrorAction Stop
    foreach ($s in $svcs) {
        $pathRaw = [string]$s.PathName
        if ([string]::IsNullOrWhiteSpace($pathRaw)) { continue }

        $exe = Get-ExePathFromCommand $pathRaw

        if (Test-SuspiciousPath $pathRaw) {
            Add-Finding High "Services" "Service executable path is suspicious." "$($s.Name) -> $pathRaw"
        }

        if ($s.StartMode -eq 'Auto' -and $pathRaw -match '\s' -and $pathRaw -notmatch '^\s*"') {
            Add-Finding Medium "Services" "Potential unquoted service path." "$($s.Name) -> $pathRaw"
        }

        if ($exe -and (Test-FileUnsigned $exe) -and $exe -notmatch '\\Windows\\System32\\') {
            Add-Finding Medium "Services" "Unsigned service executable." "$($s.Name) -> $exe"
        }
    }
}

Invoke-Check "WMI Persistence" {
    $consumers = Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    foreach ($c in $consumers) {
        $cmd = [string]$c.CommandLineTemplate
        if (Test-SuspiciousPath $cmd -or $cmd -match '(?i)powershell|cmd\.exe|wscript|cscript|mshta|rundll32') {
            Add-Finding High "WMI Persistence" "Potential WMI persistence command consumer." "$($c.Name) -> $cmd"
        } else {
            Add-Finding Low "WMI Persistence" "WMI command consumer exists (review)." "$($c.Name) -> $cmd"
        }
    }
}

Invoke-Check "Port Proxy" {
    $out = netsh interface portproxy show all 2>$null
    if ($LASTEXITCODE -eq 0 -and $out) {
        $joined = ($out -join "`n").Trim()
        if ($joined -match '\d+\.\d+\.\d+\.\d+\s+\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+') {
            Add-Finding High "Port Proxy" "PortProxy entries exist (possible tunneling/backdoor path)." $joined
        }
    }
}

Invoke-Check "Listening Ports" {
    $watchPorts = @(4444,1337,5555,6666,9001,31337)
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($l in $listeners) {
        $pid = $l.OwningProcess
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue
        $path = [string]$proc.ExecutablePath

        if ($watchPorts -contains $l.LocalPort) {
            Add-Finding High "Listening Ports" "Process listening on commonly abused port." "PID=$pid Port=$($l.LocalPort) Path=$path"
        }

        if ($path -and (Test-SuspiciousPath $path)) {
            Add-Finding High "Listening Ports" "Process from suspicious path is listening." "PID=$pid Port=$($l.LocalPort) Path=$path"
        }
    }
}

Invoke-Check "Patch Recency" {
    $latest = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($latest -and $latest.InstalledOn -lt (Get-Date).AddDays(-$PatchMaxAgeDays)) {
        Add-Finding Medium "Patch Recency" "No hotfix installed in the last $PatchMaxAgeDays days." "Last hotfix: $($latest.HotFixID) on $($latest.InstalledOn)"
    } elseif (-not $latest) {
        Add-Finding Low "Patch Recency" "Could not read hotfix history."
    }
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$jsonPath = Join-Path $OutDir "security_audit_$timestamp.json"
$csvPath  = Join-Path $OutDir "security_audit_$timestamp.csv"

$script:Findings | Sort-Object Severity, Check | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $jsonPath -Encoding UTF8
$script:Findings | Sort-Object Severity, Check | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

$summary = $script:Findings | Group-Object Severity | Sort-Object Name
Write-Host ""
Write-Host "Security audit completed."
foreach ($s in $summary) { Write-Host ("{0,-8} {1,5}" -f $s.Name, $s.Count) }
Write-Host "JSON report: $jsonPath"
Write-Host "CSV report : $csvPath"
