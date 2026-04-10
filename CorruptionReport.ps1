#Requires -RunAsAdministrator
#Requires -Version 7.2

<#
.SYNOPSIS
    Scans CBS/CSI-relevant registry hives for Unicode corruption and backs them up.

.DESCRIPTION
    Backs up HKLM\SOFTWARE and HKLM\COMPONENTS to a timestamped directory, then
    iterates the target hive paths looking for key names, value names, and string
    value data that contain characters illegal in the Windows registry / CBS store.
    Results are written to a CSV (and optionally JSON) in the backup directory.

.PARAMETER Targets
    One or more HKLM registry paths to scan. Defaults to the CBS-relevant paths.

.PARAMETER OutputDir
    Root directory under which the timestamped backup folder is created.
    Defaults to C:\.

.PARAMETER Json
    When specified, also exports the full report as a JSON file alongside the CSV.

.PARAMETER SkipBackup
    Skip the registry export step (useful when re-running after a recent backup).

.EXAMPLE
    .\CorruptionReport.ps1

.EXAMPLE
    .\CorruptionReport.ps1 -Json -Verbose

.EXAMPLE
    .\CorruptionReport.ps1 -Targets 'HKLM\COMPONENTS' -SkipBackup
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]] $Targets = @(
        'HKLM\COMPONENTS',
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
    ),

    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string] $OutputDir = 'C:\',

    [switch] $Json,
    [switch] $SkipBackup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helpers ──────────────────────────────────────────────────────────────────

# Characters legal in Windows registry / BMP XML: TAB, LF, CR, U+0020–U+D7FF, U+E000–U+FFFD
$script:BadCharPattern = [regex]'[^\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD]'

function Test-HasIllegalChars {
    param([AllowNull()][AllowEmptyString()][string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return $script:BadCharPattern.IsMatch($Text)
}

function Open-HklmSubKey {
    param([string] $SubPath)
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubPath)
    if (-not $key) { throw "Cannot open HKLM\$SubPath" }
    return $key
}

# ── Backup ───────────────────────────────────────────────────────────────────

$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$bkDir  = Join-Path $OutputDir "CBSDebug_$stamp"

if (-not $SkipBackup) {
    Write-Verbose "Creating backup directory: $bkDir"
    New-Item -ItemType Directory -Path $bkDir -Force | Out-Null

    foreach ($hive in 'SOFTWARE', 'COMPONENTS') {
        $dest = Join-Path $bkDir "${hive}_${stamp}.reg"
        Write-Verbose "Exporting HKLM\$hive → $dest"
        if ($PSCmdlet.ShouldProcess("HKLM\$hive", "reg export")) {
            $null = reg export "HKLM\$hive" $dest /y 2>&1
        }
    }
} else {
    Write-Warning 'Backup skipped (-SkipBackup). Using existing OutputDir for reports.'
    New-Item -ItemType Directory -Path $bkDir -Force | Out-Null
}

# ── Scanner ──────────────────────────────────────────────────────────────────

function Find-CBSStoreCorruption {
    [CmdletBinding()]
    param([string] $RootKeyPath)

    if ($RootKeyPath -notmatch '^HKLM\\(?<hive>[^\\]+)(?:\\(?<sub>.+))?$') {
        throw "Path must start with HKLM\<Hive>[\<SubKey>]: $RootKeyPath"
    }

    $hive   = $Matches['hive']
    $subKey = $Matches['sub']

    $root = Open-HklmSubKey $(if ($subKey) { "$hive\$subKey" } else { $hive })

    $suspects = [System.Collections.Concurrent.ConcurrentBag[pscustomobject]]::new()
    $stack    = [System.Collections.Generic.Stack[Microsoft.Win32.RegistryKey]]::new()
    $stack.Push($root)

    Write-Verbose "Scanning: $RootKeyPath"

    while ($stack.Count) {
        $key = $stack.Pop()

        try {
            $fullName = $key.Name

            # Key name
            if (Test-HasIllegalChars $fullName) {
                $suspects.Add([pscustomobject]@{
                    Type      = 'KeyName'
                    Key       = $fullName
                    ValueName = $null
                    Value     = $null
                })
            }

            # Value names and string data
            foreach ($valueName in $key.GetValueNames()) {
                if (Test-HasIllegalChars $valueName) {
                    $suspects.Add([pscustomobject]@{
                        Type      = 'ValueName'
                        Key       = $fullName
                        ValueName = $valueName
                        Value     = $null
                    })
                }

                $data = $key.GetValue($valueName)
                if ($data -is [string] -and (Test-HasIllegalChars $data)) {
                    $suspects.Add([pscustomobject]@{
                        Type      = 'ValueData'
                        Key       = $fullName
                        ValueName = $valueName
                        Value     = $data
                    })
                }
            }

            # Recurse into sub-keys
            foreach ($childName in $key.GetSubKeyNames()) {
                if (Test-HasIllegalChars $childName) {
                    $suspects.Add([pscustomobject]@{
                        Type      = 'SubkeyName'
                        Key       = "$fullName\$childName"
                        ValueName = $null
                        Value     = $null
                    })
                }
                $child = $key.OpenSubKey($childName)
                if ($child) { $stack.Push($child) }
            }
        } catch {
            Write-Verbose "  [SKIP] $($key.Name): $_"
        }
    }

    [pscustomobject]@{
        Root     = $RootKeyPath
        Suspects = $suspects.ToArray()
        Count    = $suspects.Count
    }
}

# ── Run ──────────────────────────────────────────────────────────────────────

Write-Host "$($PSStyle.Bold)Scanning $($Targets.Count) target(s)…$($PSStyle.Reset)"

$results = $Targets | ForEach-Object -ThrottleLimit 4 -Parallel {
    # Re-import helpers in parallel runspace
    $script:BadCharPattern = [regex]'[^\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD]'

    function Test-HasIllegalChars {
        param([AllowNull()][AllowEmptyString()][string] $Text)
        if ([string]::IsNullOrEmpty($Text)) { return $false }
        return $script:BadCharPattern.IsMatch($Text)
    }

    function Open-HklmSubKey {
        param([string] $SubPath)
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubPath)
        if (-not $key) { throw "Cannot open HKLM\$SubPath" }
        return $key
    }

    $RootKeyPath = $_

    if ($RootKeyPath -notmatch '^HKLM\\(?<hive>[^\\]+)(?:\\(?<sub>.+))?$') {
        throw "Invalid path: $RootKeyPath"
    }

    $hive   = $Matches['hive']
    $subKey = $Matches['sub']
    $root   = Open-HklmSubKey $(if ($subKey) { "$hive\$subKey" } else { $hive })

    $suspects = [System.Collections.Generic.List[pscustomobject]]::new()
    $stack    = [System.Collections.Generic.Stack[Microsoft.Win32.RegistryKey]]::new()
    $stack.Push($root)

    while ($stack.Count) {
        $key = $stack.Pop()
        try {
            $fullName = $key.Name

            if (Test-HasIllegalChars $fullName) {
                $suspects.Add([pscustomobject]@{ Type='KeyName'; Key=$fullName; ValueName=$null; Value=$null })
            }

            foreach ($vn in $key.GetValueNames()) {
                if (Test-HasIllegalChars $vn) {
                    $suspects.Add([pscustomobject]@{ Type='ValueName'; Key=$fullName; ValueName=$vn; Value=$null })
                }
                $vv = $key.GetValue($vn)
                if ($vv -is [string] -and (Test-HasIllegalChars $vv)) {
                    $suspects.Add([pscustomobject]@{ Type='ValueData'; Key=$fullName; ValueName=$vn; Value=$vv })
                }
            }

            foreach ($cn in $key.GetSubKeyNames()) {
                if (Test-HasIllegalChars $cn) {
                    $suspects.Add([pscustomobject]@{ Type='SubkeyName'; Key="$fullName\$cn"; ValueName=$null; Value=$null })
                }
                $ck = $key.OpenSubKey($cn)
                if ($ck) { $stack.Push($ck) }
            }
        } catch {}
    }

    [pscustomobject]@{ Root = $RootKeyPath; Suspects = $suspects.ToArray(); Count = $suspects.Count }
}

# ── Output ───────────────────────────────────────────────────────────────────

$flat       = $results | ForEach-Object { $_.Suspects }
$csvPath    = Join-Path $bkDir "CBS_Corruption_Report_$stamp.csv"
$jsonPath   = Join-Path $bkDir "CBS_Corruption_Report_$stamp.json"

$flat | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

if ($Json) {
    $results | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "JSON report : $jsonPath"
}

# Per-target summary
$results | ForEach-Object {
    $color = if ($_.Count -gt 0) { $PSStyle.Foreground.Red } else { $PSStyle.Foreground.Green }
    Write-Host "  ${color}[$($_.Count) suspects]$($PSStyle.Reset)  $($_.Root)"
}

Write-Host ""
Write-Host "Total suspects : $($flat.Count)"
Write-Host "CSV report     : $csvPath"
Write-Host "Backup dir     : $bkDir"
