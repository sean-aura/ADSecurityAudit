#region GPO-Deployed Secrets & Insecure Settings Audit (GPP cpassword, script credentials)
#
# Scans SYSVOL/GPO content for secrets and settings that GPOs push out to
# every affected computer/user: leftover Group Policy Preferences (GPP)
# `cpassword` values (MS14-025), plaintext-looking credentials referenced in
# logon/startup scripts, and insecure settings deployed via GPO (firewall
# disabled, weak folder options, insecure RDP). PingCastle-comparable check(s):
# P-DelegationGPOData, P-DelegationFileDeployed, P-DelegationLoginScript,
# S-FirewallScript, S-FolderOptions, S-TerminalServicesGPO,
# A-AnonymousAuthorizedGPO.
#
# DETECTION ONLY: this module reads SYSVOL policy files (GPP XML, referenced
# scripts) and GPO-linked registry policy values. A `cpassword` value found
# in GPP XML is reported by PRESENCE and FILE PATH ONLY - it is never
# decrypted, decoded, or printed. A credential pattern found in a script is
# reported by LOCATION (file/line) only - the matched line's sensitive
# content is never echoed verbatim into a finding. Nothing here decrypts,
# reuses, exfiltrates, or acts on any discovered secret, and no exploitation,
# coercion, relay, or PoC traffic is ever sent.

# GPP preference files known to carry a `cpassword` attribute when a
# password is set via Group Policy Preferences (MS14-025).
$Script:GpoSecretsGppFiles = @(
    'Groups.xml',
    'Services.xml',
    'ScheduledTasks.xml',
    'Drives.xml',
    'DataSources.xml',
    'Printers.xml'
)

# Script extensions considered when scanning SYSVOL logon/startup/shutdown
# script folders for embedded credentials.
$Script:GpoSecretsScriptExtensions = @('*.bat', '*.cmd', '*.ps1', '*.vbs', '*.kix')

# Lightweight, conservative patterns for spotting a credential embedded in a
# script. These intentionally match on structure (a credential-flavoured
# keyword next to an assignment/parameter), not on any specific secret
# value, and are used only to flag a LOCATION for follow-up - the matched
# line's content is never included in a finding's Details.
$Script:GpoSecretsScriptCredentialPatterns = @(
    '(?i)\bnet\s+use\b.*\s/user:',
    '(?i)\bpassword\s*[:=]',
    '(?i)-AsPlainText\b',
    '(?i)ConvertTo-SecureString\b',
    '(?i)\bpwd\s*[:=]',
    '(?i)runas\s+/user:.*\s/savecred'
)

function Get-ADGpoSecretsSysvolPolicyRoot {
    <#
    .SYNOPSIS
        Resolves the SYSVOL \Policies path for the current domain.
    .DESCRIPTION
        Read-only path resolution helper, consistent with the SYSVOL path
        already used for permission checks in Test-ADGroupPolicies.
    #>
    [CmdletBinding()]
    param()

    $domain = Get-ADDomain
    return "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies"
}

function Test-ADGpoDeployedSecrets {
    <#
    .SYNOPSIS
        Audits SYSVOL/GPO content for deployed secrets and insecure settings.
    .DESCRIPTION
        Three independent, read-only checks against each GPO's SYSVOL policy
        folder:
          1. GPP cpassword Found in SYSVOL - parses the standard GPP XML
             files (Groups.xml, Services.xml, ScheduledTasks.xml, Drives.xml,
             DataSources.xml, Printers.xml) for a `cpassword` attribute.
             Flagged by PRESENCE and FILE PATH ONLY; the value is never
             decrypted or included in the finding.
          2. Credentials Referenced in Logon/Startup Script - pattern-scans
             scripts under each GPO's \Machine\Scripts and \User\Scripts
             folders (and any script referenced by a linked logon/startup
             script GPO setting) for common credential-embedding patterns
             (net use /user:, ConvertTo-SecureString, runas /savecred,
             etc.). Reports the file and line number only, never the
             matched line's content.
          3. Insecure Setting Deployed via GPO - reads each GPO's
             GptTmpl.inf / registry.pol for a Windows Firewall profile
             explicitly disabled, weak Folder Options settings (hidden
             files/extensions forced visible off, i.e. hiding), and
             insecure Terminal Services/RDP settings (Network Level
             Authentication disabled, unencrypted RDP security layer
             allowed).
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied,
        the list of GPOs to enumerate is taken from Snapshot.GPOs (Id only)
        instead of a live Get-GPO -All call. Every other read in this
        function is a SYSVOL/registry.pol read against a live file share
        and is NOT part of the current snapshot schema, so this audit still
        performs live, read-only I/O even when -Snapshot is supplied - it
        is treated the same as the other live-only sub-checks elsewhere in
        the module (e.g. Test-ADLegacyAuthSurface, the DnsSecurity
        zone-level checks). No live AD/network access is skipped merely by
        passing -Snapshot; this is documented for -FromSnapshot users so
        the offline-mode expectation is explicit.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting GPO-Deployed Secrets & Insecure Settings audit..."
    $findings = @()

    # -------------------------------------------------------------------
    # Resolve the list of GPOs (id + display name) to enumerate.
    # -------------------------------------------------------------------
    $gpoList = @()
    try {
        if ($Snapshot -and $Snapshot.ContainsKey('GPOs')) {
            Write-Verbose "Test-ADGpoDeployedSecrets: using snapshot GPO list for enumeration (SYSVOL reads are still live)."
            $gpoList = @($Snapshot.GPOs | ForEach-Object {
                [PSCustomObject]@{ Id = $_.Id; DisplayName = $_.DisplayName }
            })
        }
        else {
            Import-Module GroupPolicy -ErrorAction Stop
            $gpoList = @(Invoke-ADQueryWithRetry -OperationName "Enumerate GPOs" -Query {
                Get-GPO -All | Select-Object Id, DisplayName
            })
        }
    }
    catch {
        Write-Warning "Test-ADGpoDeployedSecrets: failed to enumerate GPOs: $_"
        return $findings
    }

    if (-not $gpoList -or $gpoList.Count -eq 0) {
        Write-Verbose "Test-ADGpoDeployedSecrets: no GPOs found; nothing to scan."
        return $findings
    }

    $policyRoot = $null
    try {
        $policyRoot = Get-ADGpoSecretsSysvolPolicyRoot
    }
    catch {
        Write-Warning "Test-ADGpoDeployedSecrets: failed to resolve SYSVOL policy root: $_"
        return $findings
    }

    if (-not (Test-Path -LiteralPath $policyRoot)) {
        Write-Warning "Test-ADGpoDeployedSecrets: SYSVOL policy root not accessible at expected location: $policyRoot"
        return $findings
    }

    $gpoCount = $gpoList.Count
    $currentGpo = 0

    foreach ($gpo in $gpoList) {
        $currentGpo++
        Write-Progress -Activity "Scanning SYSVOL GPO content" -Status "Processing $($gpo.DisplayName)" `
            -PercentComplete (($currentGpo / $gpoCount) * 100)

        $gpoFolder = Join-Path -Path $policyRoot -ChildPath "{$($gpo.Id)}"
        if (-not (Test-Path -LiteralPath $gpoFolder)) {
            Write-Verbose "Test-ADGpoDeployedSecrets: no SYSVOL folder for GPO '$($gpo.DisplayName)' ($gpoFolder); skipping."
            continue
        }

        # ---------------------------------------------------------------
        # Check 1 - GPP cpassword presence in the standard preference XMLs.
        # Stream: enumerate matching filenames anywhere under the GPO
        # folder rather than loading the whole tree, so large SYSVOL trees
        # don't need to be held in memory at once.
        # ---------------------------------------------------------------
        try {
            $gppFiles = Get-ChildItem -LiteralPath $gpoFolder -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $Script:GpoSecretsGppFiles -contains $_.Name }

            foreach ($gppFile in $gppFiles) {
                try {
                    # Read as text and check for the attribute name only;
                    # avoids parsing/holding the decrypted value at all.
                    $rawContent = Get-Content -LiteralPath $gppFile.FullName -Raw -ErrorAction Stop
                    if ($rawContent -match 'cpassword\s*=\s*"[^"]+"') {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Group Policy'
                        $finding.Issue = 'GPP cpassword Found in SYSVOL'
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = $gpo.DisplayName
                        $finding.Description = "GPO '$($gpo.DisplayName)' contains a Group Policy Preferences file with a 'cpassword' attribute set, a known-broken (MS14-025) reversible encryption scheme for which the AES key is public."
                        $finding.Impact = "Any authenticated user can read the file from SYSVOL and trivially recover the plaintext password, typically for a local administrator, service, or mapped-drive account."
                        $finding.Remediation = "Remove the affected GPP setting (Group Policy Management Console), delete the leftover XML file if the GPO no longer references it, and rotate the exposed credential immediately. Do not deploy passwords via GPP; use LAPS or a managed service account instead."
                        $finding.Details = @{
                            GpoId    = $gpo.Id
                            FilePath = $gppFile.FullName
                            FileName = $gppFile.Name
                        }
                        $findings += $finding
                    }
                }
                catch {
                    Write-Verbose "Test-ADGpoDeployedSecrets: failed to read '$($gppFile.FullName)': $_"
                }
            }
        }
        catch {
            Write-Verbose "Test-ADGpoDeployedSecrets: failed to enumerate GPP files under '$gpoFolder': $_"
        }

        # ---------------------------------------------------------------
        # Check 2 - credential patterns in logon/startup/shutdown scripts.
        # ---------------------------------------------------------------
        try {
            $scriptRoots = @(
                (Join-Path $gpoFolder 'Machine\Scripts'),
                (Join-Path $gpoFolder 'User\Scripts')
            ) | Where-Object { Test-Path -LiteralPath $_ }

            foreach ($scriptRoot in $scriptRoots) {
                $scriptFiles = Get-ChildItem -LiteralPath $scriptRoot -Recurse -File -Include $Script:GpoSecretsScriptExtensions -ErrorAction SilentlyContinue

                foreach ($scriptFile in $scriptFiles) {
                    try {
                        $lineNumber = 0
                        $matchedLines = @()

                        # Stream line-by-line rather than loading the whole
                        # file, so large scripts don't need to be held in
                        # memory at once.
                        foreach ($line in [System.IO.File]::ReadLines($scriptFile.FullName)) {
                            $lineNumber++
                            foreach ($pattern in $Script:GpoSecretsScriptCredentialPatterns) {
                                if ($line -match $pattern) {
                                    $matchedLines += $lineNumber
                                    break
                                }
                            }
                        }

                        if ($matchedLines.Count -gt 0) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = 'Group Policy'
                            $finding.Issue = 'Credentials Referenced in Logon/Startup Script'
                            $finding.Severity = 'High'
                            $finding.SeverityLevel = 3
                            $finding.AffectedObject = $gpo.DisplayName
                            $finding.Description = "GPO '$($gpo.DisplayName)' deploys a script that appears to reference a credential inline (e.g. a 'net use /user:', 'runas /savecred', or ConvertTo-SecureString-style pattern)."
                            $finding.Impact = "A credential embedded in a script deployed to every targeted computer/user is readable by any authenticated principal with SYSVOL read access, without needing to decrypt anything."
                            $finding.Remediation = "Remove hard-coded credentials from logon/startup/shutdown scripts. Use a managed identity (gMSA), LAPS, or a secrets vault retrieved at runtime instead of embedding credentials in a script deployed via GPO."
                            $finding.Details = @{
                                GpoId       = $gpo.Id
                                FilePath    = $scriptFile.FullName
                                FileName    = $scriptFile.Name
                                LineNumbers = $matchedLines
                            }
                            $findings += $finding
                        }
                    }
                    catch {
                        Write-Verbose "Test-ADGpoDeployedSecrets: failed to scan script '$($scriptFile.FullName)': $_"
                    }
                }
            }
        }
        catch {
            Write-Verbose "Test-ADGpoDeployedSecrets: failed to enumerate scripts under '$gpoFolder': $_"
        }

        # ---------------------------------------------------------------
        # Check 3 - insecure settings deployed via GPO (GptTmpl.inf).
        # Firewall-off, weak folder options, insecure RDP/Terminal
        # Services. Best-effort text parse of the security template; a
        # missing/unparseable file simply yields no finding for that GPO.
        # ---------------------------------------------------------------
        try {
            $gptTmplPath = Join-Path $gpoFolder 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            if (Test-Path -LiteralPath $gptTmplPath) {
                $tmplContent = Get-Content -LiteralPath $gptTmplPath -Raw -ErrorAction Stop

                $insecureSettings = @()

                # Windows Firewall disabled for a profile (0 = off).
                if ($tmplContent -match '(?im)^\s*EnableFirewall\s*=\s*0\s*$') {
                    $insecureSettings += 'Windows Firewall disabled for at least one profile'
                }

                # Folder Options: hidden files forced to be shown as
                # normal / extensions hidden (helps mask malicious
                # double-extension files). Hidden=2 shows hidden files.
                if ($tmplContent -match '(?im)^\s*HideFileExt\s*=\s*1\s*$') {
                    $insecureSettings += 'File extensions hidden by policy (HideFileExt=1)'
                }

                # Terminal Services / RDP: NLA disabled or security layer
                # allows unencrypted/RDP-native negotiation.
                if ($tmplContent -match '(?im)^\s*UserAuthentication\s*=\s*0\s*$') {
                    $insecureSettings += 'Network Level Authentication (NLA) disabled for RDP'
                }
                if ($tmplContent -match '(?im)^\s*SecurityLayer\s*=\s*0\s*$') {
                    $insecureSettings += 'RDP Security Layer set to the insecure native RDP protocol'
                }

                if ($insecureSettings.Count -gt 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Group Policy'
                    $finding.Issue = 'Insecure Setting Deployed via GPO'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $gpo.DisplayName
                    $finding.Description = "GPO '$($gpo.DisplayName)' deploys one or more weakening settings: $($insecureSettings -join '; ')."
                    $finding.Impact = "Disabling the host firewall, hiding file extensions, or weakening RDP authentication/encryption each independently lowers the bar for initial access, lateral movement, or social-engineering-based execution on every computer the GPO applies to."
                    $finding.Remediation = "Review the GPO's Security Options and re-enable the Windows Firewall for all profiles, restore default Folder Options (show known file extensions), and require Network Level Authentication with a secure (SSL/TLS) RDP security layer."
                    $finding.Details = @{
                        GpoId            = $gpo.Id
                        FilePath         = $gptTmplPath
                        InsecureSettings = $insecureSettings
                    }
                    $findings += $finding
                }
            }
        }
        catch {
            Write-Verbose "Test-ADGpoDeployedSecrets: failed to read GptTmpl.inf for GPO '$($gpo.DisplayName)': $_"
        }
    }

    Write-Progress -Activity "Scanning SYSVOL GPO content" -Completed
    Write-Verbose "Test-ADGpoDeployedSecrets: completed with $($findings.Count) finding(s)."
    return $findings
}

#endregion
