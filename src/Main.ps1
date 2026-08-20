#region Main Audit Function

function Start-ADSecurityAudit {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ExportPath = ".",
        
        [Parameter()]
        [int]$InactiveDaysThreshold = 90,
        
        [Parameter()]
        [int]$PasswordAgeThreshold = 180,
        
        [Parameter()]
        [string[]]$IncludeTests,
        
        [Parameter()]
        [string[]]$ExcludeTests = @(),
        
        [Parameter()]
        [switch]$IncludePrivilegedUsersReport,

        # Multi-domain-forest override: forces every AD query in this run
        # (domain lookup, DC discovery, and every audit test) to explicitly
        # target this domain/DC rather than letting the AD module's default
        # "serverless" bind resolve against the invoking account's own
        # logon domain. Accepts a domain FQDN (e.g. 'domainb.corp.com') or
        # a specific DC FQDN/hostname (e.g. 'dc01.domainb.corp.com').
        # DEFAULT WHEN OMITTED: the current user's own domain
        # ($env:USERDNSDOMAIN) - not the machine's joined domain - is used
        # automatically, so the common case ("audit my own domain") no
        # longer depends on the AD module's ambient resolution at all. Pass
        # -Server explicitly only when you need to target a domain OTHER
        # than your own account's domain (e.g. auditing Domain B while
        # logged in as a Domain A account), or when running under
        # alternate credentials via `runas /netonly` (see
        # Resolve-ADSecurityAuditTargetServer in Common.ps1 for why the
        # default can't reliably detect that case on its own). Ignored
        # (with a warning) if combined with -FromSnapshot, since that mode
        # performs no live AD access at all.
        [Parameter()]
        [string]$Server,

        # Added in v1.3.0 (collect-once snapshot contract, see
        # docs/features/02-domain-snapshot.md). Path to a JSON snapshot
        # produced by Get-ADSnapshot -ToJson. When supplied, the audit is
        # re-run offline against that snapshot via Invoke-ADRuleSet instead
        # of querying AD live - no live AD access is performed.
        [Parameter()]
        [string]$FromSnapshot,

        # As of v1.19.0, all 27 registered tests declare -Snapshot support
        # (fully or partially - see Invoke-ADRuleSet's help for the small
        # number of remaining live-only sub-checks). This switch/skip
        # mechanism remains in place for any future new test that hasn't
        # been retrofitted yet, so by default -FromSnapshot SKIPS an
        # unsupported test rather than silently falling back to live
        # queries, to honor the "no live AD access" contract above. Pass
        # this switch to restore the old behaviour and run those tests live
        # alongside the offline ones.
        [Parameter()]
        [switch]$AllowLiveFallbackForUnsupportedTests
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $effectiveServer = $null

    # Fixed: -ExportPath (e.g. ".\foldername") was passed straight into
    # Join-Path/[System.IO.File]::WriteAllText below while still relative.
    # See Resolve-ADSecurityAuditPath in Common.ps1 for the full
    # explanation - short version: a later raw .NET write-test call
    # resolves relative paths differently than the PowerShell cmdlets
    # above it do, so a perfectly valid relative -ExportPath could
    # silently be checked against the wrong directory and throw "Export
    # path is not writable". Resolving to an absolute path up front (pure
    # string computation, doesn't require the path to exist) avoids that
    # entirely, and makes every downstream Join-Path/New-Item/Write-Host
    # message operate on (and print) an unambiguous absolute path.
    try {
        $ExportPath = Resolve-ADSecurityAuditPath -Path $ExportPath
    }
    catch {
        Write-Error "Could not resolve -ExportPath '$ExportPath' to an absolute path: $_"
        return
    }

    # Reset the offline-skip-note tracker (v1.19.1) so notes from a
    # previous Start-ADSecurityAudit call in the same PowerShell session
    # never leak into this run's HTML report.
    Reset-ADOfflineSkipNotes
    
    if (-not (Test-Path $ExportPath)) {
        try {
            Write-Verbose "Start-ADSecurityAudit: export path '$ExportPath' does not exist; creating it..."
            New-Item -Path $ExportPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error "Export path does not exist and could not be created: $ExportPath. Error: $_"
            return
        }
    }
    
    $testFile = Join-Path $ExportPath "test_write_$(Get-Random).tmp"
    try {
        [System.IO.File]::WriteAllText($testFile, "test")
        Remove-Item $testFile -Force
    }
    catch {
        Write-Error "Export path is not writable: $ExportPath. Error: $_"
        return
    }
    
    $logPath = Join-Path $ExportPath "ADSecurityAudit_Log_$timestamp.txt"
    Start-Transcript -Path $logPath -Force
    
    try {
        $startTime = Get-Date
        Write-Host "`n==================================================" -ForegroundColor Cyan
        Write-Host "Active Directory Security Assessment" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "Start Time: $startTime`n" -ForegroundColor Gray
        
        if ($FromSnapshot) {
            if ($Server) {
                Write-Warning "-Server '$Server' was supplied together with -FromSnapshot; ignoring it, since offline/-FromSnapshot mode performs no live AD access."
            }
            # --- Offline re-analysis path (v1.3.0): no live AD access ---
            Write-Host "Offline mode: re-analysing snapshot '$FromSnapshot' (no live AD access)`n" -ForegroundColor Cyan

            if (-not (Test-Path $FromSnapshot)) {
                Write-Error "Snapshot file not found: $FromSnapshot"
                return
            }

            try {
                $rawSnapshot = Get-Content -Path $FromSnapshot -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $snapshot = ConvertTo-ADHashtable -InputObject $rawSnapshot
            }
            catch {
                Write-Error "Failed to load snapshot from '$FromSnapshot': $_"
                return
            }

            $domain = $snapshot.Domain
            if (-not $domain) {
                Write-Error "Snapshot '$FromSnapshot' does not contain domain information; cannot proceed."
                return
            }

            Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Green
            Write-Host "Domain DN: $($domain.DistinguishedName)`n" -ForegroundColor Green
            Write-Host "Snapshot collected: $($snapshot.CollectedDate)`n" -ForegroundColor Gray

            # Determine which tests to run (same semantics as live mode).
            if ($IncludeTests) {
                $testsToRun = $Script:ADTestFunctionRegistry.Keys | Where-Object { $_ -in $IncludeTests -and $_ -notin $ExcludeTests }
            }
            else {
                $testsToRun = $Script:ADTestFunctionRegistry.Keys | Where-Object { $_ -notin $ExcludeTests }
            }

            if (-not $AllowLiveFallbackForUnsupportedTests) {
                $unsupportedTests = @($testsToRun | Where-Object {
                    $fn = Get-Command -Name $Script:ADTestFunctionRegistry[$_] -ErrorAction SilentlyContinue
                    $fn -and -not $fn.Parameters.ContainsKey('Snapshot')
                })
                if ($unsupportedTests.Count -gt 0) {
                    Write-Host "Note: $($unsupportedTests.Count) test(s) have no offline/-Snapshot support yet and will be skipped (no live AD access performed): $($unsupportedTests -join ', ')" -ForegroundColor Yellow
                    Write-Host "Pass -AllowLiveFallbackForUnsupportedTests to run them live instead.`n" -ForegroundColor Yellow
                }
            }

            Write-Host "Running $($testsToRun.Count) test(s) via Invoke-ADRuleSet...`n" -ForegroundColor Yellow
            $allFindings = @(Invoke-ADRuleSet -Snapshot $snapshot -IncludeTests $testsToRun `
                -InactiveDaysThreshold $InactiveDaysThreshold -PasswordAgeThreshold $PasswordAgeThreshold `
                -AllowLiveFallbackForUnsupportedTests:$AllowLiveFallbackForUnsupportedTests)

            $skipNotesForConsole = @(Get-ADOfflineSkipNotes)
            if ($skipNotesForConsole.Count -gt 0) {
                $stillLiveCountForConsole = @($skipNotesForConsole | Where-Object { $_.Mode -eq 'StillLive' }).Count
                $skippedCountForConsole = $skipNotesForConsole.Count - $stillLiveCountForConsole
                Write-Host "Offline coverage note: $skippedCountForConsole sub-check(s) skipped, $stillLiveCountForConsole sub-check(s) still ran live - see the HTML report's 'Offline Mode Coverage Notes' section for the full breakdown.`n" -ForegroundColor Yellow
            }

            if ($IncludePrivilegedUsersReport) {
                Write-Warning "IncludePrivilegedUsersReport requires live AD access and is not available in -FromSnapshot mode; skipping."
            }
            $privilegedUsers = $null
        }
        else {
        # Verify AD module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Error "Active Directory PowerShell module is not installed. Please install RSAT tools."
            return
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop

        # Resolve the effective server: the explicit -Server value if one
        # was passed, otherwise the current user's own domain
        # ($env:USERDNSDOMAIN) by default rather than leaving "no -Server"
        # ambient/ambiguous - see Resolve-ADSecurityAuditTargetServer for
        # why. $effectiveServer is $null only when neither is available
        # (e.g. a local, non-domain logon session), in which case behavior
        # is unchanged from before this feature existed.
        $effectiveServer = Resolve-ADSecurityAuditTargetServer -Server $Server

        # Multi-domain-forest override (see -Server param comment above):
        # installs a -Server default for every Get-AD*/Set-AD* call made
        # anywhere in this run - not just the two calls immediately below,
        # but every audit test's own Get-ADDomain/Get-ADObject/Get-ADUser/
        # Get-ADComputer/etc. calls too - so the whole run targets the
        # domain the operator specified (or their own domain, by default)
        # instead of whatever domain the invoking account's default AD
        # binding would otherwise resolve to. Always cleared in the outer
        # finally block below, so it never leaks into a later
        # Start-ADSecurityAudit call in the same session.
        if ($effectiveServer) {
            $serverSource = if ($Server) { 'explicit -Server' } else { "your own domain, `$env:USERDNSDOMAIN" }
            Write-Host "Server override: forcing all AD queries to target '$effectiveServer' ($serverSource)`n" -ForegroundColor Cyan
            Set-ADSecurityAuditTargetServer -Server $effectiveServer
        }

        Write-Verbose "Testing Domain Controller connectivity..."
        try {
            $domainParams = @{ ErrorAction = 'Stop' }
            if ($effectiveServer) { $domainParams['Server'] = $effectiveServer }
            $domain = Get-ADDomain @domainParams

            # Attempt to discover multiple DCs for failover
            $domainControllers = @()
            try {
                # Get-ADSecurityAuditDomainController (Common.ps1), not a
                # bare Get-ADDomainController -Filter *: the latter queries
                # the forest-wide Configuration container and returns every
                # domain's DCs regardless of -Server, which could silently
                # hand $connectedDC below a DC from the WRONG domain even
                # with an active -Server override.
                $domainControllers = Get-ADSecurityAuditDomainController -Server $effectiveServer | Select-Object -First 3
            }
            catch {
                Write-Verbose "Could not enumerate all DCs, falling back to discovery: $_"
            }

            if (-not $domainControllers -or $domainControllers.Count -eq 0) {
                if ($effectiveServer) {
                    # An override is active (explicit or the user-domain
                    # default): do NOT fall back to -Discover here. DC
                    # Locator's -Discover uses subnet/site mapping (or the
                    # caller's own logon domain) to pick a DC, which is the
                    # exact "resolves to the wrong domain" behavior the
                    # override exists to bypass. Resolve directly against
                    # the requested target instead.
                    $domainControllers = @(Get-ADDomainController -Identity $effectiveServer -Server $effectiveServer -ErrorAction Stop)
                }
                else {
                    $domainControllers = @(Get-ADDomainController -Discover -ErrorAction Stop)
                }
            }

            # Find a reachable DC
            $connectedDC = $null
            foreach ($dc in $domainControllers) {
                Write-Verbose "Testing connectivity to DC: $($dc.HostName)"
                if (Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet) {
                    $connectedDC = $dc
                    Write-Verbose "Successfully connected to Domain Controller: $($dc.HostName)"
                    break
                }
                else {
                    Write-Verbose "Cannot reach Domain Controller: $($dc.HostName)"
                }
            }

            if (-not $connectedDC) {
                Write-Warning "Cannot reach any discovered Domain Controllers. Proceeding with default DC..."
                $connectedDC = $domainControllers[0]
            }

            $dc = $connectedDC
        }
        catch {
            Write-Error "Failed to connect to Active Directory Domain: $_"
            return
        }
        
        Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Green
        Write-Host "Domain DN: $($domain.DistinguishedName)`n" -ForegroundColor Green
        
        # Define all tests - including the new DomainAdminEquivalence test
        $allTests = @{
            'UserAccounts' = { Test-ADUserSecurity -InactiveDaysThreshold $InactiveDaysThreshold -PasswordAgeThreshold $PasswordAgeThreshold }
            'PrivilegedGroups' = { Test-ADPrivilegedGroups }
            'AdminSDHolder' = { Test-AdminSDHolder }
            'GroupPolicies' = { Test-ADGroupPolicies }
            'ReplicationSecurity' = { Test-ADReplicationSecurity }
            'DomainSecurity' = { Test-ADDomainSecurity }
            'DangerousPermissions' = { Test-ADDangerousPermissions }
            'CertificateServices' = { Test-ADCertificateServices }
            'ADCSExtended' = { Test-ADCSExtended }
            'KRBTGTAccount' = { Test-KRBTGTAccount -MaxPasswordAgeDays 180 }
            'DomainTrusts' = { Test-ADDomainTrusts }
            'LAPSDeployment' = { Test-LAPSDeployment }
            'AuditPolicyConfiguration' = { Test-AuditPolicyConfiguration }
            'ConstrainedDelegation' = { Test-ConstrainedDelegation }
            'DomainAdminEquivalence' = { Test-ADDomainAdminEquivalence }
            'MachineAccountQuota' = { Test-ADMachineAccountQuota -Server $effectiveServer }
            'DomainHardeningFlags' = { Test-ADDomainHardeningFlags }
            'CoercionAndRelayExposure' = { Test-ADCoercionAndRelayExposure }
            'DnsSecurity' = { Test-ADDnsSecurity }
            'LegacyAuthSurface' = { Test-ADLegacyAuthSurface }
            'KerberosHardening' = { Test-ADKerberosHardening }
            'StaleObjectDepth' = { Test-ADStaleObjectDepth }
            'GpoDeployedSecrets' = { Test-ADGpoDeployedSecrets }
            'KnownDCVulnerabilities' = { Test-ADKnownDCVulnerabilities }
            'ExchangeEscalation' = { Test-ADExchangeEscalation }
            'RodcSecurity' = { Test-ADRodcSecurity }
            'ControlPaths' = { Test-ADControlPaths }
        }
        
        # Determine which tests to run
        if ($IncludeTests) {
            $testsToRun = $allTests.Keys | Where-Object { $_ -in $IncludeTests -and $_ -notin $ExcludeTests }
        }
        else {
            $testsToRun = $allTests.Keys | Where-Object { $_ -notin $ExcludeTests }
        }
        
        # Run tests and collect findings
        $allFindings = @()
        $totalTestCount = @($testsToRun).Count
        $currentTestIndex = 0
        
        foreach ($testName in $testsToRun) {
            $currentTestIndex++
            Write-Progress -Activity "Running Active Directory Security Audit" `
                -Status "Test $currentTestIndex of $totalTestCount`: $testName" `
                -PercentComplete (($currentTestIndex / [math]::Max(1, $totalTestCount)) * 100)
            Write-Host "Running test: $testName..." -ForegroundColor Yellow
            
            try {
                $testResults = & $allTests[$testName]
                
                # Handle both ADSecurityFinding objects and PSCustomObject (from DomainAdminEquivalence)
                if ($testResults) {
                    foreach ($result in $testResults) {
                        # Convert PSCustomObject to ADSecurityFinding if needed
                        if ($result -is [PSCustomObject] -and $result -isnot [ADSecurityFinding]) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = $result.Category
                            $finding.Issue = $result.Issue
                            $finding.Severity = $result.Severity
                            $finding.SeverityLevel = if ($result.SeverityLevel) { $result.SeverityLevel } else {
                                switch ($result.Severity) {
                                    'Critical' { 4 }
                                    'High' { 3 }
                                    'Medium' { 2 }
                                    'Low' { 1 }
                                    default { 0 }
                                }
                            }
                            $finding.AffectedObject = $result.AffectedObject
                            $finding.Description = $result.Description
                            $finding.Impact = $result.Impact
                            $finding.Remediation = $result.Remediation
                            $finding.Details = if ($result.Details) { $result.Details } else { @{} }
                            $allFindings += $finding
                        }
                        else {
                            $allFindings += $result
                        }
                    }
                }
                
                $criticalCount = ($testResults | Where-Object { $_.Severity -eq 'Critical' }).Count
                $highCount = ($testResults | Where-Object { $_.Severity -eq 'High' }).Count
                $mediumCount = ($testResults | Where-Object { $_.Severity -eq 'Medium' }).Count
                $lowCount = ($testResults | Where-Object { $_.Severity -eq 'Low' }).Count
                
                Write-Host "  Found: $criticalCount Critical, $highCount High, $mediumCount Medium, $lowCount Low`n" -ForegroundColor Gray
            }
            catch {
                Write-Warning "Test '$testName' failed: $_"
            }
        }
        
        Write-Progress -Activity "Running Active Directory Security Audit" -Completed
        
        # Enumerate privileged users if requested
        $privilegedUsers = $null
        if ($IncludePrivilegedUsersReport) {
            Write-Host "Enumerating privileged users..." -ForegroundColor Yellow
            try {
                $privilegedUsers = Get-ADPrivilegedUsers
                Write-Host "  Found: $($privilegedUsers.Count) privileged users`n" -ForegroundColor Gray
            }
            catch {
                Write-Warning "Failed to enumerate privileged users: $_"
            }
        }
        }
        
        $endTime = Get-Date
        $duration = $endTime - $startTime

        # Defensive: flatten $allFindings before ANY consumer touches it -
        # including the summary counts just below. A jagged/nested array -
        # a top-level element that is itself a sub-array of several
        # findings, rather than one - can slip in above if any invoked
        # test scriptblock emits more than one array to its own output
        # pipeline (the assembly loop's `else` branch then appends that
        # whole array as a single nested element instead of spreading it
        # into individual findings). Left unflattened, the summary counts
        # below would silently undercount (Where-Object can't see into a
        # nested array element's .Severity), and Set-ADFindingMetadata
        # further down - which has a strongly-typed
        # [ADSecurityFinding]$Finding parameter - throws "Cannot process
        # argument transformation on parameter 'Finding'" the moment its
        # tagging loop reaches such an element, failing after
        # Stop-Transcript has already run in the finally block and before
        # any report file is written. Get-ADRiskScore/Get-ADRetestComparison
        # already defend against this on their own inputs via this same
        # helper; applying it here, immediately after assembly, protects
        # every downstream consumer instead of just scoring.
        $allFindings = ConvertTo-ADFlatFindingsArray -Findings $allFindings
        
        # Generate summary
        Write-Host "`n==================================================" -ForegroundColor Cyan
        Write-Host "Audit Summary" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        
        $summary = @{
            Critical = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
            High = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
            Medium = ($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
            Low = ($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
        }

        # Tag every finding with MITRE / ANSSI / Weight from the central mapping
        # table so findings are born score/MITRE-aware (v1.2.0 contract layer).
        foreach ($finding in $allFindings) {
            [void](Set-ADFindingMetadata -Finding $finding)
        }

        # Compute the risk score, per-category sub-scores, and ANSSI maturity.
        $riskScore = Get-ADRiskScore -Findings $allFindings
        
        Write-Host "Total Findings: $($allFindings.Count)" -ForegroundColor White
        Write-Host "  Critical: $($summary.Critical)" -ForegroundColor Red
        Write-Host "  High: $($summary.High)" -ForegroundColor DarkRed
        Write-Host "  Medium: $($summary.Medium)" -ForegroundColor Yellow
        Write-Host "  Low: $($summary.Low)" -ForegroundColor Gray

        Write-Host "`nRisk Score: $($riskScore.TotalScore)/100 (higher = worse)" -ForegroundColor White
        Write-Host "ANSSI Maturity: $($riskScore.MaturityLabel)" -ForegroundColor White
        if ($riskScore.CategoryScores -and $riskScore.CategoryScores.Count -gt 0) {
            $worst = $riskScore.CategoryScores[0]
            Write-Host "Worst Category: $($worst.Category) ($($worst.Score)/100)" -ForegroundColor Gray
        }
        
        if ($privilegedUsers) {
            Write-Host "`nPrivileged Users: $($privilegedUsers.Count)" -ForegroundColor White
        }
        
        Write-Host "`nDuration: $($duration.TotalSeconds) seconds" -ForegroundColor Gray
        
        # Export results
        if ($allFindings.Count -gt 0) {
            Write-Progress -Activity "Exporting Audit Reports" -Status "Writing JSON report..." -PercentComplete 10

            # Export to JSON
            $jsonPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.json"
            $allFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            Write-Host "`nDetailed report exported to: $jsonPath" -ForegroundColor Green
            
            # Export to HTML
            Write-Progress -Activity "Exporting Audit Reports" -Status "Building HTML report..." -PercentComplete 40
            $htmlPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.html"
            $reportRunMode = if ($FromSnapshot) { 'Offline (Snapshot)' } else { 'Live' }
            $reportSnapshotCollectedDate = $null
            if ($FromSnapshot -and $snapshot.CollectedDate) {
                # CollectedDate may come back as [string] after the JSON
                # round-trip (-ToJson / -FromSnapshot); coerce defensively
                # rather than letting a bad string fail parameter binding.
                $reportSnapshotCollectedDate = if ($snapshot.CollectedDate -is [datetime]) {
                    $snapshot.CollectedDate
                }
                else {
                    try { [datetime]$snapshot.CollectedDate } catch { $null }
                }
            }
            $offlineSkipNotes = @(Get-ADOfflineSkipNotes)
            Export-ADSecurityReportHTML -Findings $allFindings -OutputPath $htmlPath -Domain $domain.DNSRoot -Summary $summary -Duration $duration -PrivilegedUsers $privilegedUsers -RiskScore $riskScore -RunMode $reportRunMode -SnapshotCollectedDate $reportSnapshotCollectedDate -OfflineSkipNotes $offlineSkipNotes
            Write-Host "HTML report exported to: $htmlPath" -ForegroundColor Green
            
            # Export to CSV with formula injection protection
            # NOTE (output contract): existing columns are never reordered or
            # removed. New flat fields are APPENDED after DetectedDate.
            #
            # SeverityLevel and Details were previously missing entirely from
            # this Select-Object list despite existing on every finding (and
            # therefore in the JSON export) - the CSV silently carried less
            # information than the JSON it's supposed to be a flat view of.
            # Appended at the end (after Weight, the last existing column)
            # rather than inserted after DetectedDate, so this fix itself
            # doesn't reorder/renumber any pre-existing column a downstream
            # consumer may reference positionally.
            Write-Progress -Activity "Exporting Audit Reports" -Status "Writing CSV report..." -PercentComplete 70
            $csvPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.csv"
            $allFindings | Select-Object Category, Issue, Severity, AffectedObject, Description, Impact, Remediation, DetectedDate, MitreTechnique, AnssiControl, Weight, SeverityLevel, Details |
                ForEach-Object {
                    [PSCustomObject]@{
                        Category = $_.Category | ConvertTo-SafeCsvValue
                        Issue = $_.Issue | ConvertTo-SafeCsvValue
                        Severity = $_.Severity | ConvertTo-SafeCsvValue
                        AffectedObject = $_.AffectedObject | ConvertTo-SafeCsvValue
                        Description = $_.Description | ConvertTo-SafeCsvValue
                        Impact = $_.Impact | ConvertTo-SafeCsvValue
                        Remediation = $_.Remediation | ConvertTo-SafeCsvValue
                        DetectedDate = $_.DetectedDate
                        MitreTechnique = $_.MitreTechnique | ConvertTo-SafeCsvValue
                        AnssiControl = $_.AnssiControl | ConvertTo-SafeCsvValue
                        Weight = $_.Weight
                        SeverityLevel = $_.SeverityLevel
                        # Compact JSON string, not a native CSV column-per-key -
                        # Details is an open-ended per-check hashtable (different
                        # keys per Issue), so there's no fixed column set to
                        # flatten it into without the schema changing per-check.
                        # Still sanitized against formula injection like every
                        # other free-text column.
                        Details = ($_.Details | ConvertTo-Json -Compress -Depth 5) | ConvertTo-SafeCsvValue
                    }
                } |
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "CSV report exported to: $csvPath" -ForegroundColor Green

            # Export the score / maturity / MITRE roll-up as a sidecar JSON so
            # the summary does not pollute the per-finding CSV/JSON schema.
            $scorePath = Join-Path $ExportPath "AD_Security_Score_$timestamp.json"
            $riskScore | ConvertTo-Json -Depth 6 | Out-File -FilePath $scorePath -Encoding UTF8
            Write-Host "Score summary exported to: $scorePath" -ForegroundColor Green
        }
        
        # Export privileged users report with formula injection protection
        if ($privilegedUsers -and $privilegedUsers.Count -gt 0) {
            $privilegedUsersCsvPath = Join-Path $ExportPath "AD_Privileged_Users_$timestamp.csv"

            $privilegedUsers | Select-Object SamAccountName, DisplayName, UserPrincipalName, Enabled, PasswordLastSet, `
                PasswordNeverExpires, LastLogonDate, AdminCount, PrivilegedGroupsString, Title, Department, `
                DoesNotRequirePreAuth, TrustedForDelegation, HasSPN, SPNCount |
                ForEach-Object {
                    [PSCustomObject]@{
                        SamAccountName = $_.SamAccountName | ConvertTo-SafeCsvValue
                        DisplayName = $_.DisplayName | ConvertTo-SafeCsvValue
                        UserPrincipalName = $_.UserPrincipalName | ConvertTo-SafeCsvValue
                        Enabled = $_.Enabled
                        PasswordLastSet = $_.PasswordLastSet
                        PasswordNeverExpires = $_.PasswordNeverExpires
                        LastLogonDate = $_.LastLogonDate
                        AdminCount = $_.AdminCount
                        PrivilegedGroupsString = $_.PrivilegedGroupsString | ConvertTo-SafeCsvValue
                        Title = $_.Title | ConvertTo-SafeCsvValue
                        Department = $_.Department | ConvertTo-SafeCsvValue
                        DoesNotRequirePreAuth = $_.DoesNotRequirePreAuth
                        TrustedForDelegation = $_.TrustedForDelegation
                        HasSPN = $_.HasSPN
                        SPNCount = $_.SPNCount
                    }
                } |
                Export-Csv -Path $privilegedUsersCsvPath -NoTypeInformation -Encoding UTF8

            Write-Host "Privileged users report exported to: $privilegedUsersCsvPath" -ForegroundColor Green
        }
        
        Write-Progress -Activity "Exporting Audit Reports" -Completed
        
        Write-Host "`n==================================================" -ForegroundColor Cyan
        Write-Host "Audit Complete" -ForegroundColor Cyan
        Write-Host "==================================================`n" -ForegroundColor Cyan
        
        return $allFindings
    }
    finally {
        if ($effectiveServer) {
            Clear-ADSecurityAuditTargetServer
        }
        Stop-Transcript
    }
}
