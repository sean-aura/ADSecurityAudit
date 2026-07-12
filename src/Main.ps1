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
        
        Write-Verbose "Testing Domain Controller connectivity..."
        try {
            $domain = Get-ADDomain -ErrorAction Stop

            # Attempt to discover multiple DCs for failover
            $domainControllers = @()
            try {
                $domainControllers = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue |
                    Select-Object -First 3
            }
            catch {
                Write-Verbose "Could not enumerate all DCs, falling back to discovery: $_"
            }

            if (-not $domainControllers -or $domainControllers.Count -eq 0) {
                $domainControllers = @(Get-ADDomainController -Discover -ErrorAction Stop)
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
            'MachineAccountQuota' = { Test-ADMachineAccountQuota }
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
            Write-Progress -Activity "Exporting Audit Reports" -Status "Writing CSV report..." -PercentComplete 70
            $csvPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.csv"
            $allFindings | Select-Object Category, Issue, Severity, AffectedObject, Description, Impact, Remediation, DetectedDate, MitreTechnique, AnssiControl, Weight |
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
        Stop-Transcript
    }
}
