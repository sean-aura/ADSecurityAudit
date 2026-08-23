#region Domain Security Settings

function Test-ADDomainSecurity {
    <#
    .SYNOPSIS
        Audits domain-wide password policy, functional level, Recycle Bin,
        legacy OS presence, tombstone lifetime, and AzureADSSOACC key
        rotation.
    .DESCRIPTION
        PDC-ONLY CHECKS, NOTED ACCORDINGLY: every live query in this
        function (password policy, domain/forest functional level,
        Recycle Bin feature state, tombstone lifetime) reads a single
        domain- or forest-wide attribute/feature that is identical
        regardless of which DC answers - there is no per-DC state to
        enumerate here, unlike a true per-DC probe. All of it goes through
        $__adServer (Get-ADSecurityAuditTargetServerValue), which follows
        the module's normal three-mode -Server contract: omitted or a
        domain name resolves to that domain's PDC Emulator specifically
        (the authoritative source for domain/forest-wide config); an
        explicit, specific DC is honored exactly as given. The legacy-OS
        computer sweep and AzureADSSOACC check are ordinary domain-wide
        object queries, not per-DC probes, for the same reason.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied,
        reads Snapshot.PasswordPolicy/.Forest/.RecycleBinEnabled/
        Domain.DomainMode/.TombstoneLifetimeDays and Snapshot.Computers -
        no live AD access is performed. Added in v1.19.0.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting domain security settings audit..."
    $findings = @()

    if ($Snapshot) {
        Write-Verbose "Test-ADDomainSecurity: running from snapshot (no live AD access)."

        if ($Snapshot.ContainsKey('PasswordPolicy') -and $Snapshot.PasswordPolicy) {
            $pwdPolicy = $Snapshot.PasswordPolicy

            if ($pwdPolicy.MinPasswordLength -lt 14) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Security'
                $finding.Issue = 'Weak Minimum Password Length'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = 'Default Domain Password Policy'
                $finding.Description = "Minimum password length is set to $($pwdPolicy.MinPasswordLength) characters."
                $finding.Impact = "Short passwords are easier to crack through brute-force and dictionary attacks."
                $finding.Remediation = "Increase minimum password length to at least 14 characters: Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14"
                $finding.EstimatedEffort = 'Medium — a Default Domain Policy GPO change affecting every future password change; needs a short monitoring window as users adjust.'
                $finding.KnownRisks = 'Minimal technical risk; may increase helpdesk load and require re-training users with short passwords, since the new minimum only applies at each account''s next password change.'
                $finding.BackupRollback = 'Easy — revert the GPO value; effective at next Group Policy refresh, no data loss, not retroactive.'
                $finding.Details = @{
                    CurrentLength = $pwdPolicy.MinPasswordLength
                    RecommendedLength = 14
                }
                $findings += $finding
            }

            if ($pwdPolicy.ComplexityEnabled -eq $false) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Security'
                $finding.Issue = 'Password Complexity Disabled'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = 'Default Domain Password Policy'
                $finding.Description = "Password complexity requirements are disabled."
                $finding.Impact = "Users can set simple, easily guessable passwords, significantly increasing the risk of compromise."
                $finding.Remediation = "Enable password complexity: Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled `$true"
                $finding.EstimatedEffort = 'Medium — a Default Domain Policy GPO change affecting every future password change; needs a short monitoring window as users adjust.'
                $finding.KnownRisks = 'Enforcing complexity starts rejecting non-compliant password changes going forward and may increase helpdesk password-reset volume, a documented operational side effect rather than a technical break.'
                $finding.BackupRollback = 'Easy — revert the GPO setting; effective at next Group Policy refresh, no data loss, and not retroactive to existing passwords.'
                $finding.Details = @{
                    ComplexityEnabled = $pwdPolicy.ComplexityEnabled
                }
                $findings += $finding
            }

            if ($pwdPolicy.ReversibleEncryptionEnabled -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Security'
                $finding.Issue = 'Reversible Encryption Enabled Domain-Wide'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = 'Default Domain Password Policy'
                $finding.Description = "Reversible password encryption is enabled at the domain level."
                $finding.Impact = "All passwords are stored in a format equivalent to plaintext, making them easily retrievable by attackers."
                $finding.Remediation = "Disable reversible encryption immediately: Set-ADDefaultDomainPasswordPolicy -ReversibleEncryptionEnabled `$false"
                $finding.EstimatedEffort = 'Medium — disabling the setting alone doesn''t clear already-stored reversibly-encrypted password copies for existing accounts, so plan a follow-up forced password change for previously affected accounts.'
                $finding.KnownRisks = 'The existing stored reversible-encryption copy persists for each account until its next password change, so disabling the GPO setting alone doesn''t retroactively protect current passwords, a documented Microsoft behavior.'
                $finding.BackupRollback = 'Easy — revert the GPO setting; no data loss, though re-enabling doesn''t restore already-cleared reversible copies.'
                $finding.Details = @{
                    ReversibleEncryptionEnabled = $pwdPolicy.ReversibleEncryptionEnabled
                }
                $findings += $finding
            }
        }
        else {
            Write-Verbose "Test-ADDomainSecurity: snapshot has no PasswordPolicy entry; skipping password policy checks."
        }

        $domainLevel = if ($Snapshot.Domain) { $Snapshot.Domain.DomainMode } else { $null }
        $forestLevel = if ($Snapshot.ContainsKey('Forest') -and $Snapshot.Forest) { $Snapshot.Forest.ForestMode } else { $null }
        $deprecatedLevels = @('Windows2000Domain', 'Windows2003Domain', 'Windows2008Domain', 'Windows2008R2Domain', 'Windows2012Domain')

        if ($domainLevel -and $domainLevel -in $deprecatedLevels) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Outdated Domain Functional Level'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = 'Domain Functional Level'
            $finding.Description = "Domain functional level is set to '$domainLevel', which is outdated."
            $finding.Impact = "Older functional levels lack modern security features and may support deprecated authentication protocols."
            $finding.Remediation = "Raise domain functional level after ensuring all DCs are running a supported OS: Set-ADDomainMode -DomainMode Windows2016Domain (or higher)"
            $finding.EstimatedEffort = 'High — every DC in the domain must already be at or above the target OS level before the raise succeeds, requiring a domain-wide inventory and sign-off before proceeding.'
            $finding.KnownRisks = 'Low technical risk from the raise itself; the main risk is procedural — confirm no down-level DCs remain, and that domain-functional-level-gated features (e.g. Protected Users, Kerberos armoring/FAST support) aren''t silently unavailable at the current level.'
            $finding.BackupRollback = 'Hard/Limited — like forest functional level, a raised domain functional level is designed not to be rolled back once every DC has adopted it; treat the raise as a one-way step.'
            $finding.Details = @{
                CurrentLevel = $domainLevel
                ForestLevel = $forestLevel
                RecommendedLevel = 'Windows2016Domain or higher'
            }
            $findings += $finding
        }

        if ($forestLevel -and $forestLevel -in $deprecatedLevels) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Outdated Forest Functional Level'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = 'Forest Functional Level'
            $finding.Description = "Forest functional level is set to '$forestLevel', which is outdated."
            $finding.Impact = "The forest functional level gates which security features are available forest-wide, independent of any single domain's own functional level: the AD Recycle Bin requires Windows Server 2008 R2 forest mode, and the Privileged Access Management (PAM) optional feature requires Windows Server 2016 forest mode. An outdated forest functional level silently blocks these features even when every domain in the forest looks current."
            $finding.Remediation = "Raise the forest functional level after confirming every domain in the forest is already at or above the target level: Set-ADForestMode -ForestMode Windows2016Forest (or higher)"
            $finding.EstimatedEffort = 'High — every DC in every domain of the forest must already be running the target Windows Server version before the raise will succeed, so this needs a forest-wide inventory and sign-off from every domain admin, not just the forest root.'
            $finding.KnownRisks = 'Low technical risk to clients or applications from the raise itself; the main risk is procedural — a raised forest functional level cannot be cleanly undone, so confirm no domain still has down-level DCs and that no AD-integrated product (e.g. Exchange) pins to the current level before proceeding.'
            $finding.BackupRollback = 'Hard/Limited — per Microsoft documentation a forest functional level generally cannot be lowered once raised, with one narrow exception (Windows Server 2012 down to 2008 R2, only if the AD Recycle Bin has not been enabled); there is no attribute-level export or standard AD backup mechanism that undoes this change.'
            $finding.OperationalNotes = 'Raising the forest functional level does not raise domain functional levels, which are configured and must be raised separately if the goal is also to unlock domain-level features.'
            $finding.Details = @{
                CurrentLevel = $forestLevel
                RecommendedLevel = 'Windows2016Forest or higher'
            }
            $findings += $finding
        }

        if ($Snapshot.ContainsKey('TombstoneLifetimeDays') -and $null -ne $Snapshot.TombstoneLifetimeDays) {
            $tombstoneLifetimeDays = [int]$Snapshot.TombstoneLifetimeDays
            if ($tombstoneLifetimeDays -lt 180) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Security'
                $finding.Issue = 'Short Tombstone Lifetime'
                $finding.Severity = 'Low'
                $finding.SeverityLevel = 1
                $finding.AffectedObject = 'Forest Tombstone Lifetime'
                $finding.Description = "Forest tombstone lifetime is set to $tombstoneLifetimeDays days."
                $finding.Impact = "Tombstone lifetime caps the maximum usable age of a system-state backup and the window available to detect and recover from accidental or malicious object deletion - a backup older than this value cannot be used for an authoritative restore. This also governs msDS-deletedObjectLifetime, which defaults to the tombstone lifetime value when not independently set."
                $finding.Remediation = "Set the forest tombstone lifetime to at least 180 days on the Directory Service object's tombstoneLifetime attribute (forest-wide, not configurable per domain): Set-ADObject -Identity 'CN=Directory Service,CN=Windows NT,CN=Services,<configurationNamingContext>' -Replace @{tombstoneLifetime=180}"
                $finding.EstimatedEffort = 'Low — a single attribute change on one forest-wide object, reversible immediately, with no maintenance window needed.'
                $finding.KnownRisks = 'Low technical risk; lengthening the value only extends the object-recovery and backup-usability window going forward and does not affect current authentication, replication, or application behavior.'
                $finding.BackupRollback = 'Easy — revert tombstoneLifetime to its prior value with the same Set-ADObject command; takes effect as the change replicates, with no data-loss risk since increasing the value only lengthens, never shortens, the existing recovery window.'
                $finding.Details = @{
                    CurrentValueDays = $tombstoneLifetimeDays
                    RecommendedMinimumDays = 180
                }
                $findings += $finding
            }
        }
        else {
            Write-Verbose "Test-ADDomainSecurity: snapshot has no TombstoneLifetimeDays entry; skipping tombstone lifetime check."
        }

        if ($Snapshot.ContainsKey('RecycleBinEnabled') -and $Snapshot.RecycleBinEnabled -eq $false) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'AD Recycle Bin Not Enabled'
            $finding.Severity = 'Low'
            $finding.SeverityLevel = 1
            $finding.AffectedObject = 'AD Recycle Bin Feature'
            $finding.Description = "Active Directory Recycle Bin is not enabled."
            $finding.Impact = "Deleted AD objects cannot be easily restored, making recovery from accidental deletions or attacks more difficult."
            $finding.Remediation = "Enable AD Recycle Bin: Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <forest>"
            $finding.EstimatedEffort = 'Low — a single Enable-ADOptionalFeature command, one-time, no maintenance window.'
            $finding.KnownRisks = 'Enabling AD Recycle Bin immediately converts every existing tombstoned object in the forest into the Recycle Bin''s deleted-object model — a documented one-time side effect, not a functional access risk.'
            $finding.BackupRollback = 'Hard/Limited — per Microsoft documentation, AD Recycle Bin cannot be disabled once enabled; there is no toggle-back, only a full forest recovery, which is not a practical rollback option.'
            $finding.Details = @{
                Feature = 'Recycle Bin'
                Status = 'Disabled'
            }
            $findings += $finding
        }

        if ($Snapshot.ContainsKey('Computers')) {
            $legacyOS = @(
                'Windows XP', 'Windows Vista', 'Windows 7', 'Windows 8', 'Windows 8.1',
                'Windows Server 2003', 'Windows Server 2008', 'Windows Server 2012', 'Windows Server 2012 R2'
            )
            $legacyComputers = @(@($Snapshot.Computers) | Where-Object {
                $os = $_.OperatingSystem
                if ($os) {
                    foreach ($legacyPattern in $legacyOS) {
                        if ($os -match [regex]::Escape($legacyPattern)) { return $true }
                    }
                }
                return $false
            })

            if ($legacyComputers.Count -gt 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Security'
                $finding.Issue = 'Legacy Operating Systems in Domain'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = 'Domain Computers'
                $finding.Description = "Found $($legacyComputers.Count) computer(s) running unsupported/legacy operating systems."
                $finding.Impact = "Legacy systems lack security updates and are vulnerable to known exploits, providing easy entry points for attackers."
                $finding.Remediation = "Upgrade or isolate legacy systems. Remove computer accounts for decommissioned systems."
                $finding.EstimatedEffort = 'High — decommissioning or upgrading legacy-OS systems is an environment-wide project requiring an application-dependency inventory and phased migration, not a single change.'
                $finding.KnownRisks = 'Decommissioning or isolating a legacy-OS system can break any application still tied to it (e.g. an old line-of-business app that only runs on that OS), so this needs a dependency inventory first.'
                $finding.BackupRollback = 'Hard/Limited — upgrading or decommissioning a legacy host is generally a one-way project; where feasible, take a full backup or VM snapshot of the host before changing it as the practical safety net.'
                $finding.Details = @{
                    Count = $legacyComputers.Count
                    Computers = ($legacyComputers | Select-Object Name, OperatingSystem, LastLogonDate -First 50)
                }
                $findings += $finding
            }

            $azureSsoAccounts = @(@($Snapshot.Computers) | Where-Object { $_.SamAccountName -eq 'AZUREADSSOACC$' })
            foreach ($account in $azureSsoAccounts) {
                $passwordAge = if ($account.PasswordLastSet) { (Get-Date) - $account.PasswordLastSet } else { [TimeSpan]::MaxValue }
                if ($passwordAge.TotalDays -gt 30) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Domain Security'
                    $finding.Issue = 'Stale AzureADSSOACC Kerberos Key'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $account.SamAccountName
                    $finding.Description = "Azure AD Seamless SSO computer account password has not been rotated within the last 30 days."
                    $finding.Impact = "Stale Kerberos decryption keys increase the risk of credential compromise for Seamless SSO."
                    $finding.Remediation = "Roll over the Azure AD Seamless SSO Kerberos decryption key using Azure AD Connect or the Update-AzureADSSOForest PowerShell cmdlet. Reference: https://learn.microsoft.com/azure/active-directory/hybrid/tshoot-connect-sso#roll-over-the-kerberos-decryption-key"
                    $finding.EstimatedEffort = 'Low — a single documented cmdlet (Update-AzureADSSOForest / Azure AD Connect) rolls the key over.'
                    $finding.KnownRisks = 'Rolling the Seamless SSO Kerberos key briefly invalidates in-flight SSO tickets for that mechanism, so users may need to re-authenticate once during the rollover, a documented Microsoft behavior rather than an outage.'
                    $finding.BackupRollback = 'Easy — the key can be rolled over again at any time via the same cmdlet; no data loss, and Microsoft''s own guidance is to roll it over regularly regardless.'
                    $finding.Details = @{
                        PasswordLastSet = $account.PasswordLastSet
                        PasswordAgeDays = if ($passwordAge -ne [TimeSpan]::MaxValue) { [int]$passwordAge.TotalDays } else { 'Unknown' }
                        Reference = 'https://learn.microsoft.com/azure/active-directory/hybrid/tshoot-connect-sso#roll-over-the-kerberos-decryption-key'
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "Domain security settings audit complete (snapshot mode). Found $($findings.Count) issues."
        return $findings
    }

    try {
        $__adServer = Get-ADSecurityAuditTargetServerValue
        $domain = Get-ADDomain -Server $__adServer
        
        # Check password policy
        $defaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $__adServer
        
        if ($defaultPasswordPolicy.MinPasswordLength -lt 14) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Weak Minimum Password Length'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'Default Domain Password Policy'
            $finding.Description = "Minimum password length is set to $($defaultPasswordPolicy.MinPasswordLength) characters."
            $finding.Impact = "Short passwords are easier to crack through brute-force and dictionary attacks."
            $finding.Remediation = "Increase minimum password length to at least 14 characters: Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -Identity $($domain.DNSRoot)"
            $finding.EstimatedEffort = 'Medium — a Default Domain Policy GPO change affecting every future password change; needs a short monitoring window as users adjust.'
            $finding.KnownRisks = 'Minimal technical risk; may increase helpdesk load and require re-training users with short passwords, since the new minimum only applies at each account''s next password change.'
            $finding.BackupRollback = 'Easy — revert the GPO value; effective at next Group Policy refresh, no data loss, not retroactive.'
            $finding.Details = @{
                CurrentLength = $defaultPasswordPolicy.MinPasswordLength
                RecommendedLength = 14
            }
            $findings += $finding
        }
        
        if ($defaultPasswordPolicy.ComplexityEnabled -eq $false) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Password Complexity Disabled'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = 'Default Domain Password Policy'
            $finding.Description = "Password complexity requirements are disabled."
            $finding.Impact = "Users can set simple, easily guessable passwords, significantly increasing the risk of compromise."
            $finding.Remediation = "Enable password complexity: Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled `$true -Identity $($domain.DNSRoot)"
            $finding.EstimatedEffort = 'Medium — a Default Domain Policy GPO change affecting every future password change; needs a short monitoring window as users adjust.'
            $finding.KnownRisks = 'Enforcing complexity starts rejecting non-compliant password changes going forward and may increase helpdesk password-reset volume, a documented operational side effect rather than a technical break.'
            $finding.BackupRollback = 'Easy — revert the GPO setting; effective at next Group Policy refresh, no data loss, and not retroactive to existing passwords.'
            $finding.Details = @{
                ComplexityEnabled = $defaultPasswordPolicy.ComplexityEnabled
            }
            $findings += $finding
        }
        
        if ($defaultPasswordPolicy.ReversibleEncryptionEnabled -eq $true) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Reversible Encryption Enabled Domain-Wide'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = 'Default Domain Password Policy'
            $finding.Description = "Reversible password encryption is enabled at the domain level."
            $finding.Impact = "All passwords are stored in a format equivalent to plaintext, making them easily retrievable by attackers."
            $finding.Remediation = "Disable reversible encryption immediately: Set-ADDefaultDomainPasswordPolicy -ReversibleEncryptionEnabled `$false -Identity $($domain.DNSRoot)"
            $finding.EstimatedEffort = 'Medium — disabling the setting alone doesn''t clear already-stored reversibly-encrypted password copies for existing accounts, so plan a follow-up forced password change for previously affected accounts.'
            $finding.KnownRisks = 'The existing stored reversible-encryption copy persists for each account until its next password change, so disabling the GPO setting alone doesn''t retroactively protect current passwords, a documented Microsoft behavior.'
            $finding.BackupRollback = 'Easy — revert the GPO setting; no data loss, though re-enabling doesn''t restore already-cleared reversible copies.'
            $finding.Details = @{
                ReversibleEncryptionEnabled = $defaultPasswordPolicy.ReversibleEncryptionEnabled
            }
            $findings += $finding
        }
        
        # Check domain functional level
        $domainLevel = $domain.DomainMode
        $forestLevel = (Get-ADForest -Server $__adServer).ForestMode
        
        $deprecatedLevels = @('Windows2000Domain', 'Windows2003Domain', 'Windows2008Domain', 'Windows2008R2Domain', 'Windows2012Domain')
        
        if ($domainLevel -in $deprecatedLevels) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Outdated Domain Functional Level'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = 'Domain Functional Level'
            $finding.Description = "Domain functional level is set to '$domainLevel', which is outdated."
            $finding.Impact = "Older functional levels lack modern security features and may support deprecated authentication protocols."
            $finding.Remediation = "Raise domain functional level after ensuring all DCs are running a supported OS: Set-ADDomainMode -Identity $($domain.DNSRoot) -DomainMode Windows2016Domain (or higher)"
            $finding.EstimatedEffort = 'High — every DC in the domain must already be at or above the target OS level before the raise succeeds, requiring a domain-wide inventory and sign-off before proceeding.'
            $finding.KnownRisks = 'Low technical risk from the raise itself; the main risk is procedural — confirm no down-level DCs remain, and that domain-functional-level-gated features (e.g. Protected Users, Kerberos armoring/FAST support) aren''t silently unavailable at the current level.'
            $finding.BackupRollback = 'Hard/Limited — like forest functional level, a raised domain functional level is designed not to be rolled back once every DC has adopted it; treat the raise as a one-way step.'
            $finding.Details = @{
                CurrentLevel = $domainLevel
                ForestLevel = $forestLevel
                RecommendedLevel = 'Windows2016Domain or higher'
            }
            $findings += $finding
        }
        
        if ($forestLevel -in $deprecatedLevels) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Outdated Forest Functional Level'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = 'Forest Functional Level'
            $finding.Description = "Forest functional level is set to '$forestLevel', which is outdated."
            $finding.Impact = "The forest functional level gates which security features are available forest-wide, independent of any single domain's own functional level: the AD Recycle Bin requires Windows Server 2008 R2 forest mode, and the Privileged Access Management (PAM) optional feature requires Windows Server 2016 forest mode. An outdated forest functional level silently blocks these features even when every domain in the forest looks current."
            $finding.Remediation = "Raise the forest functional level after confirming every domain in the forest is already at or above the target level: Set-ADForestMode -ForestMode Windows2016Forest (or higher)"
            $finding.EstimatedEffort = 'High — every DC in every domain of the forest must already be running the target Windows Server version before the raise will succeed, so this needs a forest-wide inventory and sign-off from every domain admin, not just the forest root.'
            $finding.KnownRisks = 'Low technical risk to clients or applications from the raise itself; the main risk is procedural — a raised forest functional level cannot be cleanly undone, so confirm no domain still has down-level DCs and that no AD-integrated product (e.g. Exchange) pins to the current level before proceeding.'
            $finding.BackupRollback = 'Hard/Limited — per Microsoft documentation a forest functional level generally cannot be lowered once raised, with one narrow exception (Windows Server 2012 down to 2008 R2, only if the AD Recycle Bin has not been enabled); there is no attribute-level export or standard AD backup mechanism that undoes this change.'
            $finding.OperationalNotes = 'Raising the forest functional level does not raise domain functional levels, which are configured and must be raised separately if the goal is also to unlock domain-level features.'
            $finding.Details = @{
                CurrentLevel = $forestLevel
                RecommendedLevel = 'Windows2016Forest or higher'
            }
            $findings += $finding
        }

        # Check forest tombstone lifetime
        Write-Verbose "Checking forest tombstone lifetime..."
        try {
            $configContextForTombstone = Get-ADRootDSEValue -Property configurationNamingContext -Server $__adServer
            $dsObject = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configContextForTombstone" -Properties tombstoneLifetime -Server $__adServer -ErrorAction Stop
            $tombstoneLifetimeDays = if ($null -ne $dsObject.tombstoneLifetime) { [int]$dsObject.tombstoneLifetime } else { 60 }

            if ($tombstoneLifetimeDays -lt 180) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Security'
                $finding.Issue = 'Short Tombstone Lifetime'
                $finding.Severity = 'Low'
                $finding.SeverityLevel = 1
                $finding.AffectedObject = 'Forest Tombstone Lifetime'
                $finding.Description = "Forest tombstone lifetime is set to $tombstoneLifetimeDays days."
                $finding.Impact = "Tombstone lifetime caps the maximum usable age of a system-state backup and the window available to detect and recover from accidental or malicious object deletion - a backup older than this value cannot be used for an authoritative restore. This also governs msDS-deletedObjectLifetime, which defaults to the tombstone lifetime value when not independently set."
                $finding.Remediation = "Set the forest tombstone lifetime to at least 180 days on the Directory Service object's tombstoneLifetime attribute (forest-wide, not configurable per domain): Set-ADObject -Identity 'CN=Directory Service,CN=Windows NT,CN=Services,$configContextForTombstone' -Replace @{tombstoneLifetime=180}"
                $finding.EstimatedEffort = 'Low — a single attribute change on one forest-wide object, reversible immediately, with no maintenance window needed.'
                $finding.KnownRisks = 'Low technical risk; lengthening the value only extends the object-recovery and backup-usability window going forward and does not affect current authentication, replication, or application behavior.'
                $finding.BackupRollback = 'Easy — revert tombstoneLifetime to its prior value with the same Set-ADObject command; takes effect as the change replicates, with no data-loss risk since increasing the value only lengthens, never shortens, the existing recovery window.'
                $finding.Details = @{
                    CurrentValueDays = $tombstoneLifetimeDays
                    RecommendedMinimumDays = 180
                }
                $findings += $finding
            }
        }
        catch {
            Write-Verbose "Failed to read forest tombstone lifetime: $_"
        }
        
        # Check for Recycle Bin (best practice)
        $recycleBinFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Server $__adServer
        if ($recycleBinFeature.EnabledScopes.Count -eq 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'AD Recycle Bin Not Enabled'
            $finding.Severity = 'Low'
            $finding.SeverityLevel = 1
            $finding.AffectedObject = 'AD Recycle Bin Feature'
            $finding.Description = "Active Directory Recycle Bin is not enabled."
            $finding.Impact = "Deleted AD objects cannot be easily restored, making recovery from accidental deletions or attacks more difficult."
            $finding.Remediation = "Enable AD Recycle Bin: Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $($domain.Forest)"
            $finding.EstimatedEffort = 'Low — a single Enable-ADOptionalFeature command, one-time, no maintenance window.'
            $finding.KnownRisks = 'Enabling AD Recycle Bin immediately converts every existing tombstoned object in the forest into the Recycle Bin''s deleted-object model — a documented one-time side effect, not a functional access risk.'
            $finding.BackupRollback = 'Hard/Limited — per Microsoft documentation, AD Recycle Bin cannot be disabled once enabled; there is no toggle-back, only a full forest recovery, which is not a practical rollback option.'
            $finding.Details = @{
                Feature = 'Recycle Bin'
                Status = 'Disabled'
            }
            $findings += $finding
        }
        
        # Check for computers with old OS versions
        Write-Verbose "Checking for legacy operating systems..."
        $computers = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate -Server $__adServer
        
        $legacyOS = @(
            'Windows XP', 'Windows Vista', 'Windows 7', 'Windows 8', 'Windows 8.1',
            'Windows Server 2003', 'Windows Server 2008', 'Windows Server 2012', 'Windows Server 2012 R2'
        )
        
        $legacyComputers = $computers | Where-Object {
            $os = $_.OperatingSystem
            if ($os) {
                foreach ($legacyPattern in $legacyOS) {
                    if ($os -match [regex]::Escape($legacyPattern)) {
                        return $true
                    }
                }
            }
            return $false
        }
        
        if ($legacyComputers) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Legacy Operating Systems in Domain'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'Domain Computers'
            $finding.Description = "Found $($legacyComputers.Count) computer(s) running unsupported/legacy operating systems."
            $finding.Impact = "Legacy systems lack security updates and are vulnerable to known exploits, providing easy entry points for attackers."
            $finding.Remediation = "Upgrade or isolate legacy systems. Remove computer accounts for decommissioned systems."
            $finding.EstimatedEffort = 'High — decommissioning or upgrading legacy-OS systems is an environment-wide project requiring an application-dependency inventory and phased migration, not a single change.'
            $finding.KnownRisks = 'Decommissioning or isolating a legacy-OS system can break any application still tied to it (e.g. an old line-of-business app that only runs on that OS), so this needs a dependency inventory first.'
            $finding.BackupRollback = 'Hard/Limited — upgrading or decommissioning a legacy host is generally a one-way project; where feasible, take a full backup or VM snapshot of the host before changing it as the practical safety net.'
            $finding.Details = @{
                Count = $legacyComputers.Count
                Computers = ($legacyComputers | Select-Object Name, OperatingSystem, LastLogonDate -First 50)
            }
            $findings += $finding
        }

        # Check AzureADSSOACC password rotation
        Write-Verbose "Checking Azure AD Seamless SSO computer accounts..."
        $azureSsoAccounts = Get-ADComputer -LDAPFilter "(samaccountname=AZUREADSSOACC$)" -Properties PasswordLastSet, Enabled -Server $__adServer

        foreach ($account in $azureSsoAccounts) {
            $passwordAge = if ($account.PasswordLastSet) { (Get-Date) - $account.PasswordLastSet } else { [TimeSpan]::MaxValue }

            if ($passwordAge.TotalDays -gt 30) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Security'
                $finding.Issue = 'Stale AzureADSSOACC Kerberos Key'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $account.SamAccountName
                $finding.Description = "Azure AD Seamless SSO computer account password has not been rotated within the last 30 days."
                $finding.Impact = "Stale Kerberos decryption keys increase the risk of credential compromise for Seamless SSO."
                $finding.Remediation = "Roll over the Azure AD Seamless SSO Kerberos decryption key using Azure AD Connect or the Update-AzureADSSOForest PowerShell cmdlet. Reference: https://learn.microsoft.com/azure/active-directory/hybrid/tshoot-connect-sso#roll-over-the-kerberos-decryption-key"
                $finding.EstimatedEffort = 'Low — a single documented cmdlet (Update-AzureADSSOForest / Azure AD Connect) rolls the key over.'
                $finding.KnownRisks = 'Rolling the Seamless SSO Kerberos key briefly invalidates in-flight SSO tickets for that mechanism, so users may need to re-authenticate once during the rollover, a documented Microsoft behavior rather than an outage.'
                $finding.BackupRollback = 'Easy — the key can be rolled over again at any time via the same cmdlet; no data loss, and Microsoft''s own guidance is to roll it over regularly regardless.'
                $finding.Details = @{
                    PasswordLastSet = $account.PasswordLastSet
                    PasswordAgeDays = if ($passwordAge -ne [TimeSpan]::MaxValue) { [int]$passwordAge.TotalDays } else { 'Unknown' }
                    Reference = 'https://learn.microsoft.com/azure/active-directory/hybrid/tshoot-connect-sso#roll-over-the-kerberos-decryption-key'
                }
                $findings += $finding
            }
        }
        
        Write-Verbose "Domain security settings audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during domain security audit: $_"
        throw
    }
}

#endregion

