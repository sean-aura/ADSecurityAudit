#region Managed Service Account (gMSA) Password-Retrieval Audits
#
# Group Managed Service Accounts (gMSA) store their current password as an
# attribute (msDS-ManagedPassword) that AD itself rotates automatically.
# Any principal listed in the gMSA's PrincipalsAllowedToRetrieveManagedPassword
# property can read that attribute and authenticate AS the gMSA - this is
# the AD-native equivalent of a BloodHound "ReadGMSAPassword" edge, and it
# is not covered by any existing check in this module (dangerous-ACE scans
# key off ActiveDirectoryRights/ExtendedRights on the object's ACL, not this
# property, which most commonly holds a security descriptor rather than a
# conventional ACE the other checks already enumerate).
#
# DETECTION ONLY: this reads PrincipalsAllowedToRetrieveManagedPassword
# (a list of principals, never the managed-password value itself) and
# group membership used to classify a gMSA as Tier-0/privileged. No
# password, hash, or credential material is ever read, decoded, or acted
# on, and nothing here authenticates as any account.

# Well-known broad principals that should never be able to retrieve ANY
# gMSA's managed password, regardless of how privileged the gMSA is.
$Script:GmsaBroadPrincipalPattern = '(^|\\)(Everyone|Authenticated Users|Domain Users|Domain Computers|ANONYMOUS LOGON)$'

function Test-ADManagedServiceAccountSecurity {
    <#
    .SYNOPSIS
        Audits which principals can retrieve each gMSA's managed password,
        flagging broad grants and grants on privileged (Tier-0-adjacent)
        gMSAs specifically.
    .DESCRIPTION
        For every Group Managed Service Account in the domain, resolves
        PrincipalsAllowedToRetrieveManagedPassword (the property that
        controls who can read msDS-ManagedPassword and so authenticate as
        the gMSA) and emits:
          - 'gMSA Password Retrievable by Broad Principal' (Critical) when
            the retrieval list includes Everyone/Authenticated Users/
            Domain Users/Domain Computers/ANONYMOUS LOGON - every domain
            principal (or every domain computer) can authenticate as this
            service identity.
          - 'Privileged gMSA Password Retrieval Not Tightly Scoped' (High)
            when the gMSA is itself Tier-0/privileged (a member of a
            protected group, or in the user-declared additional Tier-0
            scope - see Get-ADTier0Principal) and the retrieval list
            includes ANY principal that is not itself Tier-0 - i.e.
            something outside the privileged tier can authenticate as a
            privileged service identity.
        A gMSA with no retrieval principals configured at all, or whose
        retrieval list is limited to Tier-0 principals only, produces no
        finding.
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting managed service account (gMSA) audit..."
    $findings = @()

    try {
        $__adServer = Get-ADSecurityAuditTargetServerValue

        $gmsaAccounts = @()
        try {
            $gmsaAccounts = if ($__adServer) {
                Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword, ServicePrincipalNames, MemberOf, Enabled -Server $__adServer -ErrorAction Stop
            }
            else {
                Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword, ServicePrincipalNames, MemberOf, Enabled -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Test-ADManagedServiceAccountSecurity: failed to enumerate gMSAs (Get-ADServiceAccount): $_"
            return $findings
        }

        if (-not $gmsaAccounts -or @($gmsaAccounts).Count -eq 0) {
            Write-Verbose "Test-ADManagedServiceAccountSecurity: no gMSAs found in domain; nothing to check."
            return $findings
        }

        # Tier-0 lookup, same shape/source as ControlPaths.ps1 - reused
        # here to decide (a) whether a gMSA itself counts as privileged,
        # and (b) whether a given retrieval principal is itself Tier-0
        # (and so not a concern even on a privileged gMSA).
        $tier0Lookup = @{}
        try {
            foreach ($p in @(Get-ADTier0Principal)) {
                foreach ($key in @($p.DistinguishedName, $p.SID, $p.SamAccountName)) {
                    if ($key) { $tier0Lookup["$key".ToLowerInvariant()] = $true }
                }
            }
        }
        catch {
            Write-Verbose "Test-ADManagedServiceAccountSecurity: failed to resolve Tier-0 principal set: $_"
        }

        foreach ($gmsa in @($gmsaAccounts)) {
            $retrievers = @($gmsa.PrincipalsAllowedToRetrieveManagedPassword)
            if ($retrievers.Count -eq 0) { continue }

            # Resolve each retriever DN to a display name and Tier-0
            # status. A retriever is usually a group (most deployments
            # scope this to "the servers that host this service"), so
            # membership in that group - not just the group's own
            # identity - is what determines who can actually retrieve the
            # password; but per-principal resolution here (rather than
            # expanding group membership) mirrors how
            # PrincipalsAllowedToRetrieveManagedPassword is normally
            # reviewed and keeps this check's AD query volume flat
            # regardless of how large a scoping group is.
            $resolvedRetrievers = @()
            foreach ($retrieverDN in $retrievers) {
                $retrieverObj = $null
                try {
                    $retrieverObj = if ($__adServer) {
                        Get-ADObject -Identity $retrieverDN -Properties objectSID, sAMAccountName -Server $__adServer -ErrorAction Stop
                    }
                    else {
                        Get-ADObject -Identity $retrieverDN -Properties objectSID, sAMAccountName -ErrorAction Stop
                    }
                }
                catch {
                    Write-Verbose "Test-ADManagedServiceAccountSecurity: failed to resolve retriever '$retrieverDN' for gMSA '$($gmsa.Name)': $_"
                }

                $displayName = if ($retrieverObj -and $retrieverObj.sAMAccountName) { $retrieverObj.sAMAccountName } else { $retrieverDN }
                $sid = if ($retrieverObj -and $retrieverObj.objectSID) { $retrieverObj.objectSID.Value } else { $null }

                $isTier0 = $false
                foreach ($key in @($retrieverDN, $sid, $displayName)) {
                    if ($key -and $tier0Lookup.ContainsKey("$key".ToLowerInvariant())) { $isTier0 = $true; break }
                }

                $resolvedRetrievers += [PSCustomObject]@{
                    Name   = $displayName
                    SID    = $sid
                    DN     = $retrieverDN
                    IsTier0 = $isTier0
                }
            }

            # --- Check 1: broad well-known principal can retrieve ANY gMSA's password ---
            $broadHits = $resolvedRetrievers | Where-Object { $_.Name -match $Script:GmsaBroadPrincipalPattern }
            if ($broadHits.Count -gt 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Managed Service Accounts'
                $finding.Issue = 'gMSA Password Retrievable by Broad Principal'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $gmsa.Name
                $finding.Description = "gMSA '$($gmsa.Name)' allows '$(($broadHits.Name) -join ', ')' to retrieve its managed password (PrincipalsAllowedToRetrieveManagedPassword), letting essentially any domain principal authenticate as this service identity."
                $finding.Impact = "Any principal covered by the broad grant can read msDS-ManagedPassword for this gMSA and authenticate as it directly, inheriting whatever access the service account has - equivalent to a BloodHound 'ReadGMSAPassword' edge from Everyone/Authenticated Users/Domain Users/Domain Computers."
                $finding.Remediation = "Narrow PrincipalsAllowedToRetrieveManagedPassword to only the specific computer accounts (or a tightly-scoped group of them) that actually host this service: Set-ADServiceAccount -Identity '$($gmsa.Name)' -PrincipalsAllowedToRetrieveManagedPassword <specific hosts/group>"
                $finding.EstimatedEffort = 'Low - a single-attribute change on the gMSA object; confirm the actual hosting server(s) first so they remain in the narrowed list.'
                $finding.KnownRisks = 'If the narrowed list omits a server that legitimately hosts this service, that server will fail to retrieve the password at its next rotation/lookup and the service will stop authenticating - confirm every real host before narrowing.'
                $finding.BackupRollback = 'Easy - restore the prior PrincipalsAllowedToRetrieveManagedPassword value; takes effect immediately, no data loss.'
                $finding.Details = @{
                    DistinguishedName = $gmsa.DistinguishedName
                    BroadPrincipals   = ($broadHits.Name -join '; ')
                    AllRetrievers     = ($resolvedRetrievers.Name -join '; ')
                }
                $findings += $finding
            }

            # --- Check 2: privileged gMSA, non-Tier-0 principal can retrieve ---
            $gmsaSid = if ($gmsa.SID) { $gmsa.SID.Value } else { $null }
            $gmsaIsTier0 = $false
            foreach ($key in @($gmsa.DistinguishedName, $gmsaSid, $gmsa.SamAccountName)) {
                if ($key -and $tier0Lookup.ContainsKey("$key".ToLowerInvariant())) { $gmsaIsTier0 = $true; break }
            }

            if ($gmsaIsTier0) {
                $nonTier0Retrievers = $resolvedRetrievers | Where-Object { -not $_.IsTier0 -and $_.Name -notmatch $Script:GmsaBroadPrincipalPattern }
                if ($nonTier0Retrievers.Count -gt 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Managed Service Accounts'
                    $finding.Issue = 'Privileged gMSA Password Retrieval Not Tightly Scoped'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $gmsa.Name
                    $finding.Description = "gMSA '$($gmsa.Name)' is itself a privileged (Tier-0) principal, but its managed password can also be retrieved by non-Tier-0 principal(s): $(($nonTier0Retrievers.Name) -join ', ')."
                    $finding.Impact = "Compromising any of the listed non-Tier-0 principals (or a host covered by one of them) lets an attacker retrieve this gMSA's password and authenticate as a privileged service identity, effectively bridging into Tier-0 without ever touching a Domain Admin account directly."
                    $finding.Remediation = "Review whether every listed principal genuinely needs to host this privileged service. Remove any that don't: Set-ADServiceAccount -Identity '$($gmsa.Name)' -PrincipalsAllowedToRetrieveManagedPassword <confirmed hosts only>"
                    $finding.EstimatedEffort = 'Low - a single-attribute change; requires confirming with the service owner which hosts are actually legitimate.'
                    $finding.KnownRisks = 'Removing a host that legitimately runs this service breaks its ability to authenticate as the gMSA at next password lookup - confirm current hosting before narrowing.'
                    $finding.BackupRollback = 'Easy - restore the prior PrincipalsAllowedToRetrieveManagedPassword value; takes effect immediately, no data loss.'
                    $finding.Details = @{
                        DistinguishedName  = $gmsa.DistinguishedName
                        NonTier0Retrievers = ($nonTier0Retrievers.Name -join '; ')
                        AllRetrievers      = ($resolvedRetrievers.Name -join '; ')
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "Managed service account audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during managed service account audit: $_"
        throw
    }
}

#endregion
