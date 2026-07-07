# Module-level variables

$Script:SeverityLevels = @{
    Critical = 4
    High = 3
    Medium = 2
    Low = 1
    Info = 0
}

$Script:ThresholdCriticalGroupSize = 5
$Script:ThresholdStandardGroupSize = 10
$Script:ThresholdInactiveDays = 90
$Script:ThresholdPasswordAgeDays = 180

$Script:ProtectedGroups = @(
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
    'Account Operators'
    'Server Operators'
    'Backup Operators'
    'Print Operators'
    'Domain Controllers'
    'Read-only Domain Controllers'
    'Group Policy Creator Owners'
    'Cryptographic Operators'
    'Distributed COM Users'
)

# Extended Rights GUIDs - these are for checking ACEs with ExtendedRight permissions
# Note: WriteOwner, WriteDacl, GenericAll, GenericWrite are standard AD rights checked via 
# ActiveDirectoryRights property, NOT via GUIDs
$Script:DangerousExtendedRights = @{
    'DS-Replication-Get-Changes' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-All' = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
    'User-Force-Change-Password' = '00299570-246d-11d0-a768-00aa006e0529'
    'DS-Replication-Manage-Topology' = '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Synchronize' = '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
}

# Property GUIDs for checking WriteProperty permissions
$Script:DangerousPropertyGuids = @{
    'Member' = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    'msDS-KeyCredentialLink' = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
    'ServicePrincipalName' = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
    'msDS-AllowedToActOnBehalfOfOtherIdentity' = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
    'GPLink' = 'f30e3bc2-9ff0-11d1-b603-0000f80367c1'
    'ms-Mcs-AdmPwd' = 'ba19577d-37b2-4921-a637-429a1d99da82'
    'ms-LAPS-Password' = 'd95f499a-f5dd-4796-a2d5-6a3fba6a8e34'
    'ms-LAPS-EncryptedPassword' = 'f3531ec6-6330-4f8e-8d39-7c7867f0e4a4'
}

# Standard AD rights that indicate dangerous permissions (checked via -match on ActiveDirectoryRights)
$Script:DangerousStandardRights = @(
    'GenericAll'
    'GenericWrite'
    'WriteDacl'
    'WriteOwner'
    'AllExtendedRights'
)

# Keep legacy variable name for backward compatibility
$Script:DangerousRights = $Script:DangerousExtendedRights

class ADSecurityFinding {
    [string]$Category
    [string]$Issue
    [string]$Severity
    [int]$SeverityLevel
    [string]$Description
    [string]$Impact
    [string]$Remediation
    [string]$AffectedObject
    [hashtable]$Details
    [datetime]$DetectedDate

    # --- Additive metadata fields (introduced in v1.2.0) ---
    # These are appended to the finding/output contract and are OPTIONAL.
    # They are populated centrally from the mapping table in src/Scoring.ps1
    # via Set-ADFindingMetadata. Existing consumers that ignore them are
    # unaffected. Per the contract: finding fields are additive only.
    [string]$MitreTechnique   # MITRE ATT&CK technique id, e.g. 'T1558.001'
    [string]$AnssiControl     # ANSSI-style control id, e.g. 'vuln1_krbtgt_age'
    [int]$Weight              # Risk-score contribution (default 0)

    ADSecurityFinding() {
        $this.DetectedDate = Get-Date
        $this.Details = @{}
        $this.MitreTechnique = ''
        $this.AnssiControl = ''
        $this.Weight = 0
    }
}

# Retry helper function for AD queries with exponential backoff
function Invoke-ADQueryWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Query,

        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 2,
        [string]$OperationName = "AD Query"
    )

    $attempt = 0
    $lastError = $null

    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            return (& $Query)
        }
        catch {
            $lastError = $_
            Write-Verbose "$OperationName failed (attempt $attempt/$MaxAttempts): $_"

            if ($attempt -lt $MaxAttempts) {
                $wait = $DelaySeconds * [math]::Pow(2, $attempt - 1)
                Start-Sleep -Seconds $wait
            }
        }
    }

    Write-Warning "$OperationName failed after $MaxAttempts attempts: $lastError"
    return $null
}

# Retrieve the domain's privileged / Tier-0 principal set (users + groups).
#
# This is the single shared definition of "Tier-0" used across detection
# modules (introduced in v1.3.0 alongside Get-ADSnapshot). Later features
# (Exchange, RODC, graph-based analysis, etc.) should call this instead of
# re-deriving their own privileged-principal list, so the definition stays
# consistent everywhere it's used.
#
# Detection only: this performs read-only group-membership enumeration
# (recursive) against $Script:ProtectedGroups. It does not touch or modify
# any object.
function Get-ADTier0Principal {
    <#
    .SYNOPSIS
        Returns the set of Tier-0 (privileged) principals for the domain.
    .DESCRIPTION
        Recursively expands $Script:ProtectedGroups (Domain Admins, Enterprise
        Admins, Schema Admins, built-in Administrators, DCs, RODCs, and the
        other groups the module already treats as privileged) and returns one
        record per unique principal (user, computer, or group) along with the
        list of protected groups that grant it privileged status.

        Accepts an optional -Snapshot (as produced by Get-ADSnapshot) so
        callers can derive the Tier-0 set offline from a prior collection
        pass instead of re-querying AD live.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied and
        it contains a 'Groups' collection with member data, the Tier-0 set is
        derived from the snapshot instead of live AD queries.
    .OUTPUTS
        PSCustomObject[] with SID, SamAccountName, ObjectClass, DistinguishedName,
        and PrivilegedGroups (the protected groups this principal belongs to).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Resolving Tier-0 principal set..."
    $tier0 = [System.Collections.ArrayList]::new()
    $seen = @{}

    if ($Snapshot -and $Snapshot.ContainsKey('Groups') -and $Snapshot.Groups) {
        Write-Verbose "Get-ADTier0Principal: deriving Tier-0 set from snapshot."
        foreach ($group in $Snapshot.Groups) {
            if ($group.Name -notin $Script:ProtectedGroups) { continue }
            foreach ($memberDN in @($group.Members)) {
                if (-not $memberDN) { continue }
                if (-not $seen.ContainsKey($memberDN)) {
                    $seen[$memberDN] = [System.Collections.ArrayList]::new()
                    [void]$tier0.Add([PSCustomObject]@{
                        DistinguishedName = $memberDN
                        SID               = $null
                        SamAccountName    = $null
                        ObjectClass       = $null
                        PrivilegedGroups  = $seen[$memberDN]
                    })
                }
                [void]$seen[$memberDN].Add($group.Name)
            }
        }
        return @($tier0 | ForEach-Object { $_.PrivilegedGroupsString = ($_.PrivilegedGroups -join '; '); $_ })
    }

    foreach ($groupName in $Script:ProtectedGroups) {
        try {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
        }
        catch {
            Write-Verbose "Get-ADTier0Principal: failed to get group '$groupName': $_"
            continue
        }

        if (-not $group) { continue }

        $members = $null
        try {
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop
        }
        catch {
            Write-Verbose "Get-ADTier0Principal: failed to get members of '$groupName': $_"
            continue
        }

        foreach ($member in @($members)) {
            $key = $member.SID.Value
            if (-not $key) { $key = $member.DistinguishedName }

            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = [System.Collections.ArrayList]::new()
                [void]$tier0.Add([PSCustomObject]@{
                    DistinguishedName = $member.DistinguishedName
                    SID               = $member.SID.Value
                    SamAccountName    = $member.SamAccountName
                    ObjectClass       = $member.objectClass
                    PrivilegedGroups  = $seen[$key]
                })
            }
            [void]$seen[$key].Add($groupName)
        }
    }

    Write-Verbose "Get-ADTier0Principal: resolved $($tier0.Count) unique Tier-0 principals."
    return @($tier0 | ForEach-Object { $_.PrivilegedGroupsString = ($_.PrivilegedGroups -join '; '); $_ })
}

# Sanitize values for CSV export to prevent formula injection
function ConvertTo-SafeCsvValue {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    process {
        if ([string]::IsNullOrEmpty($Value)) {
            return $Value
        }

        # Prefix with single quote if value starts with characters that could be interpreted as formulas
        if ($Value -match '^[=+\-@\t\r]') {
            return "'" + $Value
        }

        return $Value
    }
}
