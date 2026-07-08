#region Domain Snapshot, Rule-Runner & Offline Mode
#
# This file introduces the v1.3.0 collection contract:
#
#   1. Get-ADSnapshot      - one paged, read-only collection pass over the
#                             core AD object sets, returned as a hashtable
#                             and optionally serialised with -ToJson.
#   2. Invoke-ADRuleSet    - dispatches the registered Test-* functions
#                             against a snapshot. Before splatting -Snapshot
#                             to a function it checks whether that function
#                             actually declares the parameter, so modules
#                             that haven't been retrofitted yet are simply
#                             called live instead of erroring.
#   3. ConvertTo-ADHashtable - recursive PSCustomObject -> Hashtable
#                             converter, used to rehydrate a snapshot that
#                             was serialised to JSON and reloaded (Windows
#                             PowerShell 5.1 has no ConvertFrom-Json
#                             -AsHashtable, so this is done by hand).
#
# DETECTION ONLY: every query here is a read (Get-AD*, ACL reads, registry-
# style config reads). Nothing here modifies AD, forges tickets, or talks to
# any host beyond an authenticated LDAP read.
#
# CONTRACT: adding -Snapshot to a Test-* function must never change that
# function's live-mode behaviour, and Invoke-ADRuleSet must never break on a
# function that lacks -Snapshot - it just calls it live.

# -----------------------------------------------------------------------------
# Central registry of dispatchable Test-* functions, keyed the same way as
# $allTests in src/Main.ps1. Invoke-ADRuleSet uses this list independent of
# Start-ADSecurityAudit's live-mode loop. When a new test is registered in
# Main.ps1's $allTests (per the module's three-registration convention), add
# the same key/function name here so `-FromSnapshot` / Invoke-ADRuleSet stay
# in sync with the live audit.
# -----------------------------------------------------------------------------
$Script:ADTestFunctionRegistry = [ordered]@{
    'UserAccounts'             = 'Test-ADUserSecurity'
    'PrivilegedGroups'         = 'Test-ADPrivilegedGroups'
    'AdminSDHolder'            = 'Test-AdminSDHolder'
    'GroupPolicies'            = 'Test-ADGroupPolicies'
    'ReplicationSecurity'      = 'Test-ADReplicationSecurity'
    'DomainSecurity'           = 'Test-ADDomainSecurity'
    'DangerousPermissions'     = 'Test-ADDangerousPermissions'
    'CertificateServices'      = 'Test-ADCertificateServices'
    'ADCSExtended'             = 'Test-ADCSExtended'
    'KRBTGTAccount'            = 'Test-KRBTGTAccount'
    'DomainTrusts'             = 'Test-ADDomainTrusts'
    'LAPSDeployment'           = 'Test-LAPSDeployment'
    'AuditPolicyConfiguration' = 'Test-AuditPolicyConfiguration'
    'ConstrainedDelegation'    = 'Test-ConstrainedDelegation'
    'DomainAdminEquivalence'   = 'Test-ADDomainAdminEquivalence'
    'MachineAccountQuota'      = 'Test-ADMachineAccountQuota'
    'DomainHardeningFlags'     = 'Test-ADDomainHardeningFlags'
    'CoercionAndRelayExposure' = 'Test-ADCoercionAndRelayExposure'
    'DnsSecurity'              = 'Test-ADDnsSecurity'
    'LegacyAuthSurface'        = 'Test-ADLegacyAuthSurface'
    'KerberosHardening'        = 'Test-ADKerberosHardening'
    'StaleObjectDepth'         = 'Test-ADStaleObjectDepth'
    'GpoDeployedSecrets'       = 'Test-ADGpoDeployedSecrets'
    'KnownDCVulnerabilities'   = 'Test-ADKnownDCVulnerabilities'
    'ExchangeEscalation'       = 'Test-ADExchangeEscalation'
    'RodcSecurity'             = 'Test-ADRodcSecurity'
    'ControlPaths'             = 'Test-ADControlPaths'
}

function ConvertTo-ADHashtable {
    <#
    .SYNOPSIS
        Recursively converts PSCustomObject/array output of ConvertFrom-Json
        into nested [hashtable]/[array] structures.
    .DESCRIPTION
        Windows PowerShell 5.1's ConvertFrom-Json has no -AsHashtable switch,
        but Get-ADSnapshot's consumers (Test-* functions) declare a
        [hashtable]$Snapshot parameter. This walks the deserialised object
        graph and rebuilds it as hashtables/arrays/scalars so a snapshot
        round-trips through -ToJson / -FromSnapshot without a type mismatch.
    .PARAMETER InputObject
        The object to convert (typically the output of ConvertFrom-Json).
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        $InputObject
    )

    process {
        if ($null -eq $InputObject) {
            return $null
        }
        elseif ($InputObject -is [System.Management.Automation.PSCustomObject]) {
            $hash = @{}
            foreach ($prop in $InputObject.PSObject.Properties) {
                $hash[$prop.Name] = ConvertTo-ADHashtable -InputObject $prop.Value
            }
            return $hash
        }
        elseif ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $list = New-Object System.Collections.ArrayList
            foreach ($item in $InputObject) {
                [void]$list.Add((ConvertTo-ADHashtable -InputObject $item))
            }
            return , $list.ToArray()
        }
        else {
            return $InputObject
        }
    }
}

function ConvertTo-ADFlatAce {
    <#
    .SYNOPSIS
        Flattens an AuthorizationRuleCollection (nTSecurityDescriptor.Access)
        into plain, JSON-serialisable records.
    .DESCRIPTION
        ActiveDirectoryAccessRule objects don't round-trip through
        ConvertTo-Json/ConvertFrom-Json cleanly (SID/GUID typed members,
        circular refs). This captures just the fields the detection modules
        actually evaluate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Access
    )

    foreach ($ace in $Access) {
        [PSCustomObject]@{
            IdentityReference     = "$($ace.IdentityReference.Value)"
            ActiveDirectoryRights = "$($ace.ActiveDirectoryRights)"
            AccessControlType     = "$($ace.AccessControlType)"
            IsInherited           = [bool]$ace.IsInherited
            InheritanceType       = "$($ace.InheritanceType)"
            ObjectType            = "$($ace.ObjectType)"
            InheritedObjectType   = "$($ace.InheritedObjectType)"
        }
    }
}

function Get-ADSnapshot {
    <#
    .SYNOPSIS
        Performs one paged, read-only collection pass over the core AD
        object sets and returns them as a single structured snapshot.
    .DESCRIPTION
        Collects users, computers, groups, GPOs (+ permissions), ACLs on key
        objects (AdminSDHolder, domain root, AD CS containers), AD CS
        configuration, DNS zones, domain trusts, and DC inventory in one
        pass, so the 150+ individual checks stop re-querying AD for
        overlapping data. Each collection area is independently wrapped in
        try/catch: a missing optional component (e.g. AD CS not installed)
        does not fail the whole snapshot.

        Detection only - every call here is a read. No exploitation,
        coercion, relay, or PoC traffic is performed.
    .PARAMETER ToJson
        Optional path. When supplied, the snapshot is also serialised to
        this path (ConvertTo-Json -Depth 12) for later offline re-analysis
        via Start-ADSecurityAudit -FromSnapshot.
    .OUTPUTS
        [hashtable] with keys: CollectedDate, Domain, DomainControllers,
        Users, Computers, Groups, GPOs, ACLs, ADCS, DnsZones, Trusts,
        MachineAccountQuota, DsHeuristics, DsHeuristicsDN, PreWin2000GroupDN,
        PreWin2000Members.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ToJson
    )

    Write-Verbose "Starting collect-once AD snapshot..."

    # Auto-create the -ToJson output directory up front, the same way
    # Start-ADSecurityAudit now handles -ExportPath, so a bad/missing path
    # fails fast (or just works) instead of surfacing only at the very end
    # after the whole collection pass has already run.
    if ($ToJson) {
        $toJsonDir = Split-Path -Path $ToJson -Parent
        if ($toJsonDir -and -not (Test-Path -Path $toJsonDir)) {
            try {
                Write-Verbose "Get-ADSnapshot: creating -ToJson output directory '$toJsonDir'..."
                New-Item -Path $toJsonDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "Get-ADSnapshot: could not create -ToJson output directory '$toJsonDir': $_"
                return
            }
        }
    }

    # Stage-based progress bar. Each collection area below calls Step()
    # once as it starts, so -Verbose isn't the only way to tell the
    # snapshot is still making progress (mirrors the per-test progress bar
    # in Start-ADSecurityAudit).
    $snapshotStages = @(
        'Domain & Domain Controllers', 'Machine Account Quota', 'dSHeuristics',
        'Pre-Windows 2000 Compatible Access', 'Users', 'Computers', 'Groups',
        'GPOs', 'ACLs on key objects', 'AD CS configuration', 'DNS zones',
        'Domain trusts'
    )
    $Script:ADSnapshotStageIndex = 0
    function Step-ADSnapshotProgress {
        param([Parameter(Mandatory)][string]$Stage)
        $Script:ADSnapshotStageIndex++
        Write-Progress -Activity "Collecting AD Snapshot" `
            -Status "$Script:ADSnapshotStageIndex of $($snapshotStages.Count): $Stage" `
            -PercentComplete (($Script:ADSnapshotStageIndex / $snapshotStages.Count) * 100)
    }

    $snapshot = @{
        CollectedDate     = (Get-Date)
        Domain            = $null
        DomainControllers = @()
        Users             = @()
        Computers         = @()
        Groups            = @()
        GPOs              = @()
        ACLs              = @{}
        ADCS              = @{}
        DnsZones          = @()
        Trusts            = @()
        MachineAccountQuota = $null
        DsHeuristics        = $null
        DsHeuristicsDN      = $null
        PreWin2000GroupDN   = $null
        PreWin2000Members   = @()
    }

    # --- Domain + DC inventory ---
    Step-ADSnapshotProgress -Stage 'Domain & Domain Controllers'
    try {
        Write-Verbose "Get-ADSnapshot: collecting domain info..."
        $rawDomain = Invoke-ADQueryWithRetry -OperationName 'Get-ADDomain (snapshot)' -Query {
            Get-ADDomain -ErrorAction Stop
        }
        # Same flattening fix as Users/Computers/DomainControllers above.
        $snapshot.Domain = [PSCustomObject]@{
            DistinguishedName = $rawDomain.DistinguishedName
            DNSRoot           = $rawDomain.DNSRoot
            NetBIOSName       = $rawDomain.NetBIOSName
            Forest            = $rawDomain.Forest
            DomainSID         = "$($rawDomain.DomainSID)"
        }
        Write-Verbose "Get-ADSnapshot: collected domain '$($snapshot.Domain.DNSRoot)'."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect domain info: $_"
    }

    try {
        Write-Verbose "Get-ADSnapshot: collecting domain controllers..."
        $rawDCs = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADDomainController (snapshot)' -Query {
            Get-ADDomainController -Filter * -ErrorAction Stop
        })
        # Same flattening fix as Users/Computers above - ADDomainController
        # objects carry the same class of case-variant property risk.
        $snapshot.DomainControllers = @($rawDCs | ForEach-Object {
            [PSCustomObject]@{
                Name              = $_.Name
                HostName          = $_.HostName
                ComputerObjectDN  = $_.ComputerObjectDN
                IPv4Address       = $_.IPv4Address
                IsReadOnly        = $_.IsReadOnly
                IsGlobalCatalog   = $_.IsGlobalCatalog
                Enabled           = $_.Enabled
                Site              = $_.Site
                OperatingSystem   = $_.OperatingSystem
            }
        })
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.DomainControllers.Count) domain controller(s)."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect domain controllers: $_"
    }

    # --- Machine Account Quota (ms-DS-MachineAccountQuota on domain root) ---
    # Get-ADDomain does not expose this attribute directly, so it's read via
    # a separate Get-ADObject call against the domain root DN.
    Step-ADSnapshotProgress -Stage 'Machine Account Quota'
    try {
        Write-Verbose "Get-ADSnapshot: collecting ms-DS-MachineAccountQuota..."
        $domainForMaq = if ($snapshot.Domain) { $snapshot.Domain } else { Get-ADDomain -ErrorAction Stop }
        $maqObject = Invoke-ADQueryWithRetry -OperationName 'Get-ADObject ms-DS-MachineAccountQuota (snapshot)' -Query {
            Get-ADObject -Identity $domainForMaq.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop
        }
        if ($maqObject) {
            $snapshot.MachineAccountQuota = $maqObject.'ms-DS-MachineAccountQuota'
        }
        Write-Verbose "Get-ADSnapshot: ms-DS-MachineAccountQuota = $($snapshot.MachineAccountQuota)"
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect ms-DS-MachineAccountQuota: $_"
    }

    # --- dSHeuristics (Directory Service object in the Configuration NC) ---
    Step-ADSnapshotProgress -Stage 'dSHeuristics'
    try {
        Write-Verbose "Get-ADSnapshot: collecting dSHeuristics..."
        $configContextForDsh = ([ADSI]"LDAP://RootDSE").configurationNamingContext
        $dsServiceDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configContextForDsh"
        $snapshot.DsHeuristicsDN = $dsServiceDN
        $dsServiceObject = Invoke-ADQueryWithRetry -OperationName 'Get-ADObject dSHeuristics (snapshot)' -Query {
            Get-ADObject -Identity $dsServiceDN -Properties dSHeuristics -ErrorAction Stop
        }
        if ($dsServiceObject) {
            $snapshot.DsHeuristics = $dsServiceObject.dSHeuristics
        }
        Write-Verbose "Get-ADSnapshot: dSHeuristics = '$($snapshot.DsHeuristics)'"
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect dSHeuristics: $_"
    }

    # --- Pre-Windows 2000 Compatible Access membership (flattened to DNs) ---
    Step-ADSnapshotProgress -Stage 'Pre-Windows 2000 Compatible Access'
    try {
        Write-Verbose "Get-ADSnapshot: collecting Pre-Windows 2000 Compatible Access membership..."
        $preWin2000Group = Invoke-ADQueryWithRetry -OperationName 'Get-ADGroup Pre-Windows 2000 Compatible Access (snapshot)' -Query {
            Get-ADGroup -Filter "Name -eq 'Pre-Windows 2000 Compatible Access'" -ErrorAction Stop
        }
        if ($preWin2000Group) {
            $snapshot.PreWin2000GroupDN = $preWin2000Group.DistinguishedName
            $preWin2000Members = Invoke-ADQueryWithRetry -OperationName 'Get-ADGroupMember Pre-Windows 2000 Compatible Access (snapshot)' -Query {
                Get-ADGroupMember -Identity $preWin2000Group -ErrorAction Stop
            }
            $snapshot.PreWin2000Members = @($preWin2000Members | ForEach-Object { $_.DistinguishedName })
        }
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.PreWin2000Members.Count) Pre-Windows 2000 Compatible Access member(s)."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect Pre-Windows 2000 Compatible Access membership: $_"
    }

    # --- Users (paged) ---
    #
    # NOTE (duplicate-key fix, see CHANGELOG): raw Get-ADUser objects were
    # previously stored directly in the snapshot. The ActiveDirectory
    # module's property bag can surface the same attribute under two
    # differently-cased names (e.g. the typed 'ObjectGUID' property
    # alongside a case-variant extended property) - both serialise fine to
    # JSON text, but ConvertFrom-Json's case-insensitive key comparer then
    # throws "dictionary ... contains the duplicated keys 'ObjectGuid' and
    # 'ObjectGUID'" when reading it back via -FromSnapshot. Flattening to a
    # plain PSCustomObject with an explicit, single-cased property list
    # (same pattern as Groups/GPOs/ADCS/Trusts above) avoids the whole
    # class of issue, not just this one attribute pair.
    Step-ADSnapshotProgress -Stage 'Users'
    try {
        Write-Verbose "Get-ADSnapshot: collecting users..."
        $rawUsers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADUser (snapshot)' -Query {
            Get-ADUser -Filter '*' -ResultPageSize 500 -ErrorAction Stop -Properties `
                DoesNotRequirePreAuth, UseDESKeyOnly, AllowReversiblePasswordEncryption, `
                PasswordNeverExpires, TrustedForDelegation, LastLogonDate, PasswordLastSet, `
                ServicePrincipalNames, MemberOf, Enabled, DistinguishedName, `
                UserPrincipalName, adminCount, SamAccountName, SID, Description, `
                'msDS-SupportedEncryptionTypes', userAccountControl, WhenCreated, `
                'msDS-AllowedToDelegateTo', SIDHistory, PrimaryGroupID
        })
        $snapshot.Users = @($rawUsers | ForEach-Object {
            [PSCustomObject]@{
                Name                                 = $_.Name
                SamAccountName                        = $_.SamAccountName
                DistinguishedName                     = $_.DistinguishedName
                UserPrincipalName                     = $_.UserPrincipalName
                SID                                   = "$($_.SID)"
                Description                           = $_.Description
                Enabled                                = $_.Enabled
                DoesNotRequirePreAuth                 = $_.DoesNotRequirePreAuth
                UseDESKeyOnly                          = $_.UseDESKeyOnly
                AllowReversiblePasswordEncryption     = $_.AllowReversiblePasswordEncryption
                PasswordNeverExpires                   = $_.PasswordNeverExpires
                TrustedForDelegation                   = $_.TrustedForDelegation
                LastLogonDate                          = $_.LastLogonDate
                PasswordLastSet                        = $_.PasswordLastSet
                ServicePrincipalNames                  = @($_.ServicePrincipalNames)
                MemberOf                                = @($_.MemberOf)
                adminCount                              = $_.adminCount
                'msDS-SupportedEncryptionTypes'        = $_.'msDS-SupportedEncryptionTypes'
                userAccountControl                     = $_.userAccountControl
                WhenCreated                             = $_.WhenCreated
                'msDS-AllowedToDelegateTo'              = @($_.'msDS-AllowedToDelegateTo')
                SIDHistory                              = @($_.SIDHistory | ForEach-Object { "$_" })
                PrimaryGroupID                          = $_.PrimaryGroupID
            }
        })
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.Users.Count) users."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect users: $_"
    }

    # --- Computers (paged) ---
    # Same flattening fix as Users above. Note: msDS-AllowedToActOnBehalfOfOtherIdentity
    # (RBCD) is intentionally no longer collected here - it's a binary
    # security-descriptor attribute (same risk class as nTSecurityDescriptor,
    # see the AD CS note above) and no -Snapshot-aware check currently reads
    # it from Computers (src/DelegationAudits.ps1's RBCD check is live-only).
    # Re-add it, flattened to an SDDL string, if a snapshot-aware RBCD check
    # is added later.
    Step-ADSnapshotProgress -Stage 'Computers'
    try {
        Write-Verbose "Get-ADSnapshot: collecting computers..."
        $rawComputers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADComputer (snapshot)' -Query {
            Get-ADComputer -Filter '*' -ResultPageSize 500 -ErrorAction Stop -Properties `
                OperatingSystem, OperatingSystemVersion, LastLogonDate, Enabled, `
                DistinguishedName, TrustedForDelegation, 'msDS-AllowedToDelegateTo', `
                PrimaryGroupID, SID, 'ms-Mcs-AdmPwdExpirationTime', `
                'msLAPS-PasswordExpirationTime', userAccountControl, WhenCreated, `
                SamAccountName, ServicePrincipalNames
        })
        $snapshot.Computers = @($rawComputers | ForEach-Object {
            [PSCustomObject]@{
                Name                                = $_.Name
                SamAccountName                       = $_.SamAccountName
                DistinguishedName                    = $_.DistinguishedName
                SID                                  = "$($_.SID)"
                Enabled                               = $_.Enabled
                OperatingSystem                       = $_.OperatingSystem
                OperatingSystemVersion                = $_.OperatingSystemVersion
                LastLogonDate                          = $_.LastLogonDate
                TrustedForDelegation                   = $_.TrustedForDelegation
                'msDS-AllowedToDelegateTo'              = @($_.'msDS-AllowedToDelegateTo')
                PrimaryGroupID                          = $_.PrimaryGroupID
                'ms-Mcs-AdmPwdExpirationTime'          = $_.'ms-Mcs-AdmPwdExpirationTime'
                'msLAPS-PasswordExpirationTime'        = $_.'msLAPS-PasswordExpirationTime'
                userAccountControl                     = $_.userAccountControl
                WhenCreated                             = $_.WhenCreated
                ServicePrincipalNames                  = @($_.ServicePrincipalNames)
            }
        })
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.Computers.Count) computers."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect computers: $_"
    }

    # --- Groups (paged; membership flattened to DNs for JSON-friendliness) ---
    Step-ADSnapshotProgress -Stage 'Groups'
    try {
        Write-Verbose "Get-ADSnapshot: collecting groups..."
        $rawGroups = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADGroup (snapshot)' -Query {
            Get-ADGroup -Filter '*' -ResultPageSize 500 -ErrorAction Stop -Properties `
                Members, Description, groupType, adminCount, DistinguishedName, SID
        })
        $snapshot.Groups = @($rawGroups | ForEach-Object {
            [PSCustomObject]@{
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                SID               = "$($_.SID)"
                Description       = $_.Description
                GroupType         = "$($_.groupType)"
                AdminCount        = $_.adminCount
                Members           = @($_.Members)
            }
        })
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.Groups.Count) groups."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect groups: $_"
    }

    # --- GPOs + permissions (flattened; GroupPolicy module objects don't
    #     serialise cleanly) ---
    Step-ADSnapshotProgress -Stage 'GPOs'
    try {
        Write-Verbose "Get-ADSnapshot: collecting GPOs..."
        Import-Module GroupPolicy -ErrorAction Stop
        $rawGpos = Get-GPO -All
        $snapshot.GPOs = @($rawGpos | ForEach-Object {
            $gpo = $_
            $permissions = $null
            try {
                $permissions = Get-GPPermission -Guid $gpo.Id -All -ErrorAction Stop
            }
            catch {
                Write-Verbose "Get-ADSnapshot: failed to get permissions for GPO '$($gpo.DisplayName)': $_"
            }
            [PSCustomObject]@{
                Id               = $gpo.Id.ToString()
                DisplayName      = $gpo.DisplayName
                GpoStatus        = "$($gpo.GpoStatus)"
                CreationTime     = $gpo.CreationTime
                ModificationTime = $gpo.ModificationTime
                Permissions      = @($permissions | ForEach-Object {
                    [PSCustomObject]@{
                        Trustee    = $_.Trustee.Name
                        Permission = "$($_.Permission)"
                    }
                })
            }
        })
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.GPOs.Count) GPOs."
    }
    catch {
        Write-Warning "Get-ADSnapshot: GroupPolicy collection unavailable or failed, skipping: $_"
    }

    # --- ACLs on key objects (flattened ACEs) ---
    Step-ADSnapshotProgress -Stage 'ACLs on key objects'
    try {
        Write-Verbose "Get-ADSnapshot: collecting ACLs on key objects..."
        $domainForAcl = if ($snapshot.Domain) { $snapshot.Domain } else { Get-ADDomain -ErrorAction Stop }
        $aclTargets = @{
            AdminSDHolder = "CN=AdminSDHolder,CN=System,$($domainForAcl.DistinguishedName)"
            DomainRoot    = $domainForAcl.DistinguishedName
        }

        $configContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
        $pkiContainer = "CN=Public Key Services,CN=Services,$configContext"
        $aclTargets['CertificateTemplatesContainer'] = "CN=Certificate Templates,$pkiContainer"

        foreach ($targetName in $aclTargets.Keys) {
            try {
                $obj = Get-ADObject -Identity $aclTargets[$targetName] -Properties nTSecurityDescriptor -ErrorAction Stop
                $snapshot.ACLs[$targetName] = @{
                    DistinguishedName = $obj.DistinguishedName
                    Owner             = "$($obj.nTSecurityDescriptor.Owner)"
                    Access            = @(ConvertTo-ADFlatAce -Access @($obj.nTSecurityDescriptor.Access))
                }
            }
            catch {
                Write-Verbose "Get-ADSnapshot: could not read ACL for '$targetName' ($($aclTargets[$targetName])): $_"
            }
        }
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed during ACL collection: $_"
    }

    # --- AD CS configuration (templates + CAs); optional component ---
    #
    # NOTE (perf/hang fix, see CHANGELOG): this used to request
    # -Properties * on both containers. That pulls back every attribute on
    # every template/CA object, including nTSecurityDescriptor (a full ACL,
    # with per-ACE IdentityReference objects) and other large/binary
    # attributes never read by Test-ADCSExtended. ConvertTo-Json -Depth 12
    # then has to walk that entire object graph for every template and CA,
    # which is what made -ToJson appear to hang on any domain with more
    # than a handful of templates - it wasn't stuck, it was serialising
    # kilobytes of ACL/attribute data per object with no progress reported.
    # Only the properties Test-ADCSExtended actually reads (see
    # src/CertificateServicesExtendedAudits.ps1) are requested here; keep
    # this list and that file in sync if new snapshot-aware ADCS checks are
    # added.
    Step-ADSnapshotProgress -Stage 'AD CS configuration'
    try {
        Write-Verbose "Get-ADSnapshot: collecting AD CS configuration..."
        $configContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
        $pkiContainer = "CN=Public Key Services,CN=Services,$configContext"

        $templateProperties = @(
            'displayName', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
            'msPKI-Certificate-Application-Policy', 'pKIExtendedKeyUsage'
        )
        $caProperties = @('dNSHostName', 'cACertificate')

        Write-Verbose "Get-ADSnapshot: collecting certificate templates..."
        $certTemplates = Get-ADObject -SearchBase "CN=Certificate Templates,$pkiContainer" -Filter * -Properties $templateProperties -ErrorAction Stop
        Write-Verbose "Get-ADSnapshot: collected $(@($certTemplates).Count) certificate template(s)."

        $certAuthorities = $null
        try {
            Write-Verbose "Get-ADSnapshot: collecting certificate authorities..."
            $certAuthorities = Get-ADObject -SearchBase "CN=Enrollment Services,$pkiContainer" -Filter * -Properties $caProperties -ErrorAction Stop
            Write-Verbose "Get-ADSnapshot: collected $(@($certAuthorities).Count) certificate authority(ies)."
        }
        catch {
            Write-Verbose "Get-ADSnapshot: no Enrollment Services container found: $_"
        }

        # Flatten to plain PSCustomObjects (same rationale as Groups/GPOs
        # above): the raw Get-ADObject type carries schema/property-cache
        # metadata that ConvertTo-Json otherwise has to traverse too.
        $snapshot.ADCS = @{
            Installed = $true
            CertificateTemplates = @($certTemplates | ForEach-Object {
                [PSCustomObject]@{
                    Name                                    = $_.Name
                    DistinguishedName                       = $_.DistinguishedName
                    displayName                              = $_.displayName
                    'msPKI-Certificate-Name-Flag'            = $_.'msPKI-Certificate-Name-Flag'
                    'msPKI-Enrollment-Flag'                  = $_.'msPKI-Enrollment-Flag'
                    'msPKI-Certificate-Application-Policy'   = @($_.'msPKI-Certificate-Application-Policy')
                    pKIExtendedKeyUsage                      = @($_.pKIExtendedKeyUsage)
                }
            })
            CertificateAuthorities = @($certAuthorities | ForEach-Object {
                [PSCustomObject]@{
                    Name               = $_.Name
                    DistinguishedName  = $_.DistinguishedName
                    dNSHostName        = $_.dNSHostName
                    cACertificate      = @($_.cACertificate)
                }
            })
        }
    }
    catch {
        Write-Verbose "Get-ADSnapshot: AD CS not found or not accessible, recording as not installed: $_"
        $snapshot.ADCS = @{ Installed = $false; CertificateTemplates = @(); CertificateAuthorities = @() }
    }

    # --- DNS zones (optional; AD-integrated zones live in an app partition) ---
    Step-ADSnapshotProgress -Stage 'DNS zones'
    try {
        Write-Verbose "Get-ADSnapshot: collecting DNS zones..."
        $domainForDns = if ($snapshot.Domain) { $snapshot.Domain } else { Get-ADDomain -ErrorAction Stop }
        $forest = Get-ADForest -ErrorAction SilentlyContinue
        $dnsPartitions = @(
            "DC=DomainDnsZones,$($domainForDns.DistinguishedName)"
        )
        if ($forest) {
            $forestRootDN = ($forest.RootDomain | ForEach-Object { "DC=$($_ -replace '\.', ',DC=')" })
            $dnsPartitions += "DC=ForestDnsZones,$forestRootDN"
        }

        $zones = @()
        foreach ($partition in $dnsPartitions) {
            try {
                $zones += Get-ADObject -SearchBase "CN=MicrosoftDNS,$partition" -Filter "objectClass -eq 'dnsZone'" -ErrorAction Stop |
                    Select-Object Name, DistinguishedName
            }
            catch {
                Write-Verbose "Get-ADSnapshot: no DNS zones found under '$partition': $_"
            }
        }
        $snapshot.DnsZones = @($zones)
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.DnsZones.Count) DNS zones."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed during DNS zone collection: $_"
    }

    # --- Domain trusts ---
    # Same -Properties * fix as AD CS above: only Target, TrustAttributes,
    # Direction, and TrustType are ever read from Snapshot.Trusts (see
    # src/KerberosHardeningAudits.ps1). Trusts can carry large binary
    # attributes (e.g. trustAuthIncoming/trustAuthOutgoing key history) that
    # -Properties * would otherwise pull into the JSON snapshot for no
    # reason.
    Step-ADSnapshotProgress -Stage 'Domain trusts'
    try {
        Write-Verbose "Get-ADSnapshot: collecting domain trusts..."
        $rawTrusts = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADTrust (snapshot)' -Query {
            Get-ADTrust -Filter * -Properties trustAttributes, Direction, TrustType -ErrorAction Stop
        })
        $snapshot.Trusts = @($rawTrusts | ForEach-Object {
            [PSCustomObject]@{
                Target          = $_.Target
                trustAttributes = $_.trustAttributes
                Direction       = "$($_.Direction)"
                TrustType       = "$($_.TrustType)"
            }
        })
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.Trusts.Count) trusts."
    }
    catch {
        Write-Verbose "Get-ADSnapshot: no domain trusts found or Get-ADTrust unavailable: $_"
    }

    Write-Progress -Activity "Collecting AD Snapshot" -Completed

    if ($ToJson) {
        try {
            Write-Verbose "Get-ADSnapshot: serialising snapshot to JSON (this can take a while on domains with many users/computers)..."
            $serializeStart = Get-Date
            $snapshot | ConvertTo-Json -Depth 12 | Out-File -FilePath $ToJson -Encoding UTF8
            $serializeSeconds = ((Get-Date) - $serializeStart).TotalSeconds
            Write-Verbose "Get-ADSnapshot: wrote snapshot to '$ToJson' in $([math]::Round($serializeSeconds, 1))s."
        }
        catch {
            Write-Warning "Get-ADSnapshot: failed to write -ToJson output to '$ToJson': $_"
        }
    }

    Write-Verbose "Get-ADSnapshot: collection pass complete."
    return $snapshot
}

function Invoke-ADRuleSet {
    <#
    .SYNOPSIS
        Dispatches the registered Test-* audit functions against a snapshot.
    .DESCRIPTION
        Iterates $Script:ADTestFunctionRegistry (the same test set Main.ps1's
        live audit runs) and, for each function, checks whether it declares
        a -Snapshot parameter via (Get-Command $fn).Parameters.ContainsKey
        ('Snapshot') BEFORE splatting -Snapshot to it. Functions that have
        not yet been retrofitted with -Snapshot are simply invoked live, so
        adding -Snapshot to new modules never breaks ones that lack it.

        Also forwards a small set of well-known threshold parameters
        (InactiveDaysThreshold, PasswordAgeThreshold, MaxPasswordAgeDays)
        only to functions that declare them, using the same
        parameter-existence check.
    .PARAMETER Snapshot
        The snapshot hashtable (from Get-ADSnapshot, or rehydrated via
        ConvertTo-ADHashtable after loading one from JSON).
    .PARAMETER IncludeTests
        Optional list of registry keys to run. Defaults to all registered
        tests.
    .PARAMETER ExcludeTests
        Optional list of registry keys to skip.
    .OUTPUTS
        [ADSecurityFinding[]] - the same finding objects the live audit
        produces; the output/finding schema is unchanged.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Snapshot,

        [Parameter()]
        [string[]]$IncludeTests,

        [Parameter()]
        [string[]]$ExcludeTests = @(),

        [Parameter()]
        [int]$InactiveDaysThreshold = 90,

        [Parameter()]
        [int]$PasswordAgeThreshold = 180
    )

    $candidateParams = @{
        InactiveDaysThreshold = $InactiveDaysThreshold
        PasswordAgeThreshold  = $PasswordAgeThreshold
        MaxPasswordAgeDays    = $PasswordAgeThreshold
    }

    $testKeys = $Script:ADTestFunctionRegistry.Keys
    if ($IncludeTests) {
        $testKeys = $testKeys | Where-Object { $_ -in $IncludeTests }
    }
    $testKeys = $testKeys | Where-Object { $_ -notin $ExcludeTests }
    $testKeys = @($testKeys)

    $allFindings = @()
    $totalTestCount = $testKeys.Count
    $currentTestIndex = 0

    foreach ($testKey in $testKeys) {
        $currentTestIndex++
        Write-Progress -Activity "Running Active Directory Security Audit (offline / snapshot)" `
            -Status "Test $currentTestIndex of $totalTestCount`: $testKey" `
            -PercentComplete (($currentTestIndex / [math]::Max(1, $totalTestCount)) * 100)

        $functionName = $Script:ADTestFunctionRegistry[$testKey]
        $fn = Get-Command -Name $functionName -ErrorAction SilentlyContinue

        if (-not $fn) {
            Write-Warning "Invoke-ADRuleSet: registered function '$functionName' (test '$testKey') not found; skipping."
            continue
        }

        $callParams = @{}
        foreach ($paramName in $candidateParams.Keys) {
            if ($fn.Parameters.ContainsKey($paramName)) {
                $callParams[$paramName] = $candidateParams[$paramName]
            }
        }

        # CRITICAL non-breaking check: only splat -Snapshot to functions that
        # actually declare it. Modules without the parameter are called live.
        if ($fn.Parameters.ContainsKey('Snapshot')) {
            $callParams['Snapshot'] = $Snapshot
            Write-Verbose "Invoke-ADRuleSet: running '$testKey' ($functionName) from snapshot."
        }
        else {
            Write-Verbose "Invoke-ADRuleSet: '$testKey' ($functionName) has no -Snapshot parameter; running live."
        }

        try {
            $results = & $functionName @callParams

            foreach ($result in @($results)) {
                if (-not $result) { continue }

                # Same PSCustomObject -> ADSecurityFinding normalisation as
                # Main.ps1's live loop (e.g. Test-ADDomainAdminEquivalence
                # currently returns PSCustomObject).
                if ($result -is [PSCustomObject] -and $result -isnot [ADSecurityFinding]) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = $result.Category
                    $finding.Issue = $result.Issue
                    $finding.Severity = $result.Severity
                    $finding.SeverityLevel = if ($result.SeverityLevel) {
                        $result.SeverityLevel
                    }
                    else {
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
        catch {
            Write-Warning "Invoke-ADRuleSet: test '$testKey' ($functionName) failed: $_"
        }
    }

    Write-Progress -Activity "Running Active Directory Security Audit (offline / snapshot)" -Completed

    return $allFindings
}

#endregion
