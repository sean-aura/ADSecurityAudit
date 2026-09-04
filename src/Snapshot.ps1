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
    'ADCSChaseFallback'        = 'Test-ADCSChaseFallback'
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
    .PARAMETER Server
        Optional override for which domain/DC every query in this
        collection pass targets - a domain FQDN (e.g. 'domainb.corp.com')
        or a specific DC FQDN/hostname. When omitted, defaults to the
        current user's own domain ($env:USERDNSDOMAIN) rather than the
        ambiguous default serverless bind - pass this explicitly only when
        collecting a domain OTHER than your own account's domain.
    .OUTPUTS
        [hashtable] with keys: CollectedDate, Domain, DomainControllers,
        Users, Computers, Groups, GPOs, ACLs, ADCS, DnsZones, Trusts,
        MachineAccountQuota, DsHeuristics, DsHeuristicsDN, PreWin2000GroupDN,
        PreWin2000Members, LapsSchema, PasswordPolicy, Forest,
        RecycleBinEnabled, PrivilegedUserAcls (added in v1.19.0's
        offline-parity backlog - see CHANGELOG 1.19.0 for the per-field
        breakdown of what moved from live-only to snapshot-backed).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ToJson,

        [Parameter()]
        [string]$Server
    )

    Write-Verbose "Starting collect-once AD snapshot..."

    # See Resolve-ADSecurityAuditTargetServer/Set-ADSecurityAuditTargetServer
    # in Common.ps1: -Server, if supplied, forces every Get-AD*/Set-AD* call
    # in this collection pass to explicitly target it. If NOT supplied,
    # defaults to the current user's own domain ($env:USERDNSDOMAIN)
    # instead of the ambiguous default serverless bind. Cleared before
    # every exit point below (including the early return just after this).
    # Reset run-scope notes (e.g. a "PDC-only" check running against an
    # explicitly-named non-PDC DC - see Common.ps1) before resolving
    # -Server below, which is what can add one.
    Reset-ADRunScopeNotes

    # Tracked BEFORE this call touches anything, so cleanup at every exit
    # point below only removes an override THIS call installed - not one
    # a caller already had active (e.g. this collection pass running
    # nested inside another already-scoped run). Mirrors the
    # $__adAuditServerAlreadyActive pattern used by the Test-AD* checks in
    # AdminSDAudits.ps1/DomainAdminEquivalence.ps1/etc.
    $__snapshotServerAlreadyActive = [bool](Get-ADSecurityAuditActiveServerOverride)

    $effectiveServer = if ($__snapshotServerAlreadyActive) {
        # An override is already active for this session (e.g. this
        # collection pass is running inside a Start-ADSecurityAudit run
        # that already resolved and installed one) - reuse it directly.
        # Re-running Resolve-ADSecurityAuditTargetServer against an
        # already-resolved value (a domain's PDC Emulator FQDN) would
        # misclassify it as an operator-named explicit DC and corrupt the
        # shared explicit-DC scope flag other checks in the same run rely
        # on - see Resolve-ADSecurityAuditTargetServer's own idempotency
        # guard for the full explanation. This was a real, confirmed bug.
        Get-ADSecurityAuditActiveServerOverride
    }
    else {
        Resolve-ADSecurityAuditTargetServer -Server $Server
    }
    if ($effectiveServer) {
        $serverSource = if ($Server) { 'explicit -Server' } else { "your own domain, `$env:USERDNSDOMAIN" }
        Write-Verbose "Get-ADSnapshot: all AD queries in this collection pass will explicitly target '$effectiveServer' ($serverSource)."
        Set-ADSecurityAuditTargetServer -Server $effectiveServer
    }
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
                if ($effectiveServer -and -not $__snapshotServerAlreadyActive) { Clear-ADSecurityAuditTargetServer }
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
        'Pre-Windows 2000 Compatible Access', 'Users',
        'ACLs on privileged (adminCount=1) users', 'LAPS schema presence',
        'Computers', 'Groups', 'GPOs', 'ACLs on key objects',
        'Password policy, forest mode, Recycle Bin', 'AD CS configuration',
        'DNS zones', 'Domain trusts'
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
        TotalDomainControllerCount = $null
        AllDomainControllerComputerObjectDNs = @()
        Users             = @()
        Computers         = @()
        Groups            = @()
        GPOs              = @()
        ACLs              = @{}
        ADCS              = @{}
        DnsZones          = @()
        Trusts            = @()
        MachineAccountQuota = $null
        RunScopeNotes     = @()
        DsHeuristics        = $null
        DsHeuristicsDN      = $null
        PreWin2000GroupDN   = $null
        PreWin2000Members   = @()
        LapsSchema          = $null
        PasswordPolicy      = $null
        Forest              = $null
        RecycleBinEnabled   = $null
        PrivilegedUserAcls  = @()
    }

    # --- Domain + DC inventory ---
    Step-ADSnapshotProgress -Stage 'Domain & Domain Controllers'
    try {
        Write-Verbose "Get-ADSnapshot: collecting domain info..."
        $rawDomain = Invoke-ADQueryWithRetry -OperationName 'Get-ADDomain (snapshot)' -Query {
            Get-ADDomain -Server $effectiveServer -ErrorAction Stop
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
        # Get-ADSecurityAuditDomainController, not a bare
        # Get-ADDomainController -Filter * - the latter is forest-wide
        # regardless of -Server, which would have baked OTHER domains'
        # DCs permanently into this snapshot with no way to correct it
        # later at -FromSnapshot re-analysis time. See Common.ps1 for why.
        $rawDCs = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADSecurityAuditDomainController (snapshot)' -Query {
            Get-ADSecurityAuditDomainController -Server $effectiveServer
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

    # --- True, unscoped domain-wide DC inventory (independent of -Server
    # narrowing) - for Test-ADStaleObjectDepth's "Insufficient Domain
    # Controller Count" redundancy check and its primaryGroupID=516
    # legitimacy check. ---
    #
    # snapshot.DomainControllers above is deliberately -Server-scoped (it
    # feeds live-probe-style consumers that should stay scoped to whichever
    # DC(s) this run was told to touch). But a DC-count redundancy
    # assessment and "which computer objects are legitimately DCs" are
    # properties of the DOMAIN, not of -Server scoping - baking a
    # -Server-narrowed count/DN-list into the snapshot would silently
    # undercount the domain's real DC total (or misclassify a real DC as
    # suspicious) for every future -FromSnapshot analysis of this file,
    # with no way to correct it after the fact. -IgnoreExplicitDCScope
    # still uses $effectiveServer as the query target (so this works even
    # when only one DC was reachable at collection time) but always
    # returns every DC belonging to the resolved domain.
    try {
        Write-Verbose "Get-ADSnapshot: collecting true (unscoped) domain-wide DC count/inventory..."
        $rawAllDCs = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADSecurityAuditDomainController -IgnoreExplicitDCScope (snapshot, true count)' -Query {
            Get-ADSecurityAuditDomainController -Server $effectiveServer -IgnoreExplicitDCScope
        })
        $snapshot.TotalDomainControllerCount = @($rawAllDCs).Count
        $snapshot.AllDomainControllerComputerObjectDNs = @($rawAllDCs | ForEach-Object { $_.ComputerObjectDN } | Where-Object { $_ })
        Write-Verbose "Get-ADSnapshot: true domain-wide DC count is $($snapshot.TotalDomainControllerCount)."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect the true (unscoped) domain-wide DC inventory; Test-ADStaleObjectDepth's DC-count/legitimacy checks will fall back to the possibly -Server-scoped DomainControllers list for this snapshot: $_"
    }

    # --- Machine Account Quota (ms-DS-MachineAccountQuota on domain root) ---
    # Get-ADDomain does not expose this attribute directly, so it's read via
    # a separate Get-ADObject call against the domain root DN.
    Step-ADSnapshotProgress -Stage 'Machine Account Quota'
    try {
        Write-Verbose "Get-ADSnapshot: collecting ms-DS-MachineAccountQuota..."
        $domainForMaq = if ($snapshot.Domain) { $snapshot.Domain } else { Get-ADDomain -Server $effectiveServer -ErrorAction Stop }
        $maqObject = Invoke-ADQueryWithRetry -OperationName 'Get-ADObject ms-DS-MachineAccountQuota (snapshot)' -Query {
            Get-ADObject -Identity $domainForMaq.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -Server $effectiveServer -ErrorAction Stop
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
        $configContextForDsh = Get-ADRootDSEValue -Property configurationNamingContext -Server $effectiveServer
        $dsServiceDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configContextForDsh"
        $snapshot.DsHeuristicsDN = $dsServiceDN
        $dsServiceObject = Invoke-ADQueryWithRetry -OperationName 'Get-ADObject dSHeuristics (snapshot)' -Query {
            Get-ADObject -Identity $dsServiceDN -Properties dSHeuristics -Server $effectiveServer -ErrorAction Stop
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
            Get-ADGroup -Filter "Name -eq 'Pre-Windows 2000 Compatible Access'" -Server $effectiveServer -ErrorAction Stop
        }
        if ($preWin2000Group) {
            $snapshot.PreWin2000GroupDN = $preWin2000Group.DistinguishedName
            $preWin2000Members = Invoke-ADQueryWithRetry -OperationName 'Get-ADGroupMember Pre-Windows 2000 Compatible Access (snapshot)' -Query {
                Get-ADGroupMember -Identity $preWin2000Group -Server $effectiveServer -ErrorAction Stop
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
            Get-ADUser -Filter '*' -ResultPageSize 500 -Server $effectiveServer -ErrorAction Stop -Properties `
                DoesNotRequirePreAuth, UseDESKeyOnly, AllowReversiblePasswordEncryption, `
                PasswordNeverExpires, TrustedForDelegation, LastLogonDate, PasswordLastSet, `
                ServicePrincipalNames, MemberOf, Enabled, DistinguishedName, `
                UserPrincipalName, adminCount, SamAccountName, SID, Description, `
                'msDS-SupportedEncryptionTypes', userAccountControl, WhenCreated, `
                'msDS-AllowedToDelegateTo', SIDHistory, PrimaryGroupID, `
                TrustedToAuthForDelegation, scriptPath
        })

        # --- v1.19.0 offline-parity backlog, step 29 ---
        # Shadow-credentials presence flag: a single, targeted LDAP filter
        # against (msDS-KeyCredentialLink=*), never the raw attribute value
        # (a serialised key-credential blob - same risk class as every other
        # binary/security-descriptor attribute this backlog keeps out of the
        # snapshot). Run once; cross-reference by DN during flattening.
        $shadowCredUserDNs = [System.Collections.Generic.HashSet[string]]::new()
        try {
            @(Invoke-ADQueryWithRetry -OperationName 'Get-ADUser shadow-credentials presence (snapshot)' -Query {
                Get-ADUser -LDAPFilter '(msDS-KeyCredentialLink=*)' -Server $effectiveServer -ErrorAction Stop
            }) | ForEach-Object { [void]$shadowCredUserDNs.Add($_.DistinguishedName) }
        }
        catch {
            Write-Verbose "Get-ADSnapshot: shadow-credentials presence check (Users) failed: $_"
        }

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
                TrustedToAuthForDelegation              = $_.TrustedToAuthForDelegation
                scriptPath                              = $_.scriptPath
                HasShadowCredentials                    = $shadowCredUserDNs.Contains($_.DistinguishedName)
            }
        })
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.Users.Count) users."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect users: $_"
    }

    # --- v1.19.0 offline-parity backlog, step 29 ---
    # ACLs on adminCount=1 users specifically (not every user - keeps the
    # snapshot from ballooning for accounts that will never need this data).
    # Named -Properties only, flattened immediately via ConvertTo-ADFlatAce -
    # never a raw ActiveDirectorySecurity object, even transiently.
    Step-ADSnapshotProgress -Stage 'ACLs on privileged (adminCount=1) users'
    try {
        Write-Verbose "Get-ADSnapshot: collecting ACLs on adminCount=1 users..."
        $adminCountUsersForAcl = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADUser adminCount=1 ACL (snapshot)' -Query {
            Get-ADUser -LDAPFilter '(adminCount=1)' -Properties nTSecurityDescriptor -Server $effectiveServer -ErrorAction Stop
        })
        $snapshot.PrivilegedUserAcls = @($adminCountUsersForAcl | ForEach-Object {
            [PSCustomObject]@{
                DistinguishedName = $_.DistinguishedName
                SamAccountName    = $_.SamAccountName
                Owner             = "$($_.nTSecurityDescriptor.Owner)"
                Access            = @(ConvertTo-ADFlatAce -Access @($_.nTSecurityDescriptor.Access))
            }
        })
        Write-Verbose "Get-ADSnapshot: collected ACLs for $($snapshot.PrivilegedUserAcls.Count) adminCount=1 user(s)."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect ACLs on adminCount=1 users: $_"
    }

    # --- v1.19.0 offline-parity backlog, step 23: LAPS schema presence ---
    # A one-time boolean presence check (legacy LAPS and Windows LAPS schema
    # extensions), for Test-LAPSDeployment's schema-presence gate. Booleans
    # only - no need to carry the schema object itself.
    #
    # BUGFIX: this check now runs BEFORE the Computers collection below (it
    # used to run afterwards, purely for Test-LAPSDeployment's benefit). The
    # Computers query used to unconditionally request the
    # 'ms-Mcs-AdmPwdExpirationTime' and 'msLAPS-PasswordExpirationTime'
    # attributes. Get-ADComputer -Properties throws a terminating error for
    # any attribute name that isn't defined in the schema at all (not just
    # unpopulated) - so on a domain where neither LAPS variant has ever been
    # schema-extended, that single bad -Properties list failed the *entire*
    # Get-ADComputer call. Invoke-ADQueryWithRetry swallows that failure and
    # returns $null, and the surrounding try/catch here only logs a warning -
    # so every computer in the domain silently disappeared from the snapshot
    # (and therefore from every offline check that reads Snapshot.Computers,
    # not just LAPS coverage). Now the two attribute names are only added to
    # the -Properties list when the corresponding schema extension is
    # actually present.
    Step-ADSnapshotProgress -Stage 'LAPS schema presence'
    $legacyLapsPresent = $false
    $windowsLapsPresent = $false
    try {
        Write-Verbose "Get-ADSnapshot: checking LAPS schema presence..."
        $schemaNCForLaps = Get-ADRootDSEValue -Property schemaNamingContext -Server $effectiveServer
        try {
            $legacyLapsPresent = [bool](Get-ADObject -Identity "CN=ms-Mcs-AdmPwd,$schemaNCForLaps" -Server $effectiveServer -ErrorAction SilentlyContinue)
        }
        catch {
            Write-Verbose "Get-ADSnapshot: legacy LAPS schema check failed: $_"
        }
        try {
            $windowsLapsPresent = [bool](Get-ADObject -Identity "CN=ms-LAPS-Password,$schemaNCForLaps" -Server $effectiveServer -ErrorAction SilentlyContinue)
        }
        catch {
            Write-Verbose "Get-ADSnapshot: Windows LAPS schema check failed: $_"
        }
        $snapshot.LapsSchema = @{
            LegacyLapsPresent  = $legacyLapsPresent
            WindowsLapsPresent = $windowsLapsPresent
        }
        Write-Verbose "Get-ADSnapshot: LapsSchema = Legacy:$legacyLapsPresent, Windows:$windowsLapsPresent"
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect LAPS schema presence: $_"
    }

    # --- Computers (paged) ---
    # Same flattening fix as Users above. Note: the raw
    # msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) security descriptor
    # value itself is still never collected here (same risk class as
    # nTSecurityDescriptor) - as of v1.19.0 (step 24), RBCD offline
    # detection instead uses a boolean presence flag (HasRbcdConfigured,
    # below) derived from a targeted LDAP filter.
    Step-ADSnapshotProgress -Stage 'Computers'
    try {
        Write-Verbose "Get-ADSnapshot: collecting computers..."

        # BUGFIX: only request the LAPS attribute(s) that actually exist in
        # this domain's schema - see the LAPS schema presence note above.
        # Requesting a schema-undefined property name fails the whole
        # Get-ADComputer call, not just that one column.
        $computerBaseProperties = @(
            'OperatingSystem', 'OperatingSystemVersion', 'LastLogonDate', 'Enabled',
            'DistinguishedName', 'TrustedForDelegation', 'msDS-AllowedToDelegateTo',
            'PrimaryGroupID', 'SID', 'userAccountControl', 'WhenCreated',
            'SamAccountName', 'ServicePrincipalNames', 'TrustedToAuthForDelegation',
            'PasswordLastSet', 'nTSecurityDescriptor'
        )
        $computerLapsProperties = @()
        if ($legacyLapsPresent)  { $computerLapsProperties += 'ms-Mcs-AdmPwdExpirationTime' }
        if ($windowsLapsPresent) { $computerLapsProperties += 'msLAPS-PasswordExpirationTime' }
        $computerProperties = $computerBaseProperties + $computerLapsProperties

        $rawComputers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADComputer (snapshot)' -Query {
            Get-ADComputer -Filter '*' -ResultPageSize 500 -Server $effectiveServer -ErrorAction Stop -Properties $computerProperties
        } | Where-Object { $_ })

        # --- v1.19.0 offline-parity backlog, step 24 ---
        # RBCD presence flag: targeted LDAP filter, never the raw
        # msDS-AllowedToActOnBehalfOfOtherIdentity security descriptor
        # (intentionally removed from the snapshot in v1.18.2 for the same
        # reason nTSecurityDescriptor is never stored wholesale elsewhere).
        # Scoped to computer objects, matching real-world RBCD/dMSA usage -
        # a deliberate, documented narrowing, not an oversight.
        $rbcdComputerDNs = [System.Collections.Generic.HashSet[string]]::new()
        try {
            @(Invoke-ADQueryWithRetry -OperationName 'Get-ADComputer RBCD presence (snapshot)' -Query {
                Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Server $effectiveServer -ErrorAction Stop
            }) | ForEach-Object { [void]$rbcdComputerDNs.Add($_.DistinguishedName) }
        }
        catch {
            Write-Verbose "Get-ADSnapshot: RBCD presence check failed: $_"
        }

        # --- v1.19.0 offline-parity backlog, step 29 ---
        # Shadow-credentials presence flag - same pattern as RBCD above,
        # never the raw msDS-KeyCredentialLink value.
        $shadowCredComputerDNs = [System.Collections.Generic.HashSet[string]]::new()
        try {
            @(Invoke-ADQueryWithRetry -OperationName 'Get-ADComputer shadow-credentials presence (snapshot)' -Query {
                Get-ADComputer -LDAPFilter '(msDS-KeyCredentialLink=*)' -Server $effectiveServer -ErrorAction Stop
            }) | ForEach-Object { [void]$shadowCredComputerDNs.Add($_.DistinguishedName) }
        }
        catch {
            Write-Verbose "Get-ADSnapshot: shadow-credentials presence check (Computers) failed: $_"
        }

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
                TrustedToAuthForDelegation              = $_.TrustedToAuthForDelegation
                HasRbcdConfigured                       = $rbcdComputerDNs.Contains($_.DistinguishedName)
                PasswordLastSet                         = $_.PasswordLastSet
                HasShadowCredentials                    = $shadowCredComputerDNs.Contains($_.DistinguishedName)
                Access                                   = @(ConvertTo-ADFlatAce -Access @($_.nTSecurityDescriptor.Access))
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
            Get-ADGroup -Filter '*' -ResultPageSize 500 -Server $effectiveServer -ErrorAction Stop -Properties `
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
        $rawGpos = Get-GPO -All -Server $effectiveServer

        # --- v1.19.0 offline-parity backlog, step 22 ---
        # Single pass over every OU and the domain root's gPLink attribute,
        # building a GUID -> [linked DNs] reverse index once, instead of the
        # live code's O(GPOs x OUs) per-GPO Get-ADObject -Filter "gPLink -like
        # '*<guid>*'" pattern. gPLink format: "[LDAP://cn={GUID},cn=policies,
        # cn=system,DC=...;<options>][...]" - domain functional level can put
        # gPLink on non-OU containers too, so this filters broadly rather
        # than assuming OUs only.
        $linkIndex = @{}
        try {
            $domainForGpLink = if ($snapshot.Domain) { $snapshot.Domain } else { Get-ADDomain -Server $effectiveServer -ErrorAction Stop }
            $gpLinkObjects = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADObject gPLink (snapshot)' -Query {
                Get-ADObject -Filter "gPLink -like '*'" -Properties gPLink, DistinguishedName -ResultPageSize 500 -Server $effectiveServer -ErrorAction Stop
            })
            foreach ($linkedObj in $gpLinkObjects) {
                if (-not $linkedObj.gPLink) { continue }
                $guidMatches = [regex]::Matches($linkedObj.gPLink, '(?i)cn=\{([0-9A-F-]{36})\}')
                foreach ($m in $guidMatches) {
                    $guid = $m.Groups[1].Value.ToUpper()
                    if (-not $linkIndex.ContainsKey($guid)) {
                        $linkIndex[$guid] = [System.Collections.ArrayList]::new()
                    }
                    [void]$linkIndex[$guid].Add($linkedObj.DistinguishedName)
                }
            }
        }
        catch {
            Write-Verbose "Get-ADSnapshot: gPLink single-pass collection failed (LinkedTo will be empty): $_"
        }

        $snapshot.GPOs = @($rawGpos | ForEach-Object {
            $gpo = $_
            $permissions = $null
            try {
                $permissions = Get-GPPermission -Guid $gpo.Id -All -Server $effectiveServer -ErrorAction Stop
            }
            catch {
                Write-Verbose "Get-ADSnapshot: failed to get permissions for GPO '$($gpo.DisplayName)': $_"
            }
            $gpoGuidUpper = $gpo.Id.ToString().ToUpper().Trim('{', '}')
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
                LinkedTo         = if ($linkIndex.ContainsKey($gpoGuidUpper)) { @($linkIndex[$gpoGuidUpper]) } else { @() }
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
        $domainForAcl = if ($snapshot.Domain) { $snapshot.Domain } else { Get-ADDomain -Server $effectiveServer -ErrorAction Stop }
        $aclTargets = @{
            AdminSDHolder = "CN=AdminSDHolder,CN=System,$($domainForAcl.DistinguishedName)"
            DomainRoot    = $domainForAcl.DistinguishedName
        }

        $configContext = Get-ADRootDSEValue -Property configurationNamingContext -Server $effectiveServer
        $pkiContainer = "CN=Public Key Services,CN=Services,$configContext"
        $aclTargets['CertificateTemplatesContainer'] = "CN=Certificate Templates,$pkiContainer"

        # --- Forest-level coverage backlog: Schema/Configuration NC head ACLs ---
        # Two more fixed ACL targets, for Test-ADDangerousPermissions's new
        # Schema/Configuration naming-context ACL checks. $configContext is
        # already resolved above; schemaNamingContext needs its own RootDSE
        # read (same helper already used for the LAPS check).
        $schemaContext = Get-ADRootDSEValue -Property schemaNamingContext -Server $effectiveServer
        $aclTargets['SchemaNamingContext'] = $schemaContext
        $aclTargets['ConfigurationNamingContext'] = $configContext

        # --- v1.19.0 offline-parity backlog, step 21 ---
        # Three more fixed ACL targets, added for Test-ADDangerousPermissions's
        # critical-OU sweep. Same loop, same flattening - just more dictionary
        # entries. If a domain has renamed/moved one of these containers, the
        # per-target try/catch below already handles it gracefully: the key
        # is simply absent from Snapshot.ACLs, and every -Snapshot-aware
        # consumer must check ContainsKey before reading it.
        $aclTargets['DomainControllersOU'] = "OU=Domain Controllers,$($domainForAcl.DistinguishedName)"
        $aclTargets['UsersContainer']      = "CN=Users,$($domainForAcl.DistinguishedName)"
        $aclTargets['ComputersContainer']  = "CN=Computers,$($domainForAcl.DistinguishedName)"

        foreach ($targetName in $aclTargets.Keys) {
            try {
                $obj = Get-ADObject -Identity $aclTargets[$targetName] -Properties nTSecurityDescriptor -Server $effectiveServer -ErrorAction Stop

                # --- v1.19.0 offline-parity backlog, step 26 ---
                # Audit-rule (SACL) presence, for Test-AuditPolicyConfiguration's
                # two SACL-presence checks. Reading SACL entries requires the
                # caller to both hold SeSecurityPrivilege and have explicitly
                # requested SACL_SECURITY_INFORMATION - running elevated
                # (-RunAsAdministrator) does not guarantee that by itself.
                # Fail safe: $null ("undetermined"), never a misleading
                # $false, so a collection-time privilege limitation can never
                # manifest as a false "no auditing configured" finding.
                $hasAuditRules = $null
                try {
                    $auditRules = $obj.nTSecurityDescriptor.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier])
                    $hasAuditRules = $auditRules.Count -gt 0
                }
                catch {
                    Write-Verbose "Get-ADSnapshot: could not read SACL for '$targetName': $_"
                }

                $snapshot.ACLs[$targetName] = @{
                    DistinguishedName = $obj.DistinguishedName
                    Owner             = "$($obj.nTSecurityDescriptor.Owner)"
                    Access            = @(ConvertTo-ADFlatAce -Access @($obj.nTSecurityDescriptor.Access))
                    HasAuditRules     = $hasAuditRules
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

    # --- v1.19.0 offline-parity backlog, step 27: domain-wide policy/feature state ---
    # Four small, additive single-object reads, for Test-ADDomainSecurity.
    # Each carries only the specific scalars that module reads - never the
    # whole policy/feature/forest object.
    Step-ADSnapshotProgress -Stage 'Password policy, forest mode, Recycle Bin'
    try {
        Write-Verbose "Get-ADSnapshot: collecting default domain password policy..."
        $pwdPolicy = Invoke-ADQueryWithRetry -OperationName 'Get-ADDefaultDomainPasswordPolicy (snapshot)' -Query {
            Get-ADDefaultDomainPasswordPolicy -Server $effectiveServer -ErrorAction Stop
        }
        if ($pwdPolicy) {
            $snapshot.PasswordPolicy = @{
                MinPasswordLength           = $pwdPolicy.MinPasswordLength
                ComplexityEnabled           = $pwdPolicy.ComplexityEnabled
                ReversibleEncryptionEnabled = $pwdPolicy.ReversibleEncryptionEnabled
            }
        }
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect default domain password policy: $_"
    }

    try {
        Write-Verbose "Get-ADSnapshot: collecting forest functional level..."
        $forestForSnapshot = Invoke-ADQueryWithRetry -OperationName 'Get-ADForest (snapshot)' -Query {
            Get-ADForest -Server $effectiveServer -ErrorAction Stop
        }
        if ($forestForSnapshot) {
            $snapshot.Forest = @{ ForestMode = "$($forestForSnapshot.ForestMode)" }
        }
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect forest functional level: $_"
    }

    # --- Forest-level coverage backlog: tombstone lifetime ---
    # Single scalar read off the Directory Service object in the
    # Configuration NC, for Test-ADDomainSecurity's new Short Tombstone
    # Lifetime check. An unset tombstoneLifetime attribute means the
    # effective value is 60 days (per [MS-ADTS] 6.1.1.2.4.1.1), not "no
    # value to report" - so $null is coerced to 60 here, at collection
    # time, rather than leaving that interpretation to every consumer.
    try {
        Write-Verbose "Get-ADSnapshot: collecting forest tombstone lifetime..."
        $configContextForTombstone = if ($configContext) { $configContext } else { Get-ADRootDSEValue -Property configurationNamingContext -Server $effectiveServer }
        $dsObject = Invoke-ADQueryWithRetry -OperationName 'Get-ADObject Directory Service tombstoneLifetime (snapshot)' -Query {
            Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configContextForTombstone" -Properties tombstoneLifetime -Server $effectiveServer -ErrorAction Stop
        }
        if ($dsObject) {
            $snapshot.TombstoneLifetimeDays = if ($null -ne $dsObject.tombstoneLifetime) { [int]$dsObject.tombstoneLifetime } else { 60 }
        }
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect forest tombstone lifetime: $_"
    }

    try {
        Write-Verbose "Get-ADSnapshot: checking AD Recycle Bin status..."
        $recycleBinFeature = Invoke-ADQueryWithRetry -OperationName 'Get-ADOptionalFeature Recycle Bin (snapshot)' -Query {
            Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Server $effectiveServer -ErrorAction Stop
        }
        $snapshot.RecycleBinEnabled = [bool]($recycleBinFeature -and @($recycleBinFeature.EnabledScopes).Count -gt 0)
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to check AD Recycle Bin status: $_"
    }

    # DomainMode is a simple additional field on the Domain object already
    # collected above - fold it in here rather than re-querying Get-ADDomain.
    try {
        if ($snapshot.Domain) {
            $domainModeObj = Invoke-ADQueryWithRetry -OperationName 'Get-ADDomain DomainMode (snapshot)' -Query {
                Get-ADDomain -Server $effectiveServer -ErrorAction Stop
            }
            if ($domainModeObj) {
                $snapshot.Domain = [PSCustomObject]@{
                    DistinguishedName = $snapshot.Domain.DistinguishedName
                    DNSRoot           = $snapshot.Domain.DNSRoot
                    NetBIOSName       = $snapshot.Domain.NetBIOSName
                    Forest            = $snapshot.Domain.Forest
                    DomainSID         = $snapshot.Domain.DomainSID
                    DomainMode        = "$($domainModeObj.DomainMode)"
                }
            }
        }
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect DomainMode: $_"
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
        $configContext = Get-ADRootDSEValue -Property configurationNamingContext -Server $effectiveServer
        $pkiContainer = "CN=Public Key Services,CN=Services,$configContext"

        $templateProperties = @(
            'displayName', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
            'msPKI-Certificate-Application-Policy', 'pKIExtendedKeyUsage',
            'msPKI-RA-Signature'
        )
        $caProperties = @('dNSHostName', 'cACertificate')

        Write-Verbose "Get-ADSnapshot: collecting certificate templates..."
        # -SearchScope OneLevel, not the default Subtree - see the matching
        # comment in CertificateServicesExtendedAudits.ps1. This snapshot
        # is persisted to disk for later offline analysis, so a Subtree
        # search here would have baked the "Certificate Templates"
        # container object itself into every snapshot permanently, with no
        # way to correct it later at -FromSnapshot re-analysis time.
        $certTemplates = Get-ADObject -SearchBase "CN=Certificate Templates,$pkiContainer" -SearchScope OneLevel -Filter * -Properties $templateProperties -Server $effectiveServer -ErrorAction Stop
        Write-Verbose "Get-ADSnapshot: collected $(@($certTemplates).Count) certificate template(s)."

        $certAuthorities = $null
        try {
            Write-Verbose "Get-ADSnapshot: collecting certificate authorities..."
            # Same OneLevel fix - a Subtree search also returns the
            # "Enrollment Services" container object itself, which has no
            # dNSHostName/cACertificate and would otherwise be
            # indistinguishable from a real (but misconfigured) CA once
            # baked into the snapshot.
            $certAuthorities = Get-ADObject -SearchBase "CN=Enrollment Services,$pkiContainer" -SearchScope OneLevel -Filter * -Properties $caProperties -Server $effectiveServer -ErrorAction Stop
            Write-Verbose "Get-ADSnapshot: collected $(@($certAuthorities).Count) certificate authority(ies)."
        }
        catch {
            Write-Verbose "Get-ADSnapshot: no Enrollment Services container found: $_"
        }

        # Flatten to plain PSCustomObjects (same rationale as Groups/GPOs
        # above): the raw Get-ADObject type carries schema/property-cache
        # metadata that ConvertTo-Json otherwise has to traverse too.
        #
        # v1.19.0 offline-parity backlog, step 28: per-template/per-CA ACLs
        # (via the same Get-Acl + ConvertTo-ADFlatAce mechanism used
        # everywhere else in the snapshot), read once per object here.
        # Template/CA counts are small and bounded (tens, and 1-3
        # respectively) - not the same risk class as a domain-wide sweep.
        $snapshot.ADCS = @{
            Installed = $true
            CertificateTemplates = @($certTemplates | ForEach-Object {
                $templateAclAccess = $null
                try {
                    # Get-ADObject -Properties nTSecurityDescriptor, not
                    # Get-Acl -Path "AD:..." - the latter has no -Server
                    # parameter and reads via the AD: PSDrive's ambient
                    # default domain/DC, bypassing $effectiveServer
                    # entirely and baking the WRONG domain's ACL data into
                    # this snapshot permanently with no way to correct it
                    # later at -FromSnapshot re-analysis time.
                    # nTSecurityDescriptor returns the same
                    # ActiveDirectorySecurity object (.Access, etc.) via a
                    # real, -Server-aware Get-AD* cmdlet.
                    $templateAclAccess = (Get-ADObject -Identity $_.DistinguishedName -Properties nTSecurityDescriptor -Server $effectiveServer -ErrorAction Stop).nTSecurityDescriptor.Access
                }
                catch {
                    Write-Verbose "Get-ADSnapshot: could not read ACL for certificate template '$($_.Name)': $_"
                }
                [PSCustomObject]@{
                    Name                                    = $_.Name
                    DistinguishedName                       = $_.DistinguishedName
                    displayName                              = $_.displayName
                    'msPKI-Certificate-Name-Flag'            = $_.'msPKI-Certificate-Name-Flag'
                    'msPKI-Enrollment-Flag'                  = $_.'msPKI-Enrollment-Flag'
                    'msPKI-Certificate-Application-Policy'   = @($_.'msPKI-Certificate-Application-Policy')
                    pKIExtendedKeyUsage                      = @($_.pKIExtendedKeyUsage)
                    'msPKI-RA-Signature'                     = $_.'msPKI-RA-Signature'
                    Access                                    = @(ConvertTo-ADFlatAce -Access @($templateAclAccess))
                }
            })
            CertificateAuthorities = @($certAuthorities | ForEach-Object {
                $caAclAccess = $null
                try {
                    # Get-ADObject -Properties nTSecurityDescriptor, not
                    # Get-Acl -Path "AD:..." - see the matching comment
                    # above on the certificate template ACL read for why.
                    $caAclAccess = (Get-ADObject -Identity $_.DistinguishedName -Properties nTSecurityDescriptor -Server $effectiveServer -ErrorAction Stop).nTSecurityDescriptor.Access
                }
                catch {
                    Write-Verbose "Get-ADSnapshot: could not read ACL for certificate authority '$($_.Name)': $_"
                }
                [PSCustomObject]@{
                    Name               = $_.Name
                    DistinguishedName  = $_.DistinguishedName
                    dNSHostName        = $_.dNSHostName
                    cACertificate      = @($_.cACertificate)
                    Access              = @(ConvertTo-ADFlatAce -Access @($caAclAccess))
                }
            })
        }

        # --- v1.19.1 ---
        # NTAuth/AIA/Root store cACertificate blobs, for Test-ADCSExtended's
        # ROCA/weak-signature sweep. Same data shape and risk profile as
        # CertificateAuthorities.cACertificate above (public certificate
        # bytes, not a key or secret) - just three more fixed, bounded
        # targets (a single object plus its handful of immediate children
        # each), not a domain-wide sweep.
        function Get-ADSnapshotCertBlobSource {
            param([string]$ContainerDN, [string]$Server)
            $blobs = [System.Collections.ArrayList]::new()
            try {
                $obj = Get-ADObject -Identity $ContainerDN -Properties cACertificate, cn -Server $Server -ErrorAction Stop
                foreach ($b in @($obj.cACertificate)) {
                    if ($b) { [void]$blobs.Add([PSCustomObject]@{ Source = $obj.Name; Bytes = $b }) }
                }
            }
            catch {
                Write-Verbose "Get-ADSnapshot: could not read '$ContainerDN' directly: $_"
            }
            try {
                $children = Get-ADObject -SearchBase $ContainerDN -SearchScope OneLevel -Filter * -Properties cACertificate, cn -Server $Server -ErrorAction Stop
                foreach ($child in $children) {
                    foreach ($b in @($child.cACertificate)) {
                        if ($b) { [void]$blobs.Add([PSCustomObject]@{ Source = $child.Name; Bytes = $b }) }
                    }
                }
            }
            catch {
                Write-Verbose "Get-ADSnapshot: could not enumerate children of '$ContainerDN': $_"
            }
            return @($blobs)
        }

        if ($snapshot.ADCS.Installed) {
            $snapshot.ADCS.NTAuthCertificates = @(Get-ADSnapshotCertBlobSource -ContainerDN "CN=NTAuthCertificates,$pkiContainer" -Server $effectiveServer)
            $snapshot.ADCS.AIACertificates = @(Get-ADSnapshotCertBlobSource -ContainerDN "CN=AIA,$pkiContainer" -Server $effectiveServer)
            $snapshot.ADCS.RootCACertificates = @(Get-ADSnapshotCertBlobSource -ContainerDN "CN=Certification Authorities,$pkiContainer" -Server $effectiveServer)
        }
    }
    catch {
        Write-Verbose "Get-ADSnapshot: AD CS not found or not accessible, recording as not installed: $_"
        $snapshot.ADCS = @{
            Installed = $false; CertificateTemplates = @(); CertificateAuthorities = @()
            NTAuthCertificates = @(); AIACertificates = @(); RootCACertificates = @()
        }
    }

    # --- DNS zones (optional; AD-integrated zones live in an app partition) ---
    Step-ADSnapshotProgress -Stage 'DNS zones'
    try {
        Write-Verbose "Get-ADSnapshot: collecting DNS zones..."
        $domainForDns = if ($snapshot.Domain) { $snapshot.Domain } else { Get-ADDomain -Server $effectiveServer -ErrorAction Stop }
        $forest = Get-ADForest -Server $effectiveServer -ErrorAction SilentlyContinue
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
                $zones += Get-ADObject -SearchBase "CN=MicrosoftDNS,$partition" -Filter "objectClass -eq 'dnsZone'" -Server $effectiveServer -ErrorAction Stop |
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
        # --- v1.19.0 offline-parity backlog, step 25 ---
        # Four more plain scalars (two booleans, two datetimes) added to the
        # already-narrowed property list from the v1.18.1 hang fix. No
        # binary/key-history attributes reintroduced.
        $rawTrusts = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADTrust (snapshot)' -Query {
            Get-ADTrust -Filter * -Properties trustAttributes, Direction, TrustType, `
                SIDFilteringQuarantined, SelectiveAuthentication, Created, Modified -Server $effectiveServer -ErrorAction Stop
        })
        $snapshot.Trusts = @($rawTrusts | ForEach-Object {
            [PSCustomObject]@{
                Target                   = $_.Target
                trustAttributes          = $_.trustAttributes
                Direction                = "$($_.Direction)"
                TrustType                = "$($_.TrustType)"
                SIDFilteringQuarantined  = $_.SIDFilteringQuarantined
                SelectiveAuthentication  = $_.SelectiveAuthentication
                Created                  = $_.Created
                Modified                 = $_.Modified
            }
        })
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.Trusts.Count) trusts."
    }
    catch {
        Write-Verbose "Get-ADSnapshot: no domain trusts found or Get-ADTrust unavailable: $_"
    }

    Write-Progress -Activity "Collecting AD Snapshot" -Completed

    # Persist any run-scope notes recorded during THIS collection pass
    # (e.g. -Server named an explicit, non-PDC DC) into the snapshot
    # itself, so a later -FromSnapshot analysis - which performs no live
    # resolution of its own - can still surface a scoping condition that
    # was true at collection time.
    $snapshot.RunScopeNotes = @(Get-ADRunScopeNotes)

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
    if ($effectiveServer -and -not $__snapshotServerAlreadyActive) { Clear-ADSecurityAuditTargetServer }
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
        ('Snapshot') BEFORE splatting -Snapshot to it.

        By default, a function that has not yet been retrofitted with
        -Snapshot is SKIPPED (with a warning), not run live. This is what
        actually honors Start-ADSecurityAudit -FromSnapshot's documented
        "no live AD access is performed" contract.

        As of v1.19.0, all 27 registered tests declare -Snapshot, fully or
        partially (see README's "-FromSnapshot coverage" section for the
        small number of remaining live-only sub-checks - e.g. SYSVOL's
        file-share ACL, the per-DC auditpol read - which are genuinely
        real-time machine/network state with no AD-schema equivalent and so
        stay live-only even under -Snapshot, the same way
        Test-ADCoercionAndRelayExposure's and Test-ADLegacyAuthSurface's
        live-only sub-checks already did before this release). This skip
        path remains in place for safety (e.g. a future new test that hasn't
        been retrofitted yet), it just has nothing to skip today.

        Pass -AllowLiveFallbackForUnsupportedTests to restore the old
        behaviour (run unsupported tests live instead of skipping them) if
        you specifically want a partial-live/partial-offline run.

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
    .PARAMETER AllowLiveFallbackForUnsupportedTests
        When set, tests that don't declare -Snapshot are run live instead
        of being skipped. Off by default so -FromSnapshot performs no live
        AD access unless explicitly opted into.
    .OUTPUTS
        [ADSecurityFinding[]] - the same finding objects the live audit
        produces; the output/finding schema is unchanged. Also records
        per-test outcomes (Completed/Failed/Excluded) via
        Add-ADTestCoverageEntry (Common.ps1) as a side effect, readable
        afterward via Get-ADTestCoverageTracker - a caller that doesn't
        need this (most direct callers) can simply ignore it, same as
        Get-ADOfflineSkipNotes.
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
        [int]$PasswordAgeThreshold = 180,

        [Parameter()]
        [switch]$AllowLiveFallbackForUnsupportedTests
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

    # Same "record every registered test, not just the ones that ran"
    # coverage tracking as Main.ps1's live test loop - see
    # Add-ADTestCoverageEntry's own docs (Common.ps1) for why this exists
    # here at all (Invoke-ADRuleSet is a separate dispatch path from that
    # loop, so $testCoverage was never populated for -FromSnapshot runs
    # without this). Tests filtered out by -IncludeTests/-ExcludeTests
    # before ever being attempted are recorded here; Completed/Failed/the
    # "no -Snapshot support" Excluded case are recorded per-test in the
    # loop below as each outcome becomes known.
    foreach ($registryKey in ($Script:ADTestFunctionRegistry.Keys | Sort-Object)) {
        if ($registryKey -notin $testKeys) {
            Add-ADTestCoverageEntry -TestName $registryKey -Status 'Excluded' `
                -ErrorMessage 'Not run for this scan (see -IncludeTests/-ExcludeTests used for this run).'
        }
    }

    $allFindings = @()
    $skippedTests = [System.Collections.ArrayList]::new()
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

        # CRITICAL: only splat -Snapshot to functions that actually declare
        # it. A function without -Snapshot support is SKIPPED by default -
        # not run live - so -FromSnapshot actually performs no live AD
        # access unless -AllowLiveFallbackForUnsupportedTests is set.
        if ($fn.Parameters.ContainsKey('Snapshot')) {
            $callParams['Snapshot'] = $Snapshot
            Write-Verbose "Invoke-ADRuleSet: running '$testKey' ($functionName) from snapshot."
        }
        elseif ($AllowLiveFallbackForUnsupportedTests) {
            Write-Warning "Invoke-ADRuleSet: '$testKey' ($functionName) has no -Snapshot parameter; running live (per -AllowLiveFallbackForUnsupportedTests)."
        }
        else {
            Write-Warning "Invoke-ADRuleSet: '$testKey' ($functionName) has no -Snapshot parameter yet; skipping (no live AD access performed). Pass -AllowLiveFallbackForUnsupportedTests to run it live instead."
            Add-ADOfflineSkipNote -Test $testKey -Check "Entire test: $functionName" `
                -Reason 'This test has not yet been retrofitted with -Snapshot support. Pass -AllowLiveFallbackForUnsupportedTests to run it live instead.'
            Add-ADTestCoverageEntry -TestName $testKey -Status 'Excluded' `
                -ErrorMessage 'Not run: no -Snapshot support yet for this test (see Offline Mode Coverage Notes). Pass -AllowLiveFallbackForUnsupportedTests to run it live instead.'
            [void]$skippedTests.Add($testKey)
            continue
        }

        try {
            $results = & $functionName @callParams
            $resultCount = @($results | Where-Object { $_ }).Count
            Add-ADTestCoverageEntry -TestName $testKey -Status 'Completed' -FindingCount $resultCount

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
                    $finding.EstimatedEffort = $result.EstimatedEffort
                    $finding.KnownRisks = $result.KnownRisks
                    $finding.BackupRollback = $result.BackupRollback
                    $finding.OperationalNotes = $result.OperationalNotes
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
            Add-ADTestCoverageEntry -TestName $testKey -Status 'Failed' -ErrorMessage "$_"
        }
    }

    Write-Progress -Activity "Running Active Directory Security Audit (offline / snapshot)" -Completed

    if ($skippedTests.Count -gt 0) {
        Write-Warning "Invoke-ADRuleSet: skipped $($skippedTests.Count) test(s) with no offline/-Snapshot support: $($skippedTests -join ', '). Re-run with -AllowLiveFallbackForUnsupportedTests to include them via live queries instead."
    }

    return $allFindings
}

#endregion
