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
    'KRBTGTAccount'            = 'Test-KRBTGTAccount'
    'DomainTrusts'             = 'Test-ADDomainTrusts'
    'LAPSDeployment'           = 'Test-LAPSDeployment'
    'AuditPolicyConfiguration' = 'Test-AuditPolicyConfiguration'
    'ConstrainedDelegation'    = 'Test-ConstrainedDelegation'
    'DomainAdminEquivalence'   = 'Test-ADDomainAdminEquivalence'
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
        Users, Computers, Groups, GPOs, ACLs, ADCS, DnsZones, Trusts.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ToJson
    )

    Write-Verbose "Starting collect-once AD snapshot..."

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
    }

    # --- Domain + DC inventory ---
    try {
        $snapshot.Domain = Invoke-ADQueryWithRetry -OperationName 'Get-ADDomain (snapshot)' -Query {
            Get-ADDomain -ErrorAction Stop
        }
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect domain info: $_"
    }

    try {
        $snapshot.DomainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADDomainController (snapshot)' -Query {
            Get-ADDomainController -Filter * -ErrorAction Stop
        })
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect domain controllers: $_"
    }

    # --- Users (paged) ---
    try {
        Write-Verbose "Get-ADSnapshot: collecting users..."
        $snapshot.Users = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADUser (snapshot)' -Query {
            Get-ADUser -Filter '*' -ResultPageSize 500 -ErrorAction Stop -Properties `
                DoesNotRequirePreAuth, UseDESKeyOnly, AllowReversiblePasswordEncryption, `
                PasswordNeverExpires, TrustedForDelegation, LastLogonDate, PasswordLastSet, `
                ServicePrincipalNames, MemberOf, Enabled, DistinguishedName, `
                UserPrincipalName, adminCount, SamAccountName, SID, Description, `
                'msDS-SupportedEncryptionTypes', userAccountControl, WhenCreated, `
                'msDS-AllowedToDelegateTo', SIDHistory
        })
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.Users.Count) users."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect users: $_"
    }

    # --- Computers (paged) ---
    try {
        Write-Verbose "Get-ADSnapshot: collecting computers..."
        $snapshot.Computers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADComputer (snapshot)' -Query {
            Get-ADComputer -Filter '*' -ResultPageSize 500 -ErrorAction Stop -Properties `
                OperatingSystem, OperatingSystemVersion, LastLogonDate, Enabled, `
                DistinguishedName, TrustedForDelegation, 'msDS-AllowedToDelegateTo', `
                'msDS-AllowedToActOnBehalfOfOtherIdentity', PrimaryGroupID, SID, `
                'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime', `
                userAccountControl, WhenCreated
        })
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.Computers.Count) computers."
    }
    catch {
        Write-Warning "Get-ADSnapshot: failed to collect computers: $_"
    }

    # --- Groups (paged; membership flattened to DNs for JSON-friendliness) ---
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
    try {
        Write-Verbose "Get-ADSnapshot: collecting AD CS configuration..."
        $configContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
        $pkiContainer = "CN=Public Key Services,CN=Services,$configContext"

        $certTemplates = Get-ADObject -SearchBase "CN=Certificate Templates,$pkiContainer" -Filter * -Properties * -ErrorAction Stop
        $certAuthorities = $null
        try {
            $certAuthorities = Get-ADObject -SearchBase "CN=Enrollment Services,$pkiContainer" -Filter * -Properties * -ErrorAction Stop
        }
        catch {
            Write-Verbose "Get-ADSnapshot: no Enrollment Services container found: $_"
        }

        $snapshot.ADCS = @{
            Installed             = $true
            CertificateTemplates  = @($certTemplates)
            CertificateAuthorities = @($certAuthorities)
        }
    }
    catch {
        Write-Verbose "Get-ADSnapshot: AD CS not found or not accessible, recording as not installed: $_"
        $snapshot.ADCS = @{ Installed = $false; CertificateTemplates = @(); CertificateAuthorities = @() }
    }

    # --- DNS zones (optional; AD-integrated zones live in an app partition) ---
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
    try {
        Write-Verbose "Get-ADSnapshot: collecting domain trusts..."
        $snapshot.Trusts = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADTrust (snapshot)' -Query {
            Get-ADTrust -Filter * -Properties * -ErrorAction Stop
        })
        Write-Verbose "Get-ADSnapshot: collected $($snapshot.Trusts.Count) trusts."
    }
    catch {
        Write-Verbose "Get-ADSnapshot: no domain trusts found or Get-ADTrust unavailable: $_"
    }

    if ($ToJson) {
        try {
            $snapshot | ConvertTo-Json -Depth 12 | Out-File -FilePath $ToJson -Encoding UTF8
            Write-Verbose "Get-ADSnapshot: wrote snapshot to '$ToJson'."
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

    $allFindings = @()

    foreach ($testKey in $testKeys) {
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

    return $allFindings
}

#endregion
