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

        [int]$MaxAttempts = 2,
        [int]$DelaySeconds = 1,
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

# Fixed: -ExportPath (and any other user-supplied path in this module) was
# being handed, while still possibly relative, to raw .NET file APIs
# ([System.IO.File]::WriteAllText, etc.) elsewhere. PowerShell cmdlets like
# Join-Path/Test-Path/New-Item are provider-aware and correctly resolve a
# relative path against $PWD (the shell's own current location) - but raw
# .NET APIs resolve relative paths against [Environment]::CurrentDirectory
# instead, and the two are frequently out of sync (many hosts - IDE
# integrated terminals, scheduled tasks, some launch shortcuts - leave
# [Environment]::CurrentDirectory pointing at the user's profile folder
# rather than keeping it synced to $PWD). The reported symptom: passing
# -ExportPath ".\foldername" resolved fine for the Join-Path/Test-Path
# calls, but the raw .NET write-test a few lines later in Main.ps1 silently
# resolved against the profile directory instead and threw "Export path is
# not writable" for a perfectly valid, writable relative path.
function Resolve-ADSecurityAuditPath {
    <#
    .SYNOPSIS
        Resolves a possibly-relative, possibly-nonexistent path to a
        fully-qualified absolute path, using PowerShell's own current
        location ($PWD) rather than .NET's [Environment]::CurrentDirectory.
    .DESCRIPTION
        Uses the PowerShell engine's own path resolution
        (GetUnresolvedProviderPathFromPSPath), which always honors $PWD.
        Works whether the path exists yet or not (string computation only -
        no filesystem access) and whether it was already absolute or not
        (a no-op in that case, aside from normalization).
    .PARAMETER Path
        The (possibly relative) path to resolve.
    .OUTPUTS
        [string] the fully-qualified absolute path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

# --- Multi-domain / multi-forest target override ---
#
# PROBLEM: none of the Get-AD*/Set-AD* calls anywhere in this module pass
# -Server. Without it, the AD PowerShell module uses a "serverless" bind
# that resolves against the invoking account's own logon domain (or
# whatever DC AD's client-side locator happens to pick), NOT necessarily
# the domain the operator actually intends to audit. In a multi-domain
# forest this produces exactly the reported symptom: an account from
# Domain A running the audit against/on a Domain B machine ends up reading
# Domain A's domain object, DCs, users, etc. instead of Domain B's.
#
# FIX: rather than patch every Get-AD*/Set-AD* call site individually
# (fragile - a single missed call silently reintroduces the bug),
# Set-ADSecurityAuditTargetServer installs a $PSDefaultParameterValues
# entry that auto-supplies -Server on every Get-AD*/Set-AD* cmdlet call for
# the rest of the session, until Clear-ADSecurityAuditTargetServer removes
# it. Start-ADSecurityAudit calls these around the live audit run when its
# own -Server parameter is supplied; see src/Main.ps1.
#
# $PSDefaultParameterValues is looked up by the engine at parameter-binding
# time in whatever scope is active when the cmdlet is invoked, so setting
# it at Global scope here means it applies inside every dot-sourced audit
# function in src/*.ps1, not just code in this file.
function Set-ADSecurityAuditTargetServer {
    <#
    .SYNOPSIS
        Forces every Get-AD*/Set-AD* cmdlet call for the rest of the
        session to explicitly target one domain/DC, instead of the default
        serverless bind that can silently resolve to the wrong domain in a
        multi-domain forest.
    .PARAMETER Server
        A domain FQDN (e.g. 'domainb.corp.com') or a specific DC FQDN/
        hostname (e.g. 'dc01.domainb.corp.com'). Either is accepted by
        -Server on the AD cmdlets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Server
    )
    if (-not $Global:PSDefaultParameterValues) {
        $Global:PSDefaultParameterValues = @{}
    }
    $Global:PSDefaultParameterValues['Get-AD*:Server'] = $Server
    $Global:PSDefaultParameterValues['Set-AD*:Server'] = $Server
    $Global:PSDefaultParameterValues['New-AD*:Server'] = $Server
    $Global:PSDefaultParameterValues['Remove-AD*:Server'] = $Server
    Write-Verbose "Set-ADSecurityAuditTargetServer: Get-AD*/Set-AD*/New-AD*/Remove-AD* cmdlets will now explicitly target '$Server' for the rest of this session."
}

function Clear-ADSecurityAuditTargetServer {
    <#
    .SYNOPSIS
        Removes the -Server override installed by
        Set-ADSecurityAuditTargetServer. Safe to call even if it was never
        set (no-op).
    #>
    [CmdletBinding()]
    param()
    if ($Global:PSDefaultParameterValues) {
        $Global:PSDefaultParameterValues.Remove('Get-AD*:Server')
        $Global:PSDefaultParameterValues.Remove('Set-AD*:Server')
        $Global:PSDefaultParameterValues.Remove('New-AD*:Server')
        $Global:PSDefaultParameterValues.Remove('Remove-AD*:Server')
    }
}

# When -Server isn't supplied at all, this resolves a sensible, DETERMINISTIC
# default instead of leaving it to whatever the AD module/Windows LDAP
# client's own ambient resolution happens to pick (which is the whole class
# of bug the rest of this file exists to work around). Defaults to the
# CURRENT USER's own domain - $env:USERDNSDOMAIN, the DNS domain of the
# account whose credentials are running this session, set by the LSA at
# logon - rather than the machine's joined domain, matching the most common
# operator intent ("audit the domain my account belongs to") without
# requiring -Server to be typed for that case at all.
function Resolve-ADSecurityAuditTargetServer {
    <#
    .SYNOPSIS
        Resolves the effective -Server value: the explicit value if one was
        passed, otherwise the current user's own domain
        ($env:USERDNSDOMAIN), otherwise $null (falls back to the AD
        module's own ambient resolution).
    .DESCRIPTION
        $env:USERDNSDOMAIN is set by the LSA at logon from the DOMAIN
        ACCOUNT's own domain - not $env:USERDOMAIN (NetBIOS form, can be
        the computer name for a local logon) and not the machine's own
        joined domain (Get-CimInstance Win32_ComputerSystem / Get-ADDomain
        with no override). This means the default now correctly follows
        the operator's account even when the machine itself is joined to a
        different domain in the forest - the scenario this module's
        -Server parameter was originally added to fix.

        KNOWN LIMITATION: if the caller used `runas /netonly` (or an
        equivalent alternate-credential technique) to run this session
        under a DIFFERENT domain's credentials than the one they're
        locally logged into, $env:USERDNSDOMAIN still reflects the
        original interactive logon's domain, not the alternate
        credential's domain, since /netonly does not change the process's
        inherited environment block. Pass -Server explicitly in that case.
    .PARAMETER Server
        The explicit -Server value the caller passed, if any. Empty/$null
        means "not specified".
    .OUTPUTS
        [string] the effective server to use, or $null if neither an
        explicit value nor $env:USERDNSDOMAIN is available (e.g. a local,
        non-domain logon session) - callers treat a $null return the same
        way they previously treated "no -Server given at all".
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server
    )
    if ($Server) {
        return $Server
    }
    if ($env:USERDNSDOMAIN) {
        Write-Verbose "Resolve-ADSecurityAuditTargetServer: -Server not specified; defaulting to the current user's domain (`$env:USERDNSDOMAIN): $env:USERDNSDOMAIN"
        return $env:USERDNSDOMAIN
    }
    Write-Verbose "Resolve-ADSecurityAuditTargetServer: -Server not specified and `$env:USERDNSDOMAIN is empty (e.g. a local, non-domain logon session); falling back to the AD module's own default resolution."
    return $null
}

# Several files previously read the Configuration/Schema naming context via
# a RAW ADSI bind - ([ADSI]"LDAP://RootDSE").configurationNamingContext -
# instead of the AD module's own Get-ADRootDSE cmdlet. [ADSI]"LDAP://..."
# is a System.DirectoryServices/COM object construction, NOT a PowerShell
# cmdlet call, so it is invisible to $PSDefaultParameterValues entirely -
# Set-ADSecurityAuditTargetServer's -Server override has no effect on it
# whatsoever. Left alone, it performs its own independent "serverless" LDAP
# bind that resolves via the Windows LDAP client's locator, which
# typically binds to a DC of the CALLING MACHINE's own joined domain -
# so even with -Server correctly set to a different target, every one of
# these calls would silently keep talking to the wrong domain regardless.
# This was the actual remaining root cause behind "the -Server override is
# still talking to the wrong domain" even when the operator's own account
# and machine agree with each other.
#
# Fix: go through Get-ADRootDSE instead, which IS a Get-AD* cmdlet and
# therefore honors the -Server override automatically (via the global
# default) or explicitly (via its own -Server parameter, for callers that
# have one in scope).
function Get-ADRootDSEValue {
    <#
    .SYNOPSIS
        Returns configurationNamingContext or schemaNamingContext from
        RootDSE, honoring the -Server override - unlike a raw
        [ADSI]"LDAP://RootDSE" bind, which does not.
    .PARAMETER Property
        'configurationNamingContext' or 'schemaNamingContext'.
    .PARAMETER Server
        Optional explicit override, for callers that already have -Server
        in their own parameter list. When omitted, relies on whatever
        Set-ADSecurityAuditTargetServer has installed globally, if anything.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('configurationNamingContext', 'schemaNamingContext')]
        [string]$Property,

        [Parameter()]
        [string]$Server
    )
    $rootDSEParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $rootDSEParams['Server'] = $Server }
    $rootDSE = Get-ADRootDSE @rootDSEParams
    return $rootDSE.$Property
}

# Get-ADDomainController's -Discover and -Server are mutually exclusive
# parameter sets - if Set-ADSecurityAuditTargetServer's global -Server
# default is active and a call site still uses -Discover directly (as
# several live-network-probe checks do, independent of Main.ps1's own DC
# discovery), PowerShell throws a parameter-binding error rather than
# honoring the override, and the probe is silently skipped by the
# surrounding try/catch instead of correctly targeting the requested
# domain. This centralizes the same "if an override is active, resolve
# directly against it; otherwise fall back to -Discover" logic Main.ps1
# already applies to its own DC connectivity check, so every other
# live-probe call site gets the same correctness for free.
function Get-ADSecurityAuditActiveServerOverride {
    <#
    .SYNOPSIS
        Returns the -Server value currently installed by
        Set-ADSecurityAuditTargetServer, or $null if no override is active.
    .DESCRIPTION
        A few call sites (forest-root-only group lookups, anonymous-bind/
        zone-transfer probes) need to know and explicitly reuse the ACTUAL
        override value - not just rely on $PSDefaultParameterValues to
        auto-supply it - because they either can't use a plain Get-AD*
        cmdlet call (raw network probes) or need to deliberately query a
        DIFFERENT server for one specific lookup (e.g. the forest root
        instead of the audited child domain) without losing track of what
        the "normal" override value was. Centralized here instead of each
        caller re-reading $Global:PSDefaultParameterValues directly.
    .OUTPUTS
        [string] the active -Server override, or $null.
    #>
    [CmdletBinding()]
    param()

    if ($Global:PSDefaultParameterValues -and $Global:PSDefaultParameterValues.ContainsKey('Get-AD*:Server')) {
        return $Global:PSDefaultParameterValues['Get-AD*:Server']
    }
    return $null
}

function Split-ADObjectByTargetDomain {
    <#
    .SYNOPSIS
        Splits a set of AD objects into those that belong to the domain
        currently being audited and those that don't, instead of silently
        mixing cross-domain objects into a single-domain audit's results.
    .DESCRIPTION
        -Server pins a Get-AD* cmdlet CALL to one domain, but doesn't
        guarantee every OBJECT that call returns actually belongs to that
        domain. The clearest case in this module: Get-ADGroupMember
        -Recursive walks nested group membership, and in a multi-domain
        forest a privileged group can legitimately contain members from
        OTHER domains (a universal group, or a child domain's Domain Admins
        nested into the forest root's Enterprise Admins). Get-ADGroupMember
        does not filter these out or flag them - they come back as
        ordinary member objects, indistinguishable from same-domain members
        unless something checks their own DistinguishedName.

        This is exactly the shape of the "wrong domain" failure mode this
        module's -Server override exists to prevent: an operator scoped to
        Domain B can still end up with Domain A objects quietly folded into
        Domain B's findings/report if nothing validates membership at this
        level - particularly plausible if Domain A happens to be the
        forest root (Enterprise Admins/Schema Admins live there) or the
        machine's own joined domain. Call sites that walk group membership
        should use this to make any cross-domain leakage visible (a
        Write-Warning and/or a dedicated finding) rather than silent.
    .PARAMETER InputObject
        AD objects to check (anything with a DistinguishedName property -
        users, computers, groups).
    .PARAMETER TargetDomainDN
        The DistinguishedName of the domain being audited (e.g.
        $domain.DistinguishedName). An object is considered in-scope only
        if its own DistinguishedName ends with this.
    .OUTPUTS
        PSCustomObject: InScope (array), Foreign (array).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [array]$InputObject = @(),

        [Parameter(Mandatory)]
        [string]$TargetDomainDN
    )

    $inScope = @()
    $foreign = @()
    foreach ($obj in @($InputObject)) {
        if (-not $obj -or -not $obj.DistinguishedName) {
            # Can't determine domain membership without a DN. Treated as
            # in-scope rather than silently dropped - this guard is a
            # safety net for detecting cross-domain contamination, not a
            # general-purpose filter, and a DN-less object is a different
            # (pre-existing) problem it isn't meant to paper over.
            $inScope += $obj
            continue
        }
        # Suffix match on the DN, not an exact/case-sensitive comparison -
        # DNs are case-insensitive in AD and TargetDomainDN is itself a
        # suffix of every in-domain object's own DN (e.g. an object DN of
        # "CN=user1,OU=Users,DC=domainb,DC=corp,DC=com" against a
        # TargetDomainDN of "DC=domainb,DC=corp,DC=com").
        if ($obj.DistinguishedName.ToString().ToLowerInvariant().EndsWith($TargetDomainDN.ToLowerInvariant())) {
            $inScope += $obj
        }
        else {
            $foreign += $obj
        }
    }

    return [PSCustomObject]@{
        InScope = @($inScope)
        Foreign = @($foreign)
    }
}

function Get-ADSecurityAuditDomainController {
    <#
    .SYNOPSIS
        Enumerates Domain Controllers for ONE specific domain, correctly
        scoped - unlike a bare `Get-ADDomainController -Filter`, which
        queries the forest-wide Sites/Configuration container and returns
        DCs from EVERY domain in the forest regardless of which -Server
        you bind to.
    .DESCRIPTION
        Get-ADDomainController's -Filter/-LDAPFilter parameter set searches
        the Configuration naming context (CN=Sites,CN=Configuration,...),
        which is forest-wide and replicated to every DC in the forest - so
        -Server only controls WHICH DC answers the query, not the query's
        SCOPE. Every one of this module's per-DC probes (anonymous bind,
        null session, Kerberos hardening, legacy auth, audit policy,
        known-DC-vulnerability checks, stale-object depth, RODC security,
        control-path graph, coercion/relay exposure, the main run's own DC
        connectivity check, and Get-ADSnapshot) previously used a bare
        `Get-ADDomainController -Filter *` to enumerate DCs to probe. In a
        multi-domain forest this silently returns - and every one of those
        checks then iterates over - Domain Controllers from OTHER domains
        too, regardless of an active -Server override. This is a concrete,
        confirmed explanation for "wrong domain" symptoms reported
        specifically against DCs: -Server WAS being honored for BINDING
        the query, but the query's own RESULT SET was never actually
        domain-scoped to begin with - a completely different failure mode
        than the -Server plumbing itself being broken.

        This function performs the same -Filter enumeration, then filters
        the result to DCs whose own .Domain property matches the domain
        actually resolved via Get-ADDomain against the same -Server.
        Get-ADDomain does NOT have this problem - it uses a different,
        -Identity/-Server-scoped code path, not the forest-wide
        Configuration container -Filter search does.
    .PARAMETER Server
        Optional. Passed through to both the Get-ADDomain and
        Get-ADDomainController calls - typically the active -Server
        override, when the caller wants to be explicit about it. When
        omitted, no -Server is passed to either call, so an active
        Set-ADSecurityAuditTargetServer override (if any) is still applied
        via the normal $PSDefaultParameterValues auto-injection - this
        matches every call site's pre-fix behavior exactly, so the ONLY
        behavioral change from this fix is the domain-scoping filter
        below, not how -Server itself gets resolved.
    .PARAMETER Filter
        Optional. Passed through to Get-ADDomainController's -Filter.
        Defaults to '*'. Accepts the same string or script-block filter
        syntax Get-ADDomainController itself does (e.g. a RODC-only
        filter), while still getting correct domain scoping.
    .OUTPUTS
        Array of Get-ADDomainController result objects, all confirmed to
        belong to the resolved target domain. Throws if either the
        Get-ADDomain or Get-ADDomainController call fails, mirroring the
        -ErrorAction Stop every existing call site already used on its own
        bare Get-ADDomainController call.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        $Filter = '*'
    )

    $domainParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $domainParams['Server'] = $Server }
    $targetDomainDNSRoot = (Get-ADDomain @domainParams).DNSRoot

    $dcParams = @{ Filter = $Filter; ErrorAction = 'Stop' }
    if ($Server) { $dcParams['Server'] = $Server }
    $allDCs = @(Get-ADDomainController @dcParams)

    $scoped = @($allDCs | Where-Object { $_.Domain -eq $targetDomainDNSRoot })

    $foreignCount = $allDCs.Count - $scoped.Count
    if ($foreignCount -gt 0) {
        Write-Warning "Get-ADSecurityAuditDomainController: excluded $foreignCount Domain Controller(s) belonging to a domain other than '$targetDomainDNSRoot' - Get-ADDomainController's -Filter searches the forest-wide Configuration container and returns every domain's DCs regardless of -Server."
    }

    return $scoped
}

function Get-ADTargetDomainController {
    <#
    .SYNOPSIS
        Resolves one Domain Controller for a live network probe (e.g. an
        anonymous-bind check, a zone-transfer SOA query), honoring the
        Set-ADSecurityAuditTargetServer -Server override when active
        instead of unconditionally calling -Discover.
    .OUTPUTS
        A Get-ADDomainController result object (has .HostName, etc.), or
        $null if resolution failed.
    #>
    [CmdletBinding()]
    param()

    $overrideServer = Get-ADSecurityAuditActiveServerOverride

    try {
        if ($overrideServer) {
            return (Get-ADDomainController -Identity $overrideServer -Server $overrideServer -ErrorAction Stop)
        }
        else {
            return (Get-ADDomainController -Discover -ErrorAction Stop)
        }
    }
    catch {
        Write-Verbose "Get-ADTargetDomainController: could not resolve a target DC: $_"
        return $null
    }
}

# Live per-DC registry fallback helper, used by any check that follows the
# "GPO-linked policy first, then a direct per-DC registry read if no linked
# GPO defines the value" pattern (SMBv1/signing/LmCompatibilityLevel/LLMNR/
# WSUS in LegacyAuthAudits.ps1, and the null-session check in
# DomainHardeningAudits.ps1). Promoted here in v1.20.5 from a function that
# used to be nested (and therefore private) inside
# Test-ADLegacyAuthSurface, so a second module can reuse the exact same
# read-only remote-registry logic instead of carrying its own copy.
#
# Read-only: this only ever reads a registry value via remote registry /
# Invoke-Command; it never sets, clears, or otherwise modifies one.
function Get-ADLiveRegistryValuePerDc {
    <#
    .SYNOPSIS
        Reads a single registry value directly from each of a list of
        Domain Controllers (remote registry / Invoke-Command).
    .DESCRIPTION
        Intended as the live fallback for a registry value that no linked
        GPO defines, so a locally configured (non-policy) value is still
        detected rather than silently missed. Never sets or clears a value.
    .PARAMETER DomainControllers
        Domain controller objects (as returned by Get-ADDomainController),
        each expected to expose HostName and/or Name.
    .PARAMETER Key
        Registry key path, e.g. 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'.
    .PARAMETER ValueName
        The value name to read under Key.
    .OUTPUTS
        PSCustomObject[] with DomainController, Value, and Error - one
        record per DC, Error populated (and Value $null) on read failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$DomainControllers,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$ValueName
    )
    $results = [System.Collections.ArrayList]::new()
    $regPath = "Registry::$Key"
    foreach ($dc in $DomainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } else { $dc.Name }
        try {
            $value = Invoke-ADQueryWithRetry -OperationName "Read '$Key\$ValueName' on $dcName" -Query {
                Invoke-Command -ComputerName $dcName -ErrorAction Stop -ScriptBlock {
                    param($p, $vn)
                    (Get-ItemProperty -Path $p -Name $vn -ErrorAction SilentlyContinue).$vn
                } -ArgumentList $regPath, $ValueName
            }
            [void]$results.Add([PSCustomObject]@{ DomainController = $dcName; Value = $value; Error = $null })
        }
        catch {
            Write-Verbose "Get-ADLiveRegistryValuePerDc: could not read '$Key\$ValueName' on '$dcName': $_"
            [void]$results.Add([PSCustomObject]@{ DomainController = $dcName; Value = $null; Error = "$_" })
        }
    }
    return $results
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

    if ($Snapshot -and $Snapshot.ContainsKey('Groups')) {
        Write-Verbose "Get-ADTier0Principal: deriving Tier-0 set from snapshot."
        foreach ($group in $Snapshot.Groups) {
            if ($group.Name -notin $Script:ProtectedGroups) { continue }
            foreach ($memberDN in @($group.Members)) {
                if (-not $memberDN) { continue }
                if (-not $seen.ContainsKey($memberDN)) {
                    $seen[$memberDN] = [System.Collections.ArrayList]::new()
                    [void]$tier0.Add([PSCustomObject]@{
                        DistinguishedName      = $memberDN
                        SID                    = $null
                        SamAccountName         = $null
                        ObjectClass            = $null
                        PrivilegedGroups       = $seen[$memberDN]
                        PrivilegedGroupsString = ''
                    })
                }
                [void]$seen[$memberDN].Add($group.Name)
            }
        }
        return @($tier0 | ForEach-Object { $_.PrivilegedGroupsString = ($_.PrivilegedGroups -join '; '); $_ })
    }
    elseif ($Snapshot) {
        # Fixed in v1.19.1: a -Snapshot was supplied but has no 'Groups' key
        # (e.g. a malformed or very old snapshot file). This used to fall
        # through to the live loop below unconditionally - not acceptable
        # for a genuinely offline analysis. Return an empty Tier-0 set
        # instead of making any live call.
        Write-Verbose "Get-ADTier0Principal: -Snapshot supplied but has no 'Groups' key; returning an empty Tier-0 set (no live AD access performed)."
        return @()
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
                    DistinguishedName      = $member.DistinguishedName
                    SID                    = $member.SID.Value
                    SamAccountName         = $member.SamAccountName
                    ObjectClass            = $member.objectClass
                    PrivilegedGroups       = $seen[$key]
                    PrivilegedGroupsString = ''
                })
            }
            [void]$seen[$key].Add($groupName)
        }
    }

    Write-Verbose "Get-ADTier0Principal: resolved $($tier0.Count) unique Tier-0 principals."
    return @($tier0 | ForEach-Object { $_.PrivilegedGroupsString = ($_.PrivilegedGroups -join '; '); $_ })
}

# Recursively resolve group membership entirely in-memory against a
# Get-ADSnapshot snapshot (introduced in v1.19.0 for the offline-parity
# backlog, steps 18-29). This is the offline equivalent of
# Get-ADGroupMember [-Recursive] - it never touches AD; it only walks
# already-collected Snapshot.Groups/.Users/.Computers data.
#
# Detection only: in-memory graph traversal of already-collected snapshot
# data. No exploitation, coercion, relay, or PoC code.
function Resolve-ADSnapshotGroupMember {
    <#
    .SYNOPSIS
        Resolves group membership from an in-memory Get-ADSnapshot snapshot,
        mirroring Get-ADGroupMember [-Recursive] with no live AD access.
    .DESCRIPTION
        Walks $Snapshot.Groups[].Members starting from the group identified
        by -GroupDistinguishedName. Each member DN is cross-referenced
        against Snapshot.Groups (a nested group - recursed into unless
        -DirectOnly is set), Snapshot.Users, and Snapshot.Computers (leaf
        members - emitted directly; computer accounts, gMSAs, etc. can be
        direct group members just like users).

        Cycle-safe: a $seen hashtable of visited group DNs guards against a
        group nested inside itself (directly or transitively) - AD does not
        prevent this. A cycle simply stops recursing back into a group
        already on the current path; it never hangs or overflows the stack.
    .PARAMETER Snapshot
        The snapshot hashtable (from Get-ADSnapshot / ConvertTo-ADHashtable).
    .PARAMETER GroupDistinguishedName
        The DistinguishedName of the group to resolve members for.
    .PARAMETER DirectOnly
        When set, mirrors plain Get-ADGroupMember (no -Recursive): nested
        groups are returned as members themselves, and their own members are
        not walked into.
    .OUTPUTS
        PSCustomObject[] with SamAccountName, DistinguishedName, objectClass -
        the same useful surface Get-ADGroupMember's live output exposes to
        every consumer in this module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Snapshot,

        [Parameter(Mandatory)]
        [string]$GroupDistinguishedName,

        [switch]$DirectOnly
    )

    $results = [System.Collections.ArrayList]::new()

    if (-not $Snapshot.ContainsKey('Groups')) {
        Write-Verbose "Resolve-ADSnapshotGroupMember: snapshot has no 'Groups' key; returning no members."
        return @()
    }

    # Build lookup tables once per call. Groups/Users/Computers are already
    # fully materialised in memory, so this is cheap even for a large
    # domain - it's just a dictionary index, not a new AD query.
    $groupsByDN = @{}
    foreach ($g in @($Snapshot.Groups)) {
        if ($g -and $g.DistinguishedName) {
            $groupsByDN[$g.DistinguishedName] = $g
        }
    }
    $usersByDN = @{}
    if ($Snapshot.ContainsKey('Users')) {
        foreach ($u in @($Snapshot.Users)) {
            if ($u -and $u.DistinguishedName) {
                $usersByDN[$u.DistinguishedName] = $u
            }
        }
    }
    $computersByDN = @{}
    if ($Snapshot.ContainsKey('Computers')) {
        foreach ($c in @($Snapshot.Computers)) {
            if ($c -and $c.DistinguishedName) {
                $computersByDN[$c.DistinguishedName] = $c
            }
        }
    }

    $seen = @{}

    function Resolve-Members {
        param([string]$GroupDN)

        if ($seen.ContainsKey($GroupDN)) {
            # Cycle detected (group nested inside itself, directly or
            # transitively) - stop recursing into this branch rather than
            # hang or stack-overflow. The non-cyclic members already
            # collected on other branches are unaffected.
            Write-Verbose "Resolve-ADSnapshotGroupMember: membership cycle detected at '$GroupDN'; not recursing further."
            return
        }
        $seen[$GroupDN] = $true

        $group = $groupsByDN[$GroupDN]
        if (-not $group) {
            return
        }

        foreach ($memberDN in @($group.Members)) {
            if (-not $memberDN) { continue }

            if ($groupsByDN.ContainsKey($memberDN)) {
                $nestedGroup = $groupsByDN[$memberDN]
                if ($DirectOnly) {
                    [void]$results.Add([PSCustomObject]@{
                        SamAccountName    = $nestedGroup.Name
                        DistinguishedName = $nestedGroup.DistinguishedName
                        objectClass       = 'group'
                    })
                }
                else {
                    [void]$results.Add([PSCustomObject]@{
                        SamAccountName    = $nestedGroup.Name
                        DistinguishedName = $nestedGroup.DistinguishedName
                        objectClass       = 'group'
                    })
                    Resolve-Members -GroupDN $memberDN
                }
            }
            elseif ($usersByDN.ContainsKey($memberDN)) {
                $u = $usersByDN[$memberDN]
                [void]$results.Add([PSCustomObject]@{
                    SamAccountName    = $u.SamAccountName
                    DistinguishedName = $u.DistinguishedName
                    objectClass       = 'user'
                })
            }
            elseif ($computersByDN.ContainsKey($memberDN)) {
                $c = $computersByDN[$memberDN]
                [void]$results.Add([PSCustomObject]@{
                    SamAccountName    = $c.SamAccountName
                    DistinguishedName = $c.DistinguishedName
                    objectClass       = 'computer'
                })
            }
            else {
                # Member DN doesn't resolve against any collected
                # collection (e.g. a foreign-security-principal or an
                # object class this snapshot doesn't carry). Emit a
                # best-effort record rather than silently dropping it, the
                # same "unknown, not a hard failure" posture used elsewhere
                # in this backlog (see step 20's ObjectClass fallback).
                [void]$results.Add([PSCustomObject]@{
                    SamAccountName    = $null
                    DistinguishedName = $memberDN
                    objectClass       = 'unknown'
                })
            }
        }
    }

    Resolve-Members -GroupDN $GroupDistinguishedName

    return @($results)
}

# --- v1.19.1: offline-analysis skip tracking ---
# When a test running under -Snapshot skips a sub-check that has no
# AD-schema/snapshot equivalent (SYSVOL content, live network probes,
# per-DC remoting, etc.), it records that fact here instead of just
# writing a Write-Warning that only shows up in the console transcript.
# Start-ADSecurityAudit resets this list at the start of every run and
# threads it through to Export-ADSecurityReportHTML so the HTML report
# itself can show "what wasn't scanned and why", not just the log.
$Script:ADOfflineSkipNotes = [System.Collections.ArrayList]::new()

function Reset-ADOfflineSkipNotes {
    <#
    .SYNOPSIS
        Clears the offline-skip-note list. Called once at the start of
        every Start-ADSecurityAudit run (both live and -FromSnapshot) so
        notes never leak between runs in the same PowerShell session.
    #>
    [CmdletBinding()]
    param()
    $Script:ADOfflineSkipNotes = [System.Collections.ArrayList]::new()
}

function Add-ADOfflineSkipNote {
    <#
    .SYNOPSIS
        Records one live-only sub-check for the HTML report's "Offline
        Mode Coverage Notes" section.
    .PARAMETER Test
        The registry name of the test (e.g. 'GroupPolicies'), matching
        $Script:ADTestFunctionRegistry's keys / Invoke-ADRuleSet's -IncludeTests.
    .PARAMETER Check
        Short name of the specific sub-check (e.g. 'SYSVOL file-share ACL').
    .PARAMETER Reason
        Why it can't run offline (no AD-schema/snapshot equivalent, live
        network probe, etc.) - shown verbatim in the report.
    .PARAMETER Mode
        'Skipped' (default) - the sub-check did not run at all under
        -Snapshot, so this coverage is simply missing from the results.
        'StillLive' - the sub-check ran anyway, over a live network/AD
        connection, because it has no representation in a snapshot at all
        (e.g. reading file content). Distinguished from 'Skipped' because
        it's the opposite finding-coverage story: coverage IS present, but
        -Snapshot did not actually avoid contacting a DC for this one check.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Test,

        [Parameter(Mandatory)]
        [string]$Check,

        [Parameter(Mandatory)]
        [string]$Reason,

        [Parameter()]
        [ValidateSet('Skipped', 'StillLive')]
        [string]$Mode = 'Skipped'
    )
    [void]$Script:ADOfflineSkipNotes.Add([PSCustomObject]@{
        Test   = $Test
        Check  = $Check
        Reason = $Reason
        Mode   = $Mode
    })
}

function Get-ADOfflineSkipNotes {
    <#
    .SYNOPSIS
        Returns the skip notes recorded so far in this run.
    #>
    [CmdletBinding()]
    param()
    return @($Script:ADOfflineSkipNotes)
}

function ConvertTo-ADFlatFindingsArray {
    <#
    .SYNOPSIS
        Recursively flattens a findings collection that may contain nested
        arrays, so downstream code always sees one finding-like object per
        element rather than a sub-array of several.
    .DESCRIPTION
        Defensive guard against a jagged/nested input array - e.g. a
        findings JSON export that (for reasons not fully understood -
        Main.ps1's own $allFindings += $result assembly loop flattens
        correctly, so the nesting has been observed only after a JSON
        round-trip through Get-ADRetestComparison's offline file read, not
        during a live audit run) ends up containing an element that is
        itself a sub-array of several finding objects instead of one.

        When that happens, PowerShell's member-enumeration silently turns
        every property read on that element into an array (e.g.
        $finding.Weight returns System.Object[] instead of an int), which
        then throws deep inside Get-ADRiskScore's arithmetic with a
        confusing "cannot convert System.Object[] to Int32" error rather
        than a clear message about the actual shape problem. Flattening
        immediately after the file is read means every consumer (scoring,
        finding-key matching) only ever sees real, individual finding
        objects.

        A "finding" is anything that is NOT itself an array/enumerable
        collection. Strings and dictionaries/hashtables are treated as leaf
        values (never recursed into), since a finding's own Details
        hashtable is legitimate finding-level content, not a nested
        collection of findings.
    .PARAMETER Findings
        The findings array to flatten (may already be flat - flattening an
        already-flat array is a safe no-op).
    .OUTPUTS
        A flat array where every element is a single finding-like object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings
    )

    $flat = [System.Collections.ArrayList]::new()

    function Add-ADFlatFindingItem {
        param($Item)
        if ($null -eq $Item) { return }
        $isNestedCollection = ($Item -is [System.Collections.IEnumerable]) -and
                              ($Item -isnot [string]) -and
                              ($Item -isnot [System.Collections.IDictionary])
        if ($isNestedCollection) {
            foreach ($sub in $Item) { Add-ADFlatFindingItem -Item $sub }
        }
        else {
            [void]$flat.Add($Item)
        }
    }

    foreach ($item in $Findings) { Add-ADFlatFindingItem -Item $item }

    return @($flat)
}

function Get-ADFindingMatchKey {
    <#
    .SYNOPSIS
        Builds the Category+Issue+AffectedObject key used to match the same
        finding across two different runs (e.g. a baseline and a retest).
    .DESCRIPTION
        Coarser keys (Category+Issue only) would hide partial remediation -
        e.g. 5 stale accounts down to 2 should show 3 resolved and 2 still
        open, not just "still present". This is the SINGLE SOURCE OF TRUTH
        for that key construction - Get-ADRetestComparison (RetestComparison.ps1)
        and the remediation-state store (RemediationState.ps1) both call this
        function rather than building the "$Category|$Issue|$AffectedObject"
        string independently, so the two can never disagree on what a "key" is.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Category,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Issue,
        [Parameter(Mandatory)][AllowEmptyString()][string]$AffectedObject
    )
    return "$Category|$Issue|$AffectedObject"
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

function ConvertTo-ADFriendlyDateText {
    <#
    .SYNOPSIS
        Normalizes a GeneratedDate-style value read back from a
        ConvertFrom-Json'd sidecar/report into a clean, human-readable date
        string.
    .DESCRIPTION
        Every "GeneratedDate = Get-Date" in this module is meant to end up as
        a plain, re-parseable date string once ConvertTo-Json/Out-File has
        written it to disk. Prior to this fix, several of those assignments
        stored the raw [datetime] object instead of a string. PowerShell's
        JSON serializer expands a raw [datetime] using its own ETS note
        properties (DisplayHint/DateTime/value) rather than a plain string,
        so ConvertFrom-Json hands back a PSCustomObject that renders as
        "@{value=...; DisplayHint=2; DateTime=...}" wherever it's dropped
        directly into a report - never a real error, just useless text.

        This helper is defensive on BOTH sides of that fix: it recovers a
        clean date from the old corrupted shape (so already-generated
        sidecars/exports don't need to be regenerated), and it's a no-op
        pass-through for the plain ISO-8601 strings the fixed code now
        writes.
    .PARAMETER Value
        The raw value as read from a ConvertFrom-Json'd object. Any of:
        $null/empty, a [datetime], a plain (parseable) string, or the
        corrupted PSCustomObject shape described above.
    .OUTPUTS
        A "yyyy-MM-dd HH:mm:ss" string, or $null if $Value was empty. If the
        value can't be parsed as a date at all, its best-effort string form
        is returned rather than throwing, so a report can still show
        *something* instead of failing to render.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if (-not $Value) { return $null }

    if ($Value -is [datetime]) {
        return $Value.ToString('yyyy-MM-dd HH:mm:ss')
    }

    # The corrupted legacy shape: ConvertTo-Json expanded a raw [datetime]
    # into its own DisplayHint/DateTime/value note properties instead of a
    # plain string. Recover the actual date from 'value' (the underlying
    # DateTime's own value, most reliable) or fall back to 'DateTime' (the
    # pre-formatted display string).
    if ($Value.PSObject -and ($Value.PSObject.Properties.Name -contains 'DisplayHint') -and
        (($Value.PSObject.Properties.Name -contains 'value') -or ($Value.PSObject.Properties.Name -contains 'DateTime'))) {
        $raw = if ($Value.PSObject.Properties.Name -contains 'value') { $Value.value } else { $Value.DateTime }
        try { return ([datetime]$raw).ToString('yyyy-MM-dd HH:mm:ss') }
        catch { return "$raw" }
    }

    # Plain string (the fixed, current format) or anything else stringy.
    try { return ([datetime]$Value).ToString('yyyy-MM-dd HH:mm:ss') }
    catch { return "$Value" }
}
