#region Kerberos Hardening Depth Audit (AES enforcement, FAST/armoring, cross-trust TGT delegation)
#
# Audits Kerberos hardening depth beyond pre-auth/Kerberoasting: whether RC4
# is still permitted (account-level, domain-policy-level, and trust-level),
# whether Kerberos Armoring (FAST) is enabled (KDC and client), and whether
# a cross-forest/cross-realm trust is configured to allow TGT delegation
# across the trust boundary. PingCastle-comparable check(s): S-AesNotEnabled, T-AlgsAES,
# S-KerberosArmoring, S-KerberosArmoringDC, T-TGTDelegation.
#
# DETECTION ONLY: this module reads msDS-SupportedEncryptionTypes bitmasks
# on accounts, GPO-linked (and, as a fallback, direct per-DC) registry
# policy values for the domain-wide Kerberos encryption-type and FAST/
# armoring settings, and trustAttributes flags on domain trusts via
# Get-ADTrust. It never sets, clears, or otherwise modifies any account
# attribute, policy, or registry value, never forges or requests a Kerberos
# ticket, and performs no exploitation, coercion, relay, or PoC traffic.

# Kerberos supported-encryption-type bit flags (msDS-SupportedEncryptionTypes
# and the domain-wide 'SupportedEncryptionTypes' policy value share this
# bitmask). Matches the convention already used for the account-level check
# in src/UserAudits.ps1.
$Script:KerbEncTypeFlags = @{
    DES_CBC_CRC = 0x1
    DES_CBC_MD5 = 0x2
    RC4_HMAC    = 0x4
    AES128      = 0x8
    AES256      = 0x10
}

# trustAttributes bit flags relevant to this module (per MS-ADTS 6.1.6.7.9 /
# the well-known LSA_TRUST_ATTRIBUTE constants). Only the flags this module
# reads are listed here.
$Script:KerbTrustAttributeFlags = @{
    QUARANTINED_DOMAIN                       = 0x00000004  # SID filtering
    TRUST_USES_RC4_ENCRYPTION                = 0x00000080
    TRUST_USES_AES_KEYS                      = 0x00000100
    CROSS_ORGANIZATION_NO_TGT_DELEGATION     = 0x00000200
    CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION = 0x00000800
}

# Registry locations/value names probed by this module. Centralised here so
# the GPO-lookup and live-fallback code paths always agree on exactly what
# they are reading. Mirrors the pattern used in src/LegacyAuthAudits.ps1.
$Script:KerbHardeningRegistryTargets = @{
    DomainEncTypes = @{
        Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
        ValueName = 'SupportedEncryptionTypes'
    }
    KdcArmoring = @{
        Key       = 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc'
        ValueName = 'EnableCbacAndArmor'
    }
    ClientArmoring = @{
        Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
        ValueName = 'EnableCbacAndArmor'
    }
}

# Returns $true if the given msDS-SupportedEncryptionTypes bitmask (or an
# unset/$null value, which Windows treats as "no explicit restriction" and
# has historically defaulted to including RC4 for compatibility) permits
# RC4-HMAC. Centralised so the account-level check and any future callers
# apply the exact same semantics.
function Test-ADKerbRC4Permitted {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $EncryptionTypes
    )

    if ($null -eq $EncryptionTypes -or $EncryptionTypes -eq 0) {
        # Not configured - falls back to the account/domain default, which
        # includes RC4 unless AES-only has been explicitly enforced.
        return $true
    }

    return (([int]$EncryptionTypes) -band $Script:KerbEncTypeFlags.RC4_HMAC) -ne 0
}

function Test-ADKerberosHardening {
    <#
    .SYNOPSIS
        Audits Kerberos hardening depth: RC4 still permitted (account,
        domain-policy, and trust level), Kerberos Armoring (FAST) not
        enabled (KDC and client), and cross-trust TGT delegation.
    .DESCRIPTION
        Three checks:
          1. RC4 Kerberos Encryption Still Permitted - flags Tier-0
             (privileged) accounts and the krbtgt account whose
             msDS-SupportedEncryptionTypes bitmask permits RC4-HMAC (or is
             unset, which defaults to permitting it); domain trusts that do
             not have the TRUST_USES_AES_KEYS attribute set (so RC4 remains
             usable across that trust); and, live-only, the domain-wide
             'Network security: Configure encryption types allowed for
             Kerberos' GPO/registry policy when it is unset or still
             includes RC4/DES rather than being restricted to AES only.
          2. Kerberos Armoring (FAST) Not Enabled - live-only. Flags a
             Domain Controller / domain-wide policy state where KDC support
             for claims, compound authentication, and Kerberos armoring
             (`EnableCbacAndArmor` under the Kdc service key) and/or client
             support for the same (`EnableCbacAndArmor` under the Kerberos
             Parameters key) is not configured/enabled.
          3. Cross-Trust TGT Delegation Enabled - flags any trust whose
             trustAttributes has the CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION
             bit set, which permits a client's TGT to be forwarded across
             the trust boundary during constrained delegation (S4U2Proxy),
             widening the blast radius if the receiving side is compromised.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied,
        the account-level RC4 check reads msDS-SupportedEncryptionTypes from
        `Snapshot.Users` (matched against the Tier-0 set derived from
        `Snapshot.Groups`) and the trust-level checks (RC4-without-AES and
        cross-trust TGT delegation) read from `Snapshot.Trusts`, instead of
        live queries. The domain-wide encryption-type policy and the FAST/
        armoring checks read GPO-linked registry policy and, as a fallback,
        live per-DC registry state that is not part of the current snapshot
        schema; consistent with the -FromSnapshot contract of performing NO
        live AD/network access (see Test-ADLegacyAuthSurface,
        Test-ADCoercionAndRelayExposure, and the anonymous-bind probe in
        Test-ADDomainHardeningFlags), those portions are skipped entirely
        when -Snapshot is supplied.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting Kerberos hardening depth audit..."
    $findings = @()

    # =====================================================================
    # Check 1: RC4 Kerberos Encryption Still Permitted
    # =====================================================================
    try {
        $rc4Accounts       = [System.Collections.ArrayList]::new()
        $rc4Trusts         = [System.Collections.ArrayList]::new()
        $domainPolicyDetail = $null

        # --- 1a. Tier-0 (privileged) accounts + krbtgt (snapshot-aware) ---
        try {
            $tier0 = @(Get-ADTier0Principal -Snapshot $Snapshot)
            $tier0Dns = @($tier0 | ForEach-Object { $_.DistinguishedName } | Where-Object { $_ })

            if ($Snapshot -and $Snapshot.ContainsKey('Users') -and $Snapshot.Users) {
                Write-Verbose "Test-ADKerberosHardening: evaluating account-level RC4 permission from snapshot."
                $krbtgtDn = ($Snapshot.Users | Where-Object { $_.SamAccountName -eq 'krbtgt' } | Select-Object -First 1).DistinguishedName
                $watchDns = @($tier0Dns + $krbtgtDn | Where-Object { $_ } | Select-Object -Unique)

                foreach ($user in $Snapshot.Users) {
                    if ($user.DistinguishedName -notin $watchDns) { continue }
                    if (Test-ADKerbRC4Permitted -EncryptionTypes $user.'msDS-SupportedEncryptionTypes') {
                        [void]$rc4Accounts.Add(@{
                            SamAccountName        = $user.SamAccountName
                            DistinguishedName     = $user.DistinguishedName
                            SupportedEncryptionTypes = $user.'msDS-SupportedEncryptionTypes'
                        })
                    }
                }
            }
            else {
                Write-Verbose "Test-ADKerberosHardening: evaluating account-level RC4 permission via live queries."
                $krbtgt = Invoke-ADQueryWithRetry -OperationName 'Get-ADUser krbtgt (kerberos hardening)' -Query {
                    Get-ADUser -Filter "SamAccountName -eq 'krbtgt'" -Properties 'msDS-SupportedEncryptionTypes' -ErrorAction Stop
                }
                $watchIdentities = @($tier0 | Where-Object { $_.SID -or $_.DistinguishedName })
                foreach ($principal in $watchIdentities) {
                    try {
                        $identity = if ($principal.SID) { $principal.SID } else { $principal.DistinguishedName }
                        $adObject = Invoke-ADQueryWithRetry -OperationName "Get-ADObject $identity (kerberos hardening)" -Query {
                            Get-ADObject -Identity $identity -Properties 'msDS-SupportedEncryptionTypes', 'objectClass' -ErrorAction Stop
                        }
                        if ($adObject -and $adObject.objectClass -eq 'user' -and (Test-ADKerbRC4Permitted -EncryptionTypes $adObject.'msDS-SupportedEncryptionTypes')) {
                            [void]$rc4Accounts.Add(@{
                                SamAccountName        = $principal.SamAccountName
                                DistinguishedName     = $adObject.DistinguishedName
                                SupportedEncryptionTypes = $adObject.'msDS-SupportedEncryptionTypes'
                            })
                        }
                    }
                    catch {
                        Write-Verbose "Test-ADKerberosHardening: could not evaluate encryption types for '$($principal.DistinguishedName)': $_"
                    }
                }
                if ($krbtgt -and (Test-ADKerbRC4Permitted -EncryptionTypes $krbtgt.'msDS-SupportedEncryptionTypes')) {
                    [void]$rc4Accounts.Add(@{
                        SamAccountName        = 'krbtgt'
                        DistinguishedName     = $krbtgt.DistinguishedName
                        SupportedEncryptionTypes = $krbtgt.'msDS-SupportedEncryptionTypes'
                    })
                }
            }
        }
        catch {
            Write-Warning "Test-ADKerberosHardening: error evaluating account-level RC4 permission: $_"
        }

        # --- 1b. Trust-level: TRUST_USES_AES_KEYS not set (snapshot-aware) ---
        try {
            $trusts = if ($Snapshot -and $Snapshot.ContainsKey('Trusts') -and $Snapshot.Trusts) {
                Write-Verbose "Test-ADKerberosHardening: evaluating trust encryption from snapshot."
                @($Snapshot.Trusts)
            }
            else {
                Write-Verbose "Test-ADKerberosHardening: evaluating trust encryption via live Get-ADTrust."
                @(Invoke-ADQueryWithRetry -OperationName 'Get-ADTrust (kerberos hardening)' -Query {
                    Get-ADTrust -Filter * -Properties * -ErrorAction Stop
                })
            }

            foreach ($trust in $trusts) {
                if ($null -eq $trust.trustAttributes) { continue }
                $attrs = [int]$trust.trustAttributes
                if (($attrs -band $Script:KerbTrustAttributeFlags.TRUST_USES_AES_KEYS) -eq 0) {
                    [void]$rc4Trusts.Add(@{
                        Target          = $trust.Target
                        TrustAttributes = $attrs
                        UsesRC4Flag     = (($attrs -band $Script:KerbTrustAttributeFlags.TRUST_USES_RC4_ENCRYPTION) -ne 0)
                    })
                }
            }
        }
        catch {
            Write-Warning "Test-ADKerberosHardening: error evaluating trust-level encryption: $_"
        }

        # --- 1c. Domain-wide encryption-type policy (live-only) ---
        if (-not $Snapshot) {
            try {
                Import-Module GroupPolicy -ErrorAction Stop
                $domain = Get-ADDomain -ErrorAction Stop
                $domainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADDomainController -Filter * (kerberos hardening)' -Query {
                    Get-ADDomainController -Filter * -ErrorAction Stop
                })

                if ($domainControllers -and $domainControllers.Count -gt 0) {
                    $dcOuDn = $null
                    try {
                        $firstDcDn = $domainControllers[0].ComputerObjectDN
                        if ($firstDcDn -and $firstDcDn -match '^CN=[^,]+,(.+)$') {
                            $dcOuDn = $Matches[1]
                        }
                    }
                    catch {
                        Write-Verbose "Test-ADKerberosHardening: could not derive Domain Controllers OU: $_"
                    }
                    if (-not $dcOuDn) { $dcOuDn = "OU=Domain Controllers,$($domain.DistinguishedName)" }

                    $dcScopeGpos = @((Get-ADLinkedGposOrdered -TargetDn $dcOuDn) + (Get-ADLinkedGposOrdered -TargetDn $domain.DistinguishedName))

                    function Get-ADKerbLiveRegistryValuePerDc {
                        param([array]$DomainControllers, [string]$Key, [string]$ValueName)
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
                                Write-Verbose "Get-ADKerbLiveRegistryValuePerDc: could not read '$Key\$ValueName' on '$dcName': $_"
                                [void]$results.Add([PSCustomObject]@{ DomainController = $dcName; Value = $null; Error = "$_" })
                            }
                        }
                        return $results
                    }

                    $target = $Script:KerbHardeningRegistryTargets.DomainEncTypes
                    $policy = Get-ADPolicyRegistryValue -Gpos $dcScopeGpos -Key $target.Key -ValueName $target.ValueName

                    $aesOnlyMask = ($Script:KerbEncTypeFlags.AES128 -bor $Script:KerbEncTypeFlags.AES256)
                    $weakMask    = ($Script:KerbEncTypeFlags.DES_CBC_CRC -bor $Script:KerbEncTypeFlags.DES_CBC_MD5 -bor $Script:KerbEncTypeFlags.RC4_HMAC)

                    if ($policy) {
                        $enforcedValue = [int]$policy.Value
                        $permitsWeak = (($enforcedValue -band $weakMask) -ne 0)
                        $domainPolicyDetail = @{
                            Enforced      = $true
                            Source        = "GPO: $($policy.Source)"
                            Value         = $enforcedValue
                            PermitsRC4OrDES = $permitsWeak
                        }
                    }
                    else {
                        $perDc = Get-ADKerbLiveRegistryValuePerDc -DomainControllers $domainControllers -Key $target.Key -ValueName $target.ValueName
                        $anyWeak = $false
                        foreach ($r in $perDc) {
                            if ($null -eq $r.Value -or (([int]$r.Value) -band $weakMask) -ne 0) { $anyWeak = $true }
                        }
                        $domainPolicyDetail = @{
                            Enforced      = $false
                            Source        = 'No enforcing GPO found; observed via direct per-DC registry read (unset defaults to permitting RC4/DES)'
                            PermitsRC4OrDES = $anyWeak
                            PerDomainControllerState = @($perDc)
                        }
                    }
                }
            }
            catch {
                Write-Warning "Test-ADKerberosHardening: error evaluating domain-wide Kerberos encryption-type policy: $_"
            }
        }
        else {
            Write-Verbose "Test-ADKerberosHardening: -Snapshot supplied; domain-wide encryption-type GPO/registry policy is live-only and is skipped."
            $domainPolicyDetail = @{ Enforced = $null; Source = 'Skipped in -Snapshot mode (live-only GPO/registry check)'; PermitsRC4OrDES = $null }
        }

        $domainPolicyWeak = ($domainPolicyDetail -and $domainPolicyDetail.PermitsRC4OrDES -eq $true)

        if ($rc4Accounts.Count -gt 0 -or $rc4Trusts.Count -gt 0 -or $domainPolicyWeak) {
            $affected = @()
            if ($rc4Accounts.Count -gt 0) { $affected += ($rc4Accounts | ForEach-Object { $_.SamAccountName }) }
            if ($rc4Trusts.Count -gt 0)   { $affected += ($rc4Trusts | ForEach-Object { $_.Target }) }
            if ($domainPolicyWeak)        { $affected += 'Domain Kerberos Policy' }

            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Kerberos Security'
            $finding.Issue = 'RC4 Kerberos Encryption Still Permitted'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = ($affected -join ', ')
            $finding.Description = "RC4-HMAC Kerberos encryption is still permitted: $($rc4Accounts.Count) privileged/krbtgt account(s), $($rc4Trusts.Count) trust(s) without AES enforced$(if ($domainPolicyWeak) { ', and the domain-wide Kerberos encryption-type policy' })."
            $finding.Impact = "RC4-HMAC uses a key derived directly from the account password's NT hash, making Kerberoasted service tickets and cross-realm referral tickets far cheaper to crack offline than their AES equivalents, and allows downgrade attacks even where AES support exists elsewhere."
            $finding.Remediation = "Set 'msDS-SupportedEncryptionTypes' to AES-only (Set-ADUser -KerberosEncryptionType AES256,AES128) on privileged accounts and krbtgt, enforce 'Network security: Configure encryption types allowed for Kerberos' to AES128/AES256 only via GPO, and enable AES on cross-realm trusts (netdom trust /EnableAes  or ksetup, as appropriate) before removing RC4 domain-wide."
            $finding.Details = @{
                PrivilegedAndKrbtgtAccountsPermittingRC4 = @($rc4Accounts)
                TrustsWithoutAesEnforced                 = @($rc4Trusts)
                DomainWidePolicy                         = $domainPolicyDetail
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADKerberosHardening: no RC4-permitting accounts, trusts, or domain policy gaps found."
        }
    }
    catch {
        Write-Warning "Test-ADKerberosHardening: error during RC4 encryption audit: $_"
    }

    # =====================================================================
    # Check 2: Kerberos Armoring (FAST) Not Enabled (live-only)
    # =====================================================================
    if ($Snapshot) {
        Write-Verbose "Test-ADKerberosHardening: -Snapshot supplied; Kerberos Armoring (FAST) GPO/registry policy state is not part of the snapshot schema, so this check is skipped entirely (offline mode performs no live AD/network access)."
    }
    else {
        try {
            Import-Module GroupPolicy -ErrorAction Stop
            $domain = Get-ADDomain -ErrorAction Stop
            $domainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADDomainController -Filter * (FAST audit)' -Query {
                Get-ADDomainController -Filter * -ErrorAction Stop
            })

            if (-not $domainControllers -or $domainControllers.Count -eq 0) {
                Write-Verbose "Test-ADKerberosHardening: no Domain Controllers found; cannot evaluate FAST/armoring policy state."
            }
            else {
                $dcOuDn = $null
                try {
                    $firstDcDn = $domainControllers[0].ComputerObjectDN
                    if ($firstDcDn -and $firstDcDn -match '^CN=[^,]+,(.+)$') {
                        $dcOuDn = $Matches[1]
                    }
                }
                catch {
                    Write-Verbose "Test-ADKerberosHardening: could not derive Domain Controllers OU: $_"
                }
                if (-not $dcOuDn) { $dcOuDn = "OU=Domain Controllers,$($domain.DistinguishedName)" }

                $dcOuGpos    = Get-ADLinkedGposOrdered -TargetDn $dcOuDn
                $domainGpos  = Get-ADLinkedGposOrdered -TargetDn $domain.DistinguishedName
                $dcScopeGpos = @($dcOuGpos + $domainGpos)

                function Get-ADKerbArmorLiveRegistryValuePerDc {
                    param([array]$DomainControllers, [string]$Key, [string]$ValueName)
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
                            Write-Verbose "Get-ADKerbArmorLiveRegistryValuePerDc: could not read '$Key\$ValueName' on '$dcName': $_"
                            [void]$results.Add([PSCustomObject]@{ DomainController = $dcName; Value = $null; Error = "$_" })
                        }
                    }
                    return $results
                }

                # --- KDC-side armoring support ---
                $kdcTarget = $Script:KerbHardeningRegistryTargets.KdcArmoring
                $kdcPolicy = Get-ADPolicyRegistryValue -Gpos $dcScopeGpos -Key $kdcTarget.Key -ValueName $kdcTarget.ValueName

                $kdcEnabled = $false
                $kdcDetail  = @{}
                if ($kdcPolicy) {
                    $kdcEnabled = ([int]$kdcPolicy.Value -ge 1)
                    $kdcDetail  = @{ Source = "GPO: $($kdcPolicy.Source)"; Value = [int]$kdcPolicy.Value }
                }
                else {
                    $perDc = Get-ADKerbArmorLiveRegistryValuePerDc -DomainControllers $domainControllers -Key $kdcTarget.Key -ValueName $kdcTarget.ValueName
                    $enabledDCs = @($perDc | Where-Object { $null -ne $_.Value -and [int]$_.Value -ge 1 } | ForEach-Object { $_.DomainController })
                    $kdcEnabled = ($enabledDCs.Count -eq $domainControllers.Count -and $domainControllers.Count -gt 0)
                    $kdcDetail  = @{ Source = 'No enforcing GPO found; observed via direct per-DC registry read'; PerDomainControllerState = @($perDc) }
                }

                # --- Client-side armoring support ---
                $clientTarget = $Script:KerbHardeningRegistryTargets.ClientArmoring
                $clientPolicy = Get-ADPolicyRegistryValue -Gpos $domainGpos -Key $clientTarget.Key -ValueName $clientTarget.ValueName

                $clientEnabled = $false
                $clientDetail  = @{}
                if ($clientPolicy) {
                    $clientEnabled = ([int]$clientPolicy.Value -ge 1)
                    $clientDetail  = @{ Source = "GPO: $($clientPolicy.Source)"; Value = [int]$clientPolicy.Value }
                }
                else {
                    $perDc = Get-ADKerbArmorLiveRegistryValuePerDc -DomainControllers $domainControllers -Key $clientTarget.Key -ValueName $clientTarget.ValueName
                    $enabledDCs = @($perDc | Where-Object { $null -ne $_.Value -and [int]$_.Value -ge 1 } | ForEach-Object { $_.DomainController })
                    $clientEnabled = ($enabledDCs.Count -eq $domainControllers.Count -and $domainControllers.Count -gt 0)
                    $clientDetail  = @{ Source = 'No enforcing GPO found (domain root); observed via direct per-DC registry read as a representative sample - not every workstation/member server is probed'; PerDomainControllerState = @($perDc) }
                }

                if (-not $kdcEnabled -or -not $clientEnabled) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Kerberos Security'
                    $finding.Issue = 'Kerberos Armoring (FAST) Not Enabled'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $domain.DNSRoot
                    $finding.Description = "Kerberos Armoring (FAST) is not fully enabled: KDC support $(if ($kdcEnabled) { 'enabled' } else { 'NOT enabled' }); client support $(if ($clientEnabled) { 'enabled' } else { 'NOT enabled' })."
                    $finding.Impact = "Without FAST/armoring, the initial AS-REQ exchange is unprotected, leaving pre-authentication data exposed to offline attack and preventing use of compound authentication/claims-based conditional access policies."
                    $finding.Remediation = "Enable 'KDC support for claims, compound authentication, and Kerberos armoring' (set to at least 'Supported') on all Domain Controllers, and 'Kerberos client support for claims, compound authentication, and Kerberos armoring' domain-wide, via GPO."
                    $finding.Details = @{
                        KdcArmoringEnabled    = $kdcEnabled
                        KdcDetail             = $kdcDetail
                        ClientArmoringEnabled = $clientEnabled
                        ClientDetail          = $clientDetail
                    }
                    $findings += $finding
                }
                else {
                    Write-Verbose "Test-ADKerberosHardening: Kerberos Armoring (FAST) is enabled for both KDC and client scope."
                }
            }
        }
        catch {
            Write-Warning "Test-ADKerberosHardening: error evaluating Kerberos Armoring (FAST) policy state: $_"
        }
    }

    # =====================================================================
    # Check 3: Cross-Trust TGT Delegation Enabled (snapshot-aware)
    # =====================================================================
    try {
        $trusts = if ($Snapshot -and $Snapshot.ContainsKey('Trusts') -and $Snapshot.Trusts) {
            Write-Verbose "Test-ADKerberosHardening: evaluating cross-trust TGT delegation from snapshot."
            @($Snapshot.Trusts)
        }
        else {
            Write-Verbose "Test-ADKerberosHardening: evaluating cross-trust TGT delegation via live Get-ADTrust."
            @(Invoke-ADQueryWithRetry -OperationName 'Get-ADTrust (TGT delegation audit)' -Query {
                Get-ADTrust -Filter * -Properties * -ErrorAction Stop
            })
        }

        $delegationTrusts = [System.Collections.ArrayList]::new()
        foreach ($trust in $trusts) {
            if ($null -eq $trust.trustAttributes) { continue }
            $attrs = [int]$trust.trustAttributes
            if (($attrs -band $Script:KerbTrustAttributeFlags.CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION) -ne 0) {
                [void]$delegationTrusts.Add(@{
                    Target          = $trust.Target
                    TrustAttributes = $attrs
                    Direction       = $trust.Direction
                    TrustType       = $trust.TrustType
                })
            }
        }

        if ($delegationTrusts.Count -gt 0) {
            $targets = @($delegationTrusts | ForEach-Object { $_.Target })
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Kerberos Security'
            $finding.Issue = 'Cross-Trust TGT Delegation Enabled'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = ($targets -join ', ')
            $finding.Description = "$($delegationTrusts.Count) trust(s) have the CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION attribute set, permitting a client's TGT to be forwarded across the trust boundary during constrained delegation: $($targets -join ', ')."
            $finding.Impact = "Allowing TGTs to cross a trust boundary during S4U2Proxy widens the blast radius of a compromise on either side of the trust - a compromised resource on the trusting side can receive and potentially misuse TGT material belonging to principals from the other domain/forest."
            $finding.Remediation = "Review whether cross-organization TGT delegation is actually required for this trust; if not, clear the CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION attribute (Netdom or the appropriate trust-management tooling) so delegation stops at the trust boundary."
            $finding.Details = @{
                Trusts = @($delegationTrusts)
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADKerberosHardening: no trusts with cross-organization TGT delegation enabled found."
        }
    }
    catch {
        Write-Warning "Test-ADKerberosHardening: error evaluating cross-trust TGT delegation: $_"
    }

    Write-Verbose "Kerberos hardening depth audit complete. Found $($findings.Count) issue(s)."
    return $findings
}

#endregion
