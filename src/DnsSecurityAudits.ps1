#region AD-Integrated DNS Security Audit
#
# Audits AD-integrated DNS for the DNS-specific attack surface that most
# generic AD reviews miss: DnsAdmins group membership (a well-known
# Domain-Controller code-execution path via the DNS server's
# ServerLevelPluginDll mechanism), zone transfer exposure, insecure dynamic
# updates, and overly broad child-object creation rights on zone objects
# (the "ADIDNS" spoofing/MITM surface). PingCastle parity: P-DNSAdmin,
# P-DNSDelegation, A-DnsZoneTransfert, A-DnsZoneUpdate1, A-DnsZoneUpdate2,
# A-DnsZoneAUCreateChild.
#
# Snapshot-aware for the DnsAdmins membership check only: it reads the
# 'DnsAdmins' entry from Snapshot.Groups (Members flattened to DNs, same
# shape used by the Pre-Windows 2000 check in DomainHardeningAudits.ps1)
# when a snapshot is supplied. The per-zone checks (zone transfer, dynamic
# update, and ADIDNS CreateChild ACL) read zone-level attributes
# (dNSProperty) and ACLs (nTSecurityDescriptor) that are not part of the
# existing Snapshot.DnsZones shape (Name/DistinguishedName only), so - per
# the established -FromSnapshot contract of performing NO live AD/network
# access (see Test-ADCoercionAndRelayExposure, the anonymous-bind probe in
# Test-ADDomainHardeningFlags, and the ESC4/ESC8 checks in
# Test-ADCSExtended) - they are live-only and are skipped entirely when
# this function is invoked with -Snapshot.
#
# DETECTION ONLY: this module reads group membership, AD-integrated zone
# object attributes/ACLs, and (optionally) read-only DNS Server PowerShell
# cmdlets (Get-DnsServerZone / Get-DnsServerZoneTransfer). It never creates,
# deletes, or modifies a DNS record or zone, never registers a plugin DLL,
# and performs no exploitation, coercion, relay, or PoC traffic.

# Well-known/service SIDs that legitimately end up referenced from DnsAdmins
# in some environments and should not be flagged as "non-default" human/
# service membership. DnsAdmins itself has NO members by default, so
# anything outside this short, well-known list is reported.
$Script:DnsAdminsExpectedSids = @{
    'S-1-5-9'  = 'Enterprise Domain Controllers'
    'S-1-5-18' = 'NT AUTHORITY\SYSTEM'
    'S-1-5-20' = 'NT AUTHORITY\NETWORK SERVICE'
}

# Principals whose presence in a zone's CreateChild (or equivalent broad)
# ACE indicates the classic ADIDNS spoofing/MITM exposure: any authenticated
# user (or broader) can create arbitrary child DNS node objects in the zone.
$Script:DnsAdidnsBroadPrincipalSids = @{
    'S-1-5-11' = 'Authenticated Users'
    'S-1-1-0'  = 'Everyone'
    'S-1-5-7'  = 'ANONYMOUS LOGON'
}

# Pseudo-zone names that live alongside real zones under the
# DomainDnsZones/ForestDnsZones MicrosoftDNS container but are not
# attacker-relevant DNS zones themselves.
$Script:DnsPseudoZoneNames = @('RootDNSServers', '..TrustAnchors')

# Best-effort parser for the AD-integrated DNS zone 'dNSProperty' attribute
# (a multivalued binary attribute; each value is one DNS_PROPERTY record as
# used by the DNS Server RPC/AD storage format: a 20-byte header - 4-byte
# data length, 4 reserved bytes, 4-byte property Id, 4-byte data type, 4-byte
# flag - followed by the property's data). Only used to recover DWORD-typed
# zone properties (ALLOW_UPDATE, SECURE_SECONDARIES) when the DnsServer
# PowerShell module is not available. Returns $null (rather than a possibly
# wrong value) for anything it cannot confidently parse, so a parsing gap
# degrades to "skip this check" instead of an incorrect finding.
function Get-ADDnsZonePropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$DnsPropertyValues,

        [Parameter(Mandatory)]
        [uint32]$PropertyId
    )

    foreach ($propBytes in $DnsPropertyValues) {
        try {
            if (-not $propBytes -or $propBytes.Length -lt 24) { continue }

            $id = [BitConverter]::ToUInt32($propBytes, 8)
            if ($id -ne $PropertyId) { continue }

            # DWORD-typed property value immediately follows the 20-byte header.
            return [BitConverter]::ToUInt32($propBytes, 20)
        }
        catch {
            Write-Verbose "Get-ADDnsZonePropertyValue: failed to parse a dNSProperty value: $_"
            continue
        }
    }

    return $null
}

function Test-ADDnsSecurity {
    <#
    .SYNOPSIS
        Audits AD-integrated DNS security: DnsAdmins membership, zone
        transfer exposure, insecure dynamic updates, and ADIDNS
        (broad child-object creation) on AD-integrated zones.
    .DESCRIPTION
        Four checks:
          1. DnsAdmins group membership - any member outside a short list of
             well-known service SIDs is flagged (DnsAdmins is empty by
             default; membership grants a well-known DC code-execution path
             via the DNS server's ServerLevelPluginDll mechanism).
          2. DNS Zone Transfer Allowed - flags AD-integrated zones configured
             to transfer to any server or to any server listed as an NS
             record for the zone (i.e. not restricted to an explicit
             secondary-server list).
          3. Insecure Dynamic DNS Updates Enabled - flags zones allowing
             nonsecure (unauthenticated) dynamic updates.
          4. Authenticated Users Can Create Child Objects in DNS Zone
             (ADIDNS) - flags zones whose AD object ACL grants CreateChild
             (or an equivalently broad right) to Authenticated Users,
             Everyone, or ANONYMOUS LOGON, enabling arbitrary DNS record
             registration/spoofing.

        Checks 2-4 prefer the read-only `Get-DnsServerZone` /
        `Get-DnsServerZoneTransfer` cmdlets (DnsServer RSAT module) when
        available, and fall back to a best-effort read of the zone AD
        object's `dNSProperty` attribute when that module is not installed.
        If neither source yields a confident answer for a zone, that check
        is skipped for that zone (Verbose only) rather than guessing.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied,
        the DnsAdmins membership check is derived from `Snapshot.Groups`
        instead of a live query. The zone-level checks (transfer, dynamic
        update, ADIDNS CreateChild) read zone attributes/ACLs that are not
        part of the current snapshot schema and are live-only network/AD
        operations, so - consistent with the -FromSnapshot contract of
        performing no live AD/network access - they are skipped entirely
        when -Snapshot is supplied.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting AD-integrated DNS security audit..."
    $findings = @()

    # -------------------------------------------------------------------
    # Check 1: Non-Default Members in DnsAdmins
    # -------------------------------------------------------------------
    try {
        $nonDefaultMembers = [System.Collections.ArrayList]::new()
        $dnsAdminsDN = $null

        if ($Snapshot -and $Snapshot.ContainsKey('Groups') -and $Snapshot.Groups) {
            Write-Verbose "Test-ADDnsSecurity: using snapshot data for DnsAdmins membership."
            $dnsAdminsGroup = $Snapshot.Groups | Where-Object { $_.Name -eq 'DnsAdmins' } | Select-Object -First 1

            if ($dnsAdminsGroup) {
                $dnsAdminsDN = $dnsAdminsGroup.DistinguishedName
                foreach ($memberDN in @($dnsAdminsGroup.Members)) {
                    if (-not $memberDN) { continue }
                    $isExpected = $false
                    foreach ($sid in $Script:DnsAdminsExpectedSids.Keys) {
                        if ($memberDN -match "CN=$sid,") { $isExpected = $true; break }
                    }
                    if (-not $isExpected) {
                        [void]$nonDefaultMembers.Add($memberDN)
                    }
                }
            }
            else {
                Write-Verbose "Test-ADDnsSecurity: 'DnsAdmins' group not found in snapshot (DNS role may not be installed)."
            }
        }
        else {
            $dnsAdminsGroup = $null
            try {
                $dnsAdminsGroup = Invoke-ADQueryWithRetry -OperationName 'Get-ADGroup DnsAdmins' -Query {
                    Get-ADGroup -Filter "Name -eq 'DnsAdmins'" -ErrorAction Stop
                }
            }
            catch {
                Write-Verbose "Test-ADDnsSecurity: error looking up 'DnsAdmins' group: $_"
            }

            if ($dnsAdminsGroup) {
                $dnsAdminsDN = $dnsAdminsGroup.DistinguishedName
                $members = Invoke-ADQueryWithRetry -OperationName 'Get-ADGroupMember DnsAdmins' -Query {
                    Get-ADGroupMember -Identity $dnsAdminsGroup -ErrorAction Stop
                }

                foreach ($member in @($members)) {
                    $sidValue = if ($member.SID) { $member.SID.Value } else { $null }
                    if ($sidValue -and $Script:DnsAdminsExpectedSids.ContainsKey($sidValue)) { continue }
                    [void]$nonDefaultMembers.Add("$($member.SamAccountName) ($($member.objectClass))")
                }
            }
            else {
                Write-Verbose "Test-ADDnsSecurity: 'DnsAdmins' group not found (DNS role may not be installed on any DC)."
            }
        }

        if ($nonDefaultMembers.Count -gt 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'DNS Security'
            $finding.Issue = 'Non-Default Members in DnsAdmins'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = if ($dnsAdminsDN) { $dnsAdminsDN } else { 'DnsAdmins' }
            $finding.Description = "The 'DnsAdmins' group, which has no members by default, contains $($nonDefaultMembers.Count) member(s): $($nonDefaultMembers -join ', ')."
            $finding.Impact = "Members of DnsAdmins can configure the DNS server's `ServerLevelPluginDll` registry value, causing the DNS service (which runs as SYSTEM on the Domain Controller) to load an attacker-supplied DLL on next restart. This is a well-known path from DnsAdmins membership directly to SYSTEM-level code execution on a Domain Controller."
            $finding.Remediation = "Remove non-essential members from DnsAdmins and treat it as a Tier-0-equivalent group. Restrict `ServerLevelPluginDll` configuration rights, and where possible manage DNS via a dedicated, closely audited administrative workflow rather than broad DnsAdmins membership."
            $finding.Details = @{
                DistinguishedName = $dnsAdminsDN
                Members           = @($nonDefaultMembers)
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: no non-default DnsAdmins members found."
        }
    }
    catch {
        Write-Warning "Test-ADDnsSecurity: error auditing DnsAdmins membership: $_"
    }

    # -------------------------------------------------------------------
    # Checks 2-4: per-zone transfer / dynamic update / ADIDNS CreateChild.
    # These read zone-level attributes/ACLs that are not part of the
    # current snapshot schema and require live AD/network access, so they
    # are skipped entirely when -Snapshot is supplied (offline mode
    # performs no live AD/network access).
    # -------------------------------------------------------------------
    if ($Snapshot) {
        Write-Verbose "Test-ADDnsSecurity: -Snapshot supplied; skipping live zone transfer/dynamic-update/ADIDNS checks (offline mode performs no live AD/network access)."
        Write-Verbose "AD-integrated DNS security audit complete. Found $($findings.Count) issue(s)."
        return $findings
    }

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction SilentlyContinue

        $dnsPartitions = @("DC=DomainDnsZones,$($domain.DistinguishedName)")
        if ($forest) {
            $forestRootDN = ($forest.RootDomain | ForEach-Object { "DC=$($_ -replace '\.', ',DC=')" })
            $dnsPartitions += "DC=ForestDnsZones,$forestRootDN"
        }

        $zoneObjects = [System.Collections.ArrayList]::new()
        foreach ($partition in $dnsPartitions) {
            try {
                $zonesInPartition = Get-ADObject -SearchBase "CN=MicrosoftDNS,$partition" -Filter "objectClass -eq 'dnsZone'" `
                    -Properties dNSProperty, nTSecurityDescriptor -ErrorAction Stop
                foreach ($z in @($zonesInPartition)) {
                    if ($z.Name -in $Script:DnsPseudoZoneNames) { continue }
                    [void]$zoneObjects.Add($z)
                }
            }
            catch {
                Write-Verbose "Test-ADDnsSecurity: no DNS zones found under '$partition': $_"
            }
        }

        if ($zoneObjects.Count -eq 0) {
            Write-Verbose "Test-ADDnsSecurity: no AD-integrated DNS zones found; skipping zone-level checks."
            Write-Verbose "AD-integrated DNS security audit complete. Found $($findings.Count) issue(s)."
            return $findings
        }

        # Determine whether the read-only DnsServer module is available for
        # the more precise cmdlet-based path; otherwise fall back to the
        # dNSProperty attribute read on each zone object.
        $useDnsCmdlets = $false
        $dnsCmdletTargetDC = $null
        if (Get-Module -ListAvailable -Name DnsServer -ErrorAction SilentlyContinue) {
            try {
                $dnsCmdletTargetDC = (Invoke-ADQueryWithRetry -OperationName 'Get-ADDomainController -Discover (DNS audit)' -Query {
                    Get-ADDomainController -Discover -ErrorAction Stop
                }).HostName
                if ($dnsCmdletTargetDC) {
                    Import-Module DnsServer -ErrorAction Stop
                    $useDnsCmdlets = $true
                }
            }
            catch {
                Write-Verbose "Test-ADDnsSecurity: DnsServer module present but could not be used ($_); falling back to AD attribute reads."
                $useDnsCmdlets = $false
            }
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: DnsServer RSAT module not available; falling back to AD attribute (dNSProperty) reads for zone transfer/dynamic update."
        }

        $broadTransferZones  = [System.Collections.ArrayList]::new()
        $insecureUpdateZones = [System.Collections.ArrayList]::new()
        $adidnsZones         = [System.Collections.ArrayList]::new()
        $zoneDetailLookup    = @{}

        foreach ($zone in $zoneObjects) {
            $zoneName = $zone.Name
            $zoneDN   = $zone.DistinguishedName
            $transferSetting = $null
            $updateSetting   = $null

            if ($useDnsCmdlets) {
                try {
                    $dnsZoneInfo = Invoke-ADQueryWithRetry -OperationName "Get-DnsServerZone '$zoneName'" -Query {
                        Get-DnsServerZone -Name $zoneName -ComputerName $dnsCmdletTargetDC -ErrorAction Stop
                    }
                    if ($dnsZoneInfo -and $dnsZoneInfo.DynamicUpdate) {
                        $updateSetting = "$($dnsZoneInfo.DynamicUpdate)"
                    }
                }
                catch {
                    Write-Verbose "Test-ADDnsSecurity: Get-DnsServerZone failed for '$zoneName': $_"
                }

                try {
                    $dnsTransferInfo = Invoke-ADQueryWithRetry -OperationName "Get-DnsServerZoneTransfer '$zoneName'" -Query {
                        Get-DnsServerZoneTransfer -Name $zoneName -ComputerName $dnsCmdletTargetDC -ErrorAction Stop
                    }
                    if ($dnsTransferInfo -and $dnsTransferInfo.Type) {
                        $transferSetting = "$($dnsTransferInfo.Type)"
                    }
                }
                catch {
                    Write-Verbose "Test-ADDnsSecurity: Get-DnsServerZoneTransfer failed for '$zoneName': $_"
                }
            }
            else {
                $dnsPropertyValues = @($zone.dNSProperty)
                if ($dnsPropertyValues.Count -gt 0) {
                    # DSPROPERTY_ZONE_ALLOW_UPDATE = 2 (0 = None, 1 = Nonsecure and secure, 2 = Secure only)
                    $allowUpdateRaw = Get-ADDnsZonePropertyValue -DnsPropertyValues $dnsPropertyValues -PropertyId 2
                    if ($null -ne $allowUpdateRaw) {
                        $updateSetting = switch ([int]$allowUpdateRaw) {
                            0 { 'None' }
                            1 { 'NonsecureAndSecure' }
                            2 { 'Secure' }
                            default { $null }
                        }
                    }

                    # DSPROPERTY_ZONE_SECURE_SECONDARIES = 9 (0 = any server, 1 = servers listed on Name Servers tab,
                    # 2 = explicit secondary-server list only, 3 = no transfers)
                    $secureSecondariesRaw = Get-ADDnsZonePropertyValue -DnsPropertyValues $dnsPropertyValues -PropertyId 9
                    if ($null -ne $secureSecondariesRaw) {
                        $transferSetting = switch ([int]$secureSecondariesRaw) {
                            0 { 'Any' }
                            1 { 'Named' }
                            2 { 'Specific' }
                            3 { 'None' }
                            default { $null }
                        }
                    }
                }
                else {
                    Write-Verbose "Test-ADDnsSecurity: zone '$zoneName' has no dNSProperty values to parse; skipping transfer/update checks for this zone."
                }
            }

            $zoneDetailLookup[$zoneName] = @{
                DistinguishedName = $zoneDN
                DynamicUpdate     = $updateSetting
                ZoneTransferType  = $transferSetting
            }

            if ($transferSetting -in @('Any', 'Named')) {
                [void]$broadTransferZones.Add(@{ Zone = $zoneName; Setting = $transferSetting })
            }

            if ($updateSetting -eq 'NonsecureAndSecure') {
                [void]$insecureUpdateZones.Add(@{ Zone = $zoneName; Setting = $updateSetting })
            }

            # --- ADIDNS: broad CreateChild (or equivalently broad) rights on the zone object ---
            try {
                $acl = $zone.nTSecurityDescriptor
                if ($acl -and $acl.Access) {
                    $broadPrincipalsForZone = [System.Collections.ArrayList]::new()

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }
                        if ($ace.ActiveDirectoryRights -notmatch 'CreateChild|GenericAll') { continue }

                        $identity = "$($ace.IdentityReference)"
                        foreach ($sid in $Script:DnsAdidnsBroadPrincipalSids.Keys) {
                            $wellKnownName = $Script:DnsAdidnsBroadPrincipalSids[$sid]
                            if ($identity -match [regex]::Escape($wellKnownName) -or $identity -match [regex]::Escape($sid)) {
                                [void]$broadPrincipalsForZone.Add(@{
                                    Principal = $wellKnownName
                                    Rights    = "$($ace.ActiveDirectoryRights)"
                                })
                            }
                        }
                    }

                    if ($broadPrincipalsForZone.Count -gt 0) {
                        [void]$adidnsZones.Add(@{
                            Zone              = $zoneName
                            DistinguishedName = $zoneDN
                            BroadPrincipals   = @($broadPrincipalsForZone)
                        })
                    }
                }
            }
            catch {
                Write-Verbose "Test-ADDnsSecurity: could not evaluate ACL for zone '$zoneName': $_"
            }
        }

        # -------------------------------------------------------------------
        # Finding: DNS Zone Transfer Allowed
        # -------------------------------------------------------------------
        if ($broadTransferZones.Count -gt 0) {
            $zoneNames = @($broadTransferZones | ForEach-Object { $_.Zone })
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'DNS Security'
            $finding.Issue = 'DNS Zone Transfer Allowed'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = ($zoneNames -join ', ')
            $finding.Description = "$($broadTransferZones.Count) AD-integrated zone(s) allow zone transfers to any server or to any server listed as a name server for the zone, rather than an explicit secondary-server list: $($zoneNames -join ', ')."
            $finding.Impact = "Zone transfers expose the complete contents of a DNS zone - hostnames, IP addresses, and often internal naming conventions for servers, workstations, and services - to any host that can request an AXFR, aiding network reconnaissance ahead of further attacks."
            $finding.Remediation = "Restrict zone transfers to an explicit list of authorized secondary server IP addresses (`Set-DnsServerZoneTransfer -Name <Zone> -SecureSecondaries TransferToSecureServers -SecondaryServers <IP1>,<IP2>`), or disable transfers entirely if no secondaries are in use."
            $finding.Details = @{
                Zones       = @($broadTransferZones)
                DetailByZone = $zoneDetailLookup
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: no zones with broad zone-transfer settings found."
        }

        # -------------------------------------------------------------------
        # Finding: Insecure Dynamic DNS Updates Enabled
        # -------------------------------------------------------------------
        if ($insecureUpdateZones.Count -gt 0) {
            $zoneNames = @($insecureUpdateZones | ForEach-Object { $_.Zone })
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'DNS Security'
            $finding.Issue = 'Insecure Dynamic DNS Updates Enabled'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = ($zoneNames -join ', ')
            $finding.Description = "$($insecureUpdateZones.Count) AD-integrated zone(s) permit nonsecure (unauthenticated) dynamic updates: $($zoneNames -join ', ')."
            $finding.Impact = "Nonsecure dynamic updates let any client on the network - authenticated or not - create or modify DNS records in the zone without proof of identity, enabling record spoofing/hijacking that can redirect traffic or facilitate downstream relay/MITM attacks."
            $finding.Remediation = "Set the zone to accept secure dynamic updates only (`Set-DnsServerPrimaryZone -Name <Zone> -DynamicUpdate Secure`), which restricts updates to Kerberos-authenticated domain-joined clients."
            $finding.Details = @{
                Zones        = @($insecureUpdateZones)
                DetailByZone = $zoneDetailLookup
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: no zones with insecure dynamic updates found."
        }

        # -------------------------------------------------------------------
        # Finding: Authenticated Users Can Create Child Objects in DNS Zone (ADIDNS)
        # -------------------------------------------------------------------
        if ($adidnsZones.Count -gt 0) {
            $zoneNames = @($adidnsZones | ForEach-Object { $_.Zone })
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'DNS Security'
            $finding.Issue = 'Authenticated Users Can Create Child Objects in DNS Zone'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = ($zoneNames -join ', ')
            $finding.Description = "$($adidnsZones.Count) AD-integrated zone object(s) grant broad principals (Authenticated Users, Everyone, or ANONYMOUS LOGON) the right to create child objects: $($zoneNames -join ', ')."
            $finding.Impact = "Any authenticated (or, in the worst case, unauthenticated) principal can register arbitrary new DNS node objects in the zone (ADIDNS), enabling record spoofing for names not already present - commonly used to impersonate wildcard/service names, poison WPAD-style discovery, or stage NTLM-relay/MITM attacks."
            $finding.Remediation = "Review and tighten the zone object's ACL to remove CreateChild (or broader) rights from Authenticated Users/Everyone/ANONYMOUS LOGON, restricting DNS record creation to the intended administrative or provisioning principals."
            $finding.Details = @{
                Zones = @($adidnsZones)
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: no zones with broad ADIDNS CreateChild rights found."
        }
    }
    catch {
        Write-Warning "Test-ADDnsSecurity: error auditing DNS zone security: $_"
    }

    Write-Verbose "AD-integrated DNS security audit complete. Found $($findings.Count) issue(s)."
    return $findings
}

#endregion
