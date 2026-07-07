#region Scoring, ANSSI maturity & MITRE ATT&CK mapping
#
# This file is the SINGLE SOURCE OF TRUTH for the finding/output contract's
# metadata layer. It defines:
#
#   1. $Script:ADFindingMetadataMap - one table mapping each finding Issue
#      string to its MITRE ATT&CK technique, ANSSI-style control id, and a
#      risk weight. This is the ONE place to extend when new checks are added.
#   2. $Script:MitreTechniqueNames  - id -> human-readable technique name
#      (used only for report rendering).
#   3. Set-ADFindingMetadata        - tags a finding from the table.
#   4. Get-ADRiskScore              - computes a 0-100 total (higher = worse),
#      per-category sub-scores, and a 1-5 ANSSI-style maturity bucket.
#
# CONTRACT RULES (frozen for the remainder of the backlog):
#   * Finding fields are additive only (Details stays a hashtable).
#   * ANSSI control ids follow the convention 'vuln<level>_<slug>' where
#     <level> is the ANSSI maturity level (1 = most critical hygiene gap,
#     5 = advanced). Maturity is derived from this prefix, so the prefix is
#     load-bearing - keep it as the first characters of every AnssiControl.
#
# DETECTION ONLY: nothing here performs exploitation. Scoring reads finding
# metadata that was produced by read-only configuration/attribute checks.
#
# Mapping note: MITRE technique ids are authoritative. The ANSSI control ids
# follow ANSSI's Active Directory point-of-control conventions and the
# PingCastle maturity model; review against the current official ANSSI
# control catalogue before relying on them for formal compliance reporting.

# Fallback weights by SeverityLevel (Critical=4 .. Info=0), used only when an
# Issue is not present in the mapping table.
$Script:ADScoreSeverityWeights = @{
    4 = 40   # Critical
    3 = 20   # High
    2 = 10   # Medium
    1 = 4    # Low
    0 = 1    # Info
}

# Fallback ANSSI level by SeverityLevel (used only for unmapped issues).
$Script:ADScoreSeverityAnssiLevel = @{
    4 = 1
    3 = 2
    2 = 3
    1 = 4
    0 = 5
}

# MITRE ATT&CK technique id -> display name (rendering only).
$Script:MitreTechniqueNames = @{
    'T1003'      = 'OS Credential Dumping'
    'T1003.006'  = 'OS Credential Dumping: DCSync'
    'T1037'      = 'Boot or Logon Initialization Scripts'
    'T1078.002'  = 'Valid Accounts: Domain Accounts'
    'T1078.003'  = 'Valid Accounts: Local Accounts'
    'T1087.002'  = 'Account Discovery: Domain Account'
    'T1098'      = 'Account Manipulation'
    'T1110'      = 'Brute Force'
    'T1134.005'  = 'Access Token Manipulation: SID-History Injection'
    'T1136.002'  = 'Create Account: Domain Account'
    'T1210'      = 'Exploitation of Remote Services'
    'T1482'      = 'Domain Trust Discovery'
    'T1484.001'  = 'Domain Policy Modification: Group Policy Modification'
    'T1485'      = 'Data Destruction'
    'T1556'      = 'Modify Authentication Process'
    'T1558'      = 'Steal or Forge Kerberos Tickets'
    'T1558.001'  = 'Steal or Forge Kerberos Tickets: Golden Ticket'
    'T1558.002'  = 'Steal or Forge Kerberos Tickets: Silver Ticket'
    'T1558.003'  = 'Steal or Forge Kerberos Tickets: Kerberoasting'
    'T1558.004'  = 'Steal or Forge Kerberos Tickets: AS-REP Roasting'
    'T1562.002'  = 'Impair Defenses: Disable Windows Event Logging'
    'T1649'      = 'Steal or Forge Authentication Certificates'
}

# -----------------------------------------------------------------------------
# THE central mapping table. Issue string -> @{ Mitre; Anssi; Weight }.
# Seeded for every Issue string emitted by the existing audit modules.
# To add a new check: add ONE entry here keyed by its exact Issue string.
# -----------------------------------------------------------------------------
$Script:ADFindingMetadataMap = @{

    # --- User Account ---
    'Kerberos Pre-Authentication Disabled'                  = @{ Mitre = 'T1558.004'; Anssi = 'vuln2_asrep_roastable';        Weight = 20 }
    'DES Encryption Enabled'                                = @{ Mitre = 'T1558.003'; Anssi = 'vuln2_des_enabled';            Weight = 20 }
    'Reversible Password Encryption'                        = @{ Mitre = 'T1003';     Anssi = 'vuln1_reversible_password';     Weight = 40 }
    'Password Never Expires'                                = @{ Mitre = 'T1078.002'; Anssi = 'vuln3_password_never_expires';  Weight = 10 }
    'Unconstrained Delegation Enabled'                      = @{ Mitre = 'T1558';     Anssi = 'vuln1_unconstrained_delegation';Weight = 40 }
    'Inactive Enabled Account'                              = @{ Mitre = 'T1078.002'; Anssi = 'vuln4_inactive_account';        Weight = 4  }
    'Old Password'                                          = @{ Mitre = 'T1110';     Anssi = 'vuln4_old_password';            Weight = 4  }
    'Privileged Account with SPN (Kerberoasting Risk)'     = @{ Mitre = 'T1558.003'; Anssi = 'vuln1_priv_spn_kerberoast';     Weight = 40 }
    'User Account with SPN (Kerberoasting Risk)'           = @{ Mitre = 'T1558.003'; Anssi = 'vuln3_spn_kerberoast';          Weight = 10 }
    'Privileged Account Not in Protected Users Group'      = @{ Mitre = 'T1003';     Anssi = 'vuln3_protected_users';         Weight = 10 }

    # --- Privileged Groups ---
    'Excessive Privileged Group Membership'                = @{ Mitre = 'T1078.002'; Anssi = 'vuln2_privileged_members';      Weight = 20 }
    'Nested Groups in Critical Privileged Group'           = @{ Mitre = 'T1078.002'; Anssi = 'vuln2_nested_privileged_group'; Weight = 20 }
    'Disabled User in Privileged Group'                    = @{ Mitre = 'T1078.002'; Anssi = 'vuln4_disabled_in_privileged';  Weight = 4  }

    # --- AdminSDHolder ---
    'Non-Standard Permissions on AdminSDHolder'            = @{ Mitre = 'T1098';     Anssi = 'vuln1_adminsdholder_acl';       Weight = 40 }
    'Deny ACE on AdminSDHolder'                            = @{ Mitre = 'T1098';     Anssi = 'vuln3_adminsdholder_deny_ace';  Weight = 10 }
    'Orphaned adminCount Attribute'                        = @{ Mitre = 'T1078.002'; Anssi = 'vuln4_orphaned_admincount';     Weight = 4  }
    'AdminSDHolder Ghost Account'                          = @{ Mitre = 'T1098';     Anssi = 'vuln2_adminsdholder_ghost';     Weight = 20 }
    'AdminSDHolder ACL Compromise'                         = @{ Mitre = 'T1098';     Anssi = 'vuln1_adminsdholder_compromise';Weight = 40 }
    'No Auditing on AdminSDHolder Object'                  = @{ Mitre = 'T1562.002'; Anssi = 'vuln3_no_audit_adminsdholder';  Weight = 10 }

    # --- Group Policy ---
    'Over-Permissioned GPO'                                = @{ Mitre = 'T1484.001'; Anssi = 'vuln2_gpo_overpermissioned';    Weight = 20 }
    'GPO Linked to Domain Controllers with Weak Permissions' = @{ Mitre = 'T1484.001'; Anssi = 'vuln1_gpo_dc_weak_perms';    Weight = 40 }
    'Unlinked GPO'                                         = @{ Mitre = 'T1484.001'; Anssi = 'vuln5_unlinked_gpo';            Weight = 1  }
    'Insecure SYSVOL Permissions'                          = @{ Mitre = 'T1484.001'; Anssi = 'vuln2_sysvol_permissions';      Weight = 20 }

    # --- Replication Security ---
    'Unauthorized DCSync Permissions'                      = @{ Mitre = 'T1003.006'; Anssi = 'vuln1_dcsync';                  Weight = 40 }
    'Membership in Privileged Operations Group'            = @{ Mitre = 'T1078.002'; Anssi = 'vuln3_privileged_ops_group';    Weight = 10 }

    # --- Domain Security ---
    'Weak Minimum Password Length'                         = @{ Mitre = 'T1110';     Anssi = 'vuln2_weak_min_pwd_length';     Weight = 20 }
    'Password Complexity Disabled'                         = @{ Mitre = 'T1110';     Anssi = 'vuln2_pwd_complexity_disabled'; Weight = 20 }
    'Reversible Encryption Enabled Domain-Wide'            = @{ Mitre = 'T1003';     Anssi = 'vuln1_reversible_domain_wide';  Weight = 40 }
    'Outdated Domain Functional Level'                     = @{ Mitre = 'T1078.002'; Anssi = 'vuln4_outdated_dfl';            Weight = 4  }
    'AD Recycle Bin Not Enabled'                           = @{ Mitre = 'T1485';     Anssi = 'vuln5_recycle_bin_disabled';    Weight = 1  }
    'Legacy Operating Systems in Domain'                   = @{ Mitre = 'T1210';     Anssi = 'vuln3_legacy_os';               Weight = 10 }
    'Stale AzureADSSOACC Kerberos Key'                     = @{ Mitre = 'T1558.002'; Anssi = 'vuln2_azuread_sso_key';         Weight = 20 }

    # --- Domain Trusts ---
    'Bidirectional Domain Trust'                           = @{ Mitre = 'T1482';     Anssi = 'vuln4_bidirectional_trust';     Weight = 4  }
    'SID Filtering Disabled on External Trust'             = @{ Mitre = 'T1134.005'; Anssi = 'vuln1_sid_filtering_disabled';  Weight = 40 }
    'Forest Trust Without Selective Authentication'        = @{ Mitre = 'T1482';     Anssi = 'vuln3_no_selective_auth';       Weight = 10 }
    'Trust Password Not Recently Rotated'                  = @{ Mitre = 'T1558';     Anssi = 'vuln3_trust_pwd_rotation';      Weight = 10 }

    # --- Certificate Services (AD CS / ESC) ---
    'Certificate Template Allows Subject Alternative Name (ESC1)'        = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc1';        Weight = 40 }
    'Certificate Template Allows Subject Alternative Name (Restricted)'  = @{ Mitre = 'T1649'; Anssi = 'vuln2_adcs_esc1_restricted'; Weight = 20 }
    'Certificate Template with No EKU Restrictions (ESC2)'              = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc2';        Weight = 40 }
    'Enrollment Agent Template with Low-Privilege Enrollment (ESC3)'    = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc3';        Weight = 40 }
    'Certificate Template Does Not Require RA Signatures'               = @{ Mitre = 'T1649'; Anssi = 'vuln2_adcs_ra_signature'; Weight = 20 }
    'Overly Permissive CA Permissions (ESC7)'                          = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc7';        Weight = 40 }
    'Low-Privilege CA Management Rights'                               = @{ Mitre = 'T1649'; Anssi = 'vuln2_adcs_ca_mgmt';     Weight = 20 }

    # --- Kerberos Security (KRBTGT) ---
    'KRBTGT Password Age Exceeds Recommended Threshold'   = @{ Mitre = 'T1558.001'; Anssi = 'vuln1_krbtgt_age';              Weight = 40 }
    'KRBTGT Password Approaching Rotation Threshold'      = @{ Mitre = 'T1558.001'; Anssi = 'vuln3_krbtgt_approaching';      Weight = 10 }
    'KRBTGT Password Last Set Date Unknown'               = @{ Mitre = 'T1558.001'; Anssi = 'vuln3_krbtgt_unknown';          Weight = 10 }

    # --- LAPS Deployment ---
    'LAPS Not Deployed'                                    = @{ Mitre = 'T1078.003'; Anssi = 'vuln2_laps_not_deployed';       Weight = 20 }
    'Incomplete LAPS Coverage'                            = @{ Mitre = 'T1078.003'; Anssi = 'vuln3_laps_incomplete';         Weight = 10 }
    'Expired LAPS Passwords'                              = @{ Mitre = 'T1078.003'; Anssi = 'vuln3_laps_expired';            Weight = 10 }

    # --- Audit Policy ---
    'Insufficient Audit Policy Configuration'             = @{ Mitre = 'T1562.002'; Anssi = 'vuln3_audit_insufficient';      Weight = 10 }
    'Advanced Audit Policy Verification Required'         = @{ Mitre = 'T1562.002'; Anssi = 'vuln4_audit_verify';            Weight = 4  }
    'No Auditing on Domain Root Object'                   = @{ Mitre = 'T1562.002'; Anssi = 'vuln3_no_audit_domain_root';    Weight = 10 }

    # --- Kerberos Delegation ---
    'User Account with Protocol Transition (T2A4D)'      = @{ Mitre = 'T1558';     Anssi = 'vuln1_user_protocol_transition'; Weight = 40 }
    'User Account with Constrained Delegation'           = @{ Mitre = 'T1558';     Anssi = 'vuln2_user_constrained_deleg';   Weight = 20 }
    'Computer Account with Protocol Transition (T2A4D)'  = @{ Mitre = 'T1558';     Anssi = 'vuln2_computer_protocol_transition'; Weight = 20 }
    'Resource-Based Constrained Delegation Configured'   = @{ Mitre = 'T1558';     Anssi = 'vuln2_rbcd';                     Weight = 20 }

    # --- Dangerous Permissions ---
    'Enterprise Key Admins Over-Privileged (Misconfiguration Bug)'              = @{ Mitre = 'T1556'; Anssi = 'vuln2_enterprise_key_admins'; Weight = 20 }
    'Enterprise Key Admins Permissions Not Scoped to msDS-KeyCredentialLink'    = @{ Mitre = 'T1556'; Anssi = 'vuln3_enterprise_key_admins_scope'; Weight = 10 }
    'Dangerous Rights on Critical OU'                    = @{ Mitre = 'T1098';     Anssi = 'vuln1_dangerous_ou_rights';      Weight = 40 }

    # --- Legacy Attack Vector / Admin Equivalence ---
    'Shadow Credentials Detected'                        = @{ Mitre = 'T1556';     Anssi = 'vuln1_shadow_credentials';       Weight = 40 }
    'SID History Injection (Same Domain)'                = @{ Mitre = 'T1134.005'; Anssi = 'vuln1_sid_history_injection';     Weight = 40 }
    'Privileged SID in History'                          = @{ Mitre = 'T1134.005'; Anssi = 'vuln1_privileged_sid_history';    Weight = 40 }
    'Legacy Logon Script Defined'                        = @{ Mitre = 'T1037';     Anssi = 'vuln4_legacy_logon_script';      Weight = 4  }
    'Domain Admin Equivalent Access Detected'            = @{ Mitre = 'T1078.002'; Anssi = 'vuln2_da_equivalent_access';      Weight = 20 }

    # --- Machine Account Quota ---
    'Default Machine Account Quota Not Restricted'       = @{ Mitre = 'T1136.002'; Anssi = 'vuln2_maq_default';              Weight = 20 }
    'Non-Zero Machine Account Quota'                     = @{ Mitre = 'T1136.002'; Anssi = 'vuln3_maq_nonzero';              Weight = 10 }

    # --- Domain Hardening (dsHeuristics, Pre-Win2000, anonymous binding) ---
    'Dangerous dsHeuristics Flag Set'                    = @{ Mitre = 'T1556';     Anssi = 'vuln2_dsheuristics_dangerous';  Weight = 20 }
    'Broad Membership in Pre-Windows 2000 Compatible Access' = @{ Mitre = 'T1078.002'; Anssi = 'vuln2_prewin2000_broad';    Weight = 20 }
    'Anonymous LDAP / RootDSE Binding Permitted'         = @{ Mitre = 'T1087.002'; Anssi = 'vuln3_anonymous_bind';          Weight = 10 }
}

function Get-ADFindingMetadataMap {
    <#
    .SYNOPSIS
        Returns the central Issue -> {Mitre, Anssi, Weight} mapping table.
    .DESCRIPTION
        Exposes the single source of truth so callers/tests can inspect or
        validate coverage. Returns a clone so the live table is not mutated.
    #>
    [CmdletBinding()]
    param()
    return $Script:ADFindingMetadataMap.Clone()
}

function Set-ADFindingMetadata {
    <#
    .SYNOPSIS
        Tags an ADSecurityFinding with MITRE / ANSSI / Weight from the central map.
    .DESCRIPTION
        Looks the finding's Issue string up in $Script:ADFindingMetadataMap and
        populates MitreTechnique, AnssiControl, and Weight. Idempotent. For
        issues not yet in the table, falls back to severity-derived defaults so
        scoring still degrades gracefully (and emits a verbose warning so the
        gap can be closed by adding a table entry).
    .PARAMETER Finding
        The finding to tag. Mutated in place and also returned for pipelining.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ADSecurityFinding]$Finding
    )

    process {
        $meta = $Script:ADFindingMetadataMap[$Finding.Issue]

        if ($null -ne $meta) {
            $Finding.MitreTechnique = $meta.Mitre
            $Finding.AnssiControl   = $meta.Anssi
            $Finding.Weight         = $meta.Weight
        }
        else {
            Write-Verbose "Set-ADFindingMetadata: no mapping for Issue '$($Finding.Issue)'; using severity-derived defaults."
            $sev = $Finding.SeverityLevel
            if (-not $Script:ADScoreSeverityWeights.ContainsKey($sev)) { $sev = 0 }

            if ($Finding.Weight -le 0) {
                $Finding.Weight = $Script:ADScoreSeverityWeights[$sev]
            }
            if ([string]::IsNullOrEmpty($Finding.AnssiControl)) {
                $lvl = $Script:ADScoreSeverityAnssiLevel[$sev]
                $Finding.AnssiControl = "vuln${lvl}_unmapped"
            }
        }

        return $Finding
    }
}

function Get-ADRiskScore {
    <#
    .SYNOPSIS
        Computes a 0-100 risk score (higher = worse), per-category sub-scores,
        and a 1-5 ANSSI-style maturity level for a set of findings.
    .DESCRIPTION
        Scoring model (PingCastle-aligned):
          * Each finding contributes its Weight (set from the central map).
            Findings without metadata are tagged on the fly.
          * Each category's sub-score is the sum of its findings' weights,
            capped at 100.
          * The TotalScore is the MAX of the category sub-scores - i.e. an
            environment is rated by its worst risk area (PingCastle semantics).
        Maturity (ANSSI-style 1..5, higher = better):
          * Derived from the 'vuln<level>_' prefix of each AnssiControl.
          * Maturity = the lowest level present among findings (a single
            level-1 gap caps maturity at 1). With no findings, maturity = 5.
        Detection only - this function reads finding metadata; it performs no
        queries against any host.
    .PARAMETER Findings
        Array of ADSecurityFinding objects.
    .OUTPUTS
        PSCustomObject with TotalScore, MaturityLevel, MaturityLabel,
        CategoryScores (array), MitreSummary (array), and counts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings
    )

    $maturityLabels = @{
        1 = 'Level 1 - Critical gaps (basic hygiene not met)'
        2 = 'Level 2 - Partial hygiene'
        3 = 'Level 3 - Standard hardening'
        4 = 'Level 4 - Advanced hardening'
        5 = 'Level 5 - Optimal'
    }

    # Empty environment => best possible posture.
    if (-not $Findings -or $Findings.Count -eq 0) {
        return [PSCustomObject]@{
            TotalScore     = 0
            MaturityLevel  = 5
            MaturityLabel  = $maturityLabels[5]
            CategoryScores = @()
            MitreSummary   = @()
            FindingCount   = 0
            WeightedPoints = 0
            SeverityCounts = [PSCustomObject]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
        }
    }

    $categoryPoints = @{}
    $categoryCounts = @{}
    $mitreCounts    = @{}
    $totalPoints    = 0
    $minLevel       = 5
    $sevCounts      = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }

    foreach ($finding in $Findings) {
        # Ensure metadata is present (idempotent; tags raw findings).
        if ([string]::IsNullOrEmpty($finding.AnssiControl) -or $finding.Weight -le 0) {
            [void](Set-ADFindingMetadata -Finding $finding)
        }

        $cat = if ([string]::IsNullOrEmpty($finding.Category)) { 'Uncategorized' } else { $finding.Category }
        $w   = [int]$finding.Weight

        if (-not $categoryPoints.ContainsKey($cat)) {
            $categoryPoints[$cat] = 0
            $categoryCounts[$cat] = 0
        }
        $categoryPoints[$cat] += $w
        $categoryCounts[$cat]++
        $totalPoints += $w

        # MITRE technique tally
        if (-not [string]::IsNullOrEmpty($finding.MitreTechnique)) {
            if (-not $mitreCounts.ContainsKey($finding.MitreTechnique)) {
                $mitreCounts[$finding.MitreTechnique] = 0
            }
            $mitreCounts[$finding.MitreTechnique]++
        }

        # ANSSI level from the 'vuln<level>_' prefix -> maturity.
        if ($finding.AnssiControl -match '^vuln([1-5])_') {
            $lvl = [int]$Matches[1]
            if ($lvl -lt $minLevel) { $minLevel = $lvl }
        }

        switch ($finding.Severity) {
            'Critical' { $sevCounts.Critical++ }
            'High'     { $sevCounts.High++ }
            'Medium'   { $sevCounts.Medium++ }
            'Low'      { $sevCounts.Low++ }
            default    { $sevCounts.Info++ }
        }
    }

    # Per-category sub-scores (each capped 0-100), sorted worst-first.
    $categoryScores = foreach ($cat in $categoryPoints.Keys) {
        [PSCustomObject]@{
            Category = $cat
            Score    = [math]::Min(100, $categoryPoints[$cat])
            Findings = $categoryCounts[$cat]
        }
    }
    $categoryScores = @($categoryScores | Sort-Object -Property Score, Findings -Descending)

    # PingCastle-style global score = worst category.
    $totalScore = 0
    if ($categoryScores.Count -gt 0) {
        $totalScore = ($categoryScores | Measure-Object -Property Score -Maximum).Maximum
    }

    # MITRE summary (technique id + name + count), most-frequent first.
    $mitreSummary = foreach ($id in $mitreCounts.Keys) {
        $name = if ($Script:MitreTechniqueNames.ContainsKey($id)) { $Script:MitreTechniqueNames[$id] } else { 'Unknown technique' }
        [PSCustomObject]@{
            Technique = $id
            Name      = $name
            Count     = $mitreCounts[$id]
        }
    }
    $mitreSummary = @($mitreSummary | Sort-Object -Property Count, Technique -Descending)

    return [PSCustomObject]@{
        TotalScore     = [int]$totalScore
        MaturityLevel  = [int]$minLevel
        MaturityLabel  = $maturityLabels[[int]$minLevel]
        CategoryScores = $categoryScores
        MitreSummary   = $mitreSummary
        FindingCount   = $Findings.Count
        WeightedPoints = $totalPoints
        SeverityCounts = [PSCustomObject]$sevCounts
    }
}

#endregion
