"""
NOTE (this branch only): offline/-Snapshot mode has been removed from this
codebase (see src/Snapshot.ps1, Get-ADSnapshot, Invoke-ADRuleSet,
-FromSnapshot - all gone). This script still runs fine on its own (it's
plain Python with no dependency on the PowerShell module), and the JSON it
produces is kept as example/reference data - but nothing in this repo
currently consumes that JSON. See tests/fixtures/README.md for details.

build-forcedfail-fixtures.py - maintainer utility (Python 3, not part of the
ADSecurityAudit PowerShell module itself) that regenerates the three tiered
-FromSnapshot fixtures under tests/fixtures/:

    ForcedFail-100pct-Snapshot.json  - every controllable "dirty area" ON
    ForcedFail-60pct-Snapshot.json   - ~60% of dirty areas ON
    ForcedFail-25pct-Snapshot.json   - ~25% of dirty areas ON

These JSON files are what actually ships and what -FromSnapshot consumes -
Python is only needed if you're REGENERATING them, e.g. after adding a new
"dirty area" toggle to cover a new/changed check. See the "Maintenance"
section in tests/fixtures/README.md before editing this file.

Run with:  python3 tools/build-forcedfail-fixtures.py
(writes into tests/fixtures/ - update the output paths below if run from
a different working directory)

Schema note: every field this script emits matches the shape
src/Snapshot.ps1's Get-ADSnapshot function produces - see that file (and
its ConvertTo-ADHashtable companion) if you're unsure what shape a new
field should take. Do not guess; copy the real collection code's shape.
"""
import json
from datetime import datetime, timedelta

DOMAIN_DN = "DC=contoso,DC=local"
NETBIOS = "CONTOSO"
DNSROOT = "contoso.local"
DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"

def dn(cn, container=f"CN=Users,{DOMAIN_DN}"):
    return f"CN={cn},{container}"

def sid(rid):
    return f"{DOMAIN_SID}-{rid}"

now = datetime(2026, 9, 4, 8, 0, 0)
old = now - timedelta(days=400)

def ace(identity, rights, object_type="00000000-0000-0000-0000-000000000000",
        access_type="Allow", inherited=False, inherited_object_type="00000000-0000-0000-0000-000000000000",
        inheritance_type="None"):
    return {
        "IdentityReference": identity, "ActiveDirectoryRights": rights,
        "AccessControlType": access_type, "IsInherited": inherited,
        "InheritanceType": inheritance_type, "ObjectType": object_type,
        "InheritedObjectType": inherited_object_type,
    }

LEGIT_ACES = [
    ace("NT AUTHORITY\\SYSTEM", "GenericAll"),
    ace(f"{NETBIOS}\\Domain Admins", "GenericAll"),
    ace(f"{NETBIOS}\\Enterprise Admins", "GenericAll"),
    ace("BUILTIN\\Administrators", "GenericAll"),
]

administrator_dn = dn("Administrator")
old_admin_dn = dn("old.admin")
svc_sql_dn = dn("svc-sql", f"CN=Managed Service Accounts,{DOMAIN_DN}")
jsmith_dn = dn("j.smith")
migration_svc_dn = dn("migration.svc")
krbtgt_dn = dn("krbtgt")
helpdesk_svc_dn = dn("svc-helpdesk")
backup_svc_dn = dn("svc-backup")

dc01_dn = "CN=DC01,OU=Domain Controllers," + DOMAIN_DN
dc02_dn = "CN=DC02,OU=Domain Controllers," + DOMAIN_DN
legacy_srv_dn = f"CN=LEGACY-SRV01,CN=Computers,{DOMAIN_DN}"
web01_dn = f"CN=WEB01,CN=Computers,{DOMAIN_DN}"


def build_snapshot(t):
    """t is a dict of toggle_name -> bool. See TOGGLE_DEFAULTS below for the
    full list of 23 independently-controllable "dirty areas", each mapped
    to (at least) one of the 23 -Snapshot-capable checks."""

    users = [
        {
            "Name": "Administrator", "SamAccountName": "Administrator", "DistinguishedName": administrator_dn,
            "UserPrincipalName": "administrator@contoso.local", "SID": sid(500),
            "Description": "Built-in account for administering the computer/domain",
            "Enabled": True, "DoesNotRequirePreAuth": False, "UseDESKeyOnly": False,
            "AllowReversiblePasswordEncryption": False, "PasswordNeverExpires": True,
            "TrustedForDelegation": False, "LastLogonDate": now.isoformat(), "PasswordLastSet": old.isoformat(),
            "ServicePrincipalNames": [], "MemberOf": [f"CN=Domain Admins,CN=Users,{DOMAIN_DN}"],
            "adminCount": 1,
            "msDS-SupportedEncryptionTypes": 4 if t["rc4_kerberos"] else 24,
            "userAccountControl": 512, "WhenCreated": old.isoformat(),
            "msDS-AllowedToDelegateTo": [], "SIDHistory": [], "PrimaryGroupID": 513,
            "TrustedToAuthForDelegation": False, "scriptPath": None, "HasShadowCredentials": False,
        },
        {
            "Name": "KRBTGT", "SamAccountName": "krbtgt", "DistinguishedName": krbtgt_dn,
            "UserPrincipalName": None, "SID": sid(502), "Description": "Key Distribution Center Service Account",
            "Enabled": False, "DoesNotRequirePreAuth": False, "UseDESKeyOnly": False,
            "AllowReversiblePasswordEncryption": False, "PasswordNeverExpires": True,
            "TrustedForDelegation": False, "LastLogonDate": None, "PasswordLastSet": old.isoformat(),
            "ServicePrincipalNames": [], "MemberOf": [], "adminCount": 1,
            "msDS-SupportedEncryptionTypes": 4 if t["rc4_kerberos"] else 24,
            "userAccountControl": 514, "WhenCreated": old.isoformat(),
            "msDS-AllowedToDelegateTo": [], "SIDHistory": [], "PrimaryGroupID": 513,
            "TrustedToAuthForDelegation": False, "scriptPath": None, "HasShadowCredentials": False,
        },
        {
            "Name": "svc-sql", "SamAccountName": "svc-sql", "DistinguishedName": svc_sql_dn,
            "UserPrincipalName": "svc-sql@contoso.local", "SID": sid(1105),
            "Description": "SQL Server service account", "Enabled": True,
            "DoesNotRequirePreAuth": False, "UseDESKeyOnly": False,
            "AllowReversiblePasswordEncryption": False, "PasswordNeverExpires": True if t["kerberoastable"] else False,
            "TrustedForDelegation": False, "LastLogonDate": now.isoformat(), "PasswordLastSet": old.isoformat(),
            "ServicePrincipalNames": ["MSSQLSvc/sql01.contoso.local:1433"] if t["kerberoastable"] else [],
            "MemberOf": [], "adminCount": 0,
            "msDS-SupportedEncryptionTypes": 4 if t["rc4_kerberos"] else 24,
            "userAccountControl": 512, "WhenCreated": old.isoformat(),
            "msDS-AllowedToDelegateTo": [], "SIDHistory": [], "PrimaryGroupID": 513,
            "TrustedToAuthForDelegation": False, "scriptPath": None, "HasShadowCredentials": False,
        },
        {
            "Name": "J. Smith", "SamAccountName": "j.smith", "DistinguishedName": jsmith_dn,
            "UserPrincipalName": "j.smith@contoso.local", "SID": sid(1106),
            "Description": "Marketing", "Enabled": True,
            "DoesNotRequirePreAuth": bool(t["asrep_roastable"]), "UseDESKeyOnly": False,
            "AllowReversiblePasswordEncryption": False, "PasswordNeverExpires": False,
            "TrustedForDelegation": False, "LastLogonDate": now.isoformat(), "PasswordLastSet": old.isoformat(),
            "ServicePrincipalNames": [], "MemberOf": [], "adminCount": 0,
            "msDS-SupportedEncryptionTypes": 24,  # AES-only (8+16), no RC4 bit
            "userAccountControl": 4194816,
            "WhenCreated": old.isoformat(), "msDS-AllowedToDelegateTo": [], "SIDHistory": [],
            "PrimaryGroupID": 513, "TrustedToAuthForDelegation": False, "scriptPath": None,
            "HasShadowCredentials": False,
        },
        {
            "Name": "migration.svc", "SamAccountName": "migration.svc", "DistinguishedName": migration_svc_dn,
            "UserPrincipalName": "migration.svc@contoso.local", "SID": sid(1107),
            "Description": "Legacy migration account", "Enabled": True,
            "DoesNotRequirePreAuth": False, "UseDESKeyOnly": False,
            "AllowReversiblePasswordEncryption": False, "PasswordNeverExpires": True,
            "TrustedForDelegation": False, "LastLogonDate": old.isoformat(), "PasswordLastSet": old.isoformat(),
            "ServicePrincipalNames": [],
            "MemberOf": [f"CN=Backup Operators,CN=Builtin,{DOMAIN_DN}"] if t["suspicious_group_membership"] else [],
            "adminCount": 0, "msDS-SupportedEncryptionTypes": 24,  # AES-only (8+16), no RC4 bit
            "userAccountControl": 512,
            "WhenCreated": old.isoformat(), "msDS-AllowedToDelegateTo": [],
            "SIDHistory": [sid(500)] if t["sid_history"] else [],
            "PrimaryGroupID": 513, "TrustedToAuthForDelegation": False,
            "scriptPath": "legacy-logon.bat" if t["legacy_logon_script"] else None,
            "HasShadowCredentials": False,
        },
        {
            "Name": "old.admin", "SamAccountName": "old.admin", "DistinguishedName": old_admin_dn,
            "UserPrincipalName": "old.admin@contoso.local", "SID": sid(1108),
            "Description": "Former helpdesk lead", "Enabled": True,
            "DoesNotRequirePreAuth": False, "UseDESKeyOnly": False,
            "AllowReversiblePasswordEncryption": False, "PasswordNeverExpires": True,
            "TrustedForDelegation": False, "LastLogonDate": old.isoformat(), "PasswordLastSet": old.isoformat(),
            "ServicePrincipalNames": [], "MemberOf": [],
            "adminCount": 1 if t["adminsdholder_ghost"] else 0,
            "msDS-SupportedEncryptionTypes": 24,  # AES-only (8+16), no RC4 bit
            "userAccountControl": 512,
            "WhenCreated": old.isoformat(), "msDS-AllowedToDelegateTo": [], "SIDHistory": [],
            "PrimaryGroupID": 513, "TrustedToAuthForDelegation": False, "scriptPath": None,
            "HasShadowCredentials": False,
        },
        {
            "Name": "IT Helpdesk Service", "SamAccountName": "svc-helpdesk", "DistinguishedName": helpdesk_svc_dn,
            "UserPrincipalName": "svc-helpdesk@contoso.local", "SID": sid(1109),
            "Description": "Helpdesk automation account", "Enabled": True,
            "DoesNotRequirePreAuth": False, "UseDESKeyOnly": False,
            "AllowReversiblePasswordEncryption": False, "PasswordNeverExpires": True,
            "TrustedForDelegation": False, "LastLogonDate": now.isoformat(), "PasswordLastSet": old.isoformat(),
            "ServicePrincipalNames": [], "MemberOf": [], "adminCount": 0,
            "msDS-SupportedEncryptionTypes": 24,  # AES-only (8+16), no RC4 bit
            "userAccountControl": 512,
            "WhenCreated": old.isoformat(), "msDS-AllowedToDelegateTo": [], "SIDHistory": [],
            "PrimaryGroupID": 513, "TrustedToAuthForDelegation": False, "scriptPath": None,
            "HasShadowCredentials": False,
        },
        {
            "Name": "Backup Service", "SamAccountName": "svc-backup", "DistinguishedName": backup_svc_dn,
            "UserPrincipalName": "svc-backup@contoso.local", "SID": sid(1110),
            "Description": "Backup software service account", "Enabled": True,
            "DoesNotRequirePreAuth": False, "UseDESKeyOnly": False,
            "AllowReversiblePasswordEncryption": False, "PasswordNeverExpires": True,
            "TrustedForDelegation": False, "LastLogonDate": now.isoformat(), "PasswordLastSet": old.isoformat(),
            "ServicePrincipalNames": [], "MemberOf": [], "adminCount": 0,
            "msDS-SupportedEncryptionTypes": 24,  # AES-only (8+16), no RC4 bit
            "userAccountControl": 512,
            "WhenCreated": old.isoformat(), "msDS-AllowedToDelegateTo": [], "SIDHistory": [],
            "PrimaryGroupID": 513, "TrustedToAuthForDelegation": False, "scriptPath": None,
            "HasShadowCredentials": False,
        },
    ]

    privileged_user_acls = [{
        "DistinguishedName": administrator_dn, "SamAccountName": "Administrator",
        "Owner": f"{NETBIOS}\\Domain Admins",
        "Access": ([ace(f"{NETBIOS}\\svc-helpdesk", "GenericWrite"), ace(f"{NETBIOS}\\svc-helpdesk", "GenericWrite")]
                   if t["domain_admin_equivalence_evidence"] else []),
    }]

    computers = [
        {
            "Name": "DC01", "SamAccountName": "DC01$", "DistinguishedName": dc01_dn, "SID": sid(1001),
            "Enabled": True, "OperatingSystem": "Windows Server 2022 Standard", "OperatingSystemVersion": "10.0 (20348)",
            "LastLogonDate": now.isoformat(), "TrustedForDelegation": True,
            "msDS-AllowedToDelegateTo": [], "PrimaryGroupID": 516,
            "ms-Mcs-AdmPwdExpirationTime": None, "msLAPS-PasswordExpirationTime": None,
            "userAccountControl": 532480, "WhenCreated": old.isoformat(),
            "ServicePrincipalNames": ["HOST/dc01.contoso.local"], "TrustedToAuthForDelegation": False,
            "HasRbcdConfigured": False, "PasswordLastSet": old.isoformat(), "HasShadowCredentials": False,
            "Access": LEGIT_ACES,
        },
        {
            "Name": "DC02", "SamAccountName": "DC02$", "DistinguishedName": dc02_dn, "SID": sid(1002),
            "Enabled": True, "OperatingSystem": "Windows Server 2022 Standard", "OperatingSystemVersion": "10.0 (20348)",
            "LastLogonDate": now.isoformat(), "TrustedForDelegation": True,
            "msDS-AllowedToDelegateTo": [], "PrimaryGroupID": 516,
            "ms-Mcs-AdmPwdExpirationTime": None, "msLAPS-PasswordExpirationTime": None,
            "userAccountControl": 532480, "WhenCreated": old.isoformat(),
            "ServicePrincipalNames": ["HOST/dc02.contoso.local"], "TrustedToAuthForDelegation": False,
            "HasRbcdConfigured": False, "PasswordLastSet": old.isoformat(), "HasShadowCredentials": False,
            "Access": LEGIT_ACES,
        },
        {
            "Name": "LEGACY-SRV01", "SamAccountName": "LEGACY-SRV01$", "DistinguishedName": legacy_srv_dn,
            "SID": sid(1201), "Enabled": True, "OperatingSystem": "Windows Server 2008 R2 Standard",
            "OperatingSystemVersion": "6.1 (7601)", "LastLogonDate": old.isoformat(),
            "TrustedForDelegation": bool(t["unconstrained_delegation"]),
            "msDS-AllowedToDelegateTo": [], "PrimaryGroupID": 515,
            "ms-Mcs-AdmPwdExpirationTime": None, "msLAPS-PasswordExpirationTime": None,
            "userAccountControl": 4096, "WhenCreated": old.isoformat(),
            "ServicePrincipalNames": ["HOST/legacy-srv01.contoso.local"], "TrustedToAuthForDelegation": False,
            "HasRbcdConfigured": False, "PasswordLastSet": old.isoformat(),
            "HasShadowCredentials": bool(t["shadow_credentials"]),
            "Access": LEGIT_ACES,
        },
        {
            "Name": "WEB01", "SamAccountName": "WEB01$", "DistinguishedName": web01_dn, "SID": sid(1202),
            "Enabled": True, "OperatingSystem": "Windows Server 2022 Standard", "OperatingSystemVersion": "10.0 (20348)",
            "LastLogonDate": now.isoformat(), "TrustedForDelegation": False,
            "msDS-AllowedToDelegateTo": [], "PrimaryGroupID": 515,
            "ms-Mcs-AdmPwdExpirationTime": 133700000000000000, "msLAPS-PasswordExpirationTime": None,
            "userAccountControl": 4096, "WhenCreated": old.isoformat(),
            "ServicePrincipalNames": ["HTTP/web01.contoso.local"], "TrustedToAuthForDelegation": False,
            "HasRbcdConfigured": bool(t["rbcd_configured"]), "PasswordLastSet": now.isoformat(), "HasShadowCredentials": False,
            "Access": LEGIT_ACES,
        },
    ]

    groups = [
        {"Name": "Domain Admins", "DistinguishedName": f"CN=Domain Admins,CN=Users,{DOMAIN_DN}", "SID": sid(512),
         "Description": "Designated administrators of the domain", "GroupType": "-2147483646", "AdminCount": 1,
         "Members": [administrator_dn]},
        {"Name": "Enterprise Admins", "DistinguishedName": f"CN=Enterprise Admins,CN=Users,{DOMAIN_DN}", "SID": sid(519),
         "Description": "Designated administrators of the enterprise", "GroupType": "-2147483646", "AdminCount": 1, "Members": []},
        {"Name": "Schema Admins", "DistinguishedName": f"CN=Schema Admins,CN=Users,{DOMAIN_DN}", "SID": sid(518),
         "Description": "Designated administrators of the schema", "GroupType": "-2147483646", "AdminCount": 1, "Members": []},
        {"Name": "Administrators", "DistinguishedName": f"CN=Administrators,CN=Builtin,{DOMAIN_DN}", "SID": "S-1-5-32-544",
         "Description": "Administrators have complete and unrestricted access", "GroupType": "-2147483643", "AdminCount": 1,
         "Members": [f"CN=Domain Admins,CN=Users,{DOMAIN_DN}"]},
        {"Name": "Backup Operators", "DistinguishedName": f"CN=Backup Operators,CN=Builtin,{DOMAIN_DN}", "SID": "S-1-5-32-551",
         "Description": "Backup Operators can override security restrictions", "GroupType": "-2147483643", "AdminCount": 0,
         "Members": [migration_svc_dn] if t["suspicious_group_membership"] else []},
        {"Name": "Account Operators", "DistinguishedName": f"CN=Account Operators,CN=Builtin,{DOMAIN_DN}", "SID": "S-1-5-32-548",
         "Description": "Members can administer domain user and group accounts", "GroupType": "-2147483643", "AdminCount": 0, "Members": []},
        {"Name": "Server Operators", "DistinguishedName": f"CN=Server Operators,CN=Builtin,{DOMAIN_DN}", "SID": "S-1-5-32-549",
         "Description": "Members can administer domain servers", "GroupType": "-2147483643", "AdminCount": 0, "Members": []},
        {"Name": "Print Operators", "DistinguishedName": f"CN=Print Operators,CN=Builtin,{DOMAIN_DN}", "SID": "S-1-5-32-550",
         "Description": "Members can administer domain printers", "GroupType": "-2147483643", "AdminCount": 0, "Members": []},
        {"Name": "Cryptographic Operators", "DistinguishedName": f"CN=Cryptographic Operators,CN=Builtin,{DOMAIN_DN}", "SID": "S-1-5-32-569",
         "Description": "Members are authorized to perform cryptographic operations", "GroupType": "-2147483643", "AdminCount": 0, "Members": []},
        {"Name": "Distributed COM Users", "DistinguishedName": f"CN=Distributed COM Users,CN=Builtin,{DOMAIN_DN}", "SID": "S-1-5-32-562",
         "Description": "Members are allowed to launch, activate and use DCOM objects", "GroupType": "-2147483643", "AdminCount": 0, "Members": []},
        {"Name": "Group Policy Creator Owners", "DistinguishedName": f"CN=Group Policy Creator Owners,CN=Users,{DOMAIN_DN}", "SID": sid(520),
         "Description": "Members can modify Group Policy for the domain", "GroupType": "-2147483646", "AdminCount": 0, "Members": []},
        {"Name": "Domain Controllers", "DistinguishedName": f"CN=Domain Controllers,CN=Users,{DOMAIN_DN}", "SID": sid(516),
         "Description": "All domain controllers in the domain", "GroupType": "-2147483646", "AdminCount": 1, "Members": [dc01_dn, dc02_dn]},
        {"Name": "Enterprise Domain Controllers", "DistinguishedName": "CN=Enterprise Domain Controllers,CN=ForeignSecurityPrincipals," + DOMAIN_DN,
         "SID": "S-1-5-9", "Description": "Well-known group", "GroupType": "-2147483646", "AdminCount": 0, "Members": []},
        {"Name": "Read-only Domain Controllers", "DistinguishedName": f"CN=Read-only Domain Controllers,CN=Users,{DOMAIN_DN}", "SID": sid(521),
         "Description": "Members are Read-Only Domain Controllers", "GroupType": "-2147483646", "AdminCount": 0, "Members": []},
        {"Name": "Enterprise Key Admins", "DistinguishedName": f"CN=Enterprise Key Admins,CN=Users,{DOMAIN_DN}", "SID": sid(527),
         "Description": "Members can perform administrative actions on key objects", "GroupType": "-2147483646", "AdminCount": 0, "Members": []},
        {"Name": "DnsAdmins", "DistinguishedName": f"CN=DnsAdmins,CN=Users,{DOMAIN_DN}", "SID": sid(1151),
         "Description": "DNS Administrators Group", "GroupType": "-2147483646", "AdminCount": 0,
         "Members": [backup_svc_dn] if t["dnsadmins_member"] else []},
    ]

    gpo_perms = [{"Trustee": "Domain Admins", "Permission": "GpoEditDeleteModifySecurity"}]
    if t["gpo_permissions"]:
        gpo_perms.append({"Trustee": "Authenticated Users", "Permission": "GpoEditDeleteModifySecurity"})
    gpos = [
        {"Id": "11111111-1111-1111-1111-111111111111", "DisplayName": "Default Domain Policy",
         "GpoStatus": "AllSettingsEnabled", "CreationTime": old.isoformat(), "ModificationTime": old.isoformat(),
         "Permissions": gpo_perms, "LinkedTo": [DOMAIN_DN]},
        {"Id": "22222222-2222-2222-2222-222222222222", "DisplayName": "Old Test Policy - 2019",
         "GpoStatus": "AllSettingsEnabled", "CreationTime": old.isoformat(), "ModificationTime": old.isoformat(),
         "Permissions": [{"Trustee": "Domain Admins", "Permission": "GpoEditDeleteModifySecurity"}],
         "LinkedTo": [] if t["unlinked_gpo"] else [DOMAIN_DN]},
    ]

    admin_sd_holder_access = list(LEGIT_ACES)
    if t["dangerous_aces_adminsdholder"]:
        admin_sd_holder_access += [
            ace(f"{NETBIOS}\\svc-helpdesk", "GenericAll", object_type="00000000-0000-0000-0000-000000000000"),
            ace(f"{NETBIOS}\\svc-helpdesk", "GenericAll", object_type="bf967a86-0de6-11d0-a285-00aa003049e2"),
            ace(f"{NETBIOS}\\svc-backup", "WriteProperty"),
        ]

    domain_root_access = list(LEGIT_ACES)
    if t["dcsync_aces"]:
        domain_root_access += [
            ace(f"{NETBIOS}\\svc-sync", "ExtendedRight", object_type="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),
            ace(f"{NETBIOS}\\svc-sync", "ExtendedRight", object_type="1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"),
        ]
    if t["eka_overprivilege"]:
        domain_root_access += [ace(f"{NETBIOS}\\Enterprise Key Admins", "GenericAll")]
    if t["exchange_escalation"]:
        domain_root_access += [ace(f"{NETBIOS}\\Exchange Trusted Subsystem", "WriteDacl")]

    schema_nc_access = list(LEGIT_ACES)
    if t["schema_config_nc_aces"]:
        schema_nc_access += [ace(f"{NETBIOS}\\svc-helpdesk", "WriteDacl")]

    config_nc_access = list(LEGIT_ACES)
    if t["schema_config_nc_aces"]:
        config_nc_access += [
            ace(f"{NETBIOS}\\svc-helpdesk", "GenericAll", object_type="00000000-0000-0000-0000-000000000000"),
            ace(f"{NETBIOS}\\svc-helpdesk", "GenericAll", object_type="bf967a86-0de6-11d0-a285-00aa003049e2"),
        ]

    dc_ou_access = list(LEGIT_ACES)
    if t["critical_ou_ace"]:
        dc_ou_access += [ace(f"{NETBIOS}\\svc-helpdesk", "GenericAll")]

    acls = {
        "AdminSDHolder": {"DistinguishedName": f"CN=AdminSDHolder,CN=System,{DOMAIN_DN}", "Owner": f"{NETBIOS}\\Domain Admins",
                           "HasAuditRules": not t["no_sacl_audit"], "Access": admin_sd_holder_access},
        "DomainRoot": {"DistinguishedName": DOMAIN_DN, "Owner": f"{NETBIOS}\\Domain Admins",
                       "HasAuditRules": not t["no_sacl_audit"], "Access": domain_root_access},
        "SchemaNamingContext": {"DistinguishedName": f"CN=Schema,CN=Configuration,{DOMAIN_DN}", "Owner": f"{NETBIOS}\\Domain Admins",
                                 "HasAuditRules": True, "Access": schema_nc_access},
        "ConfigurationNamingContext": {"DistinguishedName": f"CN=Configuration,{DOMAIN_DN}", "Owner": f"{NETBIOS}\\Domain Admins",
                                        "HasAuditRules": True, "Access": config_nc_access},
        "DomainControllersOU": {"DistinguishedName": f"OU=Domain Controllers,{DOMAIN_DN}", "Owner": f"{NETBIOS}\\Domain Admins",
                                 "HasAuditRules": True, "Access": dc_ou_access},
        "UsersContainer": {"DistinguishedName": f"CN=Users,{DOMAIN_DN}", "Owner": f"{NETBIOS}\\Domain Admins",
                            "HasAuditRules": True, "Access": LEGIT_ACES},
        "ComputersContainer": {"DistinguishedName": f"CN=Computers,{DOMAIN_DN}", "Owner": f"{NETBIOS}\\Domain Admins",
                                "HasAuditRules": True, "Access": LEGIT_ACES},
        "CertificateTemplatesContainer": {"DistinguishedName": f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{DOMAIN_DN}",
                                           "Owner": f"{NETBIOS}\\Domain Admins", "HasAuditRules": False, "Access": LEGIT_ACES},
    }

    template_access = list(LEGIT_ACES)
    if t["adcs_esc1_esc2"]:
        template_access += [
            ace(f"{NETBIOS}\\Domain Users", "ExtendedRight", object_type="0e10c968-78fb-11d2-90d4-00c04f79dc55"),
            ace(f"{NETBIOS}\\Domain Users", "ExtendedRight", object_type="a05b8cc2-17bc-4802-a710-e7c15ab866a2"),
        ]
    if t["adcs_esc4"]:
        template_access += [ace(f"{NETBIOS}\\Domain Users", "WriteDacl")]

    ca_access = list(LEGIT_ACES)
    if t["adcs_esc7_lowpriv"]:
        ca_access += [
            ace(f"{NETBIOS}\\svc-helpdesk", "GenericAll", object_type="00000000-0000-0000-0000-000000000000"),
            ace(f"{NETBIOS}\\svc-helpdesk", "GenericAll", object_type="bf967a86-0de6-11d0-a285-00aa003049e2"),
            ace(f"{NETBIOS}\\Domain Users", "ExtendedRight", object_type="0e10c968-78fb-11d2-90d4-00c04f79dc55"),
            ace(f"{NETBIOS}\\Domain Users", "ExtendedRight", object_type="a05b8cc2-17bc-4802-a710-e7c15ab866a2"),
        ]

    adcs = {
        "Installed": True,
        "CertificateTemplates": [{
            "Name": "VulnWebServer", "DistinguishedName": f"CN=VulnWebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{DOMAIN_DN}",
            "displayName": "Vulnerable Web Server Template",
            "msPKI-Certificate-Name-Flag": 1 if t["adcs_esc1_esc2"] else 0,
            "msPKI-Enrollment-Flag": 0,
            "msPKI-Certificate-Application-Policy": [],
            "pKIExtendedKeyUsage": [] if t["adcs_esc1_esc2"] else ["1.3.6.1.5.5.7.3.2"],
            "msPKI-RA-Signature": 0,
            "Access": template_access,
        }],
        "CertificateAuthorities": [{
            "Name": "CONTOSO-CA01",
            "DistinguishedName": f"CN=CONTOSO-CA01,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{DOMAIN_DN}",
            "dNSHostName": "ca01.contoso.local", "cACertificate": [], "Access": ca_access,
        }],
        "NTAuthCertificates": [], "AIACertificates": [], "RootCACertificates": [],
    }

    dns_zones = [
        {"Name": "contoso.local", "DistinguishedName": f"DC=contoso.local,CN=MicrosoftDNS,DC=DomainDnsZones,{DOMAIN_DN}"},
        {"Name": "_msdcs.contoso.local", "DistinguishedName": f"DC=_msdcs.contoso.local,CN=MicrosoftDNS,DC=ForestDnsZones,{DOMAIN_DN}"},
    ]

    trusts = [{
        "Target": "partner.external", "trustAttributes": 8, "Direction": "Bidirectional", "TrustType": "Uplevel",
        "SIDFilteringQuarantined": not t["trust_quarantine_disabled"], "SelectiveAuthentication": False,
        "Created": old.isoformat(), "Modified": old.isoformat(),
    }]

    snapshot = {
        "CollectedDate": now.isoformat(),
        "Domain": {"DistinguishedName": DOMAIN_DN, "DNSRoot": DNSROOT, "NetBIOSName": NETBIOS, "Forest": DNSROOT, "DomainSID": DOMAIN_SID},
        "DomainControllers": [
            {"Name": "DC01", "HostName": "dc01.contoso.local", "ComputerObjectDN": dc01_dn, "IPv4Address": "10.0.0.10",
             "IsReadOnly": False, "IsGlobalCatalog": True, "Enabled": True, "Site": "Default-First-Site-Name",
             "OperatingSystem": "Windows Server 2022 Standard"},
            {"Name": "DC02", "HostName": "dc02.contoso.local", "ComputerObjectDN": dc02_dn, "IPv4Address": "10.0.0.11",
             "IsReadOnly": False, "IsGlobalCatalog": True, "Enabled": True, "Site": "Default-First-Site-Name",
             "OperatingSystem": "Windows Server 2022 Standard"},
        ],
        "TotalDomainControllerCount": 2,
        "AllDomainControllerComputerObjectDNs": [dc01_dn, dc02_dn],
        "Users": users,
        "PrivilegedUserAcls": privileged_user_acls,
        "Computers": computers,
        "Groups": groups,
        "GPOs": gpos,
        "ACLs": acls,
        "ADCS": adcs,
        "DnsZones": dns_zones,
        "Trusts": trusts,
        "MachineAccountQuota": 10 if t["machine_account_quota"] else 0,
        "RunScopeNotes": [],
        "DsHeuristics": None,
        "DsHeuristicsDN": f"CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{DOMAIN_DN}",
        "PreWin2000GroupDN": f"CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{DOMAIN_DN}",
        "PreWin2000Members": (["CN=ANONYMOUS LOGON,CN=WellKnown Security Principals,CN=Configuration," + DOMAIN_DN]
                               if t["pre_win2000_members"] else []),
        "LapsSchema": {"LegacyLapsPresent": not t["laps_not_deployed"], "WindowsLapsPresent": not t["laps_not_deployed"]},
        "PasswordPolicy": ({"MinPasswordLength": 7, "ComplexityEnabled": False, "ReversibleEncryptionEnabled": True}
                            if t["weak_password_policy"] else
                            {"MinPasswordLength": 14, "ComplexityEnabled": True, "ReversibleEncryptionEnabled": False}),
        "Forest": {"ForestMode": "Windows2008R2Forest" if t["old_forest_mode"] else "Windows2016Forest"},
        "TombstoneLifetimeDays": 60,
        "RecycleBinEnabled": not t["recycle_bin_disabled"],
    }
    return snapshot


# The 23 independently-controllable "dirty areas", each feeding at least one
# of the 23 -Snapshot-capable checks (5 more registered checks -
# KnownDCVulnerabilities, GpoDeployedSecrets, LegacyAuthSurface,
# CoercionAndRelayExposure, RodcSecurity - always return zero findings under
# -FromSnapshot by design, regardless of fixture data, and so cannot be
# toggled here - see tests/fixtures/README.md).
ALL_TOGGLES = [
    "rc4_kerberos", "kerberoastable", "asrep_roastable", "sid_history",
    "legacy_logon_script", "adminsdholder_ghost", "suspicious_group_membership",
    "dangerous_aces_adminsdholder", "dcsync_aces", "eka_overprivilege",
    "exchange_escalation", "schema_config_nc_aces", "critical_ou_ace",
    "gpo_permissions", "unlinked_gpo", "adcs_esc1_esc2", "adcs_esc4",
    "adcs_esc7_lowpriv", "dnsadmins_member", "trust_quarantine_disabled",
    "weak_password_policy", "laps_not_deployed", "recycle_bin_disabled",
    "old_forest_mode", "no_sacl_audit", "unconstrained_delegation",
    "shadow_credentials", "rbcd_configured", "domain_admin_equivalence_evidence",
    "pre_win2000_members", "machine_account_quota",
]

def profile(on_list):
    return {k: (k in on_list) for k in ALL_TOGGLES}

ALL_ON = profile(ALL_TOGGLES)

# ~60% tier: keep the highest-signal, most illustrative issue in each
# category area on; turn off enough areas to land near 60% of the 23
# achievable checks.
SIXTY_ON = profile([
    "rc4_kerberos", "kerberoastable", "sid_history", "adminsdholder_ghost",
    "suspicious_group_membership", "dangerous_aces_adminsdholder", "dcsync_aces",
    "eka_overprivilege", "schema_config_nc_aces", "critical_ou_ace",
    "gpo_permissions", "adcs_esc1_esc2", "adcs_esc7_lowpriv", "dnsadmins_member",
    "trust_quarantine_disabled", "weak_password_policy", "laps_not_deployed",
    "unconstrained_delegation", "domain_admin_equivalence_evidence",
])

# ~25% tier: only a small, spread-out handful of clearly-bad items remain.
TWENTYFIVE_ON = profile([
    "rc4_kerberos", "sid_history", "dangerous_aces_adminsdholder",
    "adcs_esc1_esc2", "laps_not_deployed", "weak_password_policy",
    "dnsadmins_member", "pre_win2000_members",
])

import sys
import os

output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tests', 'fixtures')

for name, prof in [("ForcedFail-100pct-Snapshot", ALL_ON), ("ForcedFail-60pct-Snapshot", SIXTY_ON), ("ForcedFail-25pct-Snapshot", TWENTYFIVE_ON)]:
    snap = build_snapshot(prof)
    on_count = sum(1 for v in prof.values() if v)
    out_path = os.path.join(output_dir, f"{name}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(snap, f, indent=2)
    print(f"{name}: {on_count}/{len(ALL_TOGGLES)} toggle areas ON ({on_count/len(ALL_TOGGLES)*100:.0f}%) -> {out_path}")
