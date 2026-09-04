import json

import pytest

from sia.config import Defaults
from sia.inputs import ServerRow, StrongAccountRow
from sia.payloads import (
    build_bulk_target_sets, build_fqdn_rule, build_policy, build_policy_update, build_principal,
    build_secret_payload, build_target_set, build_target_set_update, build_vault_account, description_for, exact_fqdns,
    is_owned_policy, is_owned_target_set, names_match, ownership_marker, policy_name_for, policy_signature, policy_status,
    render, sanitize_template, split_fqdn, validate_template,
)

DEFAULTS = Defaults(time_zone="America/New_York")
OWNER = "sia-policy-automation"
MARK = "[managed-by:sia-policy-automation]"
NAME = "web01.corp.example.com"


def server(**overrides) -> ServerRow:
    base = dict(fqdn="web01.corp.example.com", strong_account="SA-corp-rdp", groups=("SIA-Web-Admins",),
                policy_name=None, assign_groups=None, domain=None, description=None, line=2)
    base.update(overrides)
    return ServerRow(**base)


GROUP_ROW = {"InternalName": "b1f9c0e2-1111-2222-3333-444455556666", "SystemName": "SIA-Web-Admins",
             "DisplayName": "SIA Web Admins", "DirectoryServiceUuid": "09B9A9B0-6CE8-465F-AB03-65766D33B05E",
             "ServiceInstanceLocalized": "CyberArk Cloud Directory", "ServiceType": "CDS"}

TEMPLATE = {
    "metadata": {"policyId": "tpl-1", "name": "Reference", "timeZone": "Europe/London", "policyTags": ["ref"],
                 "status": {"status": "Active", "statusCode": "OK"}, "createdBy": {"user": "x"},
                 "policyEntitlement": {"targetCategory": "VM", "locationType": "FQDN/IP", "policyType": "Recurring"}},
    "conditions": {"accessWindow": {"daysOfTheWeek": [1, 2, 3], "fromHour": "07:00", "toHour": "19:00"},
                   "maxSessionDuration": 2, "idleTime": 5, "someFutureField": {"x": 1}},
    "behavior": {"connectAs": {"ssh": {"username": "root"},
                               "rdp": {"localEphemeralUser": {"assignGroups": ["Administrators", "Backup Operators"],
                                                              "enableEphemeralUserReconnect": True}}}},
    "delegationClassification": "Restricted",
    "principals": [{"id": "someone"}],
    "targets": {"FQDN/IP": {"fqdnRules": [{"operator": "EXACTLY", "computernamePattern": "ref.corp.local"}]}},
}


def test_split_and_templates():
    assert split_fqdn("web01.corp.example.com") == ("web01", "corp.example.com")
    s = server()
    assert render("SIA-RDP-{hostname}", s) == "SIA-RDP-web01"
    assert render("{fqdn}|{domain}", s) == "web01.corp.example.com|corp.example.com"
    assert render("{protocol}", s) == "RDP" and render("{protocol}", server(protocol="ssh")) == "SSH"
    assert policy_name_for(s, DEFAULTS) == NAME                                   # default: the server's FQDN
    assert policy_name_for(server(policy_suffix="-ops"), DEFAULTS) == "web01.corp.example.com-ops"
    assert policy_name_for(server(policy_name="Custom", policy_suffix="-x"), DEFAULTS) == "Custom"
    assert policy_name_for(s, Defaults(policy_name_template="SIA-RDP-{hostname}")) == "SIA-RDP-web01"
    assert description_for(s, DEFAULTS) == "Automated: RDP ZSP access to web01.corp.example.com"
    with pytest.raises(ValueError, match="template"):
        render("{host}", s)
    with pytest.raises(ValueError, match="template"):
        policy_name_for(s, Defaults(policy_name_template="{host}"))


def test_secret_payload_vault_reference_uses_platform_name():
    sa = StrongAccountRow(name="SA-corp-rdp", type="vault", safe="SIA-StrongAccounts", account_name="svc_sia_rdp",
                          username=None, account_domain="corp.example.com", password_env=None, line=2)
    assert sa.sia_name == "svc_sia_rdp_SIA-StrongAccounts"
    assert build_secret_payload(sa) == {
        "secret_name": "svc_sia_rdp_SIA-StrongAccounts", "secret_type": "PCloudAccount", "is_active": True,
        "secret": {"secret_data": {"safe": "SIA-StrongAccounts", "account_name": "svc_sia_rdp"}, "tenant_encrypted": False},
        "secret_details": {"account_domain": "corp.example.com", "ephemeral_domain_user_data": {}},
    }


def test_secret_payload_credentials():
    sa = StrongAccountRow(name="SA-dmz", type="credentials", safe=None, account_name=None, username="siaprov",
                          account_domain="local", password_env="SIA_SA_SA_DMZ_PASSWORD", line=3)
    assert sa.sia_name == "SA-dmz"
    payload = build_secret_payload(sa, password="s3cret")
    assert payload["secret_name"] == "SA-dmz" and payload["secret_type"] == "ProvisionerUser"
    assert payload["secret"]["secret_data"] == {"username": "siaprov", "password": "s3cret"}
    assert payload["secret_details"]["account_domain"] == "local"
    with pytest.raises(ValueError, match="needs a password"):
        build_secret_payload(sa)


def test_secret_payload_existing_rejected():
    sa = StrongAccountRow(name="SA-legacy", type="existing", safe=None, account_name=None, username=None,
                          account_domain="local", password_env=None, line=4)
    with pytest.raises(ValueError, match="only vault/credentials"):
        build_secret_payload(sa)


def test_vault_account_payload():
    sa = StrongAccountRow(name="ADM-web01", type="vault", safe="SIA-LocalAdmins", account_name="web01-Administrator",
                          username="Administrator", account_domain="local", password_env=None, line=0, address="web01.corp.example.com")
    payload = build_vault_account(sa, "initial-pw", platform_id="WinServerLocal", address="web01.corp.example.com")
    assert payload == {"name": "web01-Administrator", "address": "web01.corp.example.com", "userName": "Administrator",
                       "platformId": "WinServerLocal", "safeName": "SIA-LocalAdmins", "secretType": "password",
                       "secret": "initial-pw", "secretManagement": {"automaticManagementEnabled": True}}
    assert build_vault_account(sa, "pw", platform_id="P", address="a", cpm_managed=False)["secretManagement"] == {"automaticManagementEnabled": False}
    with pytest.raises(ValueError, match="needs a username"):
        build_vault_account(StrongAccountRow(name="x", type="vault", safe="S", account_name="a", username=None,
                                             account_domain="local", password_env=None, line=0), "pw", platform_id="P", address="a")
    with pytest.raises(ValueError, match="needs its current password"):
        build_vault_account(sa, "", platform_id="P", address="a")
    with pytest.raises(ValueError, match="only vault accounts"):
        build_vault_account(StrongAccountRow(name="x", type="credentials", safe=None, account_name=None, username="u",
                                             account_domain="local", password_env=None, line=0), "pw", platform_id="P", address="a")


def test_target_set_payloads_carry_owner_marker():
    ts = build_target_set(server(), "sec-123", "PCloudAccount", DEFAULTS)
    assert ts == {"name": "web01.corp.example.com", "type": "Target", "secret_type": "PCloudAccount",
                  "secret_id": "sec-123", "description": f"RDP ZSP target web01.corp.example.com via SA-corp-rdp {MARK}",
                  "enable_certificate_validation": False}
    assert is_owned_target_set(ts, OWNER) and not is_owned_target_set({"description": "hand made"}, OWNER)
    ts2 = build_target_set(server(description="DMZ app"), "sec-9", "ProvisionerUser",
                           Defaults(provision_format="<user>_<session-guid>", target_set_cert_validation=True))
    assert ts2["provision_format"] == "<user>_<session-guid>" and ts2["enable_certificate_validation"] is True
    assert ts2["description"] == f"DMZ app {MARK}"
    bulk = build_bulk_target_sets({"sec-123": [ts], "sec-9": [ts2], "sec-empty": []})
    assert bulk == [{"strong_account_id": "sec-123", "target_sets": [ts]}, {"strong_account_id": "sec-9", "target_sets": [ts2]}]
    # a PUT replaces the object, so the update body re-sends cert validation / provision format rather than
    # letting them fall back to the platform default
    update = build_target_set_update(server(), "sec-1", "PCloudAccount", DEFAULTS)
    assert update == {"type": "Target", "secret_type": "PCloudAccount", "secret_id": "sec-1",
                      "description": f"RDP ZSP target web01.corp.example.com via SA-corp-rdp {MARK}",
                      "enable_certificate_validation": False}
    update2 = build_target_set_update(server(), "sec-1", "PCloudAccount",
                                      Defaults(provision_format="<user>_<session-guid>", target_set_cert_validation=True))
    assert update2["provision_format"] == "<user>_<session-guid>" and update2["enable_certificate_validation"] is True
    assert ownership_marker("x") == "managed-by:x"


def test_principal_from_identity_row():
    assert build_principal(GROUP_ROW) == {
        "id": "b1f9c0e2-1111-2222-3333-444455556666", "name": "SIA-Web-Admins", "type": "GROUP",
        "sourceDirectoryId": "09B9A9B0-6CE8-465F-AB03-65766D33B05E", "sourceDirectoryName": "CyberArk Cloud Directory"}


def test_policy_payload_golden():
    policy = build_policy(server(), [build_principal(GROUP_ROW)], DEFAULTS)
    expected = {
        "metadata": {
            "name": NAME,
            "description": "Automated: RDP ZSP access to web01.corp.example.com",
            "timeFrame": {},
            "policyEntitlement": {"targetCategory": "VM", "locationType": "FQDN/IP", "policyType": "Recurring"},
            "policyTags": ["automated", OWNER],
            "timeZone": "America/New_York",
            "status": {"status": "Active"},
        },
        "principals": [build_principal(GROUP_ROW)],
        "delegationClassification": "Unrestricted",
        "conditions": {"accessWindow": {"daysOfTheWeek": [0, 1, 2, 3, 4, 5, 6]}, "maxSessionDuration": 2, "idleTime": 10},
        "targets": {"FQDN/IP": {"fqdnRules": [{"operator": "EXACTLY", "computernamePattern": "web01.corp.example.com",
                                                "domain": "corp.example.com"}]}},
        "behavior": {"connectAs": {"rdp": {"localEphemeralUser": {"assignGroups": ["Administrators"],
                                                                   "enableEphemeralUserReconnect": False}}}},
    }
    assert policy == expected
    # metadata.status is required by the API (ArkUAPMetadata.status has no default); tenants reject a create without it
    assert build_policy(server(), [build_principal(GROUP_ROW)],
                        Defaults(policy_status="Suspended"))["metadata"]["status"] == {"status": "Suspended"}
    assert is_owned_policy(policy, OWNER) and not is_owned_policy({"metadata": {"policyTags": ["automated"]}}, OWNER)
    json.dumps(policy)  # serializable


def test_policy_overrides_and_hours():
    d = Defaults(from_hour="08:00", to_hour="18:00", days_of_week=(1, 2, 3, 4, 5), max_session_hours=4,
                 idle_minutes=15, enable_reconnect=True, policy_tags=(), owner_tag="team-x")
    s = server(assign_groups=("Remote Desktop Users",), domain="example.com", policy_name="P1", description="D1")
    policy = build_policy(s, [build_principal(GROUP_ROW)], d)
    assert policy["metadata"]["name"] == "P1" and policy["metadata"]["description"] == "D1"
    assert policy["metadata"]["policyTags"] == ["team-x"] and policy["metadata"]["timeZone"] == "GMT"
    assert policy["conditions"] == {"accessWindow": {"daysOfTheWeek": [1, 2, 3, 4, 5], "fromHour": "08:00", "toHour": "18:00"},
                                    "maxSessionDuration": 4, "idleTime": 15}
    assert policy["behavior"]["connectAs"]["rdp"]["localEphemeralUser"] == {
        "assignGroups": ["Remote Desktop Users"], "enableEphemeralUserReconnect": True}
    assert build_fqdn_rule(s) == {"operator": "EXACTLY", "computernamePattern": "web01.corp.example.com", "domain": "example.com"}


def test_too_many_tags_rejected():
    d = Defaults(policy_tags=tuple(f"t{i}" for i in range(20)))
    with pytest.raises(ValueError, match="maximum is 20"):
        build_policy(server(), [build_principal(GROUP_ROW)], d)


def test_validate_and_sanitize_template():
    assert validate_template(TEMPLATE) == []
    bad = {"metadata": {"policyEntitlement": {"targetCategory": "DB", "locationType": "FQDN/IP"}},
           "behavior": {"connectAs": {"ssh": {}}}, "conditions": {}}
    problems = validate_template(bad)
    assert any("targetCategory" in p for p in problems) and any("no connection profile" in p for p in problems) and "no conditions" in problems
    cleaned = sanitize_template(TEMPLATE)
    assert cleaned == {
        "metadata": {"timeZone": "Europe/London", "policyTags": ["ref"]},
        "conditions": {"accessWindow": {"daysOfTheWeek": [1, 2, 3], "fromHour": "07:00", "toHour": "19:00"},
                       "maxSessionDuration": 2, "idleTime": 5},
        "behavior": {"connectAs": {"rdp": {"localEphemeralUser": {"assignGroups": ["Administrators", "Backup Operators"],
                                                                  "enableEphemeralUserReconnect": True}},
                                   "ssh": {"username": "root"}}},
        "delegationClassification": "Restricted",
    }
    ssh_only = {"metadata": {"policyEntitlement": {"targetCategory": "VM", "locationType": "FQDN/IP"}},
                "behavior": {"connectAs": {"ssh": {"username": "root"}}}, "conditions": {"maxSessionDuration": 1}}
    assert validate_template(ssh_only) == []
    cleaned["conditions"]["accessWindow"]["daysOfTheWeek"].append(9)
    assert TEMPLATE["conditions"]["accessWindow"]["daysOfTheWeek"] == [1, 2, 3]  # deep copy


def test_policy_from_template_clones_approved_fields_only():
    policy = build_policy(server(), [build_principal(GROUP_ROW)], DEFAULTS, template=TEMPLATE)
    assert policy["conditions"] == sanitize_template(TEMPLATE)["conditions"]
    assert policy["behavior"] == {"connectAs": {"rdp": TEMPLATE["behavior"]["connectAs"]["rdp"]}}  # SSH profile dropped
    assert policy["metadata"]["timeZone"] == "Europe/London" and policy["metadata"]["policyTags"] == ["ref", OWNER]
    assert policy["delegationClassification"] == "Restricted"
    assert policy["metadata"]["name"] == NAME and "policyId" not in policy["metadata"]
    assert policy["metadata"]["status"] == {"status": "Active"}      # the template's status never carries over
    assert policy["principals"] == [build_principal(GROUP_ROW)]
    assert policy["targets"]["FQDN/IP"]["fqdnRules"][0]["computernamePattern"] == "web01.corp.example.com"
    policy2 = build_policy(server(assign_groups=("Users",)), [build_principal(GROUP_ROW)], DEFAULTS, template=TEMPLATE)
    assert policy2["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["assignGroups"] == ["Users"]
    assert TEMPLATE["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["assignGroups"] == ["Administrators", "Backup Operators"]


def test_policy_from_template_without_tags_or_timezone():
    template = {"metadata": {"name": "Ref"}, "conditions": {"maxSessionDuration": 1},
                "behavior": {"connectAs": {"rdp": {"domainEphemeralUser": {"assignGroups": [], "assignDomainGroups": ["G"]}}}}}
    policy = build_policy(server(), [build_principal(GROUP_ROW)], DEFAULTS, template=template)
    assert policy["metadata"]["policyTags"] == [OWNER] and policy["metadata"]["timeZone"] == "America/New_York"
    assert policy["delegationClassification"] == "Unrestricted"
    assert policy["behavior"]["connectAs"]["rdp"]["domainEphemeralUser"]["assignDomainGroups"] == ["G"]


def test_policy_requires_principals():
    with pytest.raises(ValueError, match="no principals"):
        build_policy(server(), [], DEFAULTS)


def test_policy_update_signature_status_and_fqdns():
    desired = build_policy(server(), [build_principal(GROUP_ROW)], DEFAULTS)
    existing = {**desired, "metadata": {**desired["metadata"], "policyId": "pol-42", "status": {"status": "ACTIVE"}}}
    update = build_policy_update(existing, desired)
    assert update["metadata"]["policyId"] == "pol-42" and update["metadata"]["name"] == NAME
    # an update carries the live status over: fixing principals must not silently un-suspend a policy
    assert update["metadata"]["status"] == {"status": "ACTIVE"}
    suspended = {**desired, "metadata": {**desired["metadata"], "policyId": "p", "status": "Suspended"}}
    assert build_policy_update(suspended, desired)["metadata"]["status"] == {"status": "Suspended"}
    fresh = {"metadata": {"policyId": "p"}}
    assert build_policy_update(fresh, desired)["metadata"]["status"] == {"status": "Active"}
    assert policy_signature(desired) == policy_signature(existing)
    drifted = {**existing, "principals": [{"id": "other"}]}
    assert policy_signature(drifted) != policy_signature(desired)
    assert policy_signature({"targets": {"FQDN/IP": {"fqdnRules": [{"operator": "exactly", "computernamePattern": "WEB01.corp.example.com", "domain": "CORP.example.com"}]}}})["fqdn_rules"] == [("EXACTLY", "web01.corp.example.com", "corp.example.com")]
    partial = {"metadata": {"name": NAME}, "principals": [{"id": "a"}]}          # what the list endpoint returns
    assert policy_signature(partial) == {"principals": ["a"], "fqdn_rules": None}
    assert policy_signature({"metadata": {}}) == {"principals": None, "fqdn_rules": None}
    assert policy_status(existing) == "Active" and policy_status(desired) == "Active"
    assert policy_status({"metadata": {"status": "suspended"}}) == "Suspended" and policy_status({"metadata": {}}) == ""
    assert exact_fqdns(desired) == ["web01.corp.example.com"]
    assert exact_fqdns({"targets": {"FQDN/IP": {"fqdnRules": [{"operator": "WILDCARD", "computernamePattern": "*.corp"}]}}}) == []


def test_names_match_html_escaped():
    assert names_match("R&amp;D-Admins", "R&D-Admins")
    assert not names_match("A", "B") and not names_match(None, "A")


def test_ssh_policy_behavior_and_description():
    lnx = server(fqdn="lnx01.corp.example.com", strong_account=None, protocol="ssh", ssh_username="ec2-user")
    policy = build_policy(lnx, [build_principal(GROUP_ROW)], DEFAULTS)
    assert policy["behavior"] == {"connectAs": {"ssh": {"username": "ec2-user"}}}
    assert policy["metadata"]["description"] == "Automated: SSH ZSP access to lnx01.corp.example.com"
    assert policy["targets"]["FQDN/IP"]["fqdnRules"][0]["computernamePattern"] == "lnx01.corp.example.com"
    fallback = build_policy(server(protocol="ssh", strong_account=None), [build_principal(GROUP_ROW)], Defaults(ssh_username="root"))
    assert fallback["behavior"]["connectAs"]["ssh"]["username"] == "root"
    with pytest.raises(ValueError, match="needs ssh_username"):
        build_policy(server(protocol="ssh", strong_account=None), [build_principal(GROUP_ROW)], DEFAULTS)


def test_template_profile_chosen_by_protocol():
    rdp_policy = build_policy(server(), [build_principal(GROUP_ROW)], DEFAULTS, template=TEMPLATE)
    assert set(rdp_policy["behavior"]["connectAs"]) == {"rdp"}
    ssh_policy = build_policy(server(protocol="ssh", strong_account=None), [build_principal(GROUP_ROW)], DEFAULTS, template=TEMPLATE)
    assert ssh_policy["behavior"] == {"connectAs": {"ssh": {"username": "root"}}}
    overridden = build_policy(server(protocol="ssh", strong_account=None, ssh_username="ec2-user"), [build_principal(GROUP_ROW)], DEFAULTS, template=TEMPLATE)
    assert overridden["behavior"]["connectAs"]["ssh"]["username"] == "ec2-user"
    rdp_only = {**TEMPLATE, "behavior": {"connectAs": {"rdp": TEMPLATE["behavior"]["connectAs"]["rdp"]}}}
    with pytest.raises(ValueError, match="no SSH profile"):
        build_policy(server(protocol="ssh", strong_account=None), [build_principal(GROUP_ROW)], DEFAULTS, template=rdp_only)
    ssh_only = {**TEMPLATE, "behavior": {"connectAs": {"ssh": {"username": "root"}}}}
    with pytest.raises(ValueError, match="no RDP profile"):
        build_policy(server(), [build_principal(GROUP_ROW)], DEFAULTS, template=ssh_only)


def test_domain_scoped_target_set_payload():
    """A Domain set is named after the AD domain and describes its scope, never one server."""
    web01 = server(description="per-server note", target_set_name="corp.example.com", target_set_type="Domain")
    ts = build_target_set(web01, "sec-corp", "PCloudAccount", DEFAULTS)
    assert ts == {"name": "corp.example.com", "type": "Domain", "secret_type": "PCloudAccount", "secret_id": "sec-corp",
                  "description": f"RDP ZSP domain corp.example.com via SA-corp-rdp {MARK}",
                  "enable_certificate_validation": False}
    assert is_owned_target_set(ts, OWNER)
    assert build_target_set_update(web01, "sec-corp", "PCloudAccount", DEFAULTS)["type"] == "Domain"
    # a set named after the server itself is not shared, so the per-server description still wins
    own = server(description="per-server note", target_set_name="web01.corp.example.com")
    assert build_target_set(own, "s", "PCloudAccount", DEFAULTS)["description"] == f"per-server note {MARK}"


def test_render_supports_case_variants():
    assert render("{hostname_upper}-{hostname_lower}-{domain_upper}", server()) == "WEB01-web01-CORP.EXAMPLE.COM"


def test_target_set_update_preserves_a_provision_format_it_does_not_manage():
    """[defaults] provision_format = "" means "SIA default naming", not "wipe what the target set already has"."""
    existing = {"name": NAME, "provision_format": "<user>_<session-guid>"}
    assert build_target_set_update(server(), "s", "PCloudAccount", DEFAULTS, existing)["provision_format"] == "<user>_<session-guid>"
    # a configured format still wins over the existing one
    configured = Defaults(provision_format="<user>-svc")
    assert build_target_set_update(server(), "s", "PCloudAccount", configured, existing)["provision_format"] == "<user>-svc"
    assert "provision_format" not in build_target_set_update(server(), "s", "PCloudAccount", DEFAULTS, {"name": NAME})
