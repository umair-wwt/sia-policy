"""Tenant variations the tool must absorb: the same object echoed with different casing, spelling, nulls or
projections is not drift, and a materially different one still is."""
import json

import pytest

from sia.payloads import exact_fqdns, policy_signature, policy_status, target_set_signature
from tests.fakes import FakeSIA, FakeUAP
from tests.test_resolve_reconcile import GROUP_DEFAULTS, ONE, VAULT, VAULT_SIA_NAME, WEB01_FQDN, calls, inputs, make, srv


def test_the_schema_probe_names_fields_the_tool_does_not_write():
    from sia.payloads import target_set_field_report, tenant_only_fields
    from tests.test_resolve_reconcile import DEFAULTS
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    assert tenant_only_fields(uap.policies[0], DEFAULTS) == ([], [])          # the tool's own body: nothing extra
    policy = json.loads(json.dumps(uap.policies[0]))
    policy["conditions"].update({"overrideIdleTime": True, "overrideMaxSessionDuration": True, "overrideRecording": False,
                                 "accessApproval": {"required": False, "approvers": []}, "sessionRecording": False})
    policy["metadata"]["timeFrame"] = {"fromTime": None, "toTime": None}
    policy["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["allowMappingLocalDrives"] = False
    policy["targets"]["FQDN/IP"]["ipRules"] = [{"operator": "IN_RANGE", "ipAddresses": ["10.0.0.0/8"]}]
    unknown, recognised = tenant_only_fields(policy, DEFAULTS)
    assert unknown == ["behavior.connectAs.rdp.localEphemeralUser.allowMappingLocalDrives", "conditions.sessionRecording",
                       "targets.FQDN/IP"]
    assert recognised == ["conditions.accessApproval", "conditions.overrideIdleTime", "conditions.overrideMaxSessionDuration",
                          "conditions.overrideRecording"]
    listed = {"id": "t", "name": "x", "type": "Target", "strong_account_id": "s", "someFlag": True}
    assert target_set_field_report(listed) == (["someFlag"], ["secret type", "description", "certificate validation",
                                                              "provision format"])


def test_html_escaped_name_and_description_converge():
    """CyberArk's SDK HTML-escapes both metadata strings before sending; a tenant may echo either escaped."""
    row = srv(WEB01_FQDN, "SA-corp-rdp", ["SIA-Web-Admins"], description="R&D 'ops' access <tier 1>")
    wave = inputs([row], [VAULT])
    uap = FakeUAP()
    uap.echo_html_escaped = True
    rec, sia, uap, _ = make(wave, uap=uap)
    result = rec.run()
    assert result.servers[0].policy.status == "created" and result.failures == 0

    uap.partial_list = True
    again = make(wave, sia=sia, uap=uap, update=True, drift=True)[0].run()
    assert again.servers[0].policy.status == "exists" and not calls(uap, "update_policy")

    uap.policies[0]["metadata"]["description"] = "changed"
    changed = make(wave, sia=sia, uap=uap, drift=True, dry_run=True)[0].run().servers[0].policy
    assert changed.status == "drift"
    assert 'description differs (description: "changed" -> "R&D \'ops\' access <tier 1>")' in changed.detail


def test_a_null_time_frame_echo_converges():
    """The tool sends timeFrame: {}; a tenant may echo null for the same unset state."""
    uap = FakeUAP()
    uap.echo_defaults = uap.echo_null_blocks = True
    rec, sia, uap, _ = make(ONE, uap=uap)
    result = rec.run()
    assert result.servers[0].policy.status == "created" and result.failures == 0
    assert (policy_signature({"metadata": {"timeFrame": None}})["time_frame"]
            == policy_signature({"metadata": {"timeFrame": {}}})["time_frame"] == ())
    assert policy_signature({"metadata": {}})["time_frame"] is None          # a projection without the key: unknown


def test_target_set_account_link_under_its_other_names_is_not_drift():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    sia.echo_strong_account_id = True
    result = make(ONE, sia=sia, uap=uap, update=True, drift=True)[0].run()
    assert result.servers[0].target_set.status == "exists" and not calls(sia, "update_target_set")
    assert target_set_signature({"strongAccountId": "s-1"})["secret_id"] == "s-1"
    assert target_set_signature({"name": "x"})["secret_id"] == ""                 # the link is never "unknown"


def test_target_set_fields_the_listing_omits_or_recases_are_not_drift():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    for ts in sia.target_sets:
        ts["type"] = "target"                                   # the casing this tenant chose
        ts["secret_type"] = "pcloudaccount"
    result = make(ONE, sia=sia, uap=uap, update=True, drift=True)[0].run()
    assert result.servers[0].target_set.status == "exists" and not calls(sia, "update_target_set")

    sia.omit_target_set_fields = {"type", "secret_type"}
    result = make(ONE, sia=sia, uap=uap, update=True, drift=True)[0].run()
    assert result.servers[0].target_set.status == "exists" and not calls(sia, "update_target_set")
    assert target_set_signature({"name": "x"})["secret_type"] is None            # absent: unknown, not ""


def test_a_configured_target_set_setting_is_set_when_the_listing_omits_it_and_verified_as_far_as_it_can_be():
    """A tenant that omits unset fields has not applied the tool's certificate validation: one PUT sets it. If the
    listing never echoes the field, the read-back says so once instead of failing every update forever."""
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    for ts in sia.target_sets:
        ts.pop("enable_certificate_validation", None)
    from dataclasses import replace
    from tests.test_resolve_reconcile import DEFAULTS
    configured = replace(DEFAULTS, target_set_cert_validation=True)
    sia.omit_target_set_fields = {"enable_certificate_validation"}
    result = make(ONE, sia=sia, uap=uap, defaults=configured, update=True, drift=True)[0].run()
    assert result.servers[0].target_set.status == "updated"
    assert calls(sia, "update_target_set")[-1][1]["enable_certificate_validation"] is True
    assert any("do not carry certificate validation" in w for w in result.warnings)


def test_strong_account_type_mismatch_fails_and_blocks_dependents():
    sia = FakeSIA(secrets=[{"secret_id": "s-9", "secret_type": "ProvisionerUser", "secret_name": VAULT_SIA_NAME, "is_active": True}])
    result = make(ONE, sia=sia)[0].run()
    secret = result.secrets["SA-corp-rdp"]
    assert secret.status == "failed" and secret.ref == "s-9"
    assert "is a ProvisionerUser, but 'SA-corp-rdp' is type=vault (PCloudAccount)" in secret.detail
    assert result.servers[0].target_set.status == "blocked" and result.servers[0].policy.status == "blocked"
    assert not calls(sia, "bulk_create_target_sets") and not calls(sia, "create_secret")


@pytest.mark.parametrize("flag, status", [
    (False, "inactive"), ("false", "inactive"), (0, "inactive"), ("Inactive", "inactive"),
    (True, "exists"), ("true", "exists"), (1, "exists"), (None, "exists"), ("maybe", "unverified"),
])
def test_strong_account_active_flag_spellings(flag, status):
    sia = FakeSIA(secrets=[{"secret_id": "s-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME, "is_active": flag}])
    result = make(ONE, sia=sia)[0].run()
    assert result.secrets["SA-corp-rdp"].status == status


def test_extra_target_rules_are_drift_never_a_note():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    uap.policies[0]["targets"]["FQDN/IP"]["ipRules"] = [{"operator": "IN_RANGE", "ipAddresses": ["10.0.0.0/8"]}]
    uap.policies[0]["targets"]["AWS"] = {"regions": ["us-east-1"]}
    outcome = make(ONE, sia=sia, uap=uap, drift=True, dry_run=True)[0].run().servers[0].policy
    assert outcome.status == "drift" and not outcome.notes
    assert ('extra target rules differ (AWS: {"regions": ["us-east-1"]} -> absent; '
            'FQDN/IP: {"ipRules": [{"ipAddresses": ["10.0.0.0/8"], "operator": "IN_RANGE"}]} -> absent)') in outcome.detail


def test_targets_without_an_fqdn_block_are_unverified_under_drift():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    policy = uap.policies[0]
    policy["targets"] = {"fqdn/ip": policy["targets"].pop("FQDN/IP")}          # keyed the way this tenant spells it
    outcome = make(ONE, sia=sia, uap=uap, drift=True, dry_run=True)[0].run().servers[0].policy
    assert outcome.status == "unverified" and "no FQDN/IP rules block" in outcome.detail
    quick = make(ONE, sia=sia, uap=uap, dry_run=True)[0].run().servers[0].policy
    assert quick.status == "exists" and "add --drift to compare targets" in quick.detail
    assert "targets checked" not in quick.detail


def test_a_status_less_list_projection_is_settled_with_one_full_read():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0

    class StatusLessList(FakeUAP):
        def list_policies(self, **kwargs):
            rows = super().list_policies(**kwargs)
            for row in rows:
                row["metadata"].pop("status", None)
            return rows

    statusless = StatusLessList(uap.policies)
    outcome = make(ONE, sia=sia, uap=statusless, dry_run=True)[0].run().servers[0].policy
    assert outcome.status == "exists" and calls(statusless, "get_policy")


def test_policy_status_spellings():
    assert policy_status({"metadata": {"status": {"status": "ACTIVE"}}}) == "Active"
    assert policy_status({"metadata": {"status": "validating"}}) == "Validating"
    assert policy_status({"metadata": {"status": {"status": "PartiallyActive"}}}) == "PartiallyActive"
    assert policy_status({"metadata": {}}) == ""


def test_short_host_fqdn_rules_compare_by_the_fqdn_they_target():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    rule = uap.policies[0]["targets"]["FQDN/IP"]["fqdnRules"][0]
    rule["computernamePattern"] = "WEB01"                       # this tenant splits host and DNS domain
    assert make(ONE, sia=sia, uap=uap, drift=True, dry_run=True)[0].run().servers[0].policy.status == "exists"
    assert exact_fqdns(uap.policies[0]) == [WEB01_FQDN]
    rule["computernamePattern"] = "web02"
    assert make(ONE, sia=sia, uap=uap, drift=True, dry_run=True)[0].run().servers[0].policy.status == "drift"


def test_owner_tag_and_marker_casing_do_not_lose_ownership():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    tags = uap.policies[0]["metadata"]["policyTags"]
    tags[:] = [tag.upper() for tag in tags]
    for ts in sia.target_sets:
        ts["description"] = ts["description"].upper()
    # the owned-tag list filter is the tenant's and may well be case-sensitive too; look the policy up by name
    result = make(ONE, sia=sia, uap=uap, drift=True, dry_run=True, lookup="search")[0].run()
    sr = result.servers[0]
    assert sr.policy.status == "exists" and not sr.policy.notes            # re-cased tags are the same tags
    assert "unmanaged" not in sr.policy.detail and "unmanaged" not in sr.target_set.detail


def test_principal_ids_compare_case_insensitively_and_directory_names_are_labels():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    for principal in uap.policies[0]["principals"]:
        principal["id"] = principal["id"].upper()
        principal["sourceDirectoryName"] = "Renamed Directory"
    assert make(ONE, sia=sia, uap=uap, dry_run=True)[0].run().servers[0].policy.status == "exists"

    rec, sia, uap, _ = make(ONE, defaults=GROUP_DEFAULTS)
    assert rec.run().failures == 0
    for principal in uap.policies[0]["principals"]:
        principal["id"] = principal["id"].lower()
        principal["sourceDirectoryId"] = principal["sourceDirectoryId"].lower()
        principal["sourceDirectoryName"] = "Renamed Directory"
    assert make(ONE, sia=sia, uap=uap, defaults=GROUP_DEFAULTS, dry_run=True)[0].run().servers[0].policy.status == "exists"
