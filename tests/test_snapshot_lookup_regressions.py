"""Filtered misses must not hide existing objects or discard contrary listing evidence."""
from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from sia.clients import UAP_VM_FILTER
from sia.http import SIAApiError
from sia.reconcile import ReconcileError
from tests.fakes import FakeSIA, FakeUAP
from tests.test_resolve_reconcile import (
    MARK, ONE, VAULT, VAULT_SIA_NAME, WEB01, WEB01_FQDN, WEB02_FQDN, calls, inputs, make,
)


class BlindPolicySearchUAP(FakeUAP):
    def list_policies(self, *, text=None, filter_query=None, max_pages=1000):
        if text:
            self.calls.append(("list_policies", (text, filter_query)))
            return []
        return super().list_policies(text=text, filter_query=filter_query, max_pages=max_pages)


@pytest.mark.parametrize("policy_name", [None, "Custom operations policy"])
@pytest.mark.parametrize("update", [False, True])
def test_independent_blind_policy_search_recovers_renamed_policy(policy_name, update):
    inp = inputs([replace(WEB01, policy_name=policy_name)], [VAULT])
    seed, sia, original, _ = make(inp)
    assert seed.run().failures == 0
    original_id = original.policies[0]["metadata"]["policyId"]
    original.policies[0]["metadata"]["name"] = "Renamed in the UI"
    uap = BlindPolicySearchUAP(copy.deepcopy(original.policies))
    uap._counter = 100  # A mistaken create must not collide with the fake's seeded policy ID.
    sia.calls.clear()

    result = make(inp, sia=sia, uap=uap, lookup="search", update=update)[0].run()

    outcome = result.servers[0].policy
    assert outcome.status == ("updated" if update else "drift")
    assert outcome.ref == original_id and len(uap.policies) == 1
    assert not calls(uap, "create_policy") and not calls(sia, "bulk_create_target_sets")
    # No unrelated SIA miss or template lookup may be needed to discover a blind UAP filter.
    assert not calls(sia, "list_secrets") and sia.capabilities.name_filter_reliable
    assert [query for query in calls(uap, "list_policies") if query[0] is None] == [(None, UAP_VM_FILTER)]
    if policy_name:
        assert (policy_name, UAP_VM_FILTER) in calls(uap, "list_policies")
    if update:
        assert calls(uap, "update_policy")[0][0] == original_id
        assert uap.policies[0]["metadata"]["name"] == (policy_name or WEB01_FQDN)


def test_nonempty_policy_query_still_confirms_a_missing_custom_policy_name():
    custom = replace(WEB01, policy_name="Operations access", principals=("SIA-Platform-Ops",), line=3)
    inp = inputs([WEB01, custom], [VAULT])
    seed, sia, original, _ = make(inp)
    assert seed.run().failures == 0
    hidden = next(policy for policy in original.policies if policy["metadata"]["name"] == custom.policy_name)
    hidden_id = hidden["metadata"]["policyId"]
    hidden["metadata"]["name"] = "Renamed operations access"

    class PartialPolicySearchUAP(FakeUAP):
        def list_policies(self, **kwargs):
            rows = super().list_policies(**kwargs)
            return [row for row in rows if row["metadata"]["policyId"] != hidden_id] if kwargs.get("text") else rows

    uap = PartialPolicySearchUAP(copy.deepcopy(original.policies))
    uap._counter = 100
    result = make(inp, sia=sia, uap=uap, lookup="search")[0].run()

    assert [row.policy.status for row in result.servers] == ["exists", "drift"]
    assert result.servers[1].policy.ref == hidden_id and len(uap.policies) == 2
    assert not calls(uap, "create_policy")
    assert [query for query in calls(uap, "list_policies") if query[0] is None] == [(None, UAP_VM_FILTER)]


def test_failed_confirming_policy_listing_stops_before_any_write():
    class InvalidPolicyListingUAP(BlindPolicySearchUAP):
        def list_policies(self, **kwargs):
            if not kwargs.get("text"):
                raise SIAApiError("GET", "/api/policies", 200, "malformed policy listing", cause="malformed_response")
            return super().list_policies(**kwargs)

    sia, uap = FakeSIA(), InvalidPolicyListingUAP()
    with pytest.raises(SIAApiError, match="malformed policy listing"):
        make(ONE, sia=sia, uap=uap, lookup="search")[0].run()
    assert not calls(sia, "create_secret") and not calls(sia, "bulk_create_target_sets")
    assert not calls(uap, "create_policy")


def test_confirming_target_set_listing_keeps_conflicts_for_already_found_names():
    class PartialTargetSetFilterSIA(FakeSIA):
        def list_target_sets(self, **kwargs):
            rows = super().list_target_sets(**kwargs)
            return rows[:1] if kwargs.get("name") else rows

    secret = {"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME}
    targets = [{"id": identifier, "name": WEB01_FQDN, "type": "Target", "secret_id": "sec-1",
                "secret_type": "PCloudAccount"} for identifier in ("target-a", "target-b")]
    sia, uap = PartialTargetSetFilterSIA([secret], targets), FakeUAP()
    inp = inputs([WEB01, replace(WEB01, fqdn=WEB02_FQDN, line=3)], [VAULT])

    with pytest.raises(ReconcileError, match="ambiguous target set"):
        make(inp, sia=sia, uap=uap, lookup="search")[0].run()
    assert (None, None) in calls(sia, "list_target_sets")
    assert not calls(sia, "bulk_create_target_sets") and not calls(sia, "update_target_set")
    assert not calls(uap, "create_policy")


def per_account_sia(*, old_id_key="secret_id", target_name=WEB01_FQDN, target_type="Target"):
    secrets = [{"secret_id": "sec-new", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME},
               {old_id_key: "sec-old", "secret_type": "PCloudAccount", "secret_name": "Unreferenced account"}]
    target = {"id": "target-old", "name": target_name, "type": target_type,
              "secret_id": "sec-old", "secret_type": "PCloudAccount", "description": "Created manually"}
    sia = FakeSIA(secrets, [target])
    sia.capabilities.targetsets_list_unfiltered = False
    return sia


@pytest.mark.parametrize("lookup", ["list", "search"])
@pytest.mark.parametrize("adopt", [False, True])
def test_per_account_snapshot_finds_old_binding_and_enforces_adoption(lookup, adopt):
    sia = per_account_sia()
    result = make(ONE, sia=sia, lookup=lookup, only="targetsets", update=True, adopt_all=adopt)[0].run()

    outcome = result.servers[0].target_set
    assert outcome.status == ("updated" if adopt else "drift")
    assert not calls(sia, "bulk_create_target_sets")
    assert ("sec-old", None) in calls(sia, "list_target_sets")
    assert calls(sia, "list_secrets") == [None]  # Reuse the initial listing in list mode.
    if adopt:
        assert sia.target_sets[0]["secret_id"] == "sec-new" and MARK in sia.target_sets[0]["description"]
        assert len(calls(sia, "update_target_set")) == 1
    else:
        assert "--adopt" in outcome.detail and sia.target_sets[0]["secret_id"] == "sec-old"
        assert not calls(sia, "update_target_set")


def test_per_account_discovery_handles_camelcase_secret_id_and_shared_domain_set():
    domain = "corp.example.com"
    rows = [replace(WEB01, target_set_name=domain, target_set_type="Domain"),
            replace(WEB01, fqdn=WEB02_FQDN, target_set_name=domain, target_set_type="Domain", line=3)]
    sia = per_account_sia(old_id_key="secretId", target_name=domain, target_type="Domain")
    result = make(inputs(rows, [VAULT]), sia=sia, lookup="search", dry_run=True)[0].run()

    assert all(row.target_set.status == "drift" for row in result.servers)
    assert all("shared" in row.target_set.detail or "every server" in row.target_set.detail for row in result.servers)
    assert calls(sia, "list_target_sets").count(("sec-old", None)) == 1
    assert calls(sia, "list_secrets") == [None]
    assert not calls(sia, "bulk_create_target_sets")


@pytest.mark.parametrize("failed_read", ["secrets", "old-account-targets"])
def test_incomplete_per_account_discovery_stops_before_any_write(failed_read):
    class IncompleteSIA(FakeSIA):
        def list_secrets(self, **kwargs):
            if failed_read == "secrets":
                raise SIAApiError("GET", "/api/secrets", 200, "incomplete discovery", cause="malformed_response")
            return super().list_secrets(**kwargs)

        def list_target_sets(self, **kwargs):
            if failed_read == "old-account-targets" and kwargs.get("strong_account_id") == "sec-old":
                raise SIAApiError("GET", "/api/targetsets", 200, "incomplete discovery", cause="malformed_response")
            return super().list_target_sets(**kwargs)

    original = per_account_sia()
    sia, uap = IncompleteSIA(original.secrets, original.target_sets), FakeUAP()
    sia.capabilities.targetsets_list_unfiltered = False
    with pytest.raises(SIAApiError, match="incomplete discovery"):
        make(ONE, sia=sia, uap=uap, lookup="search", update=True, adopt_all=True)[0].run()
    assert not calls(sia, "create_secret") and not calls(sia, "bulk_create_target_sets")
    assert not calls(sia, "update_target_set") and not calls(uap, "create_policy")


def test_complete_per_account_search_does_not_enumerate_unrelated_accounts():
    sia = per_account_sia()
    sia.target_sets[0]["secret_id"] = "sec-new"
    result = make(ONE, sia=sia, lookup="search", dry_run=True)[0].run()

    assert result.servers[0].target_set.status == "exists"
    assert calls(sia, "list_target_sets") == [("sec-new", None)]
    assert not calls(sia, "list_secrets")
