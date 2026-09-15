"""Success requires read-back evidence that a write reached the requested tenant state."""
from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest

from sia.checkpoint import Checkpoint
from sia.http import SIAApiError
from tests.fakes import FakeSIA, FakeUAP
from tests.test_resolve_reconcile import DEFAULTS, GROUP_DEFAULTS, ONE, calls, make


class PrincipalLessListUAP(FakeUAP):
    """A valid list projection that omits the authorization block."""

    def list_policies(self, **kwargs):
        rows = super().list_policies(**kwargs)
        for row in rows:
            row.pop("principals", None)
        return rows


def test_principal_less_list_projection_fetches_full_policy_before_passing():
    seed, sia, original, _ = make(ONE)
    assert seed.run().failures == 0
    original.policies[0]["principals"][0]["id"] = "wrong-role"
    uap = PrincipalLessListUAP(copy.deepcopy(original.policies))

    result = make(ONE, sia=sia, uap=uap, dry_run=True, only="policies", drift=False)[0].run()

    assert result.servers[0].policy.status == "drift"
    assert "principals differ" in result.servers[0].policy.detail
    assert calls(uap, "get_policy") == [result.servers[0].policy.ref]


def test_policy_remains_unverified_when_full_response_omits_principals():
    seed, sia, original, _ = make(ONE)
    assert seed.run().failures == 0

    class PrincipalLessEverywhereUAP(PrincipalLessListUAP):
        def get_policy(self, policy_id):
            row = super().get_policy(policy_id)
            row.pop("principals", None)
            return row

    uap = PrincipalLessEverywhereUAP(copy.deepcopy(original.policies))
    result = make(ONE, sia=sia, uap=uap, dry_run=True, only="policies", drift=False)[0].run()

    outcome = result.servers[0].policy
    assert outcome.status == "unverified" and outcome.ref
    assert "missing principals" in outcome.detail and "cannot confirm who has access" in outcome.detail
    assert not calls(uap, "update_policy")


def test_policy_create_requires_full_readback_convergence(tmp_path):
    class WrongCreateUAP(FakeUAP):
        def create_policy(self, payload):
            policy_id = super().create_policy(payload)
            self.policies[-1]["principals"] = [{"id": "wrong-role", "name": "Wrong", "type": "ROLE"}]
            return policy_id

    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    result = make(ONE, uap=WrongCreateUAP(), checkpoint=checkpoint)[0].run()
    outcome = result.servers[0].policy

    assert outcome.status == "unverified" and outcome.ref == "pol-1"
    assert "read-back still differs in principals" in outcome.detail
    assert outcome.diagnostic["mutation_state"] == "applied"
    assert checkpoint.done_count() == 0


def test_role_migration_update_is_unverified_when_put_does_not_converge(tmp_path):
    seed, sia, group_uap, _ = make(ONE, defaults=GROUP_DEFAULTS)
    assert seed.run().failures == 0

    class NoOpUpdateUAP(FakeUAP):
        def update_policy(self, policy_id, payload):
            self.calls.append(("update_policy", (policy_id, payload)))

    uap = NoOpUpdateUAP(copy.deepcopy(group_uap.policies))
    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    result = make(ONE, sia=sia, uap=uap, update=True, checkpoint=checkpoint)[0].run()
    outcome = result.servers[0].policy

    assert calls(uap, "update_policy")[0][1]["principals"][0]["type"] == "ROLE"
    assert uap.policies[0]["principals"][0]["type"] == "GROUP"
    assert outcome.status == "unverified" and "read-back still differs in principals" in outcome.detail
    assert outcome.diagnostic["mutation_state"] == "applied" and outcome.ref
    assert checkpoint.done_count() == 0


def test_policy_readback_polls_until_normalized_state_converges():
    seed, sia, original, _ = make(ONE)
    assert seed.run().failures == 0
    original.policies[0]["conditions"]["idleTime"] = 99

    class EventuallyConsistentUAP(FakeUAP):
        stale = None

        def update_policy(self, policy_id, payload):
            self.stale = copy.deepcopy(self.policies[0])
            super().update_policy(policy_id, payload)

        def get_policy(self, policy_id):
            if self.stale is not None:
                self.calls.append(("get_policy", policy_id))
                stale, self.stale = self.stale, None
                return stale
            return super().get_policy(policy_id)

    uap = EventuallyConsistentUAP(copy.deepcopy(original.policies))
    result = make(ONE, sia=sia, uap=uap, update=True, status_polls=2)[0].run()

    assert result.servers[0].policy.status == "updated"
    assert calls(uap, "get_policy") == ["pol-1", "pol-1"]


@pytest.mark.parametrize(("defaults", "expected_status", "suspended_ok"), [
    (DEFAULTS, "Active", False),
    (replace(DEFAULTS, policy_status="Suspended"), "Suspended", True),
])
def test_transient_policy_status_uses_configured_stable_update_intent(
        defaults, expected_status, suspended_ok):
    uap = FakeUAP()
    uap.create_status = defaults.policy_status
    seed, sia, uap, _ = make(ONE, uap=uap, defaults=defaults)
    assert seed.run().failures == 0
    uap.policies[0]["metadata"]["status"] = {"status": "Warning"}
    uap.policies[0]["principals"] = []

    preview = make(
        ONE, sia=sia, uap=uap, defaults=defaults, dry_run=True, update=True,
        suspended_ok=suspended_ok)[0].run().servers[0].policy
    assert preview.status == "planned"
    assert f"status Warning -> {expected_status}" in preview.detail

    outcome = make(
        ONE, sia=sia, uap=uap, defaults=defaults, update=True,
        suspended_ok=suspended_ok)[0].run().servers[0].policy
    payload = calls(uap, "update_policy")[-1][1]
    assert payload["metadata"]["status"] == {"status": expected_status}
    assert outcome.status == "updated"


def test_stable_active_status_is_preserved_when_update_default_is_suspended():
    seed, sia, uap, _ = make(ONE)
    assert seed.run().failures == 0
    uap.policies[0]["principals"] = []
    staged_default = replace(DEFAULTS, policy_status="Suspended")

    outcome = make(ONE, sia=sia, uap=uap, defaults=staged_default, update=True)[0].run().servers[0].policy

    assert calls(uap, "update_policy")[-1][1]["metadata"]["status"] == {"status": "Active"}
    assert outcome.status == "updated"


def test_role_directory_normalization_does_not_block_verified_update():
    seed, sia, original, _ = make(ONE)
    assert seed.run().failures == 0
    original.policies[0]["principals"] = []

    class DirectoryNormalizingUAP(FakeUAP):
        def update_policy(self, policy_id, payload):
            super().update_policy(policy_id, payload)
            principal = self.policies[0]["principals"][0]
            principal["sourceDirectoryId"] = "tenant-normalized-id"
            principal["sourceDirectoryName"] = "Tenant normalized directory"

    uap = DirectoryNormalizingUAP(copy.deepcopy(original.policies))
    outcome = make(ONE, sia=sia, uap=uap, update=True)[0].run().servers[0].policy

    assert outcome.status == "updated"


def test_target_set_update_requires_exact_account_filtered_readback(tmp_path):
    seed, original, uap, _ = make(ONE)
    assert seed.run().failures == 0
    original.target_sets[0]["secret_id"] = "wrong-secret"

    class NoOpTargetSIA(FakeSIA):
        def update_target_set(self, name, payload):
            self.calls.append(("update_target_set", (name, payload)))
            return copy.deepcopy(self.target_sets[0])

    sia = NoOpTargetSIA(copy.deepcopy(original.secrets), copy.deepcopy(original.target_sets))
    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    result = make(ONE, sia=sia, uap=uap, update=True, status_polls=2, checkpoint=checkpoint)[0].run()
    outcome = result.servers[0].target_set

    assert outcome.status == "unverified" and outcome.ref
    assert "did not return the requested target set" in outcome.detail
    assert outcome.diagnostic["mutation_state"] == "applied"
    update_index = next(i for i, call in enumerate(sia.calls) if call[0] == "update_target_set")
    # Filtered by the strong account, which is what makes the re-pointed set invisible here. The name filter only
    # saves pages, so each empty name-filtered read is confirmed against the account's listing before the write is
    # reported as unverified.
    assert [call[1] for call in sia.calls[update_index + 1:] if call[0] == "list_target_sets"] == [
        ("sec-1", "web01.corp.example.com"), ("sec-1", None), ("sec-1", "web01.corp.example.com"), ("sec-1", None)]
    assert checkpoint.done_count() == 0


def test_target_set_readback_confirms_an_empty_name_filtered_read_against_the_account():
    seed, original, uap, _ = make(ONE)
    assert seed.run().failures == 0
    original.target_sets[0]["secret_id"] = "wrong-secret"

    class BlindNameFilterSIA(FakeSIA):
        def list_target_sets(self, *, strong_account_id=None, name=None):
            if name:
                self.calls.append(("list_target_sets", (strong_account_id, name)))
                return []
            return super().list_target_sets(strong_account_id=strong_account_id)

    sia = BlindNameFilterSIA(copy.deepcopy(original.secrets), copy.deepcopy(original.target_sets))
    result = make(ONE, sia=sia, uap=uap, update=True)[0].run()

    assert result.servers[0].target_set.status == "updated" and sia.target_sets[0]["secret_id"] == "sec-1"
    update_index = next(i for i, call in enumerate(sia.calls) if call[0] == "update_target_set")
    assert [call[1] for call in sia.calls[update_index + 1:] if call[0] == "list_target_sets"] == [
        ("sec-1", "web01.corp.example.com"), ("sec-1", None)]


def test_target_set_readback_retries_transient_failure_then_converges():
    seed, original, uap, _ = make(ONE)
    assert seed.run().failures == 0
    original.target_sets[0]["secret_id"] = "wrong-secret"

    class TransientReadFailureSIA(FakeSIA):
        pending = None
        failed_once = False

        def update_target_set(self, name, payload):
            self.calls.append(("update_target_set", (name, payload)))
            self.pending = (name, copy.deepcopy(payload))
            return copy.deepcopy(self.target_sets[0])

        def list_target_sets(self, **kwargs):
            if self.pending and not self.failed_once:
                self.failed_once = True
                raise SIAApiError("GET", "/api/targetsets", 503, "temporarily unavailable")
            if self.pending:
                name, payload = self.pending
                next(row for row in self.target_sets if row["name"] == name).update(payload)
                self.pending = None
            return super().list_target_sets(**kwargs)

    sia = TransientReadFailureSIA(copy.deepcopy(original.secrets), copy.deepcopy(original.target_sets))
    result = make(ONE, sia=sia, uap=uap, update=True, status_polls=2)[0].run()

    assert result.servers[0].target_set.status == "updated"
    assert sia.target_sets[0]["secret_id"] == "sec-1"


def test_target_set_accepted_state_survives_readback_interruption(tmp_path):
    seed, original, uap, _ = make(ONE)
    assert seed.run().failures == 0
    original.target_sets[0]["secret_id"] = "wrong-secret"

    class InterruptedReadbackSIA(FakeSIA):
        updated = False

        def update_target_set(self, name, payload):
            self.calls.append(("update_target_set", (name, payload)))
            self.updated = True
            return copy.deepcopy(self.target_sets[0])

        def list_target_sets(self, **kwargs):
            if self.updated:
                raise KeyboardInterrupt
            return super().list_target_sets(**kwargs)

    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    sia = InterruptedReadbackSIA(copy.deepcopy(original.secrets), copy.deepcopy(original.target_sets))
    rec = make(ONE, sia=sia, uap=uap, update=True, checkpoint=checkpoint)[0]

    with pytest.raises(KeyboardInterrupt) as raised:
        rec.run()
    result = raised.value.partial_result
    outcome = result.servers[0].target_set
    assert outcome.status == "unverified" and outcome.ref == "web01.corp.example.com"
    assert outcome.diagnostic["mutation_state"] == "applied"
    assert result.incomplete and result.interrupted and checkpoint.done_count() == 0


def test_policy_create_converges_on_a_dual_control_tenant(tmp_path):
    """A tenant with dual control echoes accessApproval {"required": false, "approvers": []} for every policy."""
    uap = FakeUAP()
    uap.echo_defaults = uap.echo_dual_control = True
    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    rec, sia, uap, _ = make(ONE, uap=uap, checkpoint=checkpoint)
    result = rec.run()
    outcome = result.servers[0].policy

    assert outcome.status == "created" and outcome.ref == "pol-1"
    assert result.failures == 0 and checkpoint.done_count() == 1
    assert not calls(uap, "update_policy")

    uap.partial_list = True                   # the real list endpoint carries no targets: --drift fetches the echo
    again = make(ONE, sia=sia, uap=uap, drift=True)[0].run()
    assert again.servers[0].policy.status == "exists" and "targets checked" in again.servers[0].policy.detail
    assert len(calls(uap, "create_policy")) == 1 and not calls(uap, "update_policy")


def test_policy_create_converges_on_a_tenant_that_overrides_session_settings(tmp_path):
    """A tenant with policy-level session settings reads every policy back with overrideIdleTime and
    overrideMaxSessionDuration true (those settings were sent) and overrideRecording false (none was)."""
    uap = FakeUAP()
    uap.echo_defaults = uap.echo_session_overrides = True
    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    rec, sia, uap, _ = make(ONE, uap=uap, checkpoint=checkpoint)
    result = rec.run()
    outcome = result.servers[0].policy

    assert outcome.status == "created" and outcome.ref == "pol-1"
    assert result.failures == 0 and checkpoint.done_count() == 1
    (payload,) = calls(uap, "create_policy")
    assert not any(key.startswith("override") for key in payload["conditions"])
    assert not calls(uap, "update_policy")

    uap.partial_list = True                   # the real list endpoint carries no targets: --drift fetches the echo
    again = make(ONE, sia=sia, uap=uap, drift=True)[0].run()
    assert again.servers[0].policy.status == "exists" and "targets checked" in again.servers[0].policy.detail
    assert len(calls(uap, "create_policy")) == 1 and not calls(uap, "update_policy")


def test_policy_update_converges_on_a_tenant_that_overrides_session_settings():
    seed, sia, uap, _ = make(ONE)
    assert seed.run().failures == 0
    uap.policies[0]["conditions"]["idleTime"] = 99
    uap.echo_defaults = uap.echo_session_overrides = uap.partial_list = True
    result = make(ONE, sia=sia, uap=uap, update=True, drift=True)[0].run()
    outcome = result.servers[0].policy

    assert outcome.status == "updated"
    assert "access conditions differ (idle minutes: 99 -> 10)" in outcome.detail and "override" not in outcome.detail
    ((_policy_id, update),) = calls(uap, "update_policy")
    assert not any(key.startswith("override") for key in update["conditions"])


def test_policy_update_preserves_fields_only_the_tenant_carries():
    """A PUT replaces the object: leaves the tool never writes travel with the update instead of being reset."""
    seed, sia, uap, _ = make(ONE)
    assert seed.run().failures == 0
    policy = uap.policies[0]
    policy["conditions"]["idleTime"] = 99                          # a value the tool wrote, changed in the portal
    policy["conditions"]["someFutureField"] = {"x": 1}             # a field the tool never writes
    policy["metadata"]["policyTags"].append("cost-center:42")      # a tag added in the portal
    result = make(ONE, sia=sia, uap=uap, update=True, drift=True)[0].run()
    outcome = result.servers[0].policy

    assert outcome.status == "updated" and result.failures == 0
    assert "access conditions differ (idle minutes: 99 -> 10)" in outcome.detail
    assert "someFutureField" not in outcome.detail and "cost-center" not in outcome.detail
    assert outcome.notes == ("policy tags: tenant also carries cost-center:42",       # notes follow the signature order
                             'access conditions: tenant also carries someFutureField={"x": 1}')
    ((_policy_id, payload),) = calls(uap, "update_policy")
    assert payload["conditions"]["idleTime"] == 10 and payload["conditions"]["someFutureField"] == {"x": 1}
    assert payload["metadata"]["policyTags"][-1] == "cost-center:42"
    stored = uap.policies[0]
    assert stored["conditions"]["someFutureField"] == {"x": 1} and "cost-center:42" in stored["metadata"]["policyTags"]


def test_a_field_only_the_tenant_carries_is_a_note_not_drift():
    seed, sia, uap, _ = make(ONE)
    assert seed.run().failures == 0
    uap.policies[0]["conditions"]["someFutureField"] = {"x": 1}
    result = make(ONE, sia=sia, uap=uap, update=True, drift=True)[0].run()
    outcome = result.servers[0].policy
    assert outcome.status == "exists" and not calls(uap, "update_policy")
    assert outcome.notes == ('access conditions: tenant also carries someFutureField={"x": 1}',)


def test_strict_mode_resets_fields_only_the_tenant_carries():
    seed, sia, uap, _ = make(ONE)
    assert seed.run().failures == 0
    uap.policies[0]["conditions"]["someFutureField"] = {"x": 1}
    strict = replace(DEFAULTS, readback_extra_keys="fail")
    result = make(ONE, sia=sia, uap=uap, update=True, drift=True, defaults=strict)[0].run()
    outcome = result.servers[0].policy
    assert outcome.status == "updated" and not outcome.notes
    assert 'access conditions differ (someFutureField: {"x": 1} -> absent)' in outcome.detail
    ((_policy_id, payload),) = calls(uap, "update_policy")
    assert "someFutureField" not in payload["conditions"] and "someFutureField" not in uap.policies[0]["conditions"]


def test_the_tools_own_silence_is_still_managed():
    """Access hours the tool leaves out mean "full days", and a tag the tool writes must be present: the tenant
    changing either is drift, not a note."""
    seed, sia, uap, _ = make(ONE)
    assert seed.run().failures == 0
    window = uap.policies[0]["conditions"]["accessWindow"]
    window.update({"fromHour": "07:00", "toHour": "19:00"})
    result = make(ONE, sia=sia, uap=uap, drift=True, dry_run=True)[0].run()
    outcome = result.servers[0].policy
    assert outcome.status == "drift" and not outcome.notes
    assert 'access conditions differ (from hour: "07:00" -> absent; to hour: "19:00" -> absent)' in outcome.detail

    window.pop("fromHour"), window.pop("toHour")
    uap.policies[0]["metadata"]["policyTags"].remove("automated")
    outcome = make(ONE, sia=sia, uap=uap, drift=True, dry_run=True)[0].run().servers[0].policy
    assert outcome.status == "drift"
    assert 'policy tags differ (tags: ["sia-policy-automation"] -> ["automated", "sia-policy-automation"])' in outcome.detail


class SessionOverrideContradictingUAP(FakeUAP):
    """Stores every new policy with its idle-time override switched off and a recording override switched on."""

    def create_policy(self, payload):
        policy_id = super().create_policy(payload)
        self.policies[-1]["conditions"].update(
            {"overrideIdleTime": False, "overrideMaxSessionDuration": True, "overrideRecording": True})
        return policy_id


def test_policy_create_is_unverified_when_a_session_override_contradicts_the_request(tmp_path):
    """overrideIdleTime: false beside the idle time that was sent means the policy is not applying it: a managed
    difference. overrideRecording: true is a setting the tool never writes: a note."""
    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    result = make(ONE, uap=SessionOverrideContradictingUAP(), checkpoint=checkpoint)[0].run()
    outcome = result.servers[0].policy

    assert outcome.status == "unverified" and outcome.ref == "pol-1"
    assert "read-back still differs in conditions (idle time override: false -> true)" in outcome.detail
    assert outcome.notes == ("access conditions: tenant also carries overrideRecording=true",)
    differences = outcome.diagnostic["details"]["differences"]["conditions"]
    assert differences["changed"] == ["overrideIdleTime"] and differences["unmanaged"] == ["overrideRecording"]
    assert differences["tenant"]["overrideIdleTime"] is False and differences["tenant"]["overrideRecording"] is True
    assert "overrideMaxSessionDuration" not in differences["tenant"]    # agrees with maxSessionDuration: an echo
    assert not any(key.startswith("override") for key in differences["requested"])
    assert result.failures == 1 and checkpoint.done_count() == 0


class ApprovalEnforcingUAP(FakeUAP):
    """Stores every new policy with dual control switched on, whatever the request said."""

    def create_policy(self, payload):
        policy_id = super().create_policy(payload)
        self.policies[-1]["conditions"]["accessApproval"] = {"required": True, "approvers": []}
        return policy_id


def test_policy_create_notes_a_field_only_the_tenant_carries(tmp_path):
    """A dual-control tenant that enforces approval adds a field the tool never sent. The write converged on every
    field the tool did send, so the row succeeds with a note instead of failing."""
    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    result = make(ONE, uap=ApprovalEnforcingUAP(), checkpoint=checkpoint)[0].run()
    outcome = result.servers[0].policy

    assert outcome.status == "created" and outcome.ref == "pol-1"
    assert outcome.notes == ('access conditions: tenant also carries accessApproval={"required": true}',)
    diagnostic = outcome.diagnostic
    assert diagnostic["code"] == "SIA-TENANT-FIELDS" and diagnostic["severity"] == "info"
    assert diagnostic["mutation_state"] == "applied"
    differences = diagnostic["details"]["differences"]["conditions"]
    assert differences["tenant"]["accessApproval"] == {"required": True}
    assert differences["changed"] == [] and differences["unmanaged"] == ["accessApproval"]
    json.dumps(diagnostic)                    # the JSON report carries it as-is
    assert result.failures == 0 and checkpoint.done_count() == 1


def test_policy_create_is_unverified_on_a_tenant_field_in_strict_mode(tmp_path):
    """[defaults] readback_extra_keys = "fail" keeps the older verdict: anything the tool did not send is a difference."""
    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    strict = replace(DEFAULTS, readback_extra_keys="fail")
    result = make(ONE, uap=ApprovalEnforcingUAP(), checkpoint=checkpoint, defaults=strict)[0].run()
    outcome = result.servers[0].policy

    assert outcome.status == "unverified" and outcome.ref == "pol-1" and not outcome.notes
    assert 'read-back still differs in conditions (accessApproval: {"required": true} -> absent)' in outcome.detail
    diagnostic = outcome.diagnostic
    assert diagnostic["code"] == "SIA-API-RESPONSE" and diagnostic["mutation_state"] == "applied"
    differences = diagnostic["details"]["differences"]["conditions"]
    assert differences["tenant"]["accessApproval"] == {"required": True}
    assert "accessApproval" not in differences["requested"] and differences["changed"] == ["accessApproval"]
    assert diagnostic["details"]["status"] == "Active" and diagnostic["details"]["policy_id"] == "pol-1"
    assert any("show-policy" in action for action in diagnostic["actions"])
    assert result.failures == 1 and checkpoint.done_count() == 0


def test_ignore_readback_keys_silences_a_tenant_field():
    quiet = replace(DEFAULTS, ignore_readback_keys=("conditions.accessApproval",))
    outcome = make(ONE, uap=ApprovalEnforcingUAP(), defaults=quiet)[0].run().servers[0].policy
    assert outcome.status == "created" and not outcome.notes and outcome.diagnostic is None


def test_policy_update_readback_names_the_values_that_did_not_converge():
    seed, sia, original, _ = make(ONE)
    assert seed.run().failures == 0
    original.policies[0]["conditions"]["idleTime"] = 99

    class NoOpUpdateUAP(FakeUAP):
        def update_policy(self, policy_id, payload):
            self.calls.append(("update_policy", (policy_id, payload)))

    uap = NoOpUpdateUAP(copy.deepcopy(original.policies))
    result = make(ONE, sia=sia, uap=uap, update=True, drift=True)[0].run()
    outcome = result.servers[0].policy

    assert len(calls(uap, "update_policy")) == 1
    assert outcome.status == "unverified"
    assert "read-back still differs in conditions (idle minutes: 99 -> 10)" in outcome.detail
    assert outcome.diagnostic["details"]["differences"]["conditions"]["changed"] == ["idleTime"]
