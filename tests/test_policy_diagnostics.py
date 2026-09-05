from dataclasses import replace

from tests.fakes import FakeUAP
from tests.test_resolve_reconcile import DEFAULTS, ONE, calls, make


def test_drift_explains_actual_setting_changes():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    configured = replace(DEFAULTS, max_session_hours=4, idle_minutes=25, enable_reconnect=True)
    result = make(ONE, sia=sia, uap=uap, defaults=configured, update=True, dry_run=True)[0].run()
    detail = result.servers[0].policy.detail
    assert "max session hours: 2 -> 4" in detail and "idle minutes: 10 -> 25" in detail
    assert "reconnect: false -> true" in detail


def test_unordered_days_and_groups_do_not_cause_drift():
    configured = replace(DEFAULTS, assign_local_groups=("Administrators", "Remote Desktop Users"))
    rec, sia, uap, _ = make(ONE, defaults=configured)
    assert rec.run().failures == 0
    policy = uap.policies[0]
    policy["conditions"]["accessWindow"]["daysOfTheWeek"].reverse()
    policy["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["assignGroups"].reverse()
    result = make(ONE, sia=sia, uap=uap, defaults=configured, update=True)[0].run()
    assert result.servers[0].policy.status == "exists" and not calls(uap, "update_policy")


def test_partial_policy_with_targets_still_fetches_missing_behavior():
    rec, sia, original, _ = make(ONE)
    assert rec.run().failures == 0
    class Partial(FakeUAP):
        def list_policies(self, *args, **kwargs):
            result = super().list_policies(*args, **kwargs)
            return [{key: value for key, value in policy.items() if key != "behavior"} for policy in result]
    uap = Partial(original.policies)
    result = make(ONE, sia=sia, uap=uap, defaults=replace(DEFAULTS, enable_reconnect=True), update=True)[0].run()
    assert result.servers[0].policy.status == "updated" and calls(uap, "get_policy")


def test_malformed_vault_create_blocks_dependents():
    from tests.fakes import FakePVWA
    from tests.test_resolve_reconcile import VAULT_INPUT
    class Broken(FakePVWA):
        def add_account(self, payload):
            return {}
    rec, sia, uap, _ = make(VAULT_INPUT, pvwa=Broken(), passwords={"SA-corp-rdp": "test-password"})
    result = rec.run()
    assert result.failures and all(outcome.status == "uncertain" for outcome in result.vault.values())
    assert not calls(sia, "create_secret") and not calls(uap, "create_policy")
