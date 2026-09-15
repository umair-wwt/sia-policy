import io
from dataclasses import replace

from sia.report import print_summary, print_verify, result_dict
from tests.fakes import FakeUAP
from tests.test_reconcile_verification import ApprovalEnforcingUAP
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


def test_drift_names_condition_values_outside_the_known_settings():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    policy = uap.policies[0]
    policy["conditions"]["accessApproval"] = {"required": True}
    policy["conditions"]["someFutureField"] = {"x": 1}
    # two session-override flags that agree with their settings (an echo) and one recording override that does not
    policy["conditions"].update({"overrideIdleTime": True, "overrideMaxSessionDuration": True, "overrideRecording": True})
    result = make(ONE, sia=sia, uap=uap, drift=True, dry_run=True)[0].run()
    outcome = result.servers[0].policy
    assert outcome.status == "drift"
    assert ('access conditions differ (accessApproval: {"required": true} -> absent; '
            'recording override: true -> false; someFutureField: {"x": 1} -> absent)') in outcome.detail


def test_dual_control_echo_is_not_drift():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    uap.echo_defaults = uap.echo_dual_control = uap.partial_list = True
    result = make(ONE, sia=sia, uap=uap, drift=True)[0].run()
    assert result.servers[0].policy.status == "exists" and calls(uap, "get_policy")
    result = make(ONE, sia=sia, uap=uap, update=True, drift=True)[0].run()
    assert result.servers[0].policy.status == "exists" and not calls(uap, "update_policy")


def test_session_override_echo_is_not_drift():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    uap.echo_defaults = uap.echo_session_overrides = uap.partial_list = True
    result = make(ONE, sia=sia, uap=uap, drift=True)[0].run()
    assert result.servers[0].policy.status == "exists" and calls(uap, "get_policy")
    result = make(ONE, sia=sia, uap=uap, update=True, drift=True)[0].run()
    assert result.servers[0].policy.status == "exists" and not calls(uap, "update_policy")


def test_unverified_readback_diagnostic_renders_values_in_verbose_details():
    result = make(ONE, uap=ApprovalEnforcingUAP())[0].run()
    assert result.servers[0].policy.status == "unverified"
    normal, verbose, verify = io.StringIO(), io.StringIO(), io.StringIO()
    print_summary(result, normal)
    print_summary(result, verbose, verbose=True)
    print_verify(result, verify, verbose=True)
    assert "Technical details" not in normal.getvalue()
    assert "Technical details" in verbose.getvalue() and '"accessApproval"' in verbose.getvalue()
    assert "Technical details" in verify.getvalue()
    reported = result_dict(result)["servers"][0]["policy"]["diagnostic"]["details"]["differences"]["conditions"]
    assert reported["changed"] == ["accessApproval"] and reported["tenant"]["accessApproval"] == {"required": True}
