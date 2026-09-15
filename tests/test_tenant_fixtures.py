"""Recorded tenant policies (tests/fixtures/tenants/*.json) replayed against the tool's own body.

No fixture is committed yet: record one with `show-policy NAME --save tests/fixtures/tenants/<tenant>.json`. Until
then every test here is skipped, which is the honest state of the tool's knowledge of real tenants."""
import json
from pathlib import Path

import pytest

from sia.payloads import APPROVED_CONDITION_KEYS, build_policy
from tests.fakes import FakeUAP, replay_echo
from tests.test_resolve_reconcile import DEFAULTS, ONE, WEB01, WEB_ADMINS_ROLE, calls, make

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "tenants"
FIXTURES = sorted(FIXTURE_DIR.glob("*.json"))
NO_FIXTURES = pytest.mark.skipif(not FIXTURES, reason="no recorded tenant fixture yet: show-policy NAME --save "
                                                        "tests/fixtures/tenants/<tenant>.json")


def recorded(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@NO_FIXTURES
@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_a_tool_built_policy_round_trips_through_the_recorded_echo(path):
    uap = FakeUAP()
    uap.echo_defaults = True
    uap.echo_fixture = recorded(path)
    rec, sia, uap, _ = make(ONE, uap=uap)
    result = rec.run()
    outcome = result.servers[0].policy
    assert outcome.status == "created" and result.failures == 0, f"{path.name}: {outcome.detail}"
    uap.partial_list = True
    again = make(ONE, sia=sia, uap=uap, update=True, drift=True)[0].run()
    assert again.servers[0].policy.status == "exists" and not calls(uap, "update_policy"), f"{path.name}: {again.servers[0].policy.detail}"


@NO_FIXTURES
@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_the_fake_echo_model_covers_every_recorded_condition_key(path):
    fixture_keys = set(recorded(path).get("conditions") or {})
    fake = FakeUAP()
    fake.echo_defaults = fake.echo_dual_control = fake.echo_session_overrides = True
    seed = build_policy(WEB01, [WEB_ADMINS_ROLE], DEFAULTS)
    modelled = set(fake._with_echoed_defaults(json.loads(json.dumps(seed)))["conditions"]) | set(APPROVED_CONDITION_KEYS)
    assert fixture_keys <= modelled, f"{path.name} carries conditions the fake does not model: {sorted(fixture_keys - modelled)}"


def test_replay_echo_copies_the_recording_and_derives_the_override_flags():
    body = build_policy(WEB01, [WEB_ADMINS_ROLE], DEFAULTS)
    recording = {"metadata": {"timeFrame": None},
                 "conditions": {"accessWindow": {"fromHour": None}, "accessApproval": {"required": False, "approvers": []},
                                "overrideIdleTime": False, "overrideRecording": False, "someFutureField": {"x": 1}},
                 "behavior": {"connectAs": {"ssh": None, "rdp": {"domainEphemeralUser": None,
                                                                 "localEphemeralUser": {"assignDomainGroups": []}}}}}
    echoed = replay_echo(json.loads(json.dumps(body)), recording)
    assert echoed["metadata"]["timeFrame"] is None                              # {} was sent; the tenant says null
    assert echoed["conditions"]["idleTime"] == body["conditions"]["idleTime"]   # the tool's values are untouched
    assert echoed["conditions"]["overrideIdleTime"] is True                     # derived from the idleTime that was sent
    assert echoed["conditions"]["someFutureField"] == {"x": 1} and echoed["conditions"]["accessWindow"]["fromHour"] is None
    assert echoed["behavior"]["connectAs"]["ssh"] is None
    assert echoed["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["assignDomainGroups"] == []
    assert echoed["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["assignGroups"] == body["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["assignGroups"]
