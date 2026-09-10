"""Read-back retries and malformed values cannot turn an unverified write into success."""
from copy import deepcopy
from dataclasses import replace

import pytest

from sia.checkpoint import Checkpoint
from sia.http import SIAApiError
from tests.fakes import FakeSIA, FakeUAP
from tests.test_resolve_reconcile import DEFAULTS, ONE, calls, make


@pytest.mark.parametrize("failed_reads", [1, 2])
def test_policy_readback_retries_reads_without_repeating_the_write(tmp_path, failed_reads):
    class UnavailableReads(FakeUAP):
        read_count = 0

        def get_policy(self, policy_id):
            self.read_count += 1
            if self.read_count <= failed_reads:
                raise SIAApiError("GET", "/api/policies/" + policy_id, 503, "temporarily unavailable")
            return super().get_policy(policy_id)

    tenant = UnavailableReads()
    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    result = make(ONE, uap=tenant, status_polls=2, checkpoint=checkpoint)[0].run()
    outcome = result.servers[0].policy
    assert tenant.read_count == 2
    assert len(calls(tenant, "create_policy")) == 1 and not calls(tenant, "update_policy")
    if failed_reads == 1:
        assert outcome.status == "created" and checkpoint.done_count() == 1
    else:
        assert outcome.status == "unverified" and checkpoint.done_count() == 0
        assert outcome.ref == "pol-1" and outcome.diagnostic["mutation_state"] == "applied"


@pytest.mark.parametrize(("field", "value"), [
    ("status", ["Active"]), ("status", 7), ("status", False), ("policyId", "different-policy"),
])
def test_policy_readback_rejects_malformed_status_or_wrong_object(tmp_path, field, value):
    class MalformedReadback(FakeUAP):
        def get_policy(self, policy_id):
            policy = super().get_policy(policy_id)
            policy["metadata"][field] = value
            return policy

    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    result = make(ONE, uap=MalformedReadback(), checkpoint=checkpoint)[0].run()
    outcome = result.servers[0].policy
    assert outcome.status == "unverified" and outcome.ref == "pol-1"
    assert "malformed policy object" in outcome.detail
    assert outcome.diagnostic["mutation_state"] == "applied"
    assert result.failures == 1 and checkpoint.done_count() == 0


@pytest.mark.parametrize("key", ["enable_certificate_validation", "enableCertificateValidation"])
@pytest.mark.parametrize("value", ["false", "true", 1])
def test_target_readback_rejects_non_boolean_certificate_settings(tmp_path, key, value):
    seed, original, uap, _ = make(ONE)
    assert seed.run().failures == 0

    class MalformedReadback(FakeSIA):
        updated = False

        def update_target_set(self, name, payload):
            result = super().update_target_set(name, payload)
            self.updated = True
            return result

        def list_target_sets(self, **kwargs):
            rows = super().list_target_sets(**kwargs)
            if self.updated:
                for row in rows:
                    row.pop("enable_certificate_validation", None)
                    row[key] = value
            return rows

    sia = MalformedReadback(deepcopy(original.secrets), deepcopy(original.target_sets))
    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    defaults = replace(DEFAULTS, target_set_cert_validation=True)
    result = make(ONE, sia=sia, uap=uap, defaults=defaults, update=True, checkpoint=checkpoint)[0].run()
    outcome = result.servers[0].target_set
    assert outcome.status == "unverified" and outcome.ref == ONE.servers[0].fqdn
    assert "malformed target-set object" in outcome.detail
    assert outcome.diagnostic["mutation_state"] == "applied"
    assert len(calls(sia, "update_target_set")) == 1 and checkpoint.done_count() == 0
