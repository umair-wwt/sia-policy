"""Interrupted runs retain evidence and never drain an unbounded write queue."""
import errno
import threading

import pytest

from sia.checkpoint import Checkpoint, CheckpointWriteError
from sia.reconcile import ReconcileError
from sia.report import exit_code, result_dict
from tests.fakes import FakeSIA, FakeUAP
from tests.test_resolve_reconcile import OWNER, calls, inputs, make, srv


def ssh_inputs(count=8):
    return inputs([srv(f"lnx{i:02d}.example.com", None, ["SIA-Linux-Admins"],
                       protocol="ssh", ssh_username="ec2-user") for i in range(count)], [])


def test_parallel_checkpoint_failure_stops_unscheduled_writes_and_retains_inflight(tmp_path):
    third_started = threading.Event()
    checkpoint_failed = threading.Event()

    class Tenant(FakeUAP):
        def create_policy(self, payload):
            name = payload["metadata"]["name"]
            if name == "lnx01.example.com":
                assert third_started.wait(3), "second worker never started"
            if name == "lnx02.example.com":
                third_started.set()
                assert checkpoint_failed.wait(3), "checkpoint failure was not reached"
            return super().create_policy(payload)

    class Disk(Checkpoint):
        def record(self, key, fp, statuses, refs):
            if key.startswith("lnx01."):
                checkpoint_failed.set()
                raise CheckpointWriteError(self.path, key, statuses, refs, OSError(errno.ENOSPC, "disk full"))
            return super().record(key, fp, statuses, refs)

    disk = Disk(tmp_path / "checkpoint.jsonl")
    rec, _, tenant, _ = make(ssh_inputs(), uap=Tenant(), workers=2, checkpoint=disk)
    with pytest.raises(CheckpointWriteError) as raised:
        rec.run()
    result = raised.value.partial_result
    created = calls(tenant, "create_policy")
    assert len(created) == 3
    assert {p["metadata"]["name"] for p in created} == {f"lnx{i:02d}.example.com" for i in range(3)}
    assert all(row.policy.ref for row in result.servers[:3])
    assert all(row.policy.status == "created" for row in result.servers[:3])
    assert all(row.policy.status == "blocked" for row in result.servers[3:])
    assert not any(o.status == "pending" for row in result.servers for o in (row.secret, row.target_set, row.policy))
    assert result.incomplete and not result.interrupted and exit_code(result) == 1
    assert result.diagnostics[0]["mutation_state"] == "applied"
    assert disk.done_count() == 2
    assert result_dict(result)["complete"] is False


def test_interruption_during_write_records_unknown_outcome_and_stops_queue():
    class InterruptedTenant(FakeUAP):
        def create_policy(self, payload):
            super().create_policy(payload)
            raise KeyboardInterrupt

    rec, _, tenant, _ = make(ssh_inputs(), uap=InterruptedTenant(), workers=4)
    with pytest.raises(KeyboardInterrupt) as raised:
        rec.run()
    result = raised.value.partial_result
    assert len(calls(tenant, "create_policy")) == 1
    assert result.servers[0].policy.status == "uncertain"
    assert all(row.policy.status == "blocked" for row in result.servers[1:])
    assert result.interrupted and exit_code(result) == 130
    assert result.diagnostics[0]["mutation_state"] == "unknown"


@pytest.mark.parametrize("lookup", ["list", "search"])
def test_duplicate_policy_names_with_distinct_ids_stop_before_writes(lookup):
    name = "lnx00.example.com"
    policies = [{"metadata": {"name": name, "policyId": pid, "policyTags": [OWNER]}}
                for pid in ("first", "second")]
    rec, sia, tenant, _ = make(ssh_inputs(1), uap=FakeUAP(policies), lookup=lookup)
    with pytest.raises(ReconcileError, match="ambiguous policy"):
        rec.run()
    assert not calls(tenant, "create_policy") and not calls(tenant, "update_policy")
    assert not calls(sia, "create_secret")


def test_duplicate_policy_observations_of_same_id_are_deduplicated():
    policy = {"metadata": {"name": "Case-Policy", "policyId": "same"}}
    rec, *_ = make(ssh_inputs(1))
    assert list(rec._policies_by_name([policy, dict(policy)])) == ["case-policy"]


def test_target_set_conflicting_secret_references_stop_before_writes():
    from tests.test_resolve_reconcile import ONE, VAULT_SIA_NAME, WEB01_FQDN
    tenant = FakeSIA(secrets=[{"secret_name": VAULT_SIA_NAME, "secret_id": "sa1", "secret_type": "PCloudAccount"}],
                     target_sets=[{"name": WEB01_FQDN, "type": "Target", "secret_id": sid} for sid in ("sa1", "sa2")])
    rec, sia, uap, _ = make(ONE, sia=tenant)
    with pytest.raises(ReconcileError, match="ambiguous target set"):
        rec.run()
    assert not calls(sia, "create_secret") and not calls(uap, "create_policy")
