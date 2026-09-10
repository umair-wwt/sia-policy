"""Older success records must not bypass strengthened tenant verification."""
import json

from sia.checkpoint import CHECKPOINT_VERSION, Checkpoint
from tests.test_resolve_reconcile import ONE, calls, make


def test_version_two_checkpoint_is_preserved_and_rechecked(tmp_path):
    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    rec, sia, uap, _ = make(ONE, checkpoint=checkpoint)
    assert rec.run().failures == 0
    record = json.loads(checkpoint.path.read_text())
    record["version"] = 2
    legacy = json.dumps(record) + "\n"
    checkpoint.path.write_text(legacy)
    # The old completion record says success, but the tenant grants another role.
    uap.policies[0]["principals"][0]["id"] = "different-role"
    current = Checkpoint(checkpoint.path)
    before = len(calls(uap, "list_policies"))
    result = make(ONE, sia=sia, uap=uap, dry_run=True, resume=True, checkpoint=current)[0].run()
    assert result.resumed == 0 and result.servers[0].policy.status == "drift"
    assert len(calls(uap, "list_policies")) > before
    assert any("unsupported checkpoint version 2" in warning for warning in result.warnings)
    assert current.done_count() == 0
    assert checkpoint.path.read_text() == legacy


def test_rechecked_row_appends_version_three_and_can_resume(tmp_path):
    checkpoint = Checkpoint(tmp_path / "checkpoint.jsonl")
    rec, sia, uap, _ = make(ONE, checkpoint=checkpoint)
    assert rec.run().failures == 0
    record = json.loads(checkpoint.path.read_text())
    record["version"] = 2
    legacy = json.dumps(record) + "\n"
    checkpoint.path.write_text(legacy)
    current = Checkpoint(checkpoint.path)
    result = make(ONE, sia=sia, uap=uap, resume=True, checkpoint=current)[0].run()
    assert result.resumed == 0 and result.failures == 0
    records = [json.loads(line) for line in checkpoint.path.read_text().splitlines()]
    assert [item["version"] for item in records] == [2, CHECKPOINT_VERSION]
    assert CHECKPOINT_VERSION == 3 and current.done_count() == 1
    assert checkpoint.path.read_text().startswith(legacy)

    before = (len(sia.calls), len(uap.calls))
    resumed = make(ONE, sia=sia, uap=uap, resume=True, checkpoint=Checkpoint(checkpoint.path), lookup="search")[0].run()
    assert resumed.resumed == 1 and resumed.failures == 0
    assert (len(sia.calls), len(uap.calls)) == before
