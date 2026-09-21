import io
import json
import logging
import time

import pytest

from sia.checkpoint import Checkpoint, CheckpointWriteError, fingerprint, is_done, row_key
from sia.inputs import ServerRow, StrongAccountRow
from sia.reconcile import Outcome, RunResult, ServerResult
from sia.redact import MASK, RedactingFilter, redact, register_secret, sanitize, secret_count
from sia.report import (ReportWriteError, exit_code, print_summary, print_verify, result_dict, verdict_for,
                        verify_rows, write_reports, write_verify_csv)


# ---------------------------------------------------------------- redact
def test_redact_masks_longest_first_and_short_values_as_complete_tokens():
    register_secret("abc")
    register_secret("x")
    register_secret("abcdef")
    register_secret("abcdefghij")
    assert secret_count() == 4
    assert redact("x abcdefghij y abcdef z abc extra") == f"{MASK} {MASK} y {MASK} z {MASK} extra"
    assert redact("extra example") == "extra example"  # short values do not destroy normal prose
    assert redact("") == "" and redact("nothing here") == "nothing here"
    assert redact("abcdefabcdef") == f"{MASK}{MASK}"


def test_redact_scales_with_many_secrets():
    for i in range(50_000):
        register_secret(f"pw-{i:06d}-secret")
    text = "the password pw-012345-secret leaked " * 10
    started = time.perf_counter()
    for _ in range(20):
        masked = redact(text)
    assert time.perf_counter() - started < 2.0
    assert "pw-012345-secret" not in masked and masked.count(MASK) == 10


def test_logging_filter_redacts_message_and_args():
    register_secret("hunter2-secret")
    stream = io.StringIO()
    logger = logging.getLogger("sia.test.redact")
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        logger.info("token %s in %s", "hunter2-secret", "file hunter2-secret.txt")
    finally:
        logger.removeHandler(handler)
    assert "hunter2-secret" not in stream.getvalue() and MASK in stream.getvalue()


def test_sanitize_recurses_and_masks_sensitive_fields_and_bearer_tokens():
    register_secret("known-value")
    value = {"message": "known-value", "nested": [{"password": "unknown-value"}],
             "header": "Authorization: Bearer not-registered", "secret_status": "exists"}
    clean = sanitize(value)
    assert clean["message"] == MASK and clean["nested"][0]["password"] == MASK
    assert "not-registered" not in clean["header"] and clean["secret_status"] == "exists"


# ---------------------------------------------------------------- report
def result_with(statuses):
    result = RunResult(mode="apply", lookup_mode="list", resumed=1)
    for i, (target, policy) in enumerate(statuses):
        result.servers.append(ServerResult(fqdn=f"s{i}.corp", strong_account="SA", policy_name=f"s{i}.corp",
                                           secret=Outcome("exists", "secret"), target_set=Outcome(target, f"ts {target}", f"s{i}.corp"),
                                           policy=Outcome(policy, f"policy {policy}", f"pol-{i}")))
    result.secrets["SA"] = Outcome("exists", "x")
    result.vault["SA"] = Outcome("created", "onboarded")
    return result


def test_print_summary_caps_large_runs():
    result = result_with([("exists", "exists")] * 5 + [("created", "failed"), ("exists", "drift")])
    out = io.StringIO()
    print_summary(result, out, max_rows=3)
    text = out.getvalue()
    assert "Lookup mode: list" in text and "Resumed from checkpoint: 1 row(s)" in text and "Vault accounts:" in text
    assert "s5.corp" in text and "s6.corp" in text and "s0.corp" not in text and "5 row(s) with nothing to report not shown" in text
    assert "Summary: created=2, drift=1, exists=12, failed=1" in text and "1 item(s) need attention." in text
    out = io.StringIO()
    print_summary(result_with([("exists", "exists")]), out)
    assert "s0.corp" in out.getvalue() and "not shown" not in out.getvalue()


def test_write_reports_thresholds(tmp_path):
    result = result_with([("created", "created"), ("exists", "failed")])
    json_path, csv_path = write_reports(result, tmp_path / "reports", json_max_rows=1)
    data = json.loads(json_path.read_text())
    assert data["rows"] == 2 and data["failures"] == 1 and data["counts"]["failed"] == 1 and data["resumed"] == 1
    assert data["servers"] == "2 rows: see the CSV report" and [s["fqdn"] for s in data["servers_needing_attention"]] == ["s1.corp"]
    assert data["vault_accounts"]["SA"]["status"] == "created"
    lines = csv_path.read_text().splitlines()
    assert lines[0].startswith("fqdn,strong_account,target_set_name,policy_name,secret_status") and len(lines) == 3 and "pol-1" in lines[2]
    json_path, _ = write_reports(result, tmp_path / "reports2")
    assert len(json.loads(json_path.read_text())["servers"]) == 2
    assert exit_code(result) == 1 and exit_code(result_with([("exists", "exists")])) == 0


def test_reports_never_collide_and_wrap_local_io_failures(tmp_path):
    result = result_with([("exists", "exists")])
    first = write_reports(result, tmp_path / "reports")
    second = write_reports(result, tmp_path / "reports")
    assert first != second and all(path.exists() for path in (*first, *second))

    not_a_directory = tmp_path / "blocked"
    not_a_directory.write_text("file")
    with pytest.raises(ReportWriteError) as caught:
        write_reports(result, not_a_directory)
    assert isinstance(caught.value, OSError) and caught.value.path == not_a_directory


def test_verify_verdicts_and_outputs(tmp_path):
    result = result_with([("exists", "exists"), ("planned", "planned"), ("exists", "drift"), ("exists", "inactive"),
                          ("blocked", "blocked"), ("n/a", "created"), ("skipped", "skipped")])
    verdicts = [verdict_for(sr)[0] for sr in result.servers]
    assert verdicts == ["PASS", "MISSING", "FAIL", "FAIL", "FAIL", "PASS", "SKIP"]
    assert verdict_for(result.servers[1])[1] == "target set planned: ts planned"
    out = io.StringIO()
    problems = print_verify(result, out, max_rows=100)
    text = out.getvalue()
    assert problems == 5 and "Verify: FAIL=3, MISSING=1, PASS=2, SKIP=1 (rows=7)" in text and "s1.corp [s1.corp]: MISSING" in text
    rows = verify_rows(result)
    assert rows[0][6] == "PASS" and rows[3][6] == "FAIL" and rows[3][7] == "pol-3"
    path = write_verify_csv(result, tmp_path / "v.csv")
    assert path.read_text().splitlines()[0] == "fqdn,policy_name,strong_account,secret,target_set,policy,verdict,policy_id,detail"
    out = io.StringIO()
    assert print_verify(result_with([("exists", "exists")] * 300), out, max_rows=10) == 0 and "PASS=300" in out.getvalue()


def test_uncertain_and_unverified_are_failed_verdicts():
    result = result_with([("uncertain", "exists"), ("exists", "unverified")])
    assert [verdict_for(row)[0] for row in result.servers] == ["FAIL", "FAIL"]
    diagnostics = result_dict(result)["diagnostics"]
    assert [(item["code"], item["mutation_state"]) for item in diagnostics] == [
        ("SIA-UNCERTAIN", "unknown"), ("SIA-UNVERIFIED", "unknown")]
    assert diagnostics[0]["stage"] == "target sets" and diagnostics[0]["object_name"] == "s0.corp"
    out = io.StringIO()
    print_summary(result, out)
    assert "Troubleshooting:" in out.getvalue() and "What to do next" in out.getvalue()


def test_inactive_policy_help_does_not_call_the_policy_a_strong_account():
    result = result_with([("exists", "inactive")])
    diagnostic = result_dict(result)["diagnostics"][0]
    assert diagnostic["stage"] == "policies"
    assert "set-policy-status Active" in diagnostic["actions"][0]
    assert "strong account" not in " ".join(diagnostic["actions"]).lower()

    result.servers[0].policy.detail = "fields were updated but the existing suspended state was preserved"
    assert result_dict(result)["diagnostics"][0]["mutation_state"] == "applied"


# ------------------------------------------------------------ checkpoint
def test_checkpoint_roundtrip_and_fingerprint(tmp_path):
    server = ServerRow(fqdn="a.corp", strong_account="SA", principals=("G",), policy_name=None, assign_groups=None, domain=None,
                       description=None, line=2)
    account = StrongAccountRow(name="SA", type="vault", safe="S", account_name="a", username=None, account_domain="local",
                               password_env=None, line=3)
    fp = fingerprint(server, account, "a.corp")
    assert fp == fingerprint(ServerRow(**{**vars(server), "line": 99}), StrongAccountRow(**{**vars(account), "line": 1}), "a.corp")
    assert fp != fingerprint(ServerRow(**{**vars(server), "principals": ("G", "H")}), account, "a.corp")
    assert fp != fingerprint(server, None, "a.corp") and fp != fingerprint(server, account, "other")
    cp = Checkpoint(tmp_path / "sub" / "cp.jsonl")
    assert len(cp) == 0 and cp.get(row_key("a.corp", "a.corp"), fp) is None
    cp.record(row_key("a.corp", "a.corp"), fp, {"secret": "created", "target_set": "created", "policy": "failed"},
              {"policy": None, "secret": "s1", "target_set": "a.corp"})
    assert not is_done(cp.get(row_key("a.corp", "a.corp"), fp))
    cp.record(row_key("a.corp", "a.corp"), fp, {"secret": "exists", "target_set": "exists", "policy": "created"},
              {"policy": "p1", "secret": "s1", "target_set": "a.corp"})
    record = cp.get(row_key("a.corp", "a.corp"), fp)
    assert is_done(record) and record["refs"] == {"policy": "p1", "secret": "s1", "target_set": "a.corp"} and cp.done_count() == 1
    assert cp.get(row_key("a.corp", "a.corp"), "other-fingerprint") is None
    (tmp_path / "sub" / "cp.jsonl").open("a").write("not json\n")
    fresh = Checkpoint(tmp_path / "sub" / "cp.jsonl")
    assert len(fresh) == 1 and is_done(fresh.get(row_key("a.corp", "a.corp"), fp))


def test_checkpoint_write_error_retains_completed_object_evidence(tmp_path):
    path = tmp_path / "checkpoint.jsonl"
    path.mkdir()
    checkpoint = Checkpoint(path)
    with pytest.raises(CheckpointWriteError) as caught:
        checkpoint.record("web01.corp|policy", "a" * 64,
                          {"secret": "exists", "target_set": "created", "policy": "updated"},
                          {"secret": "s1", "target_set": "web01.corp", "policy": "p1"})
    exc = caught.value
    assert exc.row_key == "web01.corp|policy" and exc.refs["policy"] == "p1"
    assert exc.statuses["policy"] == "updated" and exc.mutation_state == "applied"


# ---------------------------------------------------------------- accounts-only reports (--accounts)
from sia.reconcile import AccountResult  # noqa: E402
from sia.report import ACCOUNTS_CSV_COLUMNS, ACCOUNT_VERIFY_COLUMNS, account_verify_rows, verdict_for_account  # noqa: E402


def account_result_with(statuses):
    result = RunResult(mode="apply", lookup_mode="list", accounts_only=True)
    for i, (vault, secret) in enumerate(statuses):
        account = AccountResult(name=f"ADM-s{i}", type="credentials", sia_name=f"ADM-s{i}", username="Administrator", address=f"s{i}.corp",
                                vault=Outcome(vault, f"vault {vault}"), secret=Outcome(secret, f"secret {secret}", f"sec-{i}"))
        result.accounts.append(account)
        result.secrets[account.name] = account.secret
        if vault != "n/a":
            result.vault[account.name] = account.vault
    return result


def test_accounts_summary_table_and_totals():
    result = account_result_with([("n/a", "created"), ("n/a", "failed"), ("created", "exists")] + [("n/a", "exists")] * 3)
    out = io.StringIO()
    print_summary(result, out, max_rows=3)
    text = out.getvalue()
    assert "Scope: strong accounts only" in text and "Strong accounts:" in text and "Servers:" not in text
    assert "Account" in text and "SIA status" in text and "Vault accounts:" not in text
    assert "ADM-s0" in text and "ADM-s1" in text and "ADM-s2" in text and "ADM-s5" not in text
    assert "3 account(s) with nothing to report not shown" in text
    assert "ADM-s1: strong account failed — secret failed" in text and "ADM-s2: Vault account created — vault created" in text
    assert "Summary: created=2, exists=4, failed=1" in text and "1 item(s) need attention." in text
    assert result.failures == 1 and exit_code(result) == 1
    out = io.StringIO()
    print_summary(account_result_with([("n/a", "exists")]), out)
    assert "ADM-s0" in out.getvalue() and "not shown" not in out.getvalue() and "Details:" not in out.getvalue()


def test_accounts_reports_json_and_csv(tmp_path):
    result = account_result_with([("n/a", "created"), ("n/a", "failed")])
    data = result_dict(result)
    assert data["scope"] == "accounts" and data["rows"] == 2 and data["failures"] == 1 and data["mode"] == "apply"
    assert data["accounts"][1] == {"name": "ADM-s1", "type": "credentials", "sia_name": "ADM-s1", "username": "Administrator",
                                   "address": "s1.corp", "vault_status": "n/a", "vault_detail": "vault n/a",
                                   "secret_status": "failed", "secret_detail": "secret failed", "secret_id": "sec-1"}
    json_path, csv_path = write_reports(result, tmp_path / "reports")
    assert json_path.name.startswith("apply-accounts-") and csv_path.name.startswith("apply-accounts-")
    lines = csv_path.read_text().splitlines()
    assert lines[0] == ",".join(ACCOUNTS_CSV_COLUMNS) and len(lines) == 3
    assert lines[2] == "ADM-s1,credentials,ADM-s1,Administrator,s1.corp,n/a,vault n/a,failed,secret failed,sec-1"
    server = result_with([("exists", "exists")])
    assert result_dict(server)["scope"] == "servers" and result_dict(server)["accounts"] == []
    _, server_csv = write_reports(server, tmp_path / "reports2")
    assert server_csv.name.startswith("apply-2") and server_csv.read_text().splitlines()[0].startswith("fqdn,strong_account")
    data = result_dict(account_result_with([("n/a", "exists")] * 3), json_max_rows=2)
    assert data["accounts"] == "3 accounts: see the CSV report" and data["accounts_needing_attention"] == []


def test_account_verdicts_and_verify_output(tmp_path):
    cases = {("n/a", "exists"): "PASS", ("n/a", "created"): "PASS", ("n/a", "planned"): "MISSING", ("n/a", "inactive"): "FAIL",
             ("failed", "blocked"): "FAIL", ("n/a", "skipped"): "SKIP", ("n/a", "uncertain"): "FAIL", ("n/a", "unverified"): "FAIL",
             ("created", "exists"): "PASS", ("planned", "planned"): "MISSING"}
    for (vault, secret), expected in cases.items():
        ar = AccountResult(name="a", type="vault", sia_name="a", username="u", address="h", vault=Outcome(vault, "v"), secret=Outcome(secret, "s"))
        assert verdict_for_account(ar) == (expected, "" if expected == "PASS" else verdict_for_account(ar)[1])
    blocked = AccountResult(name="a", type="vault", sia_name="a", username="u", address="h",
                            vault=Outcome("failed", "no password"), secret=Outcome("blocked", "x"))
    assert verdict_for_account(blocked) == ("FAIL", "Vault account failed: no password")
    result = account_result_with([("n/a", "exists"), ("n/a", "planned"), ("n/a", "inactive"), ("n/a", "skipped")])
    out = io.StringIO()
    problems = print_verify(result, out)
    text = out.getvalue()
    assert problems == 3 and "Scope: strong accounts only" in text and "Verdict" in text and "SIA status" in text
    assert "ADM-s1 [ADM-s1]: MISSING — strong account planned: secret planned" in text
    assert "Verify: FAIL=1, MISSING=1, PASS=1, SKIP=1 (accounts=4)" in text
    rows = account_verify_rows(result)
    assert rows[2][7] == "FAIL" and rows[2][8] == "sec-2" and rows[0][7] == "PASS"
    path = write_verify_csv(result, tmp_path / "verify.csv")
    assert path.read_text().splitlines()[0] == ",".join(ACCOUNT_VERIFY_COLUMNS)


def test_account_reports_are_redacted():
    register_secret("hunter2-pw")
    result = account_result_with([("n/a", "failed")])
    result.accounts[0].secret.detail = "create failed: password hunter2-pw rejected"
    out = io.StringIO()
    print_summary(result, out)
    assert "hunter2-pw" not in out.getvalue() and MASK in out.getvalue()
    assert "hunter2-pw" not in json.dumps(result_dict(result))
    out = io.StringIO()
    print_verify(result, out)
    assert "hunter2-pw" not in out.getvalue()
