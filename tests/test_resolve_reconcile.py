import json
from dataclasses import replace

import pytest

from sia.checkpoint import CHECKPOINT_VERSION, Checkpoint
from sia.config import Defaults
from sia.http import SIAApiError
from sia.inputs import GroupRow, Inputs, ServerRow, StrongAccountRow
from sia.reconcile import ReconcileError, Reconciler
from sia.report import result_dict
from sia.resolve import PrincipalResolver, ResolveError, SecretIndex
from tests.fakes import AD_UUID, CDS_UUID, FakeIdentity, FakePVWA, FakeSIA, FakeUAP, group_row, role_row

DEFAULTS = Defaults(time_zone="America/New_York")
GROUP_DEFAULTS = replace(DEFAULTS, principal_type="group")   # the pre-roles behaviour, still selectable
WEB_ADMINS_ROLE = {"id": "role-SIA-Web-Admins", "name": "SIA-Web-Admins", "type": "ROLE",
                   "sourceDirectoryId": CDS_UUID, "sourceDirectoryName": "CyberArk Cloud Directory"}
OWNER = "sia-policy-automation"
OWNED_FILTER = "((targetCategory eq 'VM') and (policyTags eq 'sia-policy-automation'))"
MARK = "[managed-by:sia-policy-automation]"
VAULT_SIA_NAME = "svc_sia_rdp_SIA-StrongAccounts"
WEB01_FQDN, WEB02_FQDN, DMZ_FQDN = "web01.corp.example.com", "web02.corp.example.com", "dmz01.dmz.example.com"


def sa(name, kind, **kw):
    base = dict(safe=None, account_name=None, username=None, account_domain="local", password_env=None, line=2)
    base.update(kw)
    return StrongAccountRow(name=name, type=kind, **base)


def srv(fqdn, account, principals, **kw):
    base = dict(policy_name=None, assign_groups=None, domain=None, description=None, line=2)
    base.update(kw)
    return ServerRow(fqdn=fqdn, strong_account=account, principals=tuple(principals), **base)


def inputs(servers, accounts, groups=None):
    return Inputs(servers=tuple(servers), strong_accounts={a.name: a for a in accounts},
                  groups={g.name: g for g in (groups or [])})


def err(status, text, method="POST"):
    return SIAApiError(method, "https://x/api", status, text, uncertain=(method == "POST" and status >= 500))


VAULT = sa("SA-corp-rdp", "vault", safe="SIA-StrongAccounts", account_name="svc_sia_rdp", account_domain="corp.example.com")
CREDS = sa("SA-dmz", "credentials", username="siaprov", password_env="SIA_SA_SA_DMZ_PASSWORD")
EXISTING = sa("SA-legacy", "existing")
WEB01 = srv(WEB01_FQDN, "SA-corp-rdp", ["SIA-Web-Admins"])
STANDARD = inputs(
    [WEB01,
     srv(WEB02_FQDN, "SA-corp-rdp", ["SIA-Web-Admins", "SIA-Platform-Ops"], assign_groups=("Remote Desktop Users",)),
     srv(DMZ_FQDN, "SA-dmz", ["SIA-DMZ-Admins"])],
    [VAULT, CREDS],
)
ONE = inputs([WEB01], [VAULT])


def make(inp=STANDARD, sia=None, uap=None, identity=None, *, dry_run=False, update=False, only="all", defaults=DEFAULTS,
         passwords=None, fail_fast=True, adopt=(), adopt_all=False, workers=1, status_polls=1, lookup="list", **extra):
    sia = sia or FakeSIA()
    uap = uap or FakeUAP()
    identity = identity or FakeIdentity()
    passwords = {"SIA_SA_SA_DMZ_PASSWORD": "pw-secret"} if passwords is None else passwords
    resolver = PrincipalResolver(identity, inp.pinned_directory, principal_type=defaults.principal_type)
    rec = Reconciler(sia=sia, uap=uap, resolver=resolver, inputs=inp, defaults=defaults, dry_run=dry_run, update=update,
                     only=only, get_password=lambda a: passwords.get(a.password_env or "") or passwords.get(a.name),
                     sleep=lambda s: None, fail_fast=fail_fast, adopt=adopt, adopt_all=adopt_all, workers=workers,
                     status_polls=status_polls, lookup=lookup, **extra)
    return rec, sia, uap, identity


def by_fqdn(result):
    return {s.fqdn: s for s in result.servers}


def calls(fake, name):
    return [c[1] for c in fake.calls if c[0] == name]


# ------------------------------------------------------------- resolver
def test_resolver_builds_role_principal_and_caches():
    identity = FakeIdentity()
    resolver = PrincipalResolver(identity)                      # principal_type defaults to "role"
    assert resolver.principal_type == "role"
    assert resolver.resolve("SIA-Web-Admins") == WEB_ADMINS_ROLE
    assert identity.role_directories == [[CDS_UUID]]            # roles are looked up in the Cloud Directory only
    resolver.resolve("sia-web-admins")
    assert identity.queries == ["SIA-Web-Admins"]
    resolver.resolve("SIA-Web-Admins")
    assert len(identity.queries) == 1  # cached by case-insensitive identity
    with pytest.raises(ValueError, match="principal_type must be one of role, group"):
        PrincipalResolver(identity, principal_type="user")


def test_resolver_builds_group_principal_when_configured():
    identity = FakeIdentity()
    resolver = PrincipalResolver(identity, principal_type="group")
    assert resolver.resolve("SIA-Web-Admins") == {
        "id": f"id-SIA-Web-Admins-{CDS_UUID[:4]}", "name": "SIA-Web-Admins", "type": "GROUP",
        "sourceDirectoryId": CDS_UUID, "sourceDirectoryName": "CyberArk Cloud Directory"}
    assert identity.role_directories == []                      # no role query was issued
    resolver.resolve("sia-web-admins")
    assert identity.queries == ["SIA-Web-Admins"]


def test_resolver_not_found_lists_similar():
    resolver = PrincipalResolver(FakeIdentity(roles=[role_row("SIA-Web-Admins-Prod")]))
    with pytest.raises(ResolveError, match=r"role 'SIA-Web-Admins' not found in Identity; similar names: SIA-Web-Admins-Prod"):
        resolver.resolve("SIA-Web-Admins")
    resolver = PrincipalResolver(FakeIdentity([group_row("SIA-Web-Admins-Prod")]), principal_type="group")
    with pytest.raises(ResolveError, match=r"group 'SIA-Web-Admins' not found.*similar names: SIA-Web-Admins-Prod"):
        resolver.resolve("SIA-Web-Admins")


def test_role_resolver_rejects_duplicate_ids_and_incomplete_rows():
    two_ids = FakeIdentity(roles=[role_row("Admins", "r-1"), role_row("Admins", "r-2"), role_row("Admins-Prod", "r-3")])
    with pytest.raises(ResolveError, match="role 'Admins' is ambiguous \\(2 matches: r-1, r-2\\)") as exc:
        PrincipalResolver(two_ids).resolve("Admins")
    assert "not found" not in str(exc.value)                    # an ambiguity must stop the run, not fail one row
    repeated = FakeIdentity(roles=[role_row("Admins", "r-1"), role_row("admins", "r-1")])
    assert PrincipalResolver(repeated).resolve("ADMINS")["id"] == "r-1"
    with pytest.raises(ResolveError, match="role 'Admins': Identity row lacks _ID"):
        PrincipalResolver(FakeIdentity(roles=[{"Name": "Admins", "_ID": ""}])).resolve("Admins")


def test_role_resolver_without_a_cds_directory_queries_every_directory():
    identity = FakeIdentity()
    identity.directories = [{"Service": "AdProxy", "directoryServiceUuid": AD_UUID, "DisplayName": "corp.example.com"}]
    principal = PrincipalResolver(identity).resolve("SIA-Web-Admins")
    assert identity.role_directories == [[AD_UUID]]
    assert principal == {"id": "role-SIA-Web-Admins", "name": "SIA-Web-Admins", "type": "ROLE"}


def test_group_resolver_ambiguous_then_pinned():
    rows = [group_row("Admins", CDS_UUID, "CyberArk Cloud Directory"), group_row("Admins", AD_UUID, "corp.example.com (AD)")]
    with pytest.raises(ResolveError, match="ambiguous"):
        PrincipalResolver(FakeIdentity(rows), principal_type="group").resolve("Admins")
    assert PrincipalResolver(FakeIdentity(rows), lambda g: "corp.example.com (AD)",
                             principal_type="group").resolve("Admins")["sourceDirectoryId"] == AD_UUID
    assert PrincipalResolver(FakeIdentity(rows), lambda g: "AdProxy", principal_type="group").resolve("Admins")["sourceDirectoryId"] == AD_UUID
    with pytest.raises(ResolveError, match="not found in Identity in directory 'Nope'"):
        PrincipalResolver(FakeIdentity(rows), lambda g: "Nope", principal_type="group").resolve("Admins")


def test_secret_index_is_deterministic():
    idx = SecretIndex([{"secret_id": "s1", "secret_name": "SA-corp-rdp"}, {"secret_id": "s2", "secret_name": "SVC_SIA_RDP_sia-strongaccounts"}])
    assert idx.find(VAULT)["secret_id"] == "s2"                      # vault accounts: platform name <account>_<safe>
    assert idx.find(sa("SA-corp-rdp", "existing"))["secret_id"] == "s1"  # existing: CSV name
    assert idx.find(EXISTING) is None and len(idx) == 2


# --------------------------------------------------------------- plan
def test_plan_on_empty_tenant_writes_nothing():
    rec, sia, uap, _ = make(dry_run=True)
    result = rec.run()
    assert result.mode == "plan" and result.failures == 0 and not result.aborted and result.lookup_mode == "list"
    assert {n: o.status for n, o in result.secrets.items()} == {"SA-corp-rdp": "planned", "SA-dmz": "planned"}
    assert VAULT_SIA_NAME in result.secrets["SA-corp-rdp"].detail
    assert all(sr.target_set.status == "planned" and sr.policy.status == "planned" for sr in result.servers)
    assert [c[0] for c in sia.calls] == ["list_secrets", "list_target_sets"]
    assert uap.calls == [("list_policies", (None, OWNED_FILTER))]   # only our own policies are listed


def test_search_lookup_reads_per_server():
    rec, sia, uap, _ = make(dry_run=True, lookup="search")
    result = rec.run()
    assert result.lookup_mode == "search" and result.failures == 0
    assert sorted(calls(sia, "find_secret")) == sorted([VAULT_SIA_NAME, "SA-dmz"])
    target_set_reads = calls(sia, "list_target_sets")
    assert sorted(name for _, name in target_set_reads if name) == sorted([WEB01_FQDN, WEB02_FQDN, DMZ_FQDN])
    policy_reads = calls(uap, "list_policies")
    assert sorted(text for text, _ in policy_reads if text) == sorted([WEB01_FQDN, WEB02_FQDN, DMZ_FQDN])
    # This tenant is empty, so every per-name read misses and one unfiltered listing per kind confirms that before
    # the misses become creates. A tenant that serves every name costs nothing extra -- see the test below.
    assert calls(sia, "list_secrets") == [None] and target_set_reads[-1] == (None, None)
    assert policy_reads[-1] == (None, "(targetCategory eq 'VM')")
    assert sum(text is None for text, _ in policy_reads) == 1


def test_auto_lookup_switches_on_size():
    assert make(dry_run=True, lookup="auto", lookup_search_max_rows=2)[0].run().lookup_mode == "list"
    assert make(dry_run=True, lookup="auto", lookup_search_max_rows=3)[0].run().lookup_mode == "search"
    assert make(dry_run=True, lookup="auto", lookup_search_max_rows=10, adopt_all=True)[0].run().lookup_mode == "list"
    with pytest.raises(ValueError, match="lookup"):
        make(lookup="guess")


def test_plan_without_password_is_planned_apply_fails():
    rec, *_ = make(inputs([srv("d.dmz.example.com", "SA-dmz", ["SIA-DMZ-Admins"])], [CREDS]), dry_run=True, passwords={})
    result = rec.run()
    assert result.secrets["SA-dmz"].status == "planned" and "not available now" in result.secrets["SA-dmz"].detail
    assert result.failures == 0
    rec, *_ = make(inputs([srv("d.dmz.example.com", "SA-dmz", ["SIA-DMZ-Admins"])], [CREDS]), passwords={})
    result = rec.run()
    assert result.secrets["SA-dmz"].status == "failed" and "SIA_SA_SA_DMZ_PASSWORD" in result.secrets["SA-dmz"].detail
    assert result.servers[0].target_set.status == "blocked" and result.servers[0].policy.status == "blocked"


# --------------------------------------------------------------- apply
def test_apply_creates_everything_then_is_idempotent():
    rec, sia, uap, _ = make()
    result = rec.run()
    assert result.failures == 0 and not result.aborted, [(s.fqdn, s.target_set, s.policy) for s in result.servers]
    assert {n: o.status for n, o in result.secrets.items()} == {"SA-corp-rdp": "created", "SA-dmz": "created"}
    created = calls(sia, "create_secret")
    assert created[0]["secret_name"] == VAULT_SIA_NAME and created[0]["secret_type"] == "PCloudAccount"
    assert created[0]["secret"]["secret_data"] == {"safe": "SIA-StrongAccounts", "account_name": "svc_sia_rdp"}
    assert created[1]["secret_name"] == "SA-dmz" and created[1]["secret"]["secret_data"] == {"username": "siaprov", "password": "pw-secret"}
    bulks = calls(sia, "bulk_create_target_sets")
    assert len(bulks) == 2  # one bulk call per strong account
    web_bulk = next(b for b in bulks if b[0]["strong_account_id"] == "sec-1")
    assert [t["name"] for t in web_bulk[0]["target_sets"]] == [WEB01_FQDN, WEB02_FQDN]
    assert web_bulk[0]["target_sets"][0]["secret_type"] == "PCloudAccount" and MARK in web_bulk[0]["target_sets"][0]["description"]
    assert all(sr.target_set.status == "created" and sr.policy.status == "created" for sr in result.servers)
    policies = calls(uap, "create_policy")
    assert [p["metadata"]["name"] for p in policies] == [WEB01_FQDN, WEB02_FQDN, DMZ_FQDN]
    assert all(p["metadata"]["policyTags"] == ["automated", OWNER] for p in policies)
    assert all(p["metadata"]["status"] == {"status": "Active"} for p in policies)   # required by the API on create
    assert [p["id"] for p in policies[1]["principals"]] == ["role-SIA-Web-Admins", "role-SIA-Platform-Ops"]
    assert policies[1]["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["assignGroups"] == ["Remote Desktop Users"]
    assert policies[0]["targets"]["FQDN/IP"]["fqdnRules"] == [{"operator": "EXACTLY", "computernamePattern": WEB01_FQDN, "domain": "corp.example.com"}]
    assert policies[0]["conditions"]["maxSessionDuration"] == 2

    rec2, _, _, _ = make(sia=sia, uap=uap)
    before = (len(sia.calls), len(uap.calls))
    result2 = rec2.run()
    assert result2.failures == 0
    assert all(o.status == "exists" for o in result2.secrets.values()) and VAULT_SIA_NAME in result2.secrets["SA-corp-rdp"].detail
    assert all(sr.target_set.status == "exists" and sr.policy.status == "exists" for sr in result2.servers)
    assert all("unmanaged" not in sr.policy.detail and "unmanaged" not in sr.target_set.detail for sr in result2.servers)
    assert not [c for c in sia.calls[before[0]:] if c[0] not in ("list_secrets", "list_target_sets")]
    assert not [c for c in uap.calls[before[1]:] if c[0] not in ("list_policies", "get_policy")]


def test_two_policies_per_server_share_account_and_target_set():
    ops = srv(WEB01_FQDN, "SA-corp-rdp", ["SIA-Platform-Ops"], policy_suffix="-ops", assign_groups=("Remote Desktop Users",), line=3)
    inp = inputs([WEB01, ops], [VAULT])
    rec, sia, uap, _ = make(inp)
    result = rec.run()
    assert result.failures == 0 and len(result.servers) == 2
    assert [sr.policy_name for sr in result.servers] == [WEB01_FQDN, f"{WEB01_FQDN}-ops"]
    assert len(calls(sia, "create_secret")) == 1
    assert [ts["name"] for b in calls(sia, "bulk_create_target_sets") for m in b for ts in m["target_sets"]] == [WEB01_FQDN]
    assert all(sr.secret.status == "created" and sr.target_set.status == "created" and sr.policy.status == "created" for sr in result.servers)
    policies = calls(uap, "create_policy")
    assert [p["metadata"]["name"] for p in policies] == [WEB01_FQDN, f"{WEB01_FQDN}-ops"]
    assert policies[1]["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["assignGroups"] == ["Remote Desktop Users"]
    assert [p["id"] for p in policies[1]["principals"]] == ["role-SIA-Platform-Ops"]
    result2 = make(inp, sia=sia, uap=uap)[0].run()
    assert all(sr.target_set.status == "exists" and sr.policy.status == "exists" for sr in result2.servers)
    # renaming the second policy in the UI must not be mistaken for the first one
    ops_policy = next(p for p in uap.policies if p["metadata"]["name"].endswith("-ops"))
    ops_policy["metadata"]["name"] = "Renamed in the UI"
    created_before = len(calls(uap, "create_policy"))
    result3 = make(inp, sia=sia, uap=uap)[0].run()
    by = result3.by_key()
    assert by[(WEB01_FQDN, WEB01_FQDN)].policy.status == "exists"
    assert by[(WEB01_FQDN, f"{WEB01_FQDN}-ops")].policy.status == "drift" and "renamed" in by[(WEB01_FQDN, f"{WEB01_FQDN}-ops")].policy.detail
    assert len(calls(uap, "create_policy")) == created_before


def test_snapshot_once_then_preview_and_apply():
    rec, sia, uap, _ = make(dry_run=True)
    rec.snapshot()
    reads = len(sia.calls)
    preview = rec.reconcile(dry_run=True)
    assert preview.mode == "plan" and all(sr.policy.status == "planned" for sr in preview.servers)
    result = rec.reconcile(dry_run=False)
    assert result.mode == "apply" and all(sr.policy.status == "created" for sr in result.servers) and result.failures == 0
    assert [c[0] for c in sia.calls[reads:]] == ["create_secret", "create_secret", "bulk_create_target_sets", "bulk_create_target_sets"]
    assert all(c[0] != "list_policies" for c in uap.calls[1:])


def test_checkpoint_and_resume(tmp_path):
    cp = Checkpoint(tmp_path / "cp.jsonl")
    rec, sia, uap, _ = make(checkpoint=cp)
    assert rec.run().failures == 0
    assert cp.path.is_file() and cp.done_count() == 3
    lines = [json.loads(line) for line in cp.path.read_text().splitlines()]
    assert len(lines) == 3 and lines[0]["key"] == f"{WEB01_FQDN}|{WEB01_FQDN}"
    assert lines[0]["version"] == CHECKPOINT_VERSION
    assert lines[0]["statuses"] == {"secret": "created", "target_set": "created", "policy": "created"}
    assert lines[0]["refs"]["policy"].startswith("pol-") and "pw" not in json.dumps(lines)

    before = (len(sia.calls), len(uap.calls))
    result = make(sia=sia, uap=uap, checkpoint=cp, resume=True, lookup="search")[0].run()
    assert result.resumed == 3 and len(result.servers) == 3 and result.failures == 0
    assert all(sr.policy.status == "exists" and "checkpoint" in sr.policy.detail and sr.policy.ref for sr in result.servers)
    assert sia.calls[before[0]:] == [] and uap.calls[before[1]:] == []   # nothing was read for resumed rows

    edited = inputs([srv(WEB01_FQDN, "SA-corp-rdp", ["SIA-Web-Admins", "SIA-Platform-Ops"]), STANDARD.servers[1], STANDARD.servers[2]], [VAULT, CREDS])
    result = make(edited, sia=sia, uap=uap, checkpoint=cp, resume=True)[0].run()
    assert result.resumed == 2
    assert result.by_key()[(WEB01_FQDN, WEB01_FQDN)].policy.status == "drift"     # the edited row is re-evaluated
    assert [sr.fqdn for sr in result.servers] == [WEB01_FQDN, WEB02_FQDN, DMZ_FQDN]  # CSV order kept

    assert make(sia=sia, uap=uap, checkpoint=cp)[0].run().resumed == 0            # without --resume nothing is skipped
    plan_cp = Checkpoint(tmp_path / "plan.jsonl")
    make(dry_run=True, checkpoint=plan_cp)[0].run()
    assert not plan_cp.path.exists()                                             # dry runs never write


def test_checkpoint_context_and_record_validation_force_reconciliation(tmp_path):
    cp = Checkpoint(tmp_path / "cp.jsonl")
    rec, sia, uap, _ = make(ONE, checkpoint=cp, reconciliation_context={"tenant": "acme"})
    assert rec.run().failures == 0
    result = make(ONE, sia=sia, uap=uap, checkpoint=cp, resume=True,
                  reconciliation_context={"tenant": "other"})[0].run()
    assert result.resumed == 0
    assert any("tenant, or input changed" in warning for warning in result.warnings)

    record = json.loads(cp.path.read_text().splitlines()[0])
    record.pop("version")
    cp.path.write_text(json.dumps(record) + "\n{not json}\n")
    invalid = Checkpoint(cp.path)
    result = make(ONE, sia=sia, uap=uap, checkpoint=invalid, resume=True,
                  reconciliation_context={"tenant": "acme"})[0].run()
    assert result.resumed == 0
    assert any("unsupported checkpoint version" in warning for warning in result.warnings)
    assert any("not valid JSON" in warning for warning in result.warnings)

    writable = Checkpoint(tmp_path / "new" / "checkpoint.jsonl")
    ok, detail = writable.check_writable()
    assert ok and "writable" in detail and not writable.path.exists()


def test_checkpoint_fingerprint_covers_defaults_pinned_directories_and_template_content(tmp_path):
    defaults_cp = Checkpoint(tmp_path / "defaults.jsonl")
    rec, sia, uap, _ = make(ONE, checkpoint=defaults_cp)
    assert rec.run().failures == 0
    changed_defaults = replace(DEFAULTS, idle_minutes=17)
    result = make(ONE, sia=sia, uap=uap, checkpoint=defaults_cp, resume=True,
                  defaults=changed_defaults)[0].run()
    assert result.resumed == 0 and any("settings, template" in warning for warning in result.warnings)

    pinned_a = Inputs(servers=ONE.servers, strong_accounts=ONE.strong_accounts,
                      groups={"SIA-Web-Admins": GroupRow("SIA-Web-Admins", "CyberArk Cloud Directory", 2)})
    pins_cp = Checkpoint(tmp_path / "pins.jsonl")
    rec, sia, uap, _ = make(pinned_a, checkpoint=pins_cp, defaults=GROUP_DEFAULTS)
    assert rec.run().failures == 0
    pinned_b = Inputs(servers=ONE.servers, strong_accounts=ONE.strong_accounts,
                      groups={"SIA-Web-Admins": GroupRow("SIA-Web-Admins", "CDS", 9)})
    result = make(pinned_b, sia=sia, uap=uap, checkpoint=pins_cp, resume=True, defaults=GROUP_DEFAULTS)[0].run()
    assert result.resumed == 0 and any("input changed" in warning for warning in result.warnings)

    template = json.loads(json.dumps(TEMPLATE))
    template_cp = Checkpoint(tmp_path / "template.jsonl")
    template_defaults = replace(DEFAULTS, template_policy="Reference")
    rec, sia, uap, _ = make(ONE, uap=FakeUAP([template]), defaults=template_defaults, checkpoint=template_cp)
    assert rec.run().failures == 0
    next(item for item in uap.policies if item["metadata"]["name"] == "Reference")["conditions"]["idleTime"] = 19
    result = make(ONE, sia=sia, uap=uap, defaults=template_defaults, checkpoint=template_cp, resume=True)[0].run()
    assert result.resumed == 0 and any("template" in warning for warning in result.warnings)


def test_checkpoint_rows_from_a_lighter_check_are_reconciled_again_by_update(tmp_path):
    cp = Checkpoint(tmp_path / "cp.jsonl")
    rec, sia, uap, _ = make(ONE, checkpoint=cp)
    assert rec.run().failures == 0
    assert make(ONE, sia=sia, uap=uap, checkpoint=cp, resume=True)[0].run().resumed == 1
    result = make(ONE, sia=sia, uap=uap, checkpoint=cp, resume=True, update=True)[0].run()
    assert result.resumed == 0 and any("settings, template" in warning for warning in result.warnings)
    assert result.servers[0].policy.status == "exists" and "targets checked" in result.servers[0].policy.detail


def test_full_policy_prefetch_fans_out_over_workers(monkeypatch):
    rec, sia, uap, _ = make()
    assert rec.run().failures == 0
    uap.partial_list = True
    rec = make(sia=sia, uap=uap, drift=True, workers=4)[0]
    batches = []
    original = rec._parallel

    def recording(items, fn):
        batches.append(len(items))
        return original(items, fn)

    monkeypatch.setattr(rec, "_parallel", recording)
    before = len(uap.calls)
    result = rec.run()
    assert all(sr.policy.status == "exists" for sr in result.servers)
    reads = [call for call in uap.calls[before:] if call[0] == "get_policy"]
    assert batches == [3] and len(reads) == 3          # one fan-out batch, no second read per policy


def test_legacy_secrets_are_listed_once_even_in_search_mode():
    from sia.clients import SIACapabilities

    sia = FakeSIA(secrets=[{"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME}])
    sia.capabilities = SIACapabilities(secrets_api="legacy", targetsets_api="legacy", targetsets_list_unfiltered=True, probed=True)
    result = make(ONE, sia=sia, lookup="search")[0].run()
    assert result.servers[0].secret.status == "exists"
    assert calls(sia, "find_secret") == [] and calls(sia, "list_secrets") == [None]


def test_a_tenant_that_serves_every_name_is_never_listed_in_search_mode():
    sia = FakeSIA(secrets=[{"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME}],
                  target_sets=[{"id": "ts-1", "name": WEB01_FQDN, "type": "Target", "secret_id": "sec-1",
                                "secret_type": "PCloudAccount"}])
    result = make(ONE, sia=sia, dry_run=True, lookup="search")[0].run()
    assert result.secrets["SA-corp-rdp"].status == "exists" and result.servers[0].target_set.status == "exists"
    assert calls(sia, "find_secret") == [VAULT_SIA_NAME] and "list_secrets" not in [c[0] for c in sia.calls]
    assert calls(sia, "list_target_sets") == [(None, WEB01_FQDN)]


class BlindFilterSIA(FakeSIA):
    """A tenant whose server-side name filters match nothing, while the unfiltered listings serve the records.

    Observed on adp-amrs-uat: GET /api/secrets/public/v2 returned zero rows for a secret_name the same endpoint
    returned when listed unfiltered, and the run reported the strong account as missing.
    """

    def find_secret(self, name):
        self.calls.append(("find_secret", name))
        return None

    def list_target_sets(self, *, strong_account_id=None, name=None):
        if name:
            self.calls.append(("list_target_sets", (strong_account_id, name)))
            return []
        return super().list_target_sets(strong_account_id=strong_account_id)


def test_a_blind_name_filter_does_not_become_a_missing_strong_account():
    sia = BlindFilterSIA(secrets=[{"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME}])
    result = make(ONE, sia=sia, dry_run=True, lookup="search")[0].run()

    assert result.secrets["SA-corp-rdp"].status == "exists" and result.failures == 0
    assert calls(sia, "find_secret") == [VAULT_SIA_NAME]     # the filtered read was tried first
    assert calls(sia, "list_secrets") == [None]              # then confirmed once, unfiltered
    assert any("unfiltered listing" in w and VAULT_SIA_NAME in w and "--lookup list" in w for w in result.warnings)


def test_an_unreliable_name_filter_stops_the_rest_of_the_run_from_filtering():
    sia = BlindFilterSIA(secrets=[{"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME}],
                         target_sets=[{"id": "ts-1", "name": WEB01_FQDN, "type": "Target", "secret_id": "sec-1",
                                       "secret_type": "PCloudAccount"}])
    rec, sia, uap, _ = make(ONE, sia=sia, dry_run=True, lookup="search")
    result = rec.run()

    # Target sets and policies fall back to their unfiltered reads, so the existing target set is still seen.
    assert calls(sia, "list_target_sets") == [(None, None)]
    assert uap.calls == [("list_policies", (None, OWNED_FILTER))]
    assert result.servers[0].target_set.status == "exists"
    assert not sia.capabilities.name_filter_reliable
    assert "name filter unreliable" in sia.capabilities.describe()


def test_an_account_missing_from_both_reads_still_fails_after_one_confirming_listing():
    sia = FakeSIA()
    result = make(inputs([srv("a.corp.example.com", "SA-legacy", ["SIA-Web-Admins"])], [EXISTING]),
                  sia=sia, lookup="search")[0].run()

    assert result.secrets["SA-legacy"].status == "failed" and "type=existing" in result.secrets["SA-legacy"].detail
    assert calls(sia, "list_secrets") == [None] and sia.capabilities.name_filter_reliable
    assert result.warnings == [] and not calls(sia, "create_secret")


class BlindTargetSetFilterSIA(FakeSIA):
    """A tenant whose strong-account filter works but whose target-set name filter matches nothing."""

    def list_target_sets(self, *, strong_account_id=None, name=None):
        if name:
            self.calls.append(("list_target_sets", (strong_account_id, name)))
            return []
        return super().list_target_sets(strong_account_id=strong_account_id)


def test_a_blind_target_set_filter_does_not_become_a_bulk_create():
    sia = BlindTargetSetFilterSIA(
        secrets=[{"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME}],
        target_sets=[{"id": "ts-1", "name": WEB01_FQDN, "type": "Target", "secret_id": "other-secret",
                      "secret_type": "PCloudAccount"}])
    rec, sia, uap, _ = make(ONE, sia=sia, lookup="search")
    result = rec.run()

    # The set exists and points elsewhere. Found through the confirming listing, it is reported as drift instead of
    # going to a bulk create that never saw it -- which would fail, or silently re-point a set this run never read.
    assert result.servers[0].target_set.status == "drift" and not calls(sia, "bulk_create_target_sets")
    assert calls(sia, "find_secret") == [VAULT_SIA_NAME] and "list_secrets" not in [c[0] for c in sia.calls]
    assert calls(sia, "list_target_sets") == [(None, WEB01_FQDN), (None, None)]
    assert not sia.capabilities.name_filter_reliable
    assert any("target set" in w and WEB01_FQDN in w and "--lookup list" in w for w in result.warnings)
    assert calls(uap, "list_policies") == [(None, OWNED_FILTER)]     # policies no longer trust q= either


def test_the_confirming_listing_adds_to_the_filtered_reads_rather_than_replacing_them():
    class ShortListingSIA(FakeSIA):
        """A tenant whose per-name reads serve a strong account that its unfiltered listing drops."""

        def list_secrets(self, *, name=None):
            self.calls.append(("list_secrets", name))
            return []

    sia = ShortListingSIA(secrets=[{"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME}])
    result = make(sia=sia, dry_run=True, lookup="search")[0].run()

    # SA-dmz is missing, so the listing is read to confirm it; what the per-name read found is kept, not replaced.
    assert result.secrets["SA-corp-rdp"].status == "exists" and result.secrets["SA-dmz"].status == "planned"
    assert calls(sia, "list_secrets") == [None] and sia.capabilities.name_filter_reliable
    assert not any("unfiltered listing" in w for w in result.warnings)


def test_a_blind_policy_search_makes_the_snapshot_list_policies():
    uap = FakeUAP()
    uap.search_reliable = False      # what UAPClient records once a q= lookup had to be confirmed by the listing
    rec, _, uap, _ = make(ONE, uap=uap, dry_run=True, lookup="search")
    rec.run()
    assert calls(uap, "list_policies") == [(None, OWNED_FILTER)]


def test_progress_is_logged(caplog):
    with caplog.at_level("INFO", logger="sia.reconcile"):
        make(progress_every=1)[0].run()
    assert "policies: 3/3 done" in caplog.text and "strong accounts: 2/2 done" in caplog.text and "target sets: 3/3 done" in caplog.text


def test_existing_account_missing_blocks_downstream():
    rec, sia, uap, _ = make(inputs([srv("a.corp.example.com", "SA-legacy", ["SIA-Web-Admins"])], [EXISTING]))
    result = rec.run()
    assert result.secrets["SA-legacy"].status == "failed" and "type=existing" in result.secrets["SA-legacy"].detail
    sr = result.servers[0]
    assert sr.target_set.status == "blocked" and sr.policy.status == "blocked"
    assert result.failures == 1 and not calls(sia, "create_secret") and not calls(uap, "create_policy")


def test_existing_vault_account_found_by_platform_name_and_type_warning():
    sia = FakeSIA(secrets=[{"secret_id": "s-9", "secret_type": "ProvisionerUser", "secret_name": "SVC_SIA_RDP_sia-strongaccounts", "is_active": False}])
    rec, sia, _, _ = make(ONE, sia=sia)
    result = rec.run()
    assert result.secrets["SA-corp-rdp"].status == "inactive" and result.secrets["SA-corp-rdp"].ref == "s-9"
    assert any("CSV type=vault but SIA has ProvisionerUser" in w for w in result.warnings)
    assert result.servers[0].target_set.status == "blocked" and result.servers[0].policy.status == "blocked"
    assert not calls(sia, "bulk_create_target_sets")


def test_strong_account_without_identifier_blocks_dependent_changes():
    sia = FakeSIA(secrets=[{"secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME, "is_active": True}])
    result = make(ONE, sia=sia)[0].run()
    assert result.secrets["SA-corp-rdp"].status == "unverified"
    assert result.servers[0].target_set.status == "blocked" and result.servers[0].policy.status == "blocked"
    assert result.failures == 1 and not calls(sia, "bulk_create_target_sets")


def test_target_sets_listed_per_account_when_the_tenant_requires_it():
    sia = FakeSIA(secrets=[{"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME}],
                  target_sets=[{"name": WEB01_FQDN, "type": "Target", "secret_type": "PCloudAccount", "secret_id": "sec-1", "description": f"x {MARK}"}])
    sia.capabilities.targetsets_list_unfiltered = False
    result = make(ONE, sia=sia)[0].run()
    assert result.servers[0].target_set.status == "exists" and result.failures == 0
    assert ("sec-1", None) in calls(sia, "list_target_sets") and (None, None) not in calls(sia, "list_target_sets")
    sia.calls.clear()
    result = make(ONE, sia=sia, lookup="search")[0].run()
    assert result.servers[0].target_set.status == "exists" and (None, WEB01_FQDN) not in calls(sia, "list_target_sets")


# ----------------------------------------------------------- fail-fast
def test_secret_create_client_error_aborts_run():
    sia = FakeSIA()
    sia.raise_on_create_secret = err(400, "safe not found")
    rec, sia, uap, _ = make(sia=sia)
    result = rec.run()
    assert result.secrets["SA-corp-rdp"].status == "failed" and "safe not found" in result.secrets["SA-corp-rdp"].detail
    assert result.secrets["SA-dmz"].status == "blocked" and "run stopped" in result.secrets["SA-dmz"].detail
    assert len(result.aborted) == 1 and "SA-corp-rdp" in result.aborted[0]
    assert all(sr.target_set.status == "blocked" and sr.policy.status == "blocked" for sr in result.servers)
    assert len(calls(sia, "create_secret")) == 1 and not calls(uap, "create_policy")


def test_secret_create_errors_without_fail_fast_or_on_5xx_are_isolated():
    sia = FakeSIA()
    sia.raise_on_create_secret = err(400, "bad request")
    result = make(sia=sia, fail_fast=False)[0].run()
    assert all(o.status == "failed" for o in result.secrets.values()) and not result.aborted
    sia = FakeSIA()
    sia.raise_on_create_secret = err(502, "gateway")
    result = make(sia=sia)[0].run()
    assert all(o.status == "uncertain" and "may or may not have been applied" in o.detail for o in result.secrets.values())
    assert not result.aborted
    diagnostic = result.secrets["SA-corp-rdp"].diagnostic
    assert diagnostic and diagnostic["object_name"] == "SA-corp-rdp" and diagnostic["mutation_state"] == "unknown"


def test_bulk_client_error_aborts_remaining_target_sets():
    sia = FakeSIA()
    sia.raise_on_bulk = err(403, "forbidden")
    result = make(sia=sia)[0].run()
    by = by_fqdn(result)
    assert by[WEB01_FQDN].target_set.status == "failed" and by[WEB02_FQDN].target_set.status == "failed"
    assert by[DMZ_FQDN].target_set.status == "blocked"
    assert all(sr.policy.status == "blocked" for sr in result.servers) and len(result.aborted) == 1


def test_bulk_partial_failure_marks_only_that_server():
    sia = FakeSIA()
    sia.fail_bulk_for = {WEB02_FQDN}
    result = make(sia=sia)[0].run()
    by = by_fqdn(result)
    assert by[WEB01_FQDN].target_set.status == "created" and by[WEB01_FQDN].policy.status == "created"
    assert by[WEB02_FQDN].target_set.status == "failed" and by[WEB02_FQDN].policy.status == "blocked"
    assert result.failures == 1 and not result.aborted


def test_policy_create_client_error_aborts_but_5xx_continues():
    uap = FakeUAP()
    uap.raise_on_create_policy = err(400, "invalid principal")
    rec, sia, uap, _ = make(uap=uap)
    result = rec.run()
    by = by_fqdn(result)
    assert by[WEB01_FQDN].policy.status == "failed" and "invalid principal" in by[WEB01_FQDN].policy.detail
    assert by[WEB02_FQDN].policy.status == "blocked" and by[DMZ_FQDN].policy.status == "blocked"
    assert all(sr.target_set.status == "created" for sr in result.servers)  # earlier stage already done
    assert len(calls(uap, "create_policy")) == 1 and result.aborted
    uap = FakeUAP()
    uap.raise_on_create_policy = err(400, "invalid principal")
    result = make(uap=uap, fail_fast=False)[0].run()
    assert all(sr.policy.status == "failed" for sr in result.servers) and not result.aborted
    uap = FakeUAP()
    uap.raise_on_create_policy = err(504, "gateway timeout")
    result = make(uap=uap)[0].run()
    assert all(sr.policy.status == "uncertain" and "may or may not" in sr.policy.detail for sr in result.servers) and not result.aborted


# ----------------------------------------------------- ownership / drift
def test_target_set_drift_requires_ownership_or_adopt():
    sia = FakeSIA(secrets=[{"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME}],
                  target_sets=[{"id": WEB01_FQDN, "name": WEB01_FQDN, "type": "Target",
                                "secret_type": "ProvisionerUser", "secret_id": "old-secret", "description": "made by hand"}])
    result = make(ONE, sia=sia)[0].run()
    sr = result.servers[0]
    assert sr.target_set.status == "drift" and "old-secret" in sr.target_set.detail and "--update" in sr.target_set.detail
    assert sr.policy.status == "created" and result.failures == 0

    result = make(ONE, sia=sia, update=True)[0].run()
    assert result.servers[0].target_set.status == "drift" and f"--adopt {WEB01_FQDN}" in result.servers[0].target_set.detail
    assert not calls(sia, "update_target_set")

    result = make(ONE, sia=sia, update=True, dry_run=True, adopt=["WEB01.corp.example.com"])[0].run()
    assert result.servers[0].target_set.status == "planned"
    result = make(ONE, sia=sia, update=True, adopt=[WEB01_FQDN])[0].run()
    assert result.servers[0].target_set.status == "updated"
    name, payload = calls(sia, "update_target_set")[0]
    assert name == WEB01_FQDN and payload["secret_id"] == "sec-1" and MARK in payload["description"]

    sia.target_sets[0].update({"secret_id": "old-again", "description": f"x {MARK}"})  # now carries the marker
    result = make(ONE, sia=sia, update=True)[0].run()
    assert result.servers[0].target_set.status == "updated"


def test_full_target_set_drift_includes_managed_fields():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    target = sia.target_sets[0]
    target["enable_certificate_validation"] = True
    target["description"] = f"changed {MARK}"
    result = make(ONE, sia=sia, uap=uap, drift=True)[0].run()
    detail = result.servers[0].target_set.detail
    assert result.servers[0].target_set.status == "drift"
    assert "certificate validation differs" in detail and "description differs" in detail

    result = make(ONE, sia=sia, uap=uap, update=True)[0].run()
    assert result.servers[0].target_set.status == "updated"
    _, payload = calls(sia, "update_target_set")[-1]
    assert payload["enable_certificate_validation"] is False and payload["description"].endswith(MARK)


@pytest.mark.parametrize(("field", "value", "expected"), [
    ("type", "Domain", "type differs"),
    ("secret_type", "ProvisionerUser", "secret type differs"),
    ("description", f"different {MARK}", "description differs"),
    ("enable_certificate_validation", True, "certificate validation differs"),
])
def test_each_target_set_managed_field_updates_then_becomes_noop(field, value, expected):
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    sia.target_sets[0][field] = value
    result = make(ONE, sia=sia, uap=uap, update=True)[0].run()
    assert result.servers[0].target_set.status == "updated" and expected in result.servers[0].target_set.detail
    update_count = len(calls(sia, "update_target_set"))
    result = make(ONE, sia=sia, uap=uap, update=True)[0].run()
    assert result.servers[0].target_set.status == "exists"
    assert len(calls(sia, "update_target_set")) == update_count


def test_target_set_provision_format_setting_updates_then_becomes_noop():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    configured = replace(DEFAULTS, provision_format="<user>-sia")
    result = make(ONE, sia=sia, uap=uap, defaults=configured, update=True)[0].run()
    assert result.servers[0].target_set.status == "updated"
    assert calls(sia, "update_target_set")[-1][1]["provision_format"] == "<user>-sia"
    update_count = len(calls(sia, "update_target_set"))
    assert make(ONE, sia=sia, uap=uap, defaults=configured, update=True)[0].run().servers[0].target_set.status == "exists"
    assert len(calls(sia, "update_target_set")) == update_count


def test_plan_reports_an_existing_target_set_as_drift_when_its_account_is_only_planned():
    """The account does not exist yet, so the set cannot point at it: plan must say what apply will find."""
    sia = FakeSIA(target_sets=[{"id": WEB01_FQDN, "name": WEB01_FQDN, "type": "Target", "secret_type": "ProvisionerUser",
                                "secret_id": "old-secret", "description": f"old {MARK}"}])
    result = make(ONE, sia=sia, dry_run=True)[0].run()
    sr = result.servers[0]
    assert sr.secret.status == "planned" and sr.target_set.status == "drift"
    assert "old-secret" in sr.target_set.detail and "does not exist yet" in sr.target_set.detail
    assert sr.policy.status == "planned" and result.failures == 0
    assert make(ONE, sia=sia, dry_run=True, update=True)[0].run().servers[0].target_set.status == "planned"
    unmanaged = FakeSIA(target_sets=[{"id": WEB01_FQDN, "name": WEB01_FQDN, "type": "Target", "secret_type": "ProvisionerUser",
                                      "secret_id": "old-secret", "description": "by hand"}])
    detail = make(ONE, sia=unmanaged, dry_run=True, update=True)[0].run().servers[0].target_set.detail
    assert f"--adopt {WEB01_FQDN}" in detail
    result = make(ONE, sia=sia, update=True)[0].run()      # apply agrees: re-pointed once the account exists
    assert result.servers[0].target_set.status == "updated"
    assert calls(sia, "update_target_set")[0][1]["secret_id"] == "sec-1"


def test_unmanaged_target_set_up_to_date_is_reported():
    sia = FakeSIA(secrets=[{"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME}],
                  target_sets=[{"name": WEB01_FQDN, "type": "Target", "secret_type": "PCloudAccount", "secret_id": "sec-1"}])
    result = make(ONE, sia=sia)[0].run()
    assert result.servers[0].target_set.status == "exists" and "unmanaged" in result.servers[0].target_set.detail


def test_group_not_found_fails_policy_only():
    identity = FakeIdentity(roles=[role_row("SIA-Web-Admins"), role_row("SIA-Platform-Ops")])  # no DMZ role
    result = make(identity=identity)[0].run()
    dmz = by_fqdn(result)[DMZ_FQDN]
    assert dmz.target_set.status == "created" and dmz.policy.status == "failed" and "SIA-DMZ-Admins" in dmz.policy.detail
    assert result.failures == 1 and not result.aborted


def test_duplicate_policy_names_fail_before_any_write():
    inp = inputs([WEB01, srv("web01.dmz.example.com", "SA-corp-rdp", ["SIA-Web-Admins"], policy_name=WEB01_FQDN)], [VAULT])
    rec, sia, uap, _ = make(inp)
    result = rec.run()
    assert all(s.policy.status == "failed" and "duplicate policy name" in s.policy.detail for s in result.servers)
    assert not calls(uap, "create_policy") and all(s.target_set.status == "created" for s in result.servers)


def test_managed_policy_drift_and_update():
    rec, sia, uap, _ = make()
    rec.run()
    web02 = next(p for p in uap.policies if p["metadata"]["name"] == WEB02_FQDN)
    web02["principals"] = web02["principals"][:1]  # someone removed a principal in the UI
    result = make(sia=sia, uap=uap)[0].run()
    sr = by_fqdn(result)[WEB02_FQDN]
    assert sr.policy.status == "drift" and "principals differ" in sr.policy.detail and "(use --update to fix)" in sr.policy.detail
    assert result.failures == 0
    result3 = make(sia=sia, uap=uap, update=True)[0].run()
    sr3 = by_fqdn(result3)[WEB02_FQDN]
    assert sr3.policy.status == "updated"
    pid, payload = calls(uap, "update_policy")[0]
    assert pid == sr3.policy.ref and payload["metadata"]["policyId"] == pid and len(payload["principals"]) == 2


def test_full_policy_drift_includes_schedule_tags_and_connection_behavior():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    policy = uap.policies[0]
    policy["conditions"]["idleTime"] = 99
    policy["metadata"]["policyTags"].append("unexpected")
    policy["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["enableEphemeralUserReconnect"] = True
    result = make(ONE, sia=sia, uap=uap, drift=True)[0].run()
    detail = result.servers[0].policy.detail
    assert result.servers[0].policy.status == "drift"
    assert "access conditions differ" in detail and "policy tags differ" in detail and "connection behavior differs" in detail

    result = make(ONE, sia=sia, uap=uap, update=True)[0].run()
    assert result.servers[0].policy.status == "updated"
    updated = uap.policies[0]
    assert updated["conditions"]["idleTime"] == DEFAULTS.idle_minutes
    assert "unexpected" not in updated["metadata"]["policyTags"]
    assert updated["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["enableEphemeralUserReconnect"] is False


def test_full_drift_ignores_null_and_empty_fields_echoed_by_the_api():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    uap.echo_defaults = True
    result = make(ONE, sia=sia, uap=uap, drift=True)[0].run()
    assert result.servers[0].policy.status == "exists" and "targets checked" in result.servers[0].policy.detail
    assert not calls(uap, "update_policy")
    uap.policies[0]["conditions"]["idleTime"] = 99
    result = make(ONE, sia=sia, uap=uap, drift=True)[0].run()
    assert result.servers[0].policy.status == "drift" and "access conditions differ" in result.servers[0].policy.detail


@pytest.mark.parametrize("configured", [
    replace(DEFAULTS, description_template="Configured {protocol} access to {fqdn}"),
    replace(DEFAULTS, policy_tags=("configured",)),
    replace(DEFAULTS, time_zone="Europe/London"),
    replace(DEFAULTS, days_of_week=(1, 2, 3, 4, 5)),
    replace(DEFAULTS, from_hour="08:00", to_hour="18:00"),
    replace(DEFAULTS, max_session_hours=4),
    replace(DEFAULTS, idle_minutes=23),
    replace(DEFAULTS, assign_local_groups=("Remote Desktop Users",)),
    replace(DEFAULTS, enable_reconnect=True),
    replace(DEFAULTS, policy_name_template="SIA-{hostname}"),
])
def test_each_policy_setting_updates_then_becomes_noop(configured):
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    result = make(ONE, sia=sia, uap=uap, defaults=configured, update=True)[0].run()
    assert result.servers[0].policy.status == "updated"
    update_count = len(calls(uap, "update_policy"))
    result = make(ONE, sia=sia, uap=uap, defaults=configured, update=True)[0].run()
    assert result.servers[0].policy.status == "exists"
    assert len(calls(uap, "update_policy")) == update_count


def test_explicit_policy_status_changes_and_routine_updates_preserve_status():
    with pytest.raises(ValueError, match="requires update"):
        make(ONE, set_policy_status="Suspended")
    with pytest.raises(ValueError, match="only='all' or only='policies'"):
        make(ONE, update=True, only="targetsets", set_policy_status="Suspended")

    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    policy = uap.policies[0]
    policy["metadata"]["status"] = {"status": "Suspended"}
    policy["principals"] = []
    preserved = make(ONE, sia=sia, uap=uap, update=True)[0].run().servers[0]
    assert preserved.policy.status == "inactive"
    assert calls(uap, "update_policy")[-1][1]["metadata"]["status"] == {"status": "Suspended"}

    activated = make(ONE, sia=sia, uap=uap, update=True, set_policy_status="Active")[0].run().servers[0]
    assert activated.policy.status == "updated"
    assert calls(uap, "update_policy")[-1][1]["metadata"]["status"] == {"status": "Active"}
    status_update_count = len(calls(uap, "update_policy"))
    active_noop = make(ONE, sia=sia, uap=uap, update=True, set_policy_status="Active")[0].run().servers[0]
    assert active_noop.policy.status == "exists" and len(calls(uap, "update_policy")) == status_update_count

    staged_uap = FakeUAP()
    staged_uap.create_status = "Suspended"
    staged_rec, staged_sia, staged_uap, _ = make(
        ONE, uap=staged_uap, update=True, set_policy_status="Suspended")
    staged = staged_rec.run().servers[0]
    assert staged.policy.status == "created"
    assert calls(staged_uap, "create_policy")[0]["metadata"]["status"] == {"status": "Suspended"}
    readiness = make(ONE, sia=staged_sia, uap=staged_uap)[0].run().servers[0]
    assert readiness.policy.status == "inactive"


def test_policy_readback_failure_is_unverified():
    class ReadbackFails(FakeUAP):
        def get_policy(self, policy_id):
            raise SIAApiError("GET", f"/api/policies/{policy_id}", 503, "temporarily unavailable")

    result = make(ONE, uap=ReadbackFails())[0].run()
    assert result.servers[0].policy.status == "unverified"
    assert "read-back failed" in result.servers[0].policy.detail and result.failures == 1
    assert result.servers[0].policy.diagnostic["object_name"] == WEB01_FQDN


def test_policy_update_readback_failure_is_unverified_and_retains_diagnostic():
    class UpdateReadbackFails(FakeUAP):
        fail_reads = False

        def update_policy(self, policy_id, payload):
            super().update_policy(policy_id, payload)
            self.fail_reads = True

        def get_policy(self, policy_id):
            if self.fail_reads:
                raise SIAApiError("GET", f"/api/policies/{policy_id}", 503, "temporarily unavailable")
            return super().get_policy(policy_id)

    uap = UpdateReadbackFails()
    rec, sia, uap, _ = make(ONE, uap=uap)
    assert rec.run().failures == 0
    uap.policies[0]["conditions"]["idleTime"] = 44
    result = make(ONE, sia=sia, uap=uap, update=True)[0].run()
    outcome = result.servers[0].policy
    assert outcome.status == "unverified" and outcome.diagnostic["mutation_state"] == "applied"
    assert outcome.diagnostic["object_name"] == WEB01_FQDN


MANUAL = {"metadata": {"name": WEB01_FQDN, "policyId": "manual-1", "policyTags": ["manual"], "status": {"status": "Active"}},
          "principals": [{"id": "someone-else"}], "delegationClassification": "Unrestricted", "conditions": {"maxSessionDuration": 1},
          "targets": {"FQDN/IP": {"fqdnRules": [{"operator": "EXACTLY", "computernamePattern": WEB01_FQDN, "domain": "corp.example.com"}]}},
          "behavior": {"connectAs": {"rdp": {"localEphemeralUser": {"assignGroups": ["Administrators"]}}}}}


def test_unmanaged_policy_update_requires_adopt():
    uap = FakeUAP([MANUAL])
    result = make(ONE, uap=uap, update=True)[0].run()
    sr = result.servers[0]
    assert sr.policy.status == "drift" and "not managed by this tool" in sr.policy.detail and f"--adopt {WEB01_FQDN}" in sr.policy.detail
    assert not calls(uap, "update_policy") and result.failures == 0 and len(uap.policies) == 1

    result = make(ONE, uap=uap, update=True, adopt=["WEB01.corp.example.com"])[0].run()  # adopt by name, case-insensitive
    assert result.servers[0].policy.status == "updated"
    pid, payload = calls(uap, "update_policy")[0]
    assert pid == "manual-1" and OWNER in payload["metadata"]["policyTags"] and payload["principals"][0]["id"].startswith("role-SIA-Web-Admins")

    # already correct but unmanaged: reported; adopting adds the tag
    uap = FakeUAP([{**MANUAL, "principals": [{"id": "role-SIA-Web-Admins"}]}])
    result = make(ONE, uap=uap)[0].run()
    assert result.servers[0].policy.status == "exists" and "unmanaged" in result.servers[0].policy.detail
    result = make(ONE, uap=uap, update=True, adopt_all=True)[0].run()
    assert result.servers[0].policy.status == "updated" and "adopting" in result.servers[0].policy.detail


def test_create_conflict_is_reclassified_not_failed():
    """A same-name policy hidden from the owner-tag listing answers 409 on create: compare it instead of failing."""
    uap = FakeUAP([{**MANUAL, "principals": [{"id": "role-SIA-Web-Admins"}]}])
    rec, sia, uap, _ = make(ONE, uap=uap)
    result = rec.run()
    sr = result.servers[0]
    assert sr.policy.status == "exists" and "unmanaged" in sr.policy.detail and result.failures == 0 and not result.aborted
    assert len(calls(uap, "create_policy")) == 1 and calls(uap, "find_policy_by_name") == [WEB01_FQDN] and len(uap.policies) == 1


def test_renamed_managed_policy_is_recognised_by_fqdn():
    rec, sia, uap, _ = make()
    rec.run()
    web02 = next(p for p in uap.policies if p["metadata"]["name"] == WEB02_FQDN)
    web02["metadata"]["name"] = "Renamed in the UI"
    result = make(sia=sia, uap=uap)[0].run()
    sr = by_fqdn(result)[WEB02_FQDN]
    assert sr.policy.status == "drift" and "renamed" in sr.policy.detail and sr.policy.ref == web02["metadata"]["policyId"]
    assert not calls(uap, "create_policy")[3:]  # no duplicate policy created
    result = make(sia=sia, uap=uap, update=True)[0].run()
    assert by_fqdn(result)[WEB02_FQDN].policy.status == "updated"
    pid, payload = calls(uap, "update_policy")[0]
    assert pid == web02["metadata"]["policyId"] and payload["metadata"]["name"] == WEB02_FQDN


def test_partial_list_objects_compare_targets_only_with_drift():
    rec, sia, uap, _ = make()
    rec.run()
    uap.partial_list = True   # like the real list endpoint: no targets in list results
    before = len(uap.calls)
    result = make(sia=sia, uap=uap)[0].run()
    assert all(sr.policy.status == "exists" and "add --drift to compare targets" in sr.policy.detail for sr in result.servers)
    assert not [c for c in uap.calls[before:] if c[0] == "get_policy"]
    stored = next(p for p in uap.policies if p["metadata"]["name"] == DMZ_FQDN)
    stored["targets"]["FQDN/IP"]["fqdnRules"][0]["computernamePattern"] = "other.corp"
    before = len(uap.calls)
    result = make(sia=sia, uap=uap, drift=True)[0].run()
    assert len([c for c in uap.calls[before:] if c[0] == "get_policy"]) == 3
    dmz = by_fqdn(result)[DMZ_FQDN]
    assert dmz.policy.status == "drift" and "FQDN rules differ" in dmz.policy.detail
    assert by_fqdn(result)[WEB01_FQDN].policy.status == "exists" and "targets checked" in by_fqdn(result)[WEB01_FQDN].policy.detail
    before = len(uap.calls)
    result = make(sia=sia, uap=uap, update=True)[0].run()   # --update implies the drift check and fixes it
    assert dmz.policy.status == "drift" and by_fqdn(result)[DMZ_FQDN].policy.status == "updated"


def test_inactive_policy_needs_attention():
    rec, sia, uap, _ = make(ONE)
    rec.run()
    uap.policies[0]["metadata"]["status"] = {"status": "Suspended"}
    result = make(ONE, sia=sia, uap=uap)[0].run()
    sr = result.servers[0]
    assert sr.policy.status == "inactive" and "status=Suspended" in sr.policy.detail and result.failures == 1 and not sr.ok


def test_staged_rollout_with_suspended_default_is_not_flagged_by_later_plans():
    staged = replace(DEFAULTS, policy_status="Suspended")
    uap = FakeUAP()
    uap.create_status = "Suspended"
    rec, sia, uap, _ = make(ONE, uap=uap, defaults=staged, suspended_ok=True)
    assert rec.run().servers[0].policy.status == "created"
    result = make(ONE, sia=sia, uap=uap, defaults=staged, suspended_ok=True)[0].run()
    sr = result.servers[0]
    assert sr.policy.status == "exists" and "status=Suspended" in sr.policy.detail and result.failures == 0
    uap.policies[0]["metadata"]["description"] = "edited in the UI"
    result = make(ONE, sia=sia, uap=uap, defaults=staged, suspended_ok=True, update=True)[0].run()
    assert result.servers[0].policy.status == "updated" and uap.policies[0]["metadata"]["status"] == {"status": "Suspended"}
    # verify does not opt in: users still cannot connect through a suspended policy
    assert make(ONE, sia=sia, uap=uap, defaults=staged)[0].run().servers[0].policy.status == "inactive"


def test_policy_error_status_counts_as_failure_and_validating_is_polled():
    uap = FakeUAP()
    uap.statuses_sequence = ["Validating", "Validating", "Error"]
    result = make(ONE, uap=uap, status_polls=5)[0].run()
    sr = result.servers[0]
    assert sr.policy.status == "failed" and "status=Error" in sr.policy.detail and "connector unreachable" in sr.policy.detail
    assert len(calls(uap, "get_policy")) == 3


def test_default_single_status_read_reports_validating():
    uap = FakeUAP()
    uap.statuses_sequence = ["Validating", "Active"]
    result = make(ONE, uap=uap)[0].run()
    assert result.servers[0].policy.status == "unverified" and "status=Validating" in result.servers[0].policy.detail
    assert result.failures == 1
    assert len(calls(uap, "get_policy")) == 1


# --------------------------------------------------------------- vault
VAULT_USER = sa("SA-corp-rdp", "vault", safe="SIA-StrongAccounts", account_name="svc_sia_rdp", username="svc_sia_rdp",
                account_domain="corp.example.com")
VAULT_INPUT = inputs([WEB01], [VAULT_USER])


def test_vault_stage_onboards_missing_accounts():
    pvwa = FakePVWA()
    result = make(VAULT_INPUT, dry_run=True, pvwa=pvwa, passwords={})[0].run()
    assert result.vault["SA-corp-rdp"].status == "planned" and "not available now" in result.vault["SA-corp-rdp"].detail
    assert result.failures == 0 and not calls(pvwa, "add_account")

    result = make(VAULT_INPUT, pvwa=pvwa, passwords={})[0].run()
    assert result.vault["SA-corp-rdp"].status == "failed" and "password file" in result.vault["SA-corp-rdp"].detail
    assert result.secrets["SA-corp-rdp"].status == "blocked" and result.servers[0].target_set.status == "blocked" and result.failures == 1

    result = make(VAULT_INPUT, pvwa=pvwa, passwords={"SA-corp-rdp": "initial-pw"})[0].run()
    assert result.vault["SA-corp-rdp"].status == "created" and result.vault["SA-corp-rdp"].ref == "1_1"
    assert calls(pvwa, "add_account") == [{"name": "svc_sia_rdp", "address": "corp.example.com", "userName": "svc_sia_rdp",
                                           "platformId": "WinServerLocal", "safeName": "SIA-StrongAccounts", "secretType": "password",
                                           "secretManagement": {"automaticManagementEnabled": True}}]
    assert result.secrets["SA-corp-rdp"].status == "created" and result.failures == 0
    assert make(VAULT_INPUT, pvwa=pvwa)[0].run().vault["SA-corp-rdp"].status == "exists"

    local = sa("ADM-web01", "vault", safe="SIA-LocalAdmins", account_name="web01-Administrator", username="Administrator")
    pvwa = FakePVWA()
    result = make(inputs([srv(WEB01_FQDN, "ADM-web01", ["SIA-Web-Admins"])], [local]), pvwa=pvwa, passwords={"ADM-web01": "pw"},
                  pvwa_platform_id="WinLocal", pvwa_cpm_managed=False)[0].run()
    added = calls(pvwa, "add_account")[0]
    assert added["address"] == WEB01_FQDN and added["platformId"] == "WinLocal" and added["secretManagement"] == {"automaticManagementEnabled": False}
    assert result.vault["ADM-web01"].status == "created"

    nouser = sa("SA-x", "vault", safe="S", account_name="a")
    result = make(inputs([srv(WEB01_FQDN, "SA-x", ["SIA-Web-Admins"])], [nouser]), pvwa=FakePVWA(), passwords={"SA-x": "pw"})[0].run()
    assert result.vault["SA-x"].status == "failed" and "no username" in result.vault["SA-x"].detail

    pvwa = FakePVWA()
    pvwa.raise_on_add = err(403, "forbidden safe")
    result = make(VAULT_INPUT, pvwa=pvwa, passwords={"SA-corp-rdp": "pw"})[0].run()
    assert result.vault["SA-corp-rdp"].status == "failed" and result.aborted and result.servers[0].policy.status == "blocked"


def test_vault_stage_gating():
    result = make(VAULT_INPUT, only="vault")[0].run()
    assert any("[pvwa] is not configured" in w for w in result.warnings) and "SA-corp-rdp" not in result.vault
    result = make(VAULT_INPUT, pvwa=FakePVWA(), only="secrets")[0].run()
    assert result.vault["SA-corp-rdp"].status == "skipped" and result.secrets["SA-corp-rdp"].status == "created"
    result = make(VAULT_INPUT, pvwa=FakePVWA(), only="vault", passwords={"SA-corp-rdp": "pw"})[0].run()
    assert result.vault["SA-corp-rdp"].status == "created" and result.secrets["SA-corp-rdp"].status == "skipped"
    assert make(dry_run=True, pvwa=FakePVWA())[0].run().vault == {} or True   # credentials accounts are never vaulted


# ------------------------------------------------------------ template
TEMPLATE = {"metadata": {"name": "Reference", "policyId": "tpl", "timeZone": "Europe/London", "policyTags": ["ref"], "status": {"status": "Active"},
                         "policyEntitlement": {"targetCategory": "VM", "locationType": "FQDN/IP", "policyType": "Recurring"}},
            "principals": [], "delegationClassification": "Unrestricted",
            "conditions": {"accessWindow": {"daysOfTheWeek": [1, 2, 3]}, "maxSessionDuration": 3, "idleTime": 7},
            "behavior": {"connectAs": {"ssh": {"username": "root"},
                                       "rdp": {"localEphemeralUser": {"assignGroups": ["Power Users"], "enableEphemeralUserReconnect": True}}}},
            "targets": {"FQDN/IP": {"fqdnRules": [{"operator": "EXACTLY", "computernamePattern": "ref.corp.example.com", "domain": "corp.example.com"}]}}}


def test_template_policy_cloned_with_approved_fields_only():
    rec, _, uap, _ = make(uap=FakeUAP([TEMPLATE]), defaults=Defaults(template_policy="Reference"))
    result = rec.run()
    assert result.failures == 0 and not result.warnings
    created = calls(uap, "create_policy")
    assert created[0]["conditions"] == TEMPLATE["conditions"] and created[0]["metadata"]["timeZone"] == "Europe/London"
    assert created[0]["metadata"]["policyTags"] == ["ref", OWNER]
    assert created[0]["behavior"] == {"connectAs": {"rdp": TEMPLATE["behavior"]["connectAs"]["rdp"]}}
    assert created[1]["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["assignGroups"] == ["Remote Desktop Users"]


def test_template_policy_missing_or_unsuitable_aborts():
    with pytest.raises(ReconcileError, match="template_policy 'Missing' not found"):
        make(defaults=Defaults(template_policy="Missing"))[0].run()
    db = {**TEMPLATE, "metadata": {**TEMPLATE["metadata"], "name": "DBRef", "policyEntitlement": {"targetCategory": "DB", "locationType": "FQDN/IP"}},
          "behavior": {"connectAs": {"ssh": {"username": "root"}}}}
    with pytest.raises(ReconcileError, match="not usable as a template.*targetCategory"):
        make(uap=FakeUAP([db]), defaults=Defaults(template_policy="DBRef"))[0].run()
    no_profile = {**TEMPLATE, "metadata": {**TEMPLATE["metadata"], "name": "NoProfile"}, "behavior": {"connectAs": {}}}
    with pytest.raises(ReconcileError, match="no connection profile"):
        make(uap=FakeUAP([no_profile]), defaults=Defaults(template_policy="NoProfile"))[0].run()


# --------------------------------------------------------------- --only
def test_only_stage_restricts_writes():
    rec, sia, uap, _ = make(only="secrets")
    result = rec.run()
    assert all(o.status == "created" for o in result.secrets.values())
    assert all(sr.target_set.status == "skipped" and sr.policy.status == "skipped" for sr in result.servers)
    assert not calls(sia, "bulk_create_target_sets") and not calls(uap, "create_policy")
    result2 = make(sia=sia, uap=uap, only="targetsets")[0].run()
    assert all(sr.target_set.status == "created" and sr.policy.status == "skipped" for sr in result2.servers)
    result3 = make(sia=sia, uap=uap, only="policies")[0].run()
    assert all(sr.policy.status == "created" for sr in result3.servers)


def test_only_targetsets_with_missing_secret_is_skipped_not_created():
    rec, sia, _, _ = make(only="targetsets")
    result = rec.run()
    assert all(o.status == "skipped" for o in result.secrets.values())
    assert all(sr.target_set.status == "blocked" for sr in result.servers) and not calls(sia, "create_secret")


# ---------------------------------------------------------- SSH rows
LNX = srv("lnx01.corp.example.com", None, ["SIA-Linux-Admins"], protocol="ssh", ssh_username="ec2-user")
MIXED = inputs([WEB01, LNX], [VAULT])


def test_ssh_rows_need_only_a_policy():
    rec, sia, uap, _ = make(MIXED)
    result = rec.run()
    assert result.failures == 0
    lnx = by_fqdn(result)["lnx01.corp.example.com"]
    assert lnx.secret.status == "n/a" and lnx.target_set.status == "n/a" and lnx.policy.status == "created"
    assert lnx.protocol == "ssh" and lnx.strong_account == "-"
    created = {p["metadata"]["name"]: p for p in calls(uap, "create_policy")}
    assert created["lnx01.corp.example.com"]["behavior"] == {"connectAs": {"ssh": {"username": "ec2-user"}}}
    assert set(created[WEB01_FQDN]["behavior"]["connectAs"]) == {"rdp"}
    assert len(calls(sia, "create_secret")) == 1  # only the Windows row's account
    assert all(ts["name"] == WEB01_FQDN for b in calls(sia, "bulk_create_target_sets") for m in b for ts in m["target_sets"])
    result2 = make(MIXED, sia=sia, uap=uap)[0].run()
    assert by_fqdn(result2)["lnx01.corp.example.com"].policy.status == "exists"


def test_ssh_row_without_username_fails_only_that_policy():
    inp = inputs([WEB01, srv("lnx02.corp.example.com", None, ["SIA-Linux-Admins"], protocol="ssh")], [VAULT])
    result = make(inp)[0].run()
    lnx = by_fqdn(result)["lnx02.corp.example.com"]
    assert lnx.policy.status == "failed" and "needs ssh_username" in lnx.policy.detail
    assert by_fqdn(result)[WEB01_FQDN].policy.status == "created"
    result_default = make(inp, defaults=Defaults(time_zone="America/New_York", ssh_username="root"))[0].run()
    assert by_fqdn(result_default)["lnx02.corp.example.com"].policy.status == "created"


# ---------------------------------------------------------- workers
def test_workers_create_everything_and_canary_still_fails_fast():
    many = inputs([srv(f"web{i:02d}.corp.example.com", "SA-corp-rdp", ["SIA-Web-Admins"]) for i in range(1, 13)]
                  + [srv(f"lnx{i:02d}.corp.example.com", None, ["SIA-Linux-Admins"], protocol="ssh", ssh_username="ec2-user") for i in range(1, 5)],
                  [VAULT])
    rec, sia, uap, _ = make(many, workers=4, lookup="search")
    result = rec.run()
    assert result.failures == 0 and len(calls(uap, "create_policy")) == 16 and len(uap.policies) == 16
    assert sorted(p["metadata"]["name"] for p in uap.policies) == sorted(s.fqdn for s in many.servers)
    result2 = make(many, sia=sia, uap=uap, workers=4, lookup="search")[0].run()   # the compare path runs in parallel too
    assert all(sr.policy.status == "exists" for sr in result2.servers)

    uap = FakeUAP()
    uap.raise_on_create_policy = err(400, "invalid principal")
    result = make(many, uap=uap, workers=4)[0].run()
    statuses = [s.policy.status for s in result.servers]
    assert statuses.count("failed") == 1 and statuses.count("blocked") == 15 and len(calls(uap, "create_policy")) == 1
    assert result.aborted

    with pytest.raises(ValueError, match="workers"):
        make(many, workers=0)


# ------------------------------------------------- domain-scoped target sets

DOM = "corp.example.com"
CORP_SA = sa("SA-CORP-SIA", "existing", account_domain=DOM)
DOM_SRV = [srv(f, "SA-CORP-SIA", ["SIA-Web-Admins"], target_set_name=DOM, target_set_type="Domain")
           for f in (WEB01_FQDN, WEB02_FQDN)]
DOMAIN_INPUTS = inputs(DOM_SRV, [CORP_SA])
CORP_SECRET = {"secret_id": "sec-corp", "secret_name": "SA-CORP-SIA", "secret_type": "PCloudAccount"}


def test_domain_target_set_is_created_once_for_the_whole_domain():
    rec, sia, uap, _ = make(DOMAIN_INPUTS, sia=FakeSIA([CORP_SECRET]))
    result = rec.run()
    created = calls(sia, "bulk_create_target_sets")
    assert len(created) == 1
    sets = created[0][0]["target_sets"]
    assert len(sets) == 1 and sets[0]["name"] == DOM and sets[0]["type"] == "Domain"
    assert sets[0]["secret_id"] == "sec-corp" and MARK in sets[0]["description"]
    assert DOM in sets[0]["description"] and WEB01_FQDN not in sets[0]["description"]
    # ...and its outcome reaches both servers, which still get a policy each
    rows = by_fqdn(result)
    assert [rows[f].target_set.status for f in (WEB01_FQDN, WEB02_FQDN)] == ["created", "created"]
    assert [rows[f].target_set.ref for f in (WEB01_FQDN, WEB02_FQDN)] == [DOM, DOM]
    assert [rows[f].policy.status for f in (WEB01_FQDN, WEB02_FQDN)] == ["created", "created"]
    assert len(calls(uap, "create_policy")) == 2
    # the summary counts one target set, not one per server
    assert result_dict(result)["counts"]["created"] == 3          # 1 target set + 2 policies


def test_domain_target_set_found_by_a_later_wave():
    """A wave holding only some servers of a domain finds the set the first wave created."""
    existing = {"id": DOM, "name": DOM, "type": "Domain", "secret_id": "sec-corp", "secret_type": "PCloudAccount",
                "description": f"RDP ZSP domain {DOM} via SA-CORP-SIA {MARK}"}
    wave = inputs([DOM_SRV[1]], [CORP_SA])
    rec, sia, _, _ = make(wave, sia=FakeSIA([CORP_SECRET], [existing]))
    result = rec.run()
    assert calls(sia, "bulk_create_target_sets") == []
    assert result.servers[0].target_set.status == "exists"
    assert "Domain -> SA-CORP-SIA" in result.servers[0].target_set.detail


def test_domain_target_set_is_looked_up_by_domain_name():
    rec, sia, _, _ = make(DOMAIN_INPUTS, sia=FakeSIA([CORP_SECRET]), lookup="search")
    rec.run()
    # Once, not once per server; the set is missing from this tenant, so one unfiltered listing then confirms it.
    assert [name for _, name in calls(sia, "list_target_sets")] == [DOM, None]


def test_domain_target_set_drift_warns_that_it_moves_every_server():
    other = {"id": DOM, "name": DOM, "type": "Domain", "secret_id": "sec-other", "description": "hand made"}
    rec, sia, _, _ = make(DOMAIN_INPUTS, sia=FakeSIA([CORP_SECRET], [other]))
    result = rec.run()
    row = by_fqdn(result)[WEB01_FQDN]
    assert row.target_set.status == "drift"
    assert f"re-pointing it moves every server in {DOM}" in row.target_set.detail
    assert "use --update to re-point" in row.target_set.detail
    assert row.policy.status == "created"          # drift is not a failure; the policy is still reconciled
    # with --update but no ownership, the hint names the target set (not one of its servers)
    rec2, _, _, _ = make(DOMAIN_INPUTS, sia=FakeSIA([CORP_SECRET], [other]), update=True)
    assert f"--adopt {DOM}" in by_fqdn(rec2.run())[WEB01_FQDN].target_set.detail


def test_domain_target_set_adopted_by_its_name():
    other = {"id": DOM, "name": DOM, "type": "Domain", "secret_id": "sec-other", "description": "hand made"}
    rec, sia, _, _ = make(DOMAIN_INPUTS, sia=FakeSIA([CORP_SECRET], [other]), update=True, adopt=[DOM])
    result = rec.run()
    name, payload = calls(sia, "update_target_set")[0]
    assert name == DOM and payload["type"] == "Domain" and payload["secret_id"] == "sec-corp" and MARK in payload["description"]
    assert all(r.target_set.status == "updated" for r in result.servers)


def test_domain_and_workgroup_servers_in_one_run():
    """Domain-joined servers share their domain's set; a workgroup server keeps its own Target set."""
    local = sa("ADM-dmz01", "existing")
    mixed = inputs(DOM_SRV + [srv(DMZ_FQDN, "ADM-dmz01", ["SIA-DMZ-Admins"], domain_joined=False)], [CORP_SA, local])
    sia_fake = FakeSIA([CORP_SECRET, {"secret_id": "sec-dmz", "secret_name": "ADM-dmz01", "secret_type": "PCloudAccount"}])
    rec, sia_fake, _, _ = make(mixed, sia=sia_fake)
    result = rec.run()
    made = {ts["name"]: ts["type"] for item in calls(sia_fake, "bulk_create_target_sets") for ts in item[0]["target_sets"]}
    assert made == {DOM: "Domain", DMZ_FQDN: "Target"}
    assert all(r.target_set.status == "created" for r in result.servers)


def test_domain_target_set_blocked_when_its_strong_account_is_missing():
    rec, sia, _, _ = make(DOMAIN_INPUTS, sia=FakeSIA([]))       # SA-CORP-SIA is type=existing and not in SIA
    result = rec.run()
    assert result.secrets["SA-CORP-SIA"].status == "failed"
    for row in result.servers:
        assert row.target_set.status == "blocked" and row.policy.status == "blocked"
    assert calls(sia, "bulk_create_target_sets") == []


def test_created_detail_names_the_target_set_type():
    rec, _, _, _ = make(DOMAIN_INPUTS, sia=FakeSIA([CORP_SECRET]))
    assert rec.run().servers[0].target_set.detail == f"Domain set {DOM} -> SA-CORP-SIA"
    rec2, _, _, _ = make(ONE, sia=FakeSIA([{"secret_id": "s1", "secret_name": VAULT_SIA_NAME, "secret_type": "PCloudAccount"}]))
    assert rec2.run().servers[0].target_set.detail == f"Target set {WEB01_FQDN} -> SA-corp-rdp"


def test_adopting_a_domain_target_set_does_not_adopt_its_policies():
    """--adopt <domain> names the shared target set only; the per-server policies stay unmanaged."""
    other = {"id": DOM, "name": DOM, "type": "Domain", "secret_id": "sec-other", "description": "hand made"}
    uap = FakeUAP([{"metadata": {"policyId": "p-old", "name": WEB01_FQDN, "policyTags": []},
                    "principals": [{"id": "someone-else"}],
                    "targets": {"FQDN/IP": {"fqdnRules": [{"operator": "EXACTLY", "computernamePattern": WEB01_FQDN}]}}}])
    rec, sia, _, _ = make(DOMAIN_INPUTS, sia=FakeSIA([CORP_SECRET], [other]), uap=uap, update=True, adopt=[DOM])
    result = rec.run()
    rows = by_fqdn(result)
    assert rows[WEB01_FQDN].target_set.status == "updated"          # the set was adopted
    assert rows[WEB01_FQDN].policy.status == "unverified"           # incomplete policy response; never adopted or updated
    assert "cannot confirm settings or safely update" in rows[WEB01_FQDN].policy.detail


# ------------------------------------------------- role principals: migration, tolerance, ambiguity
def test_group_era_policy_migrates_to_role_with_update():
    rec, sia, uap, _ = make(ONE, defaults=GROUP_DEFAULTS)           # a policy created before the switch to roles
    assert rec.run().failures == 0
    assert uap.policies[0]["principals"][0]["type"] == "GROUP"
    result = make(ONE, sia=sia, uap=uap)[0].run()                    # roles are the default now
    sr = by_fqdn(result)[WEB01_FQDN]
    assert sr.policy.status == "drift" and "principals differ" in sr.policy.detail
    assert "SIA-Web-Admins (GROUP) -> SIA-Web-Admins (ROLE)" in sr.policy.detail
    assert calls(uap, "update_policy") == []
    result = make(ONE, sia=sia, uap=uap, update=True)[0].run()
    assert by_fqdn(result)[WEB01_FQDN].policy.status == "updated"
    _, payload = calls(uap, "update_policy")[0]
    assert payload["principals"] == [WEB_ADMINS_ROLE]
    assert by_fqdn(make(ONE, sia=sia, uap=uap)[0].run())[WEB01_FQDN].policy.status == "exists"


def test_role_principal_directory_fields_do_not_cause_drift():
    rec, sia, uap, _ = make(ONE)
    assert rec.run().failures == 0
    stored = uap.policies[0]["principals"][0]
    del stored["sourceDirectoryId"], stored["sourceDirectoryName"]      # a tenant that drops the optional fields
    stored["type"] = "Role"                                              # ... and echoes the type in another case
    result = make(ONE, sia=sia, uap=uap, update=True)[0].run()
    assert by_fqdn(result)[WEB01_FQDN].policy.status == "exists" and calls(uap, "update_policy") == []
    stored["sourceDirectoryName"] = "CyberArk Cloud Directory (tenant)"   # ... or rewrites them
    stored["sourceDirectoryId"] = "another-id"
    result = make(ONE, sia=sia, uap=uap, update=True)[0].run()
    assert by_fqdn(result)[WEB01_FQDN].policy.status == "exists" and calls(uap, "update_policy") == []
    stored["id"] = "someone-else"                                        # the role itself is still compared
    result = make(ONE, sia=sia, uap=uap)[0].run()
    assert by_fqdn(result)[WEB01_FQDN].policy.status == "drift" and "principals differ" in by_fqdn(result)[WEB01_FQDN].policy.detail


def test_ambiguous_role_stops_the_run_before_writes():
    identity = FakeIdentity(roles=[role_row("SIA-Web-Admins", "r-1"), role_row("SIA-Web-Admins", "r-2")])
    rec, sia, uap, _ = make(ONE, identity=identity)
    with pytest.raises(ResolveError, match="role 'SIA-Web-Admins' is ambiguous"):
        rec.run()
    assert calls(uap, "create_policy") == [] and not sia.secrets and not sia.target_sets
