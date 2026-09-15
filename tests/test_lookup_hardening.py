"""Lookups that must not trust one filtered read, one projection, or one spelling of a name."""
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

from sia.clients import SIAClient
from sia.http import HttpClient, SIAApiError
from sia.reconcile import ReconcileError
from tests.fakes import FakeResponse, FakeSIA, FakeUAP
from tests.test_http_auth_clients import http_with
from tests.test_resolve_reconcile import MANUAL, ONE, VAULT_SIA_NAME, WEB01_FQDN, calls, make


def test_a_case_sensitive_name_filter_is_diagnosed_and_the_run_switches_to_list_mode():
    """The CSV spells the account one way, the tenant stores it another; a case-sensitive server filter misses it.
    The listing finds it, the warning names the stored spelling instead of blaming the filter, and the rest of the
    run lists instead of searching."""
    sia = FakeSIA(secrets=[{"secret_id": "s-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME.upper(),
                            "is_active": True}])
    sia.case_sensitive_filters = True
    result = make(ONE, sia=sia, lookup="search", dry_run=True)[0].run()
    assert result.secrets["SA-corp-rdp"].status == "exists" and result.lookup_mode == "list"
    warning = next(w for w in result.warnings if "case-sensitive" in w)
    assert f"{VAULT_SIA_NAME!r} is stored as {VAULT_SIA_NAME.upper()!r}" in warning and "list mode" in warning
    assert not sia.capabilities.name_filter_reliable
    assert calls(sia, "list_target_sets") == [(None, None)]           # target sets were listed, not searched


def test_duplicate_names_the_run_never_touches_do_not_abort_it():
    duplicates = [{"id": "ts-a", "name": "other.corp.example.com", "type": "Target", "secret_id": "x"},
                  {"id": "ts-b", "name": "other.corp.example.com", "type": "Target", "secret_id": "y"}]
    sia = FakeSIA(target_sets=duplicates)
    uap = FakeUAP([{**MANUAL, "metadata": {**MANUAL["metadata"], "name": "other", "policyId": "p-a"}},
                   {**MANUAL, "metadata": {**MANUAL["metadata"], "name": "other", "policyId": "p-b"}}])
    result = make(ONE, sia=sia, uap=uap, dry_run=True)[0].run()
    assert result.failures == 0 and result.servers[0].policy.status == "planned"

    wanted_twice = [{"id": "ts-a", "name": WEB01_FQDN, "type": "Target", "secret_id": "x"},
                    {"id": "ts-b", "name": WEB01_FQDN, "type": "Target", "secret_id": "y"}]
    with pytest.raises(ReconcileError, match="ambiguous target set"):
        make(ONE, sia=FakeSIA(target_sets=wanted_twice), dry_run=True)[0].run()


def test_two_projections_of_one_target_set_are_one_object():
    full = {"id": "ts-1", "name": WEB01_FQDN, "type": "Target", "secret_id": "sec-1", "secret_type": "PCloudAccount",
            "description": "managed-by:sia-policy-automation", "provision_format": "<user>-x"}

    class TwoProjectionsSIA(FakeSIA):
        def list_target_sets(self, *, strong_account_id=None, name=None):
            self.calls.append(("list_target_sets", (strong_account_id, name)))
            trimmed = {key: value for key, value in full.items() if key not in ("provision_format", "description")}
            return [trimmed, dict(full)]

    sia = TwoProjectionsSIA(secrets=[{"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": VAULT_SIA_NAME}])
    rec, sia, uap, _ = make(ONE, sia=sia, dry_run=True)
    result = rec.run()
    assert result.servers[0].target_set.status == "exists"
    assert rec._target_sets[WEB01_FQDN]["provision_format"] == "<user>-x"        # the fuller projection was kept


def test_an_owned_filter_the_tenant_evaluates_differently_falls_back_to_the_listing():
    seed, sia, uap, _ = make(ONE)
    assert seed.run().failures == 0
    tags = uap.policies[0]["metadata"]["policyTags"]
    tags[:] = [tag.upper() for tag in tags]                # the fake's tag filter, like a tenant's, is exact
    result = make(ONE, sia=sia, uap=uap, dry_run=True)[0].run()
    assert result.servers[0].policy.status == "exists" and len(calls(uap, "create_policy")) == 1    # the seed's only
    assert any("owned-policy filter" in w and "returned nothing" in w for w in result.warnings)
    assert calls(uap, "list_policies")[-1] == (None, "(targetCategory eq 'VM')")


def test_a_secret_create_answering_already_exists_is_an_exists():
    class LateSecretSIA(FakeSIA):
        def find_secret(self, name):
            self.calls.append(("find_secret", name))
            return super().find_secret(name) if any(c[0] == "create_secret" for c in self.calls) else None

        def list_secrets(self, *, name=None):
            self.calls.append(("list_secrets", name))
            return [] if not any(c[0] == "create_secret" for c in self.calls) else super().list_secrets(name=name)

        def create_secret(self, payload):
            self.calls.append(("create_secret", payload))
            self.secrets.append({"secret_id": "sec-9", "secret_type": payload["secret_type"],
                                 "secret_name": payload["secret_name"], "is_active": True})
            raise SIAApiError("POST", "/api/secrets/public/v1", 409, "secret already exists")

    result = make(ONE, sia=LateSecretSIA())[0].run()
    secret = result.secrets["SA-corp-rdp"]
    assert secret.status == "exists" and secret.ref == "sec-9" and "already existed" in secret.detail
    assert result.servers[0].target_set.status == "created" and result.failures == 0


def test_retry_after_is_honoured_as_seconds_or_as_an_http_date():
    assert HttpClient._retry_delay(FakeResponse(429, headers={"Retry-After": "7"}), 0) == 7.0
    soon = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30), usegmt=True)
    assert 25.0 <= HttpClient._retry_delay(FakeResponse(429, headers={"Retry-After": soon}), 0) <= 30.0
    past = format_datetime(datetime.now(timezone.utc) - timedelta(seconds=30), usegmt=True)
    assert HttpClient._retry_delay(FakeResponse(429, headers={"Retry-After": past}), 0) == 0.0
    assert HttpClient._retry_delay(FakeResponse(429, headers={"Retry-After": "soon"}), 1) == HttpClient._backoff(1)
    assert HttpClient._retry_delay(FakeResponse(429), 2) == HttpClient._backoff(2)


def test_probe_tries_the_legacy_family_when_the_public_one_answers_400():
    client, session = http_with([FakeResponse(400, "unknown parameter count"), FakeResponse(200, {"secrets": []}),
                                 FakeResponse(200, {"target_sets": []})])
    caps = SIAClient(client, "https://x").probe()
    assert caps.secrets_api == "legacy" and session.requests[1][1].endswith("/api/secrets")


def test_a_legacy_listing_with_a_continuation_token_is_incomplete():
    client, _ = http_with([FakeResponse(200, {"secrets": [{"secret_id": "s1", "secret_name": "a"}], "b64LastEvaluatedKey": "k"})])
    with pytest.raises(SIAApiError) as caught:
        SIAClient(client, "https://x", secrets_api="legacy", targetsets_api="legacy").list_secrets()
    assert caught.value.cause == "incomplete_pagination" and "incomplete" in str(caught.value)


def test_listing_pages_are_counted_and_long_walks_are_logged(caplog):
    pages = [FakeResponse(200, {"secrets": [{"secret_id": f"s{i}", "secret_name": f"n{i}"}], "b64_last_evaluated_key": f"k{i}"})
             for i in range(20)]
    pages.append(FakeResponse(200, {"secrets": [{"secret_id": "last", "secret_name": "z"}]}))
    client, _ = http_with(pages)
    sia = SIAClient(client, "https://x", secrets_api="public", targetsets_api="legacy")
    with caplog.at_level("INFO", logger="sia.clients"):
        assert len(sia.list_secrets(name="z")) == 1
    assert sia.pages_read == 21
    assert "strong-account listing walked 21 pages" in caplog.text and "lookup_search_max_rows = 0" in caplog.text
