import pytest
import requests

from sia.auth import AuthError, PlatformTokenProvider, ServiceUserOIDCTokenProvider
from sia.clients import (
    IdentityClient,
    PerAccountTargetSetListingRequired,
    SIAClient,
    UAPClient,
)
from sia.http import HttpClient, SIAApiError
from sia.inputs import StrongAccountRow
from sia.pvwa import PVWAClient
from sia.resolve import ResolveError, SecretIndex
from tests.fakes import FakeResponse, FakeSession


def http_with(responses, **kwargs):
    session = FakeSession(responses)
    max_retries = kwargs.pop("max_retries", 0)
    return HttpClient(lambda force=False: "tok", session=session, sleep=lambda _: None,
                      max_retries=max_retries, **kwargs), session


def policy(name: str, policy_id: str) -> dict:
    return {"metadata": {"name": name, "policyId": policy_id}}


@pytest.mark.parametrize("body", [None, {}, {"secrets": None}, ["bad"], [{"secret_name": "missing-id"}]])
def test_malformed_secret_list_never_becomes_an_empty_snapshot(body):
    client, _ = http_with([FakeResponse(200, body)])
    with pytest.raises(SIAApiError) as caught:
        SIAClient(client, "https://x", secrets_api="legacy", targetsets_api="legacy").list_secrets()
    assert caught.value.cause == "malformed_response" and not caught.value.uncertain


@pytest.mark.parametrize("body", [None, {}, {"target_sets": None}, ["bad"], [{"id": "missing-name"}]])
def test_malformed_target_set_list_never_becomes_an_empty_snapshot(body):
    client, _ = http_with([FakeResponse(200, body)])
    with pytest.raises(SIAApiError) as caught:
        SIAClient(client, "https://x", secrets_api="legacy", targetsets_api="legacy").list_target_sets()
    assert caught.value.cause == "malformed_response" and not caught.value.uncertain


@pytest.mark.parametrize("body", [None, [], {}, {"results": None}, {"results": [{}]}])
def test_malformed_policy_list_never_becomes_an_empty_snapshot(body):
    client, _ = http_with([FakeResponse(200, body)])
    with pytest.raises(SIAApiError) as caught:
        UAPClient(client, "https://u").list_policies()
    assert caught.value.cause == "malformed_response" and not caught.value.uncertain


def test_settings_policy_and_identity_read_shapes_are_checked():
    client, _ = http_with([FakeResponse(200, []), FakeResponse(200, []),
                           FakeResponse(200, {"success": True, "Result": {}}),
                           FakeResponse(200, {"success": True, "Result": {"Group": {}}})])
    sia = SIAClient(client, "https://x", secrets_api="legacy", targetsets_api="legacy")
    with pytest.raises(SIAApiError, match="settings response"):
        sia.get_settings()
    with pytest.raises(SIAApiError, match="policy response"):
        UAPClient(client, "https://u").get_policy("p1")
    identity = IdentityClient(client, "https://id")
    with pytest.raises(SIAApiError, match="Results"):
        identity.list_directories()
    with pytest.raises(SIAApiError, match="Results"):
        identity.query_groups("Admins", ["d1"])


@pytest.mark.parametrize("body", ["not-json", {"success": False, "Message": "denied"},
                                   {"success": True, "Result": {"Group": {}}}])
def test_identity_post_read_errors_are_not_reported_as_mutations(body):
    client, _ = http_with([FakeResponse(200, body)])
    with pytest.raises(SIAApiError) as failed:
        IdentityClient(client, "https://id").query_groups("Admins", ["d1"])
    assert failed.value.method == "POST" and failed.value.mutation_state == "not_applicable"


def test_identity_group_deduplication_preserves_cross_directory_collisions():
    rows = [
        {"Row": {"InternalName": "same", "SystemName": "Admins", "DirectoryServiceUuid": "dir-1"}},
        {"Row": {"InternalName": "same", "SystemName": "Admins", "DirectoryServiceUuid": "dir-1"}},
        {"Row": {"InternalName": "same", "SystemName": "Admins", "DirectoryServiceUuid": "dir-2"}},
    ]
    client, _ = http_with([FakeResponse(200, {"success": True, "Result": {"Group": {"Results": rows}}})])
    found = IdentityClient(client, "https://id").query_groups("Admins", ["dir-1", "dir-2"])
    assert [row["DirectoryServiceUuid"] for row in found] == ["dir-1", "dir-2"]


def test_token_pagination_cycles_nonprogress_and_caps_are_errors():
    client, _ = http_with([
        FakeResponse(200, {"secrets": [{"secret_id": "s1", "secret_name": "A"}],
                           "b64_last_evaluated_key": "again"}),
        FakeResponse(200, {"secrets": [{"secret_id": "s2", "secret_name": "B"}],
                           "b64_last_evaluated_key": "again"}),
    ])
    with pytest.raises(SIAApiError, match="token repeated or cycled") as caught:
        SIAClient(client, "https://x", secrets_api="public", targetsets_api="legacy").list_secrets()
    assert caught.value.cause == "incomplete_pagination"

    # A repeated non-empty page is real duplication, even though the cursor changed.
    client, _ = http_with([
        FakeResponse(200, {"target_sets": [{"name": "a.corp", "type": "Target"}], "b64_last_evaluated_key": "k1"}),
        FakeResponse(200, {"target_sets": [{"name": "a.corp", "type": "Target"}], "b64_last_evaluated_key": "k2"}),
    ])
    with pytest.raises(SIAApiError, match="made no progress"):
        SIAClient(client, "https://x", secrets_api="legacy", targetsets_api="legacy").list_target_sets()

    client, _ = http_with([FakeResponse(200, {"results": [policy("A", "p1")], "nextToken": "more"})])
    with pytest.raises(SIAApiError, match="1-page safety limit"):
        UAPClient(client, "https://u").list_policies(max_pages=1)


def test_an_empty_page_with_a_fresh_cursor_keeps_paging():
    """A scan filtered server-side applies its filter after the page limit, so a page can hold zero
    matching items while the cursor still advances. Treating that as a stall stopped discovery
    outright on a tenant whose first strong-account page filtered to nothing.

    Two consecutive empty pages are included on purpose: every empty page shares one signature, so
    recording it would make the second empty page look like a duplicate of the first.
    """
    client, _ = http_with([
        FakeResponse(200, {"secrets": [], "b64_last_evaluated_key": "cursor1"}),
        FakeResponse(200, {"secrets": [], "b64_last_evaluated_key": "cursor2"}),
        FakeResponse(200, {"secrets": [{"secret_id": "s1", "secret_name": "A"}]}),
    ])
    found = SIAClient(client, "https://x", secrets_api="public", targetsets_api="legacy").list_secrets()
    assert [s["secret_id"] for s in found] == ["s1"]

    client, _ = http_with([
        FakeResponse(200, {"target_sets": [], "b64_last_evaluated_key": "k1"}),
        FakeResponse(200, {"target_sets": [{"name": "a.corp", "type": "Target"}]}),
    ])
    found = SIAClient(client, "https://x", secrets_api="legacy", targetsets_api="legacy").list_target_sets()
    assert [t["name"] for t in found] == ["a.corp"]

    client, _ = http_with([
        FakeResponse(200, {"results": [], "nextToken": "more"}),
        FakeResponse(200, {"results": [policy("A", "p1")]}),
    ])
    assert len(UAPClient(client, "https://u").list_policies()) == 1


def test_offset_and_identity_pagination_caps_are_errors():
    secrets = [{"secret_id": f"s{i}", "secret_name": f"A{i}"} for i in range(500)]
    client, _ = http_with([FakeResponse(404, "no v2"), FakeResponse(200, secrets)])
    with pytest.raises(SIAApiError, match="1-page safety limit"):
        SIAClient(client, "https://x", secrets_api="public", targetsets_api="legacy").list_secrets(max_pages=1)

    groups = [{"Row": {"InternalName": f"g{i}", "SystemName": f"G{i}"}} for i in range(200)]
    client, _ = http_with([FakeResponse(200, {"success": True, "Result": {"Group": {"Results": groups}}})])
    with pytest.raises(SIAApiError, match="1-page safety limit"):
        IdentityClient(client, "https://id").query_groups("G", ["d1"], max_pages=1)


def test_per_account_listing_uses_a_dedicated_exception():
    client, _ = http_with([FakeResponse(400, {"message": "strongAccountId is required"})])
    sia = SIAClient(client, "https://x", secrets_api="legacy", targetsets_api="legacy")
    with pytest.raises(PerAccountTargetSetListingRequired):
        sia.list_target_sets()
    assert not sia.capabilities.targetsets_list_unfiltered


def test_duplicate_exact_names_are_ambiguous_but_repeated_ids_are_deduplicated():
    client, _ = http_with([FakeResponse(200, {"secrets": [
        {"secret_id": "s1", "secret_name": "Admin"},
        {"secret_id": "s2", "secret_name": "ADMIN"},
    ]})])
    with pytest.raises(SIAApiError, match="ambiguous") as caught:
        SIAClient(client, "https://x", secrets_api="legacy", targetsets_api="legacy").find_secret("admin")
    assert caught.value.cause == "ambiguous_response"

    duplicate = policy("Server", "p1")
    client, _ = http_with([FakeResponse(200, {"results": [duplicate, dict(duplicate)]})])
    assert UAPClient(client, "https://u").find_policy_by_name("server")["metadata"]["policyId"] == "p1"

    client, _ = http_with([FakeResponse(200, {"results": [policy("Server", "p1"), policy("SERVER", "p2")]})])
    with pytest.raises(SIAApiError, match="ambiguous"):
        UAPClient(client, "https://u").find_policy_by_name("server")


@pytest.mark.parametrize("policy_id", [True, 12, [], {}])
def test_policy_create_requires_a_string_identifier(policy_id):
    client, _ = http_with([FakeResponse(200, {"policyId": policy_id})])
    with pytest.raises(SIAApiError) as caught:
        UAPClient(client, "https://u").create_policy({})
    assert caught.value.uncertain and caught.value.cause == "malformed_response"


def test_bulk_target_set_receipt_must_match_every_requested_name():
    client, _ = http_with([FakeResponse(207, {"results": [
        {"target_set_name": "different.example", "success": True},
    ]})])
    sia = SIAClient(client, "https://x", secrets_api="legacy", targetsets_api="legacy")
    with pytest.raises(SIAApiError) as caught:
        sia.bulk_create_target_sets([{"strong_account_id": "s1", "target_sets": [{"name": "wanted.example"}]}])
    assert caught.value.uncertain and caught.value.cause == "malformed_response"


def test_secret_index_rejects_only_the_referenced_ambiguous_name():
    index = SecretIndex([
        {"secret_id": "s1", "secret_name": "Admin"},
        {"secret_id": "s2", "secret_name": "ADMIN"},
        {"secret_id": "s3", "secret_name": "Other"},
    ])
    admin = StrongAccountRow("admin", "existing", None, None, None, "local", None, 1)
    other = StrongAccountRow("other", "existing", None, None, None, "local", None, 2)
    with pytest.raises(ResolveError, match="ambiguous"):
        index.find(admin)
    assert index.find(other)["secret_id"] == "s3" and len(index) == 2


def test_a_name_search_that_matches_nothing_is_confirmed_against_the_unfiltered_listing():
    """adp-amrs-uat matched nothing for a secret_name its unfiltered listing served. The same server-side filters
    back the policy and Vault-account lookups, where a false "not found" aborts a run or creates a duplicate."""
    client, session = http_with([
        FakeResponse(200, {"results": []}),                        # q=<name> matches nothing
        FakeResponse(200, {"results": [policy("web01.corp", "p1")]}),   # the unfiltered listing has it
    ])
    found = UAPClient(client, "https://u").find_policy_by_name("web01.corp")
    assert found == policy("web01.corp", "p1")
    assert [call[2]["params"].get("q") for call in session.requests] == ["web01.corp", None]

    # A policy that is genuinely absent stays absent, at the cost of exactly one confirming listing.
    client, session = http_with([FakeResponse(200, {"results": []}), FakeResponse(200, {"results": []})])
    assert UAPClient(client, "https://u").find_policy_by_name("nope") is None
    assert len(session.requests) == 2

    # A tenant whose filter works is never listed unfiltered.
    client, session = http_with([FakeResponse(200, {"results": [policy("web01.corp", "p1")]})])
    assert UAPClient(client, "https://u").find_policy_by_name("web01.corp")["metadata"]["policyId"] == "p1"
    assert len(session.requests) == 1


def test_a_vault_account_search_that_matches_nothing_is_confirmed_against_the_safe():
    session = FakeSession([
        FakeResponse(200, '"token"'),
        FakeResponse(200, {"value": []}),                                             # search=<name> finds nothing
        FakeResponse(200, {"value": [{"id": "1", "name": "Admin", "safeName": "Safe"}]}),   # the safe holds it
    ])
    pvwa = PVWAClient("https://pvwa.example", session=session, sleep=lambda _: None)
    pvwa.logon("svc", "pw")
    assert pvwa.find_account("safe", "admin")["id"] == "1"
    # The retry drops `search` but keeps the safe filter, so it scans one safe rather than the whole Vault.
    assert [call[2]["params"] for call in session.requests[1:]] == [
        {"search": "admin", "filter": "safeName eq safe"}, {"filter": "safeName eq safe"}]

    # Absent from the safe too: still None, and the duplicate-onboarding guard has cost two reads.
    session = FakeSession([FakeResponse(200, '"token"'), FakeResponse(200, {"value": []}),
                           FakeResponse(200, {"value": []})])
    pvwa = PVWAClient("https://pvwa.example", session=session, sleep=lambda _: None)
    pvwa.logon("svc", "pw")
    assert pvwa.find_account("safe", "admin") is None and len(session.requests) == 3


def test_pvwa_paginates_safely_and_rejects_duplicate_exact_accounts():
    session = FakeSession([
        FakeResponse(200, '"token"'),
        FakeResponse(200, {"value": [{"id": "1", "name": "Admin", "safeName": "Safe"}],
                           "nextLink": "/PasswordVault/API/Accounts?page=2"}),
        FakeResponse(200, {"value": [{"id": "2", "name": "ADMIN", "safeName": "SAFE"}]}),
    ])
    pvwa = PVWAClient("https://pvwa.example", session=session, sleep=lambda _: None)
    pvwa.logon("svc", "pw")
    with pytest.raises(SIAApiError, match="ambiguous") as caught:
        pvwa.find_account("safe", "admin")
    assert caught.value.cause == "ambiguous_response"

    session = FakeSession([
        FakeResponse(200, '"token"'),
        FakeResponse(200, {"value": [{"id": "1", "name": "Other", "safeName": "Safe"}],
                           "nextLink": "https://evil.example/accounts"}),
    ])
    pvwa = PVWAClient("https://pvwa.example", session=session, sleep=lambda _: None)
    pvwa.logon("svc", "pw")
    with pytest.raises(SIAApiError, match="outside") as caught:
        pvwa.find_account("safe", "admin")
    assert caught.value.cause == "malformed_response"


def test_http_cancel_check_runs_after_limiter_and_before_mutation_send():
    events = []

    class StopNow(Exception):
        pass

    class Limiter:
        def acquire(self):
            events.append("limited")

    def cancel():
        assert events == ["limited"]
        events.append("cancelled")
        raise StopNow

    session = FakeSession([FakeResponse(200, {"ok": True})])
    client = HttpClient(lambda force=False: "tok", session=session, limiter=Limiter(),
                        cancel_check=cancel)
    with pytest.raises(StopNow):
        client.post("https://x/write", json={})
    assert events == ["limited", "cancelled"] and session.requests == []

    assert client.request("POST", "https://x/read-query", mutation=False).json() == {"ok": True}
    assert events == ["limited", "cancelled", "limited"]


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("failure", [FakeResponse(503, "busy"), requests.Timeout("lost response")])
def test_mutation_failures_are_uncertain_and_never_automatically_retried(method, failure):
    def raise_failure(*_):
        raise failure

    scripted = raise_failure if isinstance(failure, requests.RequestException) else failure
    client, session = http_with([scripted, FakeResponse(200, {})])
    with pytest.raises(SIAApiError) as caught:
        client.request(method, "https://x/write", json={})
    assert caught.value.uncertain and len(session.requests) == 1


def test_explicit_post_read_retries_service_failure_without_mutation_semantics():
    client, session = http_with([FakeResponse(503, "busy"), FakeResponse(200, {"ok": True})], max_retries=1)
    response = client.request("POST", "https://x/read-query", json={}, mutation=False)
    assert response.json() == {"ok": True} and len(session.requests) == 2


def test_pvwa_cancel_check_stops_account_create_before_send():
    class StopNow(Exception):
        pass

    session = FakeSession([FakeResponse(200, '"token"')])
    pvwa = PVWAClient("https://pvwa.example", session=session, sleep=lambda _: None,
                      cancel_check=lambda: (_ for _ in ()).throw(StopNow()))
    pvwa.logon("svc", "pw")
    with pytest.raises(StopNow):
        pvwa.add_account({"name": "Admin", "safeName": "Safe"})
    assert len(session.requests) == 1


@pytest.mark.parametrize("body", [[], {"access_token": 12}, {"access_token": "tok", "expires_in": True},
                                   {"access_token": "tok", "expires_in": float("inf")}])
def test_platform_token_success_shape_is_strict(body):
    provider = PlatformTokenProvider("https://id", "svc", "pw",
                                     session=FakeSession([FakeResponse(200, body)]))
    with pytest.raises(AuthError, match="token response"):
        provider()


def test_service_user_token_success_shape_is_strict():
    provider = ServiceUserOIDCTokenProvider(
        "https://id", "svc", "pw", session=FakeSession([FakeResponse(200, ["not-an-object"])]))
    with pytest.raises(AuthError, match="token response"):
        provider()


@pytest.mark.parametrize("body, fragment", [
    ("not-json", None),
    ({"success": False, "Message": "denied"}, "denied"),
    ({"success": True, "Result": {}}, "roles object"),
    ({"success": True, "Result": {"roles": {}}}, "Results"),
    ({"success": True, "Result": {"roles": {"Results": [{"Row": {"_ID": "r1"}}]}}}, "needs a role name"),
])
def test_identity_role_query_errors_are_not_reported_as_mutations(body, fragment):
    client, _ = http_with([FakeResponse(200, body)])
    with pytest.raises(SIAApiError) as failed:
        IdentityClient(client, "https://id").query_roles("Admins", ["d1"])
    assert failed.value.method == "POST" and failed.value.mutation_state == "not_applicable"
    if fragment:
        assert fragment in str(failed.value)


def test_identity_role_deduplication_collapses_repeated_ids_only():
    rows = [{"Row": {"_ID": "same", "Name": "Admins"}}, {"Row": {"_ID": "same", "Name": "Admins"}},
            {"Row": {"_ID": "other", "Name": "Admins"}}, {"Row": {"Name": "No-Id"}}]
    client, _ = http_with([FakeResponse(200, {"success": True, "Result": {"roles": {"Results": rows}}})])
    found = IdentityClient(client, "https://id").query_roles("Admins", ["d1"])
    assert [row.get("_ID") for row in found] == ["same", "other", None]   # a row without _ID reaches the resolver


def test_identity_role_pagination_cap_is_an_error():
    roles = [{"Row": {"_ID": f"r{i}", "Name": f"R{i}"}} for i in range(200)]
    client, _ = http_with([FakeResponse(200, {"success": True, "Result": {"roles": {"Results": roles}}})])
    with pytest.raises(SIAApiError, match="Identity role pagination exceeded the 1-page safety limit"):
        IdentityClient(client, "https://id").query_roles("R", ["d1"], max_pages=1)
