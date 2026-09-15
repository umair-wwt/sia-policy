import pytest
import requests

from sia.auth import AuthError
from sia.http import SIAApiError
from sia.pvwa import PVWAClient
from tests.fakes import FakeResponse, FakeSession
from tests.test_resolve_reconcile import VAULT_INPUT, VAULT_USER, make


ACCOUNT = {"id": "1", "name": "Admin", "safeName": "Safe"}


def logged_on(*responses):
    session = FakeSession([FakeResponse(200, '"token"'), *responses])
    client = PVWAClient("https://pvwa.example", session=session, sleep=lambda _: None, max_retries=0)
    client.logon("svc", "pw")
    return client, session


def raise_error(error):
    def fail(*_):
        raise error
    return fail


class ChangingVaultSession:
    """A safe whose contents can change during the CLI's preview/approval/apply interval; search misses every name."""

    def __init__(self, accounts):
        self.accounts = list(accounts)
        self.safe_reads = 0
        self.creates = 0

    def request(self, method, url, **kwargs):
        if url.endswith("/Logon"):
            return FakeResponse(200, '"token"', url=url, method=method)
        if method == "GET":
            searching = "search" in (kwargs.get("params") or {})
            self.safe_reads += int(not searching)
            return FakeResponse(200, {"value": [] if searching else list(self.accounts)}, url=url, method=method)
        assert method == "POST" and url.endswith("/Accounts")
        self.creates += 1
        payload = kwargs["json"]
        account = {"id": f"created-{self.creates}", "name": payload["name"], "safeName": payload["safeName"]}
        self.accounts.append(account)
        return FakeResponse(201, account, url=url, method=method)


@pytest.mark.parametrize("present_before_preview", [False, True], ids=["added-after-preview", "deleted-after-preview"])
def test_apply_refreshes_the_preview_safe_snapshot(present_before_preview):
    account = {"id": "external", "name": VAULT_USER.account_name, "safeName": VAULT_USER.safe}
    session = ChangingVaultSession([account] if present_before_preview else [])
    client = PVWAClient("https://pvwa.example", session=session, sleep=lambda _: None)
    client.logon("svc", "pw")
    reconciler = make(VAULT_INPUT, pvwa=client, passwords={VAULT_USER.name: "pw"}, only="vault")[0]

    preview = reconciler.reconcile(dry_run=True)
    assert preview.vault[VAULT_USER.name].status == ("exists" if present_before_preview else "planned")
    session.accounts = [] if present_before_preview else [account]
    applied = reconciler.reconcile(dry_run=False)

    assert applied.vault[VAULT_USER.name].status == ("created" if present_before_preview else "exists")
    assert session.creates == int(present_before_preview)
    assert len(session.accounts) == 1
    assert session.safe_reads == 2


def test_safe_snapshot_is_shared_until_explicitly_reset():
    client, session = logged_on(
        FakeResponse(200, {"value": []}), FakeResponse(200, {"value": [ACCOUNT]}),
        FakeResponse(200, {"value": []}),
        FakeResponse(200, {"value": []}), FakeResponse(200, {"value": []}),
    )
    assert client.find_account("Safe", "Other") is None
    assert client.find_account("safe", "admin") == ACCOUNT
    assert len(session.requests) == 4  # one logon, two searches and one safe scan
    client.reset_lookup_cache()
    assert client.find_account("Safe", "Admin") is None
    assert len(session.requests) == 6


@pytest.mark.parametrize("receipt", [
    {"id": "1", "name": "Admin"},
    {"id": "1", "safeName": "Safe"},
    {"name": "Admin", "safeName": "Safe"},
    {"id": " ", "name": "Admin", "safeName": "Safe"},
    {"id": "1", "name": "Admin", "safeName": " "},
    {"id": "1", "name": "Admin", "safeName": "OtherSafe"},
    {"id": "1", "name": "OtherName", "safeName": "Safe"},
])
def test_incomplete_or_mismatched_create_receipt_never_becomes_cached_evidence(receipt):
    client, session = logged_on(
        FakeResponse(200, {"value": []}), FakeResponse(200, {"value": []}),
        FakeResponse(201, receipt),
        FakeResponse(200, {"value": []}), FakeResponse(200, {"value": []}),
    )
    assert client.find_account("Safe", "Admin") is None
    with pytest.raises(SIAApiError) as caught:
        client.add_account({"name": "Admin", "safeName": "Safe"})
    assert caught.value.uncertain and caught.value.cause == "malformed_response"
    assert client.find_account("Safe", "Admin") is None
    assert len(session.requests) == 6  # the failed receipt invalidated the original empty safe snapshot


@pytest.mark.parametrize("failure", [
    FakeResponse(500, {"error": "response lost after creation"}),
    FakeResponse(201, "not-json"),
    raise_error(requests.ConnectionError("response lost")),
], ids=["server-error", "invalid-json", "network-error"])
def test_uncertain_create_is_not_retried_and_invalidates_negative_cache(failure):
    client, session = logged_on(
        FakeResponse(200, {"value": []}), FakeResponse(200, {"value": []}),
        failure,
        FakeResponse(200, {"value": []}), FakeResponse(200, {"value": [ACCOUNT]}),
    )
    assert client.find_account("Safe", "Admin") is None
    with pytest.raises(SIAApiError) as caught:
        client.add_account({"name": "Admin", "safeName": "Safe"})
    assert caught.value.uncertain
    assert client.find_account("Safe", "Admin") == ACCOUNT
    assert sum(method == "POST" and url.endswith("/Accounts") for method, url, _ in session.requests) == 1
    assert len(session.requests) == 6


def test_confirmed_creation_is_added_to_the_current_safe_snapshot():
    client, session = logged_on(
        FakeResponse(200, {"value": []}), FakeResponse(200, {"value": []}),
        FakeResponse(201, ACCOUNT), FakeResponse(200, {"value": []}),
    )
    assert client.find_account("Safe", "Admin") is None
    assert client.add_account({"name": "ADMIN", "safeName": "SAFE"}) == ACCOUNT
    assert client.find_account("Safe", "Admin") == ACCOUNT
    assert len(session.requests) == 5  # the confirmed write is reused without another safe scan


def test_reauthentication_discards_accounts_visible_to_the_previous_session():
    client, session = logged_on(
        FakeResponse(200, {"value": []}), FakeResponse(200, {"value": [ACCOUNT]}),
        FakeResponse(200, '"new-token"'),
        FakeResponse(200, {"value": []}), FakeResponse(200, {"value": []}),
    )
    assert client.find_account("Safe", "Admin") == ACCOUNT
    client.logon("different-user", "new-pw")
    assert client.find_account("Safe", "Admin") is None
    assert session.requests[-1][2]["headers"]["Authorization"] == "new-token"
    assert len(session.requests) == 6


@pytest.mark.parametrize("response, error", [
    (FakeResponse(401, {"error": "denied"}), AuthError),
    (FakeResponse(200, {}), SIAApiError),
    (raise_error(KeyboardInterrupt()), KeyboardInterrupt),
], ids=["denied", "missing-token", "interrupted"])
def test_failed_reauthentication_clears_old_token_and_snapshot(response, error):
    client, session = logged_on(
        FakeResponse(200, {"value": []}), FakeResponse(200, {"value": [ACCOUNT]}), response,
    )
    assert client.find_account("Safe", "Admin") == ACCOUNT
    with pytest.raises(error):
        client.logon("different-user", "new-pw")
    with pytest.raises(SIAApiError, match="not logged on"):
        client.find_account("Safe", "Admin")
    assert len(session.requests) == 4
    assert not client._safes


@pytest.mark.parametrize("response, error", [
    (FakeResponse(200, {}), None),
    (FakeResponse(500, {}), None),
    (raise_error(KeyboardInterrupt()), KeyboardInterrupt),
], ids=["success", "server-error", "interrupted"])
def test_logoff_clears_session_state_even_when_the_request_fails(response, error):
    client, session = logged_on(
        FakeResponse(200, {"value": []}), FakeResponse(200, {"value": [ACCOUNT]}), response,
    )
    assert client.find_account("Safe", "Admin") == ACCOUNT
    if error:
        with pytest.raises(error):
            client.logoff()
    else:
        client.logoff()
    with pytest.raises(SIAApiError, match="not logged on"):
        client.find_account("Safe", "Admin")
    assert not client._safes
    client.logoff()  # an already logged-off client does not send another request
    assert len(session.requests) == 4


@pytest.mark.parametrize("next_link, expected_path", [
    ("api/Accounts?offset=50", "/PasswordVault/api/Accounts?offset=50"),
    ("API/Accounts?offset=50", "/PasswordVault/API/Accounts?offset=50"),
    ("/PasswordVault/API/Accounts?offset=50", "/PasswordVault/API/Accounts?offset=50"),
    ("https://pvwa.example/PasswordVault/API/Accounts?offset=50", "/PasswordVault/API/Accounts?offset=50"),
    ("?offset=50", "/PasswordVault/API/Accounts?offset=50"),
])
def test_safe_fallback_follows_pvwa_pagination_uri_forms(next_link, expected_path):
    client, session = logged_on(
        FakeResponse(200, {"value": []}),
        FakeResponse(200, {"value": [{**ACCOUNT, "id": "other", "name": "Other"}], "nextLink": next_link}),
        FakeResponse(200, {"value": [ACCOUNT]}),
    )
    assert client.find_account("Safe", "Admin") == ACCOUNT
    assert session.requests[-1][1] == f"https://pvwa.example{expected_path}"
    assert session.requests[-1][2]["params"] is None


@pytest.mark.parametrize("next_link", [
    "https://evil.example/api/Accounts?offset=50", "//evil.example/api/Accounts?offset=50",
    "http://pvwa.example/PasswordVault/api/Accounts?offset=50",
])
def test_pagination_never_sends_the_vault_token_to_another_origin(next_link):
    client, session = logged_on(
        FakeResponse(200, {"value": [ACCOUNT], "nextLink": next_link}),
    )
    with pytest.raises(SIAApiError, match="outside the configured PVWA origin"):
        client.find_account("Safe", "Admin")
    assert len(session.requests) == 2
