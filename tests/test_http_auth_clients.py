import base64
import json

import pytest
import requests

from sia.auth import (AuthError, PlatformTokenProvider, ServiceUserOIDCTokenProvider, jwt_claims,
                      make_identity_token_provider)
from sia.clients import IdentityClient, SIAClient, UAPClient, owned_vm_filter
from sia.http import HttpClient, RateLimiter, SIAApiError
from sia.pvwa import PVWAClient
from sia.redact import redact, register_secret
from tests.fakes import FakeResponse, FakeSession


def make_jwt(claims: dict) -> str:
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'RS256'})}.{seg(claims)}.sig"


def http_with(responses, **kw):
    session = FakeSession(responses)
    client = HttpClient(lambda force=False: "tok", session=session, sleep=lambda s: None, max_retries=3, **kw)
    return client, session


def raising(exc):
    def _raise(method, url, kw):
        raise exc
    return _raise


# ------------------------------------------------------------------ auth
def test_platform_token_fetch_cache_and_refresh():
    now = [1000.0]
    token1, token2 = make_jwt({"exp": 1900, "subdomain": "acme"}), make_jwt({"exp": 2800})
    session = FakeSession([FakeResponse(200, {"access_token": token1, "expires_in": 900}),
                           FakeResponse(200, {"access_token": token2, "expires_in": 900})])
    provider = PlatformTokenProvider("https://abc.id.cyberark.cloud/", "svc@acme", "pw-1234", session=session, clock=lambda: now[0])
    assert provider() == token1
    assert provider() == token1  # cached
    method, url, kw = session.requests[0]
    assert (method, url) == ("POST", "https://abc.id.cyberark.cloud/oauth2/platformtoken")
    assert kw["data"] == {"grant_type": "client_credentials", "client_id": "svc@acme", "client_secret": "pw-1234"}
    assert provider.claims["subdomain"] == "acme"
    now[0] = 1000 + 900 - 30  # inside the refresh margin
    assert provider() == token2
    assert len(session.requests) == 2
    assert redact(f"leak {token1} and pw-1234") == "leak *** and ***"  # tokens and secret are registered for redaction


def test_platform_token_errors_do_not_leak_secret():
    session = FakeSession([FakeResponse(401, {"error": "invalid_client", "error_description": "bad creds super-secret-pw"})])
    provider = PlatformTokenProvider("https://abc.id.cyberark.cloud", "svc@acme", "super-secret-pw", session=session)
    with pytest.raises(AuthError) as exc:
        provider()
    assert "HTTP 401" in str(exc.value) and "super-secret-pw" not in str(exc.value) and "***" in str(exc.value)
    with pytest.raises(AuthError, match="must be set"):
        PlatformTokenProvider("https://x", "", "pw")


def test_service_user_oidc_flow():
    id_token = make_jwt({"exp": 5000, "unique_name": "svc@acme"})
    session = FakeSession([
        FakeResponse(200, {"access_token": "access-1234"}),
        FakeResponse(302, "", {"Location": f"https://cyberark.cloud/redirect#id_token={id_token}&token_type=Bearer"}),
    ])
    provider = ServiceUserOIDCTokenProvider("https://abc.id.cyberark.cloud", "svc@acme", "pw-1234", session=session, clock=lambda: 1000.0)
    assert provider() == id_token and provider.name == "service_user_oidc"
    m1, u1, kw1 = session.requests[0]
    assert (m1, u1) == ("POST", "https://abc.id.cyberark.cloud/Oauth2/Token/__idaptive_cybr_user_oidc")
    assert kw1["data"] == {"grant_type": "client_credentials", "scope": "api"}
    assert isinstance(kw1["auth"], requests.auth.HTTPBasicAuth) and kw1["auth"].username == "svc@acme"
    m2, u2, kw2 = session.requests[1]
    assert (m2, u2) == ("GET", "https://abc.id.cyberark.cloud/OAuth2/Authorize/__idaptive_cybr_user_oidc")
    assert kw2["allow_redirects"] is False and kw2["headers"]["Authorization"] == "Bearer access-1234"
    assert kw2["params"] == {"client_id": "__idaptive_cybr_user_oidc", "response_type": "id_token",
                             "scope": "openid profile api", "redirect_uri": "https://cyberark.cloud/redirect"}
    assert redact("access-1234") == "***"


def test_service_user_oidc_errors():
    provider = ServiceUserOIDCTokenProvider("https://abc.id.cyberark.cloud", "svc", "pw-1234",
                                            session=FakeSession([FakeResponse(401, "nope")]))
    with pytest.raises(AuthError, match="token request failed"):
        provider()
    provider = ServiceUserOIDCTokenProvider("https://abc.id.cyberark.cloud", "svc", "pw-1234", session=FakeSession([
        FakeResponse(200, {"access_token": "a"}), FakeResponse(200, "<html>login page</html>")]))
    with pytest.raises(AuthError, match="authorization failed"):
        provider()
    provider = ServiceUserOIDCTokenProvider("https://abc.id.cyberark.cloud", "svc", "pw-1234", session=FakeSession([
        FakeResponse(200, {"access_token": "a"}), FakeResponse(302, "", {"Location": "https://cyberark.cloud/redirect#error=x"})]))
    with pytest.raises(AuthError, match="no id_token"):
        provider()


def test_make_identity_token_provider():
    platform = PlatformTokenProvider("https://abc.id.cyberark.cloud", "svc", "pw-1234", session=FakeSession([]))
    assert make_identity_token_provider("platform_token", platform, identity_url="https://abc.id.cyberark.cloud",
                                        client_id="svc", client_secret="pw-1234") is platform
    oidc = make_identity_token_provider("service_user_oidc", platform, identity_url="https://abc.id.cyberark.cloud",
                                        client_id="svc", client_secret="pw-1234", application="my_app")
    assert isinstance(oidc, ServiceUserOIDCTokenProvider) and oidc._app == "my_app"
    with pytest.raises(AuthError, match="unknown identity_auth"):
        make_identity_token_provider("bogus", platform, identity_url="https://x", client_id="svc", client_secret="pw-1234")


def test_jwt_claims_tolerates_garbage():
    assert jwt_claims("not-a-jwt") == {}
    assert jwt_claims(make_jwt({"a": 1})) == {"a": 1}


# ------------------------------------------------------------------ http
def test_get_retries_on_5xx_and_network_errors_then_succeeds():
    client, session = http_with([FakeResponse(503, "busy", {"Retry-After": "1"}),
                                 raising(requests.ConnectionError("reset")), FakeResponse(200, {"ok": True})])
    resp = client.get("https://acme.dpa.cyberark.cloud/api/settings")
    assert resp.json() == {"ok": True} and len(session.requests) == 3
    headers = session.requests[0][2]["headers"]
    assert headers["Authorization"] == "Bearer tok" and headers["X-IDAP-NATIVE-CLIENT"] == "true"


def test_post_is_never_retried_on_5xx_and_is_reported_uncertain():
    client, session = http_with([FakeResponse(502, "gateway")])
    with pytest.raises(SIAApiError) as exc:
        client.post("https://x/api/secrets", json={}, expected=(201,))
    assert len(session.requests) == 1 and exc.value.uncertain and "may or may not have been applied" in str(exc.value)


def test_post_network_error_is_uncertain_and_not_retried():
    client, session = http_with([raising(requests.Timeout("timed out"))])
    with pytest.raises(SIAApiError) as exc:
        client.post("https://x/api/policies", json={})
    assert exc.value.status == 0 and exc.value.uncertain and "network error: Timeout" in str(exc.value)
    assert len(session.requests) == 1


def test_post_retries_on_429_only():
    client, session = http_with([FakeResponse(429, "slow down", {"Retry-After": "2"}), FakeResponse(201, {"id": 1})])
    assert client.post("https://x/api/secrets", json={}, expected=(201,)).json() == {"id": 1}
    assert len(session.requests) == 2


def test_put_is_retried_on_5xx():
    client, session = http_with([FakeResponse(500, "boom"), FakeResponse(200, {})])
    client.put("https://x/api/targetsets/a.corp", json={})
    assert len(session.requests) == 2


def test_http_refreshes_token_once_on_401():
    calls = []

    def provider(force=False):
        calls.append(force)
        return "tok2" if force else "tok"

    session = FakeSession([FakeResponse(401, "expired"), FakeResponse(200, {"ok": 1})])
    client = HttpClient(provider, session=session, sleep=lambda s: None)
    assert client.get("https://x/api").json() == {"ok": 1}
    assert True in calls


def test_get_raises_structured_error_after_retries():
    client, session = http_with([FakeResponse(500, "boom") for _ in range(4)])
    with pytest.raises(SIAApiError) as exc:
        client.get("https://x/api/secrets")
    assert exc.value.status == 500 and "boom" in str(exc.value) and len(session.requests) == 4 and not exc.value.uncertain


def test_client_error_no_retry_and_redacted():
    register_secret("hunter2-secret")
    client, session = http_with([FakeResponse(400, {"message": "bad password hunter2-secret"})])
    with pytest.raises(SIAApiError) as exc:
        client.post("https://x/api/policies", json={})
    assert len(session.requests) == 1 and exc.value.client_error and not exc.value.uncertain
    assert "hunter2-secret" not in str(exc.value) and "***" in str(exc.value) and "hunter2-secret" not in exc.value.body
    assert SIAApiError("GET", "u", 404, "").not_found and not SIAApiError("GET", "u", 400, "").not_found


# ---------------------------------------------------------- rate limiter
def fake_clock():
    now = [0.0]
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        now[0] += seconds

    return now, slept, sleep


def test_rate_limiter_token_bucket_and_penalty():
    now, slept, sleep = fake_clock()
    limiter = RateLimiter(2, clock=lambda: now[0], sleep=sleep)
    assert limiter.enabled
    limiter.acquire()
    limiter.acquire()
    assert slept == []                         # a burst of `rate` requests passes immediately
    limiter.acquire()
    assert len(slept) == 1 and abs(slept[0] - 0.5) < 1e-9
    limiter.penalize(3.0)
    limiter.penalize(1.0)                      # the longest penalty wins
    limiter.acquire()
    assert slept[-1] >= 2.99
    assert not RateLimiter(0).enabled
    RateLimiter(0).acquire()                   # no-op


def test_http_client_waits_on_limiter_and_penalizes_after_429():
    now, slept, sleep = fake_clock()
    limiter = RateLimiter(100, clock=lambda: now[0], sleep=sleep)
    session = FakeSession([FakeResponse(429, "slow", {"Retry-After": "2"}), FakeResponse(200, {"ok": 1})])
    client = HttpClient(lambda force=False: "tok", session=session, sleep=lambda s: None, limiter=limiter)
    assert client.get("https://x/api").json() == {"ok": 1}
    assert len(session.requests) == 2 and any(s >= 1.99 for s in slept)   # the second attempt waited for the penalty


# --------------------------------------------------------------- clients
def test_sia_client_paginates_target_sets_and_parses_shapes():
    client, session = http_with([
        FakeResponse(200, {"target_sets": [{"name": "a.corp", "type": "Target"}], "b64_last_evaluated_key": "k1"}),
        FakeResponse(200, {"target_sets": [{"name": "b.corp", "type": "Target"}]}),
        FakeResponse(200, [{"secret_id": "s1", "secret_type": "PCloudAccount", "secret_name": "SA"}]),
        FakeResponse(201, {"secret_id": "s2"}),
        FakeResponse(207, {"results": [{"target_set_name": "c.corp", "success": True}]}),
        FakeResponse(200, {"self_hosted_pam": {"tenant_type": "SELF_HOSTED"}}),
        FakeResponse(200, {"name": "a.corp"}),
    ])
    sia = SIAClient(client, "https://acme.dpa.cyberark.cloud/", secrets_api="legacy", targetsets_api="legacy")
    assert sia.capabilities.describe() == "secrets=legacy targetsets=legacy (unfiltered listing OK)"
    assert [t["name"] for t in sia.list_target_sets()] == ["a.corp", "b.corp"]
    assert session.requests[0][2]["params"] is None and session.requests[1][2]["params"] == {"b64StartKey": "k1"}
    assert sia.list_secrets()[0]["secret_id"] == "s1"
    assert session.requests[2][2]["params"] == {"secret_type": "ProvisionerUser,PCloudAccount"}
    assert sia.create_secret({"secret_name": "x"})["secret_id"] == "s2"
    assert session.requests[3][:2] == ("POST", "https://acme.dpa.cyberark.cloud/api/secrets")
    assert sia.bulk_create_target_sets([{"strong_account_id": "s2", "target_sets": []}])[0]["success"] is True
    assert session.requests[4][2]["json"] == {"target_sets_mapping": [{"strong_account_id": "s2", "target_sets": []}]}
    assert sia.get_settings()["self_hosted_pam"]["tenant_type"] == "SELF_HOSTED"
    sia.update_target_set("a.corp", {"secret_id": "s2"})
    assert session.requests[6][:2] == ("PUT", "https://acme.dpa.cyberark.cloud/api/targetsets/a.corp")


def test_probe_detects_public_secrets_and_discovery_target_sets():
    client, session = http_with([FakeResponse(200, []), FakeResponse(404, "no such route"),
                                 FakeResponse(400, {"message": "strongAccountId is required"})])
    sia = SIAClient(client, "https://acme.dpa.cyberark.cloud")
    caps = sia.probe()
    assert caps.secrets_api == "public" and caps.targetsets_api == "discovery" and caps.targetsets_list_unfiltered is False and caps.probed
    assert session.requests[0][1] == "https://acme.dpa.cyberark.cloud/api/secrets/public/v1"
    assert session.requests[0][2]["params"] == {"secret_type": "ProvisionerUser,PCloudAccount", "count": "1"}
    assert session.requests[1][1].endswith("/api/targetsets") and session.requests[2][1].endswith("/api/discovery/targetsets")
    with pytest.raises(ValueError, match="strongAccountId"):
        sia.list_target_sets()
    assert caps.describe() == "secrets=public targetsets=discovery (listing needs strongAccountId)"


def test_probe_falls_back_to_legacy_and_propagates_real_errors():
    client, _ = http_with([FakeResponse(404, "nope"), FakeResponse(200, {"target_sets": []})])
    caps = SIAClient(client, "https://x").probe()
    assert caps.secrets_api == "legacy" and caps.targetsets_api == "legacy" and caps.targetsets_list_unfiltered
    client, _ = http_with([FakeResponse(403, "forbidden")])
    with pytest.raises(SIAApiError, match="403"):
        SIAClient(client, "https://x").probe()
    client, _ = http_with([FakeResponse(200, []), FakeResponse(404, "a"), FakeResponse(404, "b")])
    with pytest.raises(SIAApiError, match="404"):
        SIAClient(client, "https://x").probe()


def test_public_secrets_v2_pagination_then_v1_fallback():
    client, session = http_with([FakeResponse(200, {"secrets": [{"secret_name": "a"}], "b64_last_evaluated_key": "k"}),
                                 FakeResponse(200, {"secrets": [{"secret_name": "b"}]})])
    sia = SIAClient(client, "https://x", secrets_api="public", targetsets_api="legacy")
    assert [s["secret_name"] for s in sia.list_secrets()] == ["a", "b"]
    assert session.requests[0][1] == "https://x/api/secrets/public/v2" and session.requests[1][2]["params"]["b64StartKey"] == "k"
    client, session = http_with([FakeResponse(400, "v2 not here"), FakeResponse(200, [{"secret_name": "x"}] * 500),
                                 FakeResponse(200, [{"secret_name": "y"}])])
    sia = SIAClient(client, "https://x", secrets_api="public", targetsets_api="legacy")
    assert len(sia.list_secrets()) == 501
    assert session.requests[1][1] == "https://x/api/secrets/public/v1"
    assert session.requests[1][2]["params"]["count"] == "500" and session.requests[2][2]["params"]["offset"] == "500"


def test_find_secret_filters_by_name():
    client, session = http_with([FakeResponse(200, {"secrets": [{"secret_name": "ADM-web01"}, {"secret_name": "ADM-web010"}]})])
    sia = SIAClient(client, "https://x", secrets_api="public", targetsets_api="legacy")
    assert sia.find_secret("adm-web01")["secret_name"] == "ADM-web01"
    assert session.requests[0][2]["params"]["secret_name"] == "adm-web01"
    client, session = http_with([FakeResponse(200, [{"secret_name": "A"}, {"secret_name": "B"}])])
    sia = SIAClient(client, "https://x", secrets_api="legacy", targetsets_api="legacy")
    assert sia.find_secret("b")["secret_name"] == "B"
    assert "secret_name" not in session.requests[0][2]["params"]


def test_create_secret_public_falls_back_to_legacy_on_404():
    client, session = http_with([FakeResponse(404, "no route"), FakeResponse(201, {"secret_id": "s1"})])
    sia = SIAClient(client, "https://x", secrets_api="public", targetsets_api="legacy")
    assert sia.create_secret({"a": 1})["secret_id"] == "s1" and sia.capabilities.secrets_api == "legacy"
    assert session.requests[0][1] == "https://x/api/secrets/public/v1" and session.requests[1][1] == "https://x/api/secrets"


def test_target_sets_per_account_and_discovery_paths():
    client, session = http_with([FakeResponse(200, {"target_sets": [{"name": "a.corp", "secret_id": "s1"}, {"name": "b.corp", "secret_id": "s1"}]}),
                                 FakeResponse(207, {"results": []}), FakeResponse(200, {}),
                                 FakeResponse(400, {"message": "strong_account_id must be provided"})])
    sia = SIAClient(client, "https://x", secrets_api="legacy", targetsets_api="discovery")
    assert [t["name"] for t in sia.list_target_sets(strong_account_id="s1", name="A.CORP")] == ["a.corp"]
    assert session.requests[0][1] == "https://x/api/discovery/targetsets"
    assert session.requests[0][2]["params"] == {"strongAccountId": "s1", "name": "A.CORP"}
    sia.bulk_create_target_sets([])
    assert session.requests[1][1] == "https://x/api/discovery/targetsets/bulk"
    sia.update_target_set("a.corp", {})
    assert session.requests[2][1] == "https://x/api/discovery/targetsets/a.corp"
    with pytest.raises(ValueError, match="strongAccountId"):
        sia.list_target_sets()
    assert sia.capabilities.targetsets_list_unfiltered is False


def test_uap_client_pagination_find_create():
    p1 = {"metadata": {"name": "web01.corp", "policyId": "p1"}}
    p2 = {"metadata": {"name": "web01.corp-old", "policyId": "p2"}}
    client, session = http_with([
        FakeResponse(200, {"results": [p1], "nextToken": "n1"}),
        FakeResponse(200, {"results": [p2], "nextToken": None}),
        FakeResponse(200, {"results": [p1, p2]}),
        FakeResponse(200, {"policyId": "p3"}),
        FakeResponse(200, {**p1, "targets": {}}),
        FakeResponse(200, {}),
        FakeResponse(200, {"results": [p1]}),
        FakeResponse(200, {"results": []}),
    ])
    uap = UAPClient(client, "https://acme.uap.cyberark.cloud")
    assert [p["metadata"]["policyId"] for p in uap.list_policies()] == ["p1", "p2"]
    assert session.requests[0][2]["params"] == {"limit": 50, "filter": "(targetCategory eq 'VM')"}
    assert session.requests[1][2]["params"]["nextToken"] == "n1"
    assert uap.find_policy_by_name("web01.corp")["metadata"]["policyId"] == "p1"
    assert session.requests[2][2]["params"] == {"limit": 50, "q": "web01.corp"}
    assert uap.create_policy({"metadata": {"name": "x"}}) == "p3"
    assert uap.get_policy("p1")["metadata"]["policyId"] == "p1"
    uap.update_policy("p1", {"metadata": {}})
    assert session.requests[5][:2] == ("PUT", "https://acme.uap.cyberark.cloud/api/policies/p1")
    assert uap.find_policies_for_fqdn("web01.corp")[0]["metadata"]["policyId"] == "p1"
    assert session.requests[6][2]["params"] == {"limit": 50, "filter": "(targetCategory eq 'VM')", "q": "web01.corp"}
    assert owned_vm_filter("tag-1") == "((targetCategory eq 'VM') and (policyTags eq 'tag-1'))"
    assert uap.list_policies(filter_query=owned_vm_filter("tag-1")) == []
    assert session.requests[7][2]["params"]["filter"] == "((targetCategory eq 'VM') and (policyTags eq 'tag-1'))"


def test_uap_create_without_policy_id_is_error():
    client, _ = http_with([FakeResponse(200, {"something": "else"})])
    with pytest.raises(SIAApiError, match="no policyId"):
        UAPClient(client, "https://u").create_policy({})


def test_identity_client_uses_get_for_directories_and_post_for_query():
    client, session = http_with([
        FakeResponse(200, {"success": True, "Result": {"Results": [{"Row": {"Service": "CDS", "directoryServiceUuid": "u1"}}]}}),
        FakeResponse(200, {"success": True, "Result": {"Group": {"Results": [{"Row": {"SystemName": "G1", "InternalName": "i1"}}]}}}),
        FakeResponse(200, {"success": False, "Message": "Access denied"}),
    ])
    ident = IdentityClient(client, "https://abc.id.cyberark.cloud")
    assert ident.list_directories() == [{"Service": "CDS", "directoryServiceUuid": "u1"}]
    assert session.requests[0][:2] == ("GET", "https://abc.id.cyberark.cloud/Core/GetDirectoryServices")
    rows = ident.query_groups("G1", ["u1"])
    assert rows == [{"SystemName": "G1", "InternalName": "i1"}]
    assert session.requests[1][:2] == ("POST", "https://abc.id.cyberark.cloud/UserMgmt/DirectoryServiceQuery")
    body = session.requests[1][2]["json"]
    assert body["directoryServices"] == ["u1"] and json.loads(body["group"]) == {
        "_or": [{"DisplayName": {"_like": "G1"}}, {"SystemName": {"_like": "G1"}}]}
    assert "user" not in body and "roles" not in body
    with pytest.raises(SIAApiError, match="Access denied"):
        ident.query_groups("G2", ["u1"])


# ------------------------------------------------------------------ pvwa
def test_pvwa_client_logon_find_add_logoff():
    session = FakeSession([
        FakeResponse(200, '"tok-12345"'),
        FakeResponse(200, {"value": [{"id": "1_2", "name": "web01-Administrator", "safeName": "SIA-LocalAdmins"},
                                     {"id": "1_3", "name": "web01-Administrator-old", "safeName": "SIA-LocalAdmins"}]}),
        FakeResponse(201, {"id": "9_1", "name": "n"}),
        FakeResponse(200, {}),
    ])
    pv = PVWAClient("https://pvwa.corp/", auth_type="ldap", session=session, sleep=lambda s: None)
    pv.logon("svc", "pw-secret")
    method, url, kw = session.requests[0]
    assert (method, url) == ("POST", "https://pvwa.corp/PasswordVault/API/auth/LDAP/Logon")
    assert kw["json"] == {"username": "svc", "password": "pw-secret", "concurrentSession": True}
    assert redact("tok-12345 pw-secret") == "*** ***"
    assert pv.find_account("sia-localadmins", "WEB01-Administrator")["id"] == "1_2"
    kw = session.requests[1][2]
    assert kw["headers"]["Authorization"] == "tok-12345" and kw["params"] == {"search": "WEB01-Administrator", "filter": "safeName eq sia-localadmins"}
    assert pv.add_account({"name": "n"})["id"] == "9_1"
    assert session.requests[2][:2] == ("POST", "https://pvwa.corp/PasswordVault/API/Accounts")
    pv.logoff()
    assert session.requests[3][1] == "https://pvwa.corp/PasswordVault/API/auth/Logoff"
    with pytest.raises(SIAApiError, match="not logged on"):
        PVWAClient("https://p", session=FakeSession([])).find_account("s", "n")
    with pytest.raises(ValueError, match="auth_type"):
        PVWAClient("https://p", auth_type="radius")
    with pytest.raises(SIAApiError, match="no token"):
        PVWAClient("https://p", session=FakeSession([FakeResponse(200, {})])).logon("u", "p")
