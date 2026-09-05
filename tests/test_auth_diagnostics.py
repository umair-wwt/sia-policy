import pytest
import requests

from sia.auth import AuthError, PlatformTokenProvider
from sia.diagnostics import diagnose
from sia.pvwa import PVWAClient
from sia.http import SIAApiError
from tests.fakes import FakeResponse, FakeSession


def test_auth_error_exposes_structure_without_response_body():
    marker = "unregistered-server-echo"
    provider = PlatformTokenProvider(
        "https://abc.id.cyberark.cloud", "svc", "pw",
        session=FakeSession([FakeResponse(401, {"error_description": marker})]),
    )
    with pytest.raises(AuthError) as caught:
        provider()
    exc = caught.value
    assert exc.status == 401 and exc.operation == "platform token request"
    assert marker not in str(exc) and "response suppressed" in str(exc)
    diag = diagnose(exc, stage="authentication")
    assert diag.code == "SIA-AUTH-REJECTED" and diag.mutation_state == "not_applicable"
    assert marker not in str(diag.to_dict())


def test_missing_credentials_and_network_cause_have_specific_help():
    with pytest.raises(AuthError) as caught:
        PlatformTokenProvider("https://x", "", "")
    missing = diagnose(caught.value)
    assert missing.code == "SIA-AUTH-MISSING" and "SIA_CLIENT_ID" in missing.message

    failure = requests.exceptions.SSLError("certificate verify failed")
    provider = PlatformTokenProvider("https://x", "svc", "pw", session=FakeSession([lambda *_: (_ for _ in ()).throw(failure)]))
    with pytest.raises(AuthError) as caught:
        provider()
    assert caught.value.cause is failure and diagnose(caught.value).code == "SIA-TLS"


def test_pvwa_auth_failure_suppresses_body_and_keeps_status():
    marker = "server-echo-that-was-not-registered"
    pvwa = PVWAClient("https://pvwa.example", session=FakeSession([FakeResponse(403, marker)]), sleep=lambda _: None)
    with pytest.raises(AuthError) as caught:
        pvwa.logon("svc", "pw")
    assert caught.value.status == 403 and caught.value.operation == "PVWA logon"
    assert marker not in str(caught.value)
    diag = diagnose(caught.value, stage="vault")
    assert diag.code == "SIA-PERMISSION" and marker not in str(diag.to_dict())


@pytest.mark.parametrize("lookup_body", [
    [], {}, {"value": None}, {"value": ["not-an-account"]},
    {"value": [{"name": "admin", "safeName": "Safe"}]},
])
def test_pvwa_malformed_lookup_never_looks_like_a_missing_account(lookup_body):
    pvwa = PVWAClient("https://pvwa.example", session=FakeSession([
        FakeResponse(200, '"token"'), FakeResponse(200, lookup_body),
    ]), sleep=lambda _: None)
    pvwa.logon("svc", "pw")
    with pytest.raises(SIAApiError) as caught:
        pvwa.find_account("Safe", "admin")
    assert caught.value.method == "GET" and caught.value.status == 200
    assert caught.value.cause == "malformed_response" and not caught.value.uncertain


@pytest.mark.parametrize("create_body", [None, [], {}, {"id": ""}, {"id": "1", "name": "other"}])
def test_pvwa_malformed_create_receipt_is_an_uncertain_mutation(create_body):
    pvwa = PVWAClient("https://pvwa.example", session=FakeSession([
        FakeResponse(200, '"token"'), FakeResponse(201, create_body),
    ]), sleep=lambda _: None)
    pvwa.logon("svc", "pw")
    with pytest.raises(SIAApiError) as caught:
        pvwa.add_account({"name": "admin", "safeName": "Safe"})
    assert caught.value.method == "POST" and caught.value.status == 201
    assert caught.value.uncertain and caught.value.cause == "malformed_response"
    assert diagnose(caught.value).mutation_state == "unknown"
