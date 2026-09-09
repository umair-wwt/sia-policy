import logging
import ssl
import sys

import pytest

from sia import trust
from sia.config import HttpConfig

log = logging.getLogger("tests.trust")


def _unpatch_ssl() -> None:
    try:
        import truststore
    except ImportError:
        return
    truststore.extract_from_ssl()


@pytest.fixture(autouse=True)
def clean_ssl():
    """Start and finish unpatched: inject_into_ssl() patches ssl.SSLContext for the whole process,
    and any earlier test that built a Context may already have done so."""
    _unpatch_ssl()
    trust._INJECTED = False
    yield
    _unpatch_ssl()
    trust._INJECTED = False


def test_system_trust_is_the_default_source_and_patches_ssl():
    verify, source = trust.apply_trust_policy(HttpConfig(), log)
    assert verify is True
    if trust.system_trust_available():
        assert source == "system" and ssl.SSLContext is not None and trust._INJECTED
    else:
        assert source == "certifi"


def test_ca_bundle_wins_over_the_system_store_and_does_not_patch_ssl(tmp_path):
    bundle = tmp_path / "corp-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    verify, source = trust.apply_trust_policy(HttpConfig(ca_bundle=str(bundle), system_trust=True), log)
    assert verify == str(bundle) and source == "ca_bundle"
    assert not trust._INJECTED, "an explicit bundle must not be silently replaced by the system store"


def test_disabled_verification_is_reported_and_never_patches_ssl():
    verify, source = trust.apply_trust_policy(HttpConfig(verify=False, system_trust=True), log)
    assert verify is False and source == "disabled" and not trust._INJECTED


def test_opting_out_of_system_trust_falls_back_to_certifi():
    verify, source = trust.apply_trust_policy(HttpConfig(system_trust=False), log)
    assert verify is True and source == "certifi" and not trust._INJECTED


def test_missing_truststore_degrades_to_certifi_without_raising(monkeypatch):
    """The package is recommended, not required: a stripped environment must still run."""
    monkeypatch.setitem(sys.modules, "truststore", None)   # makes `import truststore` raise ImportError
    assert trust.system_trust_available() is False
    verify, source = trust.apply_trust_policy(HttpConfig(), log)
    assert verify is True and source == "certifi"
    assert trust.describe_trust(HttpConfig()) == "certifi (default trust store)"


def test_describe_trust_names_the_store_in_use(tmp_path):
    bundle = tmp_path / "corp-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    assert trust.describe_trust(HttpConfig(ca_bundle=str(bundle))) == f"CA bundle {bundle}"
    assert "VERIFICATION OFF" in trust.describe_trust(HttpConfig(verify=False))
    assert trust.describe_trust(HttpConfig(system_trust=False)) == "certifi (default trust store)"
    if trust.system_trust_available():
        assert trust.describe_trust(HttpConfig()) == trust.system_store_name()


@pytest.mark.parametrize("http_cfg_kw, expected_source", [
    ({"ca_bundle": "BUNDLE"}, "ca_bundle"),
    ({"verify": False}, "disabled"),
])
def test_explicit_settings_release_an_active_injection(tmp_path, http_cfg_kw, expected_source):
    """While injected, a bundle is only an extra anchor: the OS store is tried first and can
    authorise what the bundle would reject. An explicit setting therefore has to run un-injected."""
    if not trust.system_trust_available():
        pytest.skip("truststore is not installed")
    bundle = tmp_path / "corp-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    if http_cfg_kw.get("ca_bundle") == "BUNDLE":
        http_cfg_kw = {**http_cfg_kw, "ca_bundle": str(bundle)}
    assert trust.inject_system_trust() is True and trust._INJECTED
    _, source = trust.apply_trust_policy(HttpConfig(**http_cfg_kw), log)
    assert source == expected_source
    assert not trust._INJECTED, "the explicit setting must actually constrain trust"


def test_system_store_is_named_for_the_platform(monkeypatch):
    """Operators need to know where to look: certlm.msc on Windows, Keychain Access on macOS."""
    for platform, expected in (("win32", "Windows certificate store"),
                               ("darwin", "macOS keychain"),
                               ("linux", "system trust store")):
        monkeypatch.setattr(trust.sys, "platform", platform)
        assert trust.system_store_name() == expected
        if trust.system_trust_available():
            assert trust.describe_trust(HttpConfig()) == expected


def test_injection_is_idempotent():
    if not trust.system_trust_available():
        pytest.skip("truststore is not installed")
    assert trust.inject_system_trust() is True
    assert trust.inject_system_trust() is True


def test_trust_context_verifies_by_default():
    ctx = trust.trust_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
