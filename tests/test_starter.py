from concurrent.futures import ThreadPoolExecutor
from importlib.resources import files

import pytest

from sia.config import ConfigError, load_config
from sia.starter import ensure_starter_config, missing_tenant_fields


def test_starter_requires_real_tenant_settings(tmp_path):
    path = tmp_path / "config.toml"
    assert ensure_starter_config(path) is True
    assert missing_tenant_fields(path) == ("tenant.subdomain", "tenant.identity_url")
    with pytest.raises(ConfigError, match="subdomain"):
        load_config(path)

    text = path.read_text().replace('subdomain = ""', 'subdomain = "mytenant"')
    path.write_text(text.replace('identity_url = ""', 'identity_url = "https://myidentity.id.cyberark.cloud"'))
    assert missing_tenant_fields(path) == ()
    config = load_config(path)
    assert config.tenant.subdomain == "mytenant"
    assert config.http.verify is True
    assert config.defaults.target_set_cert_validation is True


def test_existing_config_is_never_changed(tmp_path):
    path = tmp_path / "config.toml"
    original = b"# My project settings, even if temporarily invalid.\n"
    path.write_bytes(original)
    assert ensure_starter_config(path) is False
    assert path.read_bytes() == original


def test_exclusive_creation_handles_concurrent_launches(tmp_path):
    path = tmp_path / "config.toml"
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: ensure_starter_config(path), range(8)))
    assert results.count(True) == 1
    assert path.read_bytes() == files("sia").joinpath("config.toml").read_bytes()


@pytest.mark.parametrize("target_exists", [False, True])
def test_existing_symlink_is_not_followed_or_replaced(tmp_path, target_exists):
    target = tmp_path / "actual.toml"
    if target_exists:
        target.write_text("# existing settings\n")
    path = tmp_path / "config.toml"
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks are unavailable on this system")
    assert ensure_starter_config(path) is False
    assert path.is_symlink()
    assert target.exists() is target_exists
    if target_exists:
        assert target.read_text() == "# existing settings\n"


def test_missing_parent_has_clear_error(tmp_path):
    with pytest.raises(ConfigError, match="existing writable project folder"):
        ensure_starter_config(tmp_path / "missing" / "config.toml")


def test_failed_write_does_not_leave_partial_starter(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"

    def full_disk(_):
        raise OSError("No space left on device")

    monkeypatch.setattr("sia.starter.os.fsync", full_disk)
    with pytest.raises(ConfigError, match="No space left on device"):
        ensure_starter_config(path)
    assert not path.exists()


@pytest.mark.parametrize("text, expected", [
    ("", ("tenant.subdomain", "tenant.identity_url")),
    ('[tenant]\nsubdomain = "mytenant"\nidentity_url = "  "\n', ("tenant.identity_url",)),
    ('[tenant]\nsubdomain = 42\nidentity_url = "https://identity.example"\n', ()),
])
def test_missing_fields_are_separate_from_config_validation(tmp_path, text, expected):
    path = tmp_path / "config.toml"
    path.write_text(text)
    assert missing_tenant_fields(path) == expected


@pytest.mark.parametrize("text", ['[tenant\n', 'tenant = "bad table"\n'])
def test_bad_toml_is_not_reported_as_blank_setup(tmp_path, text):
    path = tmp_path / "config.toml"
    path.write_text(text)
    with pytest.raises(ConfigError):
        missing_tenant_fields(path)
