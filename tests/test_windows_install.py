from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "windows_install.py"


def load_installer():
    import importlib.util

    spec = importlib.util.spec_from_file_location("windows_install", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def installer():
    return load_installer()


def make_project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "sia").mkdir(parents=True)
    (root / "pyproject.toml").write_text("[project]\nname='sample'\n", encoding="utf-8")
    (root / "requirements.txt").write_text("", encoding="utf-8")
    (root / "sia_onboard.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "sia" / "__init__.py").write_text("", encoding="utf-8")
    return root


def test_script_parses_on_supported_python():
    result = subprocess.run([sys.executable, str(SCRIPT), "--help"], text=True, capture_output=True)
    assert result.returncode == 0
    assert "--no-launch" in result.stdout
    assert "--python" in result.stdout
    assert "--check" in result.stdout


def test_script_syntax_stays_compatible_with_old_cmd_fallback():
    import ast

    ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT), feature_version=(3, 7))


def test_fingerprint_changes_with_source(installer, tmp_path):
    root = make_project(tmp_path)
    before = installer.source_fingerprint(root)
    (root / "sia" / "__init__.py").write_text("CHANGED = True\n", encoding="utf-8")
    assert installer.source_fingerprint(root) != before


def test_incompatible_base_python_stops_before_writes(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    monkeypatch.setattr(installer, "compatible_python", lambda _python: False)
    monkeypatch.setattr(installer, "runtime_root", lambda _root: pytest.fail("must not create runtime"))

    with pytest.raises(installer.InstallError, match="3.11"):
        installer.install(Path(sys.executable), root)


def test_runtime_uses_project_when_local_and_writable(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    monkeypatch.setattr(installer, "_project_is_local", lambda _root: True)
    assert installer.runtime_root(root) == root / ".sia-runtime"


def test_runtime_falls_back_to_local_app_data(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    local = tmp_path / "local-app-data"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setattr(installer, "_project_is_local", lambda _root: False)
    first = installer.runtime_root(root)
    second = installer.runtime_root(root)
    assert first == second
    assert first.parent.parent == local / "SIA Policy"


def test_blocked_project_runtime_falls_back_to_local_app_data(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    local = tmp_path / "local-app-data"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setattr(installer, "_project_is_local", lambda _root: True)
    real_probe = installer._runtime_directory_writable

    def probe(path):
        if path == root / ".sia-runtime":
            return False
        return real_probe(path)

    monkeypatch.setattr(installer, "_runtime_directory_writable", probe)
    assert installer.runtime_root(root).parent.parent == local / "SIA Policy"


def test_read_only_project_stops_with_actionable_error(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    monkeypatch.setattr(installer, "_directory_writable", lambda _root: False)

    with pytest.raises(installer.InstallError, match="read-only.*Documents"):
        installer.runtime_root(root)


def test_pointer_write_is_atomic_utf8_and_readable(installer, tmp_path):
    env = tmp_path / "runtime" / "envs" / "one"
    python = installer.python_in(env)
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")
    pointer = tmp_path / ".sia-python.path"

    installer.atomic_write_pointer(pointer, python)

    assert pointer.read_bytes().decode("utf-8").strip() == str(installer._absolute(python))
    assert installer.read_pointer(pointer) == env
    assert not list(tmp_path.glob(".sia-python.path.tmp-*"))


def test_corrupt_non_utf8_pointer_is_treated_as_repairable(installer, tmp_path):
    pointer = tmp_path / installer.POINTER_NAME
    pointer.write_bytes(b"\xff\xfe\xfa")
    assert installer.read_pointer(pointer) is None


def test_pointer_keeps_venv_path_instead_of_resolving_symlink(installer, tmp_path):
    env = tmp_path / "env"
    python = installer.python_in(env)
    python.parent.mkdir(parents=True)
    base = tmp_path / "base-python"
    base.write_bytes(b"")
    try:
        python.symlink_to(base)
    except OSError:
        pytest.skip("symlinks are unavailable")
    pointer = tmp_path / installer.POINTER_NAME

    installer.atomic_write_pointer(pointer, python)

    assert pointer.read_text(encoding="utf-8").strip() == str(installer._absolute(python))
    assert pointer.read_text(encoding="utf-8").strip() != str(python.resolve())


def test_failed_candidate_never_changes_working_pointer(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    runtime = root / ".sia-runtime"
    previous_env = runtime / "envs" / "previous"
    previous_python = installer.python_in(previous_env)
    previous_python.parent.mkdir(parents=True)
    previous_python.write_bytes(b"")
    pointer = root / installer.POINTER_NAME
    installer.atomic_write_pointer(pointer, previous_python)

    monkeypatch.setattr(installer, "compatible_python", lambda _python: True)
    monkeypatch.setattr(installer, "select_existing", lambda *_args: None)
    monkeypatch.setattr(installer, "_create_venv", lambda *_args: None)
    monkeypatch.setattr(installer, "_install_project", lambda *_args: (_ for _ in ()).throw(installer.InstallError("network")))

    with pytest.raises(installer.InstallError, match="network"):
        installer.install(Path(sys.executable), root)

    assert pointer.read_text(encoding="utf-8").strip() == str(installer._absolute(previous_python))
    assert not [path for path in (runtime / "envs").iterdir() if path.name != "previous"]


def test_success_points_only_after_validation(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    events = []
    monkeypatch.setattr(installer, "compatible_python", lambda _python: True)
    monkeypatch.setattr(installer, "select_existing", lambda *_args: None)

    def create(_base, env):
        python = installer.python_in(env)
        python.parent.mkdir(parents=True)
        python.write_bytes(b"")
        events.append("created")

    monkeypatch.setattr(installer, "_create_venv", create)
    monkeypatch.setattr(installer, "_install_project", lambda *_args: events.append("installed"))
    monkeypatch.setattr(installer, "validate_environment", lambda *_args, **_kwargs: events.append("validated") or True)
    original_write = installer.atomic_write_pointer

    def write(pointer, python):
        events.append("pointed")
        original_write(pointer, python)

    monkeypatch.setattr(installer, "atomic_write_pointer", write)
    python, pointer, reused = installer.install(Path(sys.executable), root)

    assert not reused
    assert events == ["created", "installed", "validated", "pointed"]
    assert pointer.read_text(encoding="utf-8").strip() == str(installer._absolute(python))
    metadata = json.loads((python.parent.parent / installer.METADATA_NAME).read_text(encoding="utf-8"))
    assert metadata["source_fingerprint"] == installer.source_fingerprint(root)


def test_source_change_during_install_does_not_switch_pointer(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    old_env = root / ".sia-runtime" / "envs" / "old"
    old_python = installer.python_in(old_env)
    old_python.parent.mkdir(parents=True)
    old_python.write_bytes(b"")
    pointer = root / installer.POINTER_NAME
    installer.atomic_write_pointer(pointer, old_python)
    monkeypatch.setattr(installer, "compatible_python", lambda _python: True)
    monkeypatch.setattr(installer, "select_existing", lambda *_args: None)

    def create(_base, env):
        python = installer.python_in(env)
        python.parent.mkdir(parents=True)
        python.write_bytes(b"")

    monkeypatch.setattr(installer, "_create_venv", create)
    monkeypatch.setattr(installer, "_install_project", lambda *_args: None)
    monkeypatch.setattr(installer, "validate_environment", lambda *_args, **_kwargs: True)
    fingerprints = iter(("before", "after"))
    monkeypatch.setattr(installer, "source_fingerprint", lambda _root: next(fingerprints))

    with pytest.raises(installer.InstallError, match="changed during installation"):
        installer.install(Path(sys.executable), root)
    assert pointer.read_text(encoding="utf-8").strip() == str(installer._absolute(old_python))


def test_reuses_verified_project_venv_without_installing(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    env = root / ".venv"
    python = installer.python_in(env)
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")
    monkeypatch.setattr(installer, "compatible_python", lambda _python: True)
    monkeypatch.setattr(
        installer,
        "validate_environment",
        lambda candidate, *_args, **_kwargs: candidate == env,
    )
    monkeypatch.setattr(installer, "_create_venv", lambda *_args: pytest.fail("should reuse"))

    selected, pointer, reused = installer.install(Path(sys.executable), root)

    assert reused
    assert selected == python
    assert pointer.read_text(encoding="utf-8").strip() == str(installer._absolute(python))


def test_post_publish_interrupt_never_removes_referenced_environment(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    monkeypatch.setattr(installer, "compatible_python", lambda _python: True)
    monkeypatch.setattr(installer, "select_existing", lambda *_args: None)

    def create(_base, env):
        python = installer.python_in(env)
        python.parent.mkdir(parents=True)
        python.write_bytes(b"")

    monkeypatch.setattr(installer, "_create_venv", create)
    monkeypatch.setattr(installer, "_install_project", lambda *_args: None)
    monkeypatch.setattr(installer, "validate_environment", lambda *_args, **_kwargs: True)
    real_publish = installer.atomic_write_pointer

    def publish_then_interrupt(pointer, python):
        real_publish(pointer, python)
        raise KeyboardInterrupt

    monkeypatch.setattr(installer, "atomic_write_pointer", publish_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        installer.install(Path(sys.executable), root)

    pointer = root / installer.POINTER_NAME
    env = installer.read_pointer(pointer)
    assert env is not None and env.is_dir()
    assert installer.pointer_references(pointer, installer.python_in(env))


def test_precommit_pointer_failure_preserves_previous_and_removes_candidate(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    old_env = root / ".sia-runtime" / "envs" / "old"
    old_python = installer.python_in(old_env)
    old_python.parent.mkdir(parents=True)
    old_python.write_bytes(b"")
    pointer = root / installer.POINTER_NAME
    installer.atomic_write_pointer(pointer, old_python)
    monkeypatch.setattr(installer, "compatible_python", lambda _python: True)
    monkeypatch.setattr(installer, "select_existing", lambda *_args: None)
    created = []

    def create(_base, env):
        created.append(env)
        python = installer.python_in(env)
        python.parent.mkdir(parents=True)
        python.write_bytes(b"")

    monkeypatch.setattr(installer, "_create_venv", create)
    monkeypatch.setattr(installer, "_install_project", lambda *_args: None)
    monkeypatch.setattr(installer, "validate_environment", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(installer, "atomic_write_pointer", lambda *_args: (_ for _ in ()).throw(OSError("locked")))

    with pytest.raises(OSError, match="locked"):
        installer.install(Path(sys.executable), root)
    assert installer.pointer_references(pointer, old_python)
    assert created and not created[0].exists()


def test_uninspectable_pointer_after_publication_attempt_retains_candidate(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    monkeypatch.setattr(installer, "compatible_python", lambda _python: True)
    monkeypatch.setattr(installer, "select_existing", lambda *_args: None)
    created = []

    def create(_base, env):
        created.append(env)
        python = installer.python_in(env)
        python.parent.mkdir(parents=True)
        python.write_bytes(b"")

    monkeypatch.setattr(installer, "_create_venv", create)
    monkeypatch.setattr(installer, "_install_project", lambda *_args: None)
    monkeypatch.setattr(installer, "validate_environment", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(installer, "atomic_write_pointer", lambda *_args: (_ for _ in ()).throw(OSError("locked")))
    monkeypatch.setattr(installer, "_pointer_reference_state", lambda *_args: None)

    with pytest.raises(OSError, match="locked"):
        installer.install(Path(sys.executable), root)
    assert created and created[0].is_dir()


def test_check_current_requires_pointer_and_current_valid_runtime(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    assert not installer.check_current(root)
    env = root / ".sia-runtime" / "envs" / "current"
    python = installer.python_in(env)
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")
    installer.atomic_write_pointer(root / installer.POINTER_NAME, python)
    monkeypatch.setattr(installer, "validate_environment", lambda candidate, *_args, **_kwargs: candidate == env)

    assert installer.check_current(root)


def test_successful_imports_without_matching_metadata_are_not_reusable(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    env = root / ".venv"
    python = installer.python_in(env)
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")
    monkeypatch.setattr(installer, "compatible_python", lambda _python: True)
    monkeypatch.setattr(
        installer,
        "_run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )

    assert not installer.validate_environment(env, root, installer.source_fingerprint(root))


def test_create_venv_repairs_missing_pip_with_ensurepip(installer, monkeypatch, tmp_path):
    env = tmp_path / "env"
    calls = []

    def fake_run(command, **_kwargs):
        calls.append([str(part) for part in command])
        if command[1:3] == ["-m", "venv"]:
            python = installer.python_in(env)
            python.parent.mkdir(parents=True)
            python.write_bytes(b"")
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[1:4] == ["-m", "pip", "--version"]:
            installed = any(call[1:3] == ["-m", "ensurepip"] for call in calls)
            return subprocess.CompletedProcess(command, 0 if installed else 1, "", "")
        if command[1:3] == ["-m", "ensurepip"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(command)

    monkeypatch.setattr(installer, "_run", fake_run)
    installer._create_venv(Path(sys.executable), env)
    assert any(call[1:3] == ["-m", "ensurepip"] for call in calls)


def test_create_venv_timeout_uses_without_pip_fallback(installer, monkeypatch, tmp_path):
    env = tmp_path / "env"
    calls = []

    def fake_run(command, **_kwargs):
        calls.append([str(part) for part in command])
        if command[1:3] == ["-m", "venv"] and "--without-pip" not in command:
            raise installer.InstallError("timed out")
        if command[1:3] == ["-m", "venv"]:
            python = installer.python_in(env)
            python.parent.mkdir(parents=True)
            python.write_bytes(b"")
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[1:3] == ["-m", "ensurepip"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[1:4] == ["-m", "pip", "--version"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(command)

    monkeypatch.setattr(installer, "_run", fake_run)
    installer._create_venv(Path(sys.executable), env)
    assert any("--without-pip" in call for call in calls)


def test_pip_timeout_continues_from_offline_wheelhouse_to_network(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path)
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "dependency.whl").write_bytes(b"wheel")
    env = tmp_path / "env"
    calls = []

    def fake_run(command, **_kwargs):
        calls.append([str(part) for part in command])
        if len(calls) == 1:
            raise installer.InstallError("offline attempt timed out")
        return subprocess.CompletedProcess(command, 0, "installed", "")

    monkeypatch.setattr(installer, "_run", fake_run)
    installer._install_project(env, root)
    assert len(calls) == 2
    assert "--no-index" in calls[0]
    assert "--no-index" not in calls[1]


def test_launch_uses_absolute_project_paths(installer, monkeypatch, tmp_path):
    root = make_project(tmp_path).resolve()
    python = (tmp_path / "runtime" / "Scripts" / "python.exe").resolve()
    captured = {}

    def fake_call(command, cwd):
        captured["command"] = command
        captured["cwd"] = cwd
        return 0

    monkeypatch.setattr(installer.subprocess, "call", fake_call)
    assert installer.launch(python, root) == 0
    assert captured["cwd"] == str(root)
    joined = "\n".join(captured["command"])
    for expected in (root / "config.toml", root / ".env", root / "input", root / "reports"):
        assert str(expected) in joined
    assert captured["command"][1:3] == ["-m", "sia.bootstrap"]
