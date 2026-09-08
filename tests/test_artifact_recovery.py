import errno
from dataclasses import replace
from pathlib import Path

import pytest

import sia.artifacts as artifacts
from sia.connect import ConnectRow, build_rows, rdp_file_name, write_connection_outputs, write_rdp_files
from sia.report import ReportWriteError, write_reports, write_verify_csv
from tests.test_connect import CFG
from tests.test_report_redact import result_with
from tests.test_resolve_reconcile import inputs, srv


def connection(path):
    return ConnectRow("web.example.com", "web", "web-policy", "Admins", "rdp", "SA", "", "", "", "",
                      "https://acme.cyberark.cloud/dpa", "acme.rdp.cyberark.cloud",
                      "secureaccess /i user@acme /s acme /a web.example.com", str(path))


def test_stage_failure_preserves_previous_csv_and_rdp(tmp_path, monkeypatch):
    csv, rdp = tmp_path / "connections.csv", tmp_path / "web.rdp"
    csv.write_text("previous csv")
    rdp.write_text("previous rdp")
    original = artifacts.os.fsync
    count = 0
    def fail_second(fd):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError(errno.ENOSPC, "disk full")
        return original(fd)
    monkeypatch.setattr(artifacts.os, "fsync", fail_second)
    with pytest.raises(artifacts.ArtifactWriteError) as caught:
        write_connection_outputs([connection(rdp)], csv)
    assert csv.read_text() == "previous csv" and rdp.read_text() == "previous rdp"
    assert not caught.value.completed_paths
    assert not list(tmp_path.glob(".*.tmp"))


def test_publish_failure_reports_complete_paths_and_preserves_failed_destination(tmp_path, monkeypatch):
    csv, rdp = tmp_path / "connections.csv", tmp_path / "web.rdp"
    rdp.write_text("previous rdp")
    original = artifacts.os.replace
    def fail_rdp(source, destination):
        if Path(destination) == rdp:
            raise PermissionError(errno.EACCES, "file open elsewhere")
        return original(source, destination)
    monkeypatch.setattr(artifacts.os, "replace", fail_rdp)
    with pytest.raises(artifacts.ArtifactWriteError) as caught:
        write_connection_outputs([connection(rdp)], csv)
    assert caught.value.completed_paths == (csv,)
    assert csv.read_text().startswith("fqdn,hostname,")
    assert rdp.read_text() == "previous rdp"


def test_report_publish_interrupt_retains_completed_json_path(tmp_path, monkeypatch):
    original = artifacts.os.link
    published = 0

    def interrupt_second(source, target):
        nonlocal published
        published += 1
        if published == 2:
            raise KeyboardInterrupt
        return original(source, target)

    monkeypatch.setattr(artifacts.os, "link", interrupt_second)
    with pytest.raises(ReportWriteError) as caught:
        write_reports(result_with([("created", "created")]), tmp_path / "reports")
    error = caught.value
    assert error.interrupted
    assert error.completed_paths == (error.paths.json_path,)
    assert error.paths.json_path.is_file() and not error.paths.csv_path.exists()


def test_interrupt_after_publish_syscall_still_records_completed_path(tmp_path, monkeypatch):
    destination = tmp_path / "result.json"
    original = artifacts.os.link

    def interrupt_after_link(source, target):
        original(source, target)
        raise KeyboardInterrupt

    monkeypatch.setattr(artifacts.os, "link", interrupt_after_link)
    with pytest.raises(artifacts.ArtifactWriteError) as caught:
        artifacts.write_artifacts([(destination, b"complete")], exclusive=(destination,))
    assert caught.value.interrupted
    assert caught.value.completed_paths == (destination,)
    assert destination.read_bytes() == b"complete"


def test_generated_exports_and_racing_publish_never_overwrite(tmp_path, monkeypatch):
    destination = tmp_path / "connect-info-fixed.csv"
    original = artifacts.os.link
    raced = False
    def racing_link(source, target):
        nonlocal raced
        if not raced:
            raced = True
            Path(target).write_text("other process")
        return original(source, target)
    monkeypatch.setattr(artifacts.os, "link", racing_link)
    first, _ = write_connection_outputs([], destination, generated=True)
    second, _ = write_connection_outputs([], destination, generated=True)
    assert len({first, second, destination}) == 3
    assert destination.read_text() == "other process"


def test_rdp_generation_error_happens_before_any_destination_write(tmp_path):
    path = tmp_path / "web.rdp"
    path.write_text("previous")
    rows = [connection(path), replace(connection(tmp_path / "bad.rdp"), fqdn="bad\ncontent")]
    with pytest.raises(Exception, match="FQDN"):
        write_rdp_files(rows)
    assert path.read_text() == "previous"


def test_duplicate_export_paths_are_rejected_before_writing(tmp_path):
    path = tmp_path / "collision"
    with pytest.raises(ValueError, match="same file"):
        write_connection_outputs([connection(path)], path)
    assert not path.exists()


def test_same_hostname_across_domains_has_distinct_deterministic_rdp_files(tmp_path):
    inventory = inputs([srv(f"web.{domain}.example", "SA", ["Admins"]) for domain in ("corp", "dmz")], [])
    names = {(row.fqdn, row.line): row.fqdn for row in inventory.servers}
    first = build_rows(inventory, CFG, names, None, suffix="acme", rdp_dir=tmp_path)
    second = build_rows(inventory, CFG, names, None, suffix="acme", rdp_dir=tmp_path)
    assert len({row.rdp_file for row in first}) == 2
    assert [row.rdp_file for row in first] == [row.rdp_file for row in second]


def test_verify_csv_keeps_old_output_when_staging_fails(tmp_path, monkeypatch):
    output = tmp_path / "verify.csv"
    output.write_text("previous")
    def fail(fd):
        raise OSError(errno.ENOSPC, "disk full")
    monkeypatch.setattr(artifacts.os, "fsync", fail)
    with pytest.raises(OSError):
        write_verify_csv(result_with([("exists", "exists")]), output)
    assert output.read_text() == "previous"


def test_generated_rdp_names_are_portable_for_reserved_and_long_names():
    assert rdp_file_name(srv("con.example.com", "SA", ["Admins"]), "policy", False) == "_con.rdp"
    server = srv("a" * 63 + ".example.com", "SA", ["Admins"])
    first = rdp_file_name(server, "p" * 200, True)
    second = rdp_file_name(server, "p" * 199 + "x", True)
    assert len(first) < 255 and first != second


def test_generated_rdp_exports_keep_existing_files_and_update_csv_references(tmp_path):
    import csv
    path = tmp_path / "web.rdp"
    path.write_text("user's existing RDP file")
    rows = [connection(path)]
    output, written = write_connection_outputs(rows, tmp_path / "connections.csv", generated_rdp=True)
    assert path.read_text() == "user's existing RDP file"
    assert written == [tmp_path / "web-01.rdp"]
    with output.open(newline="") as stream:
        assert list(csv.DictReader(stream))[0]["rdp_file"] == str(written[0])


def test_generated_rdp_suffix_cannot_collide_with_another_row(tmp_path):
    first = tmp_path / "web.rdp"
    first.write_text("previous")
    rows = [connection(first), connection(tmp_path / "web-01.rdp")]
    _, written = write_connection_outputs(rows, tmp_path / "connections.csv", generated_rdp=True)
    assert first.read_text() == "previous"
    assert len(set(written)) == 2 and all(path.is_file() for path in written)
    assert [row.rdp_file for row in rows] == [str(path) for path in written]


def test_exclusive_publish_falls_back_when_hard_links_are_unsupported(tmp_path, monkeypatch):
    def no_links(source, target):
        raise OSError(errno.EPERM, "Operation not permitted")   # exFAT, FAT32, some network shares

    monkeypatch.setattr(artifacts.os, "link", no_links)
    json_path, csv_path = write_reports(result_with([("created", "created")]), tmp_path / "reports")
    assert json_path.is_file() and csv_path.read_text().startswith("fqdn,")
    assert not list((tmp_path / "reports").glob(".*.tmp"))
    again, _ = write_reports(result_with([("created", "created")]), tmp_path / "reports")
    assert again != json_path and json_path.stat().st_size > 0          # a generated name is never reused
    csv, rdp = tmp_path / "connections.csv", tmp_path / "web.rdp"
    written, files = write_connection_outputs([connection(rdp)], csv, generated=True, generated_rdp=True)
    assert written.is_file() and files == [rdp] and rdp.read_text().startswith("full address:s:web.example.com")


def test_exclusive_fallback_never_replaces_an_existing_output(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts.os, "link", lambda source, target: (_ for _ in ()).throw(OSError(errno.EPERM, "no links")))
    destination = tmp_path / "result.json"
    destination.write_text("other process")
    with pytest.raises(artifacts.ArtifactWriteError) as caught:
        artifacts.write_artifacts([(destination, b"mine")], exclusive=(destination,))
    assert isinstance(caught.value.cause, FileExistsError) and caught.value.completed_paths == ()
    assert destination.read_text() == "other process" and not list(tmp_path.glob(".*.tmp"))


def test_interrupted_fallback_copy_leaves_no_partial_output(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts.os, "link", lambda source, target: (_ for _ in ()).throw(OSError(errno.EPERM, "no links")))
    original = artifacts.os.fsync
    calls = 0

    def interrupt_publish(fd):
        nonlocal calls
        calls += 1
        if calls == 2:      # the first fsync stages the temporary file; the second publishes the copy
            raise KeyboardInterrupt
        return original(fd)

    monkeypatch.setattr(artifacts.os, "fsync", interrupt_publish)
    destination = tmp_path / "result.json"
    with pytest.raises(artifacts.ArtifactWriteError) as caught:
        artifacts.write_artifacts([(destination, b"complete")], exclusive=(destination,))
    assert caught.value.interrupted and caught.value.completed_paths == ()
    assert not destination.exists() and not list(tmp_path.glob(".*.tmp"))
