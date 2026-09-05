"""Stage complete local outputs before publishing them, retaining partial-publish evidence."""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Iterable


class ArtifactWriteError(OSError):
    def __init__(self, path: Path, cause: BaseException, intended: tuple[Path, ...], completed: tuple[Path, ...]):
        self.path = path
        self.cause = cause
        self.intended_paths = intended
        self.completed_paths = completed
        self.interrupted = isinstance(cause, KeyboardInterrupt) or bool(getattr(cause, "interrupted", False))
        self.mutation_state = "not_applicable"
        super().__init__(getattr(cause, "errno", None), f"Could not publish output {path}: {cause}", str(path))


def write_artifacts(payloads: Iterable[tuple[Path, bytes]], *, exclusive: Iterable[Path] = ()) -> list[Path]:
    """Each output is whole or absent; earlier complete outputs survive a publish failure.

    Explicit destinations retain replacement semantics. Exclusive destinations
    use an atomic hard link so another process cannot lose an existing output.
    All temporary files live beside their destination (same filesystem).
    """
    entries = [(Path(path).expanduser(), data) for path, data in payloads]
    intended = tuple(path for path, _ in entries)
    identities = [os.path.normcase(str(path.resolve())).casefold() for path in intended]
    if len(set(identities)) != len(identities):
        raise ValueError("Multiple outputs resolve to the same file; choose distinct output paths.")
    exclusive_paths = {Path(path).expanduser() for path in exclusive}
    staged: list[tuple[Path, Path]] = []
    completed: list[Path] = []
    current = intended[0] if intended else Path(".")
    active_temporary: Path | None = None
    publication_started = False
    try:
        for current, data in entries:
            current.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix=f".{current.name}.", suffix=".tmp", dir=current.parent)
            temporary = Path(name)
            active_temporary = temporary
            staged.append((current, temporary))
            with os.fdopen(fd, "wb") as stream:
                if current.is_file():
                    os.chmod(temporary, stat.S_IMODE(current.stat().st_mode))
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        for current, temporary in staged:
            active_temporary = temporary
            publication_started = True
            if current in exclusive_paths:
                os.link(temporary, current)
            else:
                os.replace(temporary, current)
            completed.append(current)
            publication_started = False
    except (OSError, KeyboardInterrupt) as exc:
        # A signal can arrive after the publish syscall completed but before the
        # path was appended above. Recover that exact evidence from the staged
        # inode/source state instead of reporting the file as absent.
        if publication_started and active_temporary is not None and current not in completed:
            try:
                if current in exclusive_paths:
                    published = (current.exists() and active_temporary.exists()
                                 and os.path.samefile(current, active_temporary))
                else:
                    published = current.exists() and not active_temporary.exists()
                if published:
                    completed.append(current)
            except OSError:
                pass
        raise ArtifactWriteError(current, exc, intended, tuple(completed)) from exc
    finally:
        for _, temporary in staged:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return completed


def available_path(path: Path, *, reserved: set[str] | None = None) -> Path:
    """Suggest an unused name, also avoiding resolved names reserved by this batch."""
    index = 0
    candidate = path
    while (candidate.exists() or candidate.is_symlink()
           or (reserved is not None and str(candidate.resolve()).casefold() in reserved)):
        index += 1
        candidate = path.with_name(f"{path.stem}-{index:02d}{path.suffix}")
    return candidate
