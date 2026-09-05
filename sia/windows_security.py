"""Windows ACL handling for files that contain credentials.

The standard ``chmod`` compatibility layer on Windows only changes the read-only
attribute; it cannot make a file private.  This module uses native security APIs
and SID values so its behavior does not depend on the Windows display language.
"""
from __future__ import annotations

import ctypes
import os
import uuid
from dataclasses import dataclass
from pathlib import Path


class WindowsCredentialProtectionError(OSError):
    """A credential file could not be given or confirmed to have a private DACL.

    ``published`` lets an interactive caller describe the recovery accurately.
    False means no new credential bytes were placed at the destination.  True is
    reserved for a failure while confirming the destination after replacement.
    """

    def __init__(self, path: str | Path, detail: str, *, published: bool = False):
        self.path = Path(path)
        self.published = published
        state = ("The credential file was replaced, but Windows could not confirm its access controls."
                 if published else
                 "Credentials were not saved because Windows could not restrict access to the credential file.")
        super().__init__(f"{state} {detail} Path: {self.path}")


@dataclass(frozen=True)
class CredentialPermissionStatus:
    """The result of inspecting a credential file's Windows DACL."""

    secure: bool | None
    message: str

    @property
    def status(self) -> str:
        if self.secure is True:
            return "passed"
        if self.secure is False:
            return "warning"
        return "not checked"


def windows_acl_supported() -> bool:
    return os.name == "nt"


def _error_text(code: int | None = None) -> str:
    error = ctypes.get_last_error() if code is None else code
    try:
        return str(ctypes.WinError(error))
    except (AttributeError, ValueError):
        return f"Windows error {error}"


def _apis():
    """Load and type the native calls only on Windows, keeping POSIX imports safe."""
    if not windows_acl_supported():
        raise OSError("Windows ACL APIs are unavailable on this platform")
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                             wintypes.LPVOID, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID,
                                               ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        wintypes.LPVOID, ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, wintypes.LPVOID,
        wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        wintypes.LPVOID, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [wintypes.LPVOID, wintypes.DWORD,
                                ctypes.POINTER(wintypes.LPVOID)]
    advapi32.GetAce.restype = wintypes.BOOL

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.LPVOID]
    kernel32.LocalFree.restype = wintypes.LPVOID
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    return advapi32, kernel32, wintypes


def _sid_to_text(sid, advapi32, kernel32, wintypes) -> str:
    rendered = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(rendered)):
        raise OSError(_error_text())
    try:
        return rendered.value
    finally:
        kernel32.LocalFree(ctypes.cast(rendered, wintypes.LPVOID))


def _current_user_sid() -> str:
    advapi32, kernel32, wintypes = _apis()
    token = wintypes.HANDLE()
    TOKEN_QUERY = 0x0008
    TOKEN_USER = 1
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY,
                                     ctypes.byref(token)):
        raise OSError(_error_text())
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(needed))
        if not needed.value:
            raise OSError(_error_text())
        token_data = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TOKEN_USER, token_data,
                                            needed, ctypes.byref(needed)):
            raise OSError(_error_text())
        # TOKEN_USER begins with SID_AND_ATTRIBUTES; the first member is PSID.
        sid = ctypes.cast(token_data, ctypes.POINTER(wintypes.LPVOID)).contents
        return _sid_to_text(sid, advapi32, kernel32, wintypes)
    finally:
        kernel32.CloseHandle(token)


def _private_sddl() -> str:
    # SY and BA are SDDL aliases for LocalSystem and Builtin Administrators.
    # The current user SID is numeric, so none of these names are localized.
    return f"D:P(A;;FA;;;{_current_user_sid()})(A;;FA;;;SY)(A;;FA;;;BA)"


def _security_descriptor():
    advapi32, kernel32, wintypes = _apis()
    descriptor = wintypes.LPVOID()
    size = wintypes.DWORD()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            _private_sddl(), 1, ctypes.byref(descriptor), ctypes.byref(size)):
        raise OSError(_error_text())
    return descriptor, advapi32, kernel32, wintypes


def protect_credential_file(path: str | Path) -> None:
    """Replace one credential file's DACL with the private, protected DACL."""
    target = Path(path)
    try:
        descriptor, advapi32, kernel32, wintypes = _security_descriptor()
        try:
            present = wintypes.BOOL()
            defaulted = wintypes.BOOL()
            dacl = wintypes.LPVOID()
            if not advapi32.GetSecurityDescriptorDacl(
                    descriptor, ctypes.byref(present), ctypes.byref(dacl),
                    ctypes.byref(defaulted)) or not present.value:
                raise OSError(_error_text())
            # Protect the DACL from inheritance as well as applying the explicit entries.
            error = advapi32.SetNamedSecurityInfoW(
                str(target), 1, 0x00000004 | 0x80000000,
                None, None, dacl, None,
            )
            if error:
                raise OSError(_error_text(error))
        finally:
            kernel32.LocalFree(descriptor)
        status = inspect_credential_permissions(target)
        if status.secure is not True:
            raise OSError(status.message)
    except WindowsCredentialProtectionError:
        raise
    except Exception as exc:
        raise WindowsCredentialProtectionError(target, str(exc), published=False) from exc


def create_protected_temporary_file(directory: str | Path, prefix: str) -> tuple[int, Path]:
    """Create a new Windows file with the private DACL present from its first instant."""
    parent = Path(directory)
    try:
        descriptor, _advapi32, kernel32, wintypes = _security_descriptor()
    except Exception as exc:
        if isinstance(exc, WindowsCredentialProtectionError):
            raise
        raise WindowsCredentialProtectionError(parent, str(exc), published=False) from exc

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD),
                    ("lpSecurityDescriptor", wintypes.LPVOID),
                    ("bInheritHandle", wintypes.BOOL)]

    attributes = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
    GENERIC_READ_WRITE = 0x80000000 | 0x40000000
    SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
    CREATE_NEW = 1
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    handle = None
    temporary = None
    try:
        for _ in range(100):
            temporary = parent / f"{prefix}{uuid.uuid4().hex}.tmp"
            handle = kernel32.CreateFileW(
                str(temporary), GENERIC_READ_WRITE, SHARE_ALL,
                ctypes.byref(attributes), CREATE_NEW, FILE_ATTRIBUTE_NORMAL, None,
            )
            if handle != INVALID_HANDLE_VALUE:
                break
            if ctypes.get_last_error() not in (80, 183):  # ERROR_FILE_EXISTS / ALREADY_EXISTS
                raise OSError(_error_text())
        else:
            raise OSError("could not allocate a unique protected temporary file")
        import msvcrt
        try:
            fd = msvcrt.open_osfhandle(int(handle), os.O_RDWR | getattr(os, "O_BINARY", 0))
        except Exception:
            kernel32.CloseHandle(handle)
            handle = None
            raise
        handle = None  # Ownership transferred to the Python descriptor.
        status = inspect_credential_permissions(temporary)
        if status.secure is not True:
            os.close(fd)
            temporary.unlink(missing_ok=True)
            raise OSError(status.message)
        return fd, temporary
    except Exception as exc:
        if handle not in (None, INVALID_HANDLE_VALUE):
            kernel32.CloseHandle(handle)
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
        raise WindowsCredentialProtectionError(temporary or parent, str(exc), published=False) from exc
    finally:
        kernel32.LocalFree(descriptor)


def inspect_credential_permissions(path: str | Path) -> CredentialPermissionStatus:
    """Inspect the effective file DACL conservatively without changing it."""
    target = Path(path)
    if not windows_acl_supported():
        return CredentialPermissionStatus(None, "Windows ACL check is not applicable on this platform")
    if not target.exists():
        return CredentialPermissionStatus(None, f"{target} is not present")
    try:
        advapi32, kernel32, wintypes = _apis()
        dacl = wintypes.LPVOID()
        descriptor = wintypes.LPVOID()
        error = advapi32.GetNamedSecurityInfoW(
            str(target), 1, 0x00000004,
            None, None, ctypes.byref(dacl), None, ctypes.byref(descriptor),
        )
        if error:
            if descriptor:
                kernel32.LocalFree(descriptor)
            raise OSError(_error_text(error))
        try:
            if not dacl:
                return CredentialPermissionStatus(False, "Windows reports an unrestricted (null) DACL")
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not advapi32.GetSecurityDescriptorControl(
                    descriptor, ctypes.byref(control), ctypes.byref(revision)):
                raise OSError(_error_text())
            if not (control.value & 0x1000):  # SE_DACL_PROTECTED
                return CredentialPermissionStatus(
                    False, "Windows ACL inherits permissions from its parent directory")

            class ACL(ctypes.Structure):
                _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte),
                            ("AclSize", wintypes.WORD), ("AceCount", wintypes.WORD),
                            ("Sbz2", wintypes.WORD)]

            allowed = {_current_user_sid().upper(), "S-1-5-18", "S-1-5-32-544"}
            acl = ctypes.cast(dacl, ctypes.POINTER(ACL)).contents
            for index in range(acl.AceCount):
                ace = wintypes.LPVOID()
                if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                    raise OSError(_error_text())
                header = ctypes.string_at(ace, 8)
                ace_type = header[0]
                mask = int.from_bytes(header[4:8], "little")
                if ace_type == 0 and mask:  # ACCESS_ALLOWED_ACE_TYPE; SID starts at byte 8.
                    sid = _sid_to_text(wintypes.LPVOID(ace.value + 8), advapi32,
                                       kernel32, wintypes).upper()
                    if sid not in allowed:
                        return CredentialPermissionStatus(
                            False, f"Windows ACL grants access to another principal ({sid})")
                elif ace_type in (4, 5, 9, 11) and mask:
                    # Object/callback allow ACE layouts vary. Treat unrecognized grants as broad
                    # rather than claiming a credential file is private.
                    return CredentialPermissionStatus(
                        False, "Windows ACL contains an additional access-grant entry")
            return CredentialPermissionStatus(
                True, "Protected Windows ACL: current user, SYSTEM, and Administrators only")
        finally:
            kernel32.LocalFree(descriptor)
    except Exception as exc:
        return CredentialPermissionStatus(None, f"Windows ACL could not be inspected: {exc}")
