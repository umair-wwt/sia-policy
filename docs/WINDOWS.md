# Windows installation and daily use

Extract the complete project into a writable folder such as Documents, then double-click **`install.cmd`**.
Setup prepares the application and opens its terminal home. Choose `/setup` to enter your tenant information.
For later use, double-click **`Start-SIA.cmd`** in the same folder.

From PowerShell, the installation is one command:

```powershell
.\install.cmd
```

Use a normal user terminal. You do not need to activate a Python environment, add SIA to PATH, or change your
machine's execution policy. The intended desktop targets are Windows 10/11 on x64 or ARM64 with Python 3.11 or newer.
Native CI covers Windows Server 2022/2025 x64; it does not establish ARM64 or every organization's desktop policy.

## What setup handles automatically

| Situation | Automatic behavior |
|---|---|
| Normal installation | `install.cmd` starts `install.ps1` through Windows PowerShell. |
| That PowerShell host cannot run the installer | Try PowerShell 7 if available, then the Python backend directly through CMD. |
| Python is installed but missing from PATH | Check the recorded runtime, the project's `.venv`, the Python launcher, registry, and standard user install folders. Store aliases and interpreters without `venv`/`ensurepip` are skipped. |
| No compatible Python | Try the official per-user WinGet package. The PowerShell route also falls back to the official python.org installer, with bounded download retries and a verified Python Software Foundation signature before execution. |
| No app environment, an incomplete install, or changed source | Create a separate environment, install dependencies, and validate imports and installed CLI startup before selecting it. |
| `venv` cannot initialize pip normally | Retry environment creation without pip and initialize pip through Python's bundled `ensurepip`; also repair pip when it is missing from a newly created environment. |
| IT supplied a `wheelhouse` or `wheels` folder | Try its wheels without an index first, then supplement from the configured package index. Without local wheels, use the normal package route. |
| A writable project is on a network drive/share, or its runtime subfolder is not writable | Put the Python environment under `%LOCALAPPDATA%\SIA Policy\projects`; keep the configuration and launcher in the project. |
| Setup is rerun and the current environment is healthy | Verify and reuse it. Dependencies are not reinstalled on every launch. |
| Launch finds a missing, stale, or broken runtime | `Start-SIA.cmd` runs one automatic installation/repair attempt and rechecks before launching. |
| A damaged pointer file cannot be decoded | Treat it as needing repair and replace it only after finding or building a verified runtime. |
| Startup or repair is cancelled | Stop without starting another repair attempt. |

The CMD file is the entry point because a blocked `.ps1` cannot execute its own fallback. Once Python has actually
run the dependency installer, a package failure is reported rather than repeating the same package operation under
every PowerShell host or Python installation. Retries are bounded so an unrecoverable failure cannot loop forever.

The installer creates `.sia-python.path` and versioned environments in `.sia-runtime` (or the local application-data
folder for a network project). It does not overwrite `config.toml`, `.env`, input files, or reports. A failed candidate
does not replace the selected working environment. Validated environments are kept at their original paths because
[Python virtual environments are not portable](https://docs.python.org/3/library/venv.html#how-venvs-work); once a
newer environment has been verified and selected, the earlier ones in that runtime folder are removed.

## Daily commands and updates

In the SIA terminal, use `/doctor`, `/settings`, and `/help`. Commands from the README can also run from PowerShell:

```powershell
.\Start-SIA.cmd doctor
.\Start-SIA.cmd plan --input '.\input'
.\Start-SIA.cmd --help
```

Always keep the launchers with the complete source folder. After updating the source, open `Start-SIA.cmd`; it detects
changes to application code and dependency declarations and prepares a matching environment. Preserve your local
`config.toml`, `.env`, `input`, and `reports` when replacing files from a ZIP. If you move the project to another folder
or computer, open `install.cmd` there to prepare a runtime for that location.

For deployment tooling, installation without opening the app is:

```powershell
.\install.cmd --no-launch
```

To require an existing Python and prohibit automatic Python provisioning, add `--no-bootstrap`. That option still
allows pip to install app dependencies. Interpreter discovery disables the Python launcher's own install-on-demand
behavior for the current installer process, so discovering Python cannot silently provision it. IT can select a
particular approved Python through the PowerShell entry point:

```powershell
.\install.ps1 -PythonExecutable 'C:\Approved Python\python.exe' -NoBootstrap -NoLaunch
```

## Managed and offline computers

An organization's application control can block PowerShell, CMD, Python, or downloaded installers. Setup tries the
available permitted routes; it cannot grant itself rights or override Group Policy. The launcher uses a process-only
PowerShell policy flag and makes no persistent policy change. Microsoft documents that
[Group Policy takes precedence](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies).
If every available route is blocked, IT must provide an approved Python/runtime or allow the application.

For an offline install, IT must provide a compatible Python first and a complete `wheelhouse` folder beside
`install.cmd`. On a connected Windows computer with the same Python version and architecture, prepare it with:

```powershell
python -m pip download --dest wheelhouse -r requirements.txt 'setuptools>=68' wheel
```

Copy that folder with the complete project to the offline computer, then use the same `install.cmd` entry point.
Compatible dependency and build wheels must all be present; installing Python itself still needs a preinstalled or
separately supplied approved interpreter. A partial wheelhouse automatically falls through to online installation.

Rebuild the wheelhouse after upgrading SIA whenever `requirements.txt` has changed, or the offline install fails with
a missing dependency. Releases from 2026 onward add `truststore`, which is what lets SIA verify against the Windows
certificate store on an inspected network; it is a pure-Python `py3-none-any` wheel, so unlike the other
dependencies it can be downloaded on any platform and still work on Windows.

The downloader uses Windows certificate trust; pip uses its configured trust and index settings. For a corporate
proxy or private package index, use IT's approved Python/pip configuration. Do not disable TLS checks. The app's
`[http] ca_bundle` applies to CyberArk traffic, not to the installer — but because pip verifies against its own
bundled CA list rather than the Windows store, a re-signing proxy can block the download before `truststore` is ever
installed. Setup therefore retries each network install asking pip to use the Windows certificate store; see
[TLS inspection on Windows](#tls-inspection-on-windows) if it still fails. WinGet uses Microsoft's documented
[installation options](https://learn.microsoft.com/en-us/windows/package-manager/winget/install), and the signed
fallback uses Python's documented [per-user installer options](https://docs.python.org/3/using/windows.html).

## TLS inspection on Windows

Most corporate networks re-sign HTTPS with a private root (Netskope, Zscaler, Palo Alto, and similar). That root is
normally already in the Windows certificate store, pushed by Group Policy or Intune — but Python does not read that
store by default, so CyberArk traffic fails with `CERTIFICATE_VERIFY_FAILED` even though Edge and `curl` work.

`[http] system_trust` is on by default and resolves this: SIA verifies through the Windows chain engine, which reads
the machine and user Trusted Root stores. Confirm which store is active with:

```powershell
sia doctor
```

`TLS trust: Windows certificate store` means it is working. `TLS trust: certifi (default trust store)` means the
`truststore` package is missing — rerun `install.cmd`, or `py -m pip install .` in the project folder.

To check the re-signing root is actually present (replace the pattern with your proxy's name):

```powershell
Get-ChildItem Cert:\LocalMachine\Root |
  Where-Object { $_.Subject -match 'Netskope|Zscaler|goskope' } |
  Format-List Subject, Thumbprint, NotAfter
```

`certlm.msc` shows the same store in a window. If the root is missing there, that is an IT request, not a SIA setting.

**Prefer `system_trust` over exporting a bundle on Windows.** Windows populates its root store on demand through
automatic root update, so a PEM exported from it is a point-in-time snapshot that can be missing public roots the
machine simply has not needed yet. The chain engine fetches them when required; a static file cannot. Only export a
bundle when `system_trust` cannot be used:

```powershell
$out = "C:\ProgramData\sia\corp-roots.pem"
New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object {
  "-----BEGIN CERTIFICATE-----"
  [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks')
  "-----END CERTIFICATE-----"
} | Set-Content -Encoding ascii $out
```

Then point SIA at it with `sia preflight --ca-bundle C:\ProgramData\sia\corp-roots.pem`, which writes the setting
correctly escaped. A bundle takes precedence over the Windows store, and SIA stops consulting that store while one is
set — that is deliberate, so an explicitly pinned bundle is not quietly widened by whatever else the machine trusts.

If you hand-edit `config.toml` instead, remember that a double-quoted TOML value treats `\` as an escape character:
write `ca_bundle = "C:/ProgramData/sia/corp-roots.pem"`, doubled backslashes, or single quotes.

## When setup still needs help

| Message or symptom | Next action |
|---|---|
| Installer files are missing | Extract the entire ZIP; do not run a launcher from inside the archive. |
| `CERTIFICATE_VERIFY_FAILED` while installing dependencies | The installer already retries asking pip to use the Windows certificate store. If it still fails, get the proxy root as a `.pem` from IT and run `py -m pip install --cert C:\path\to\corp-root.pem .` in the project folder. |
| `invalid TOML` right after pasting a Windows path | A double-quoted value treats `\` as an escape. Use forward slashes, doubled backslashes, or single quotes — or set the path with `--ca-bundle`, which escapes it for you. |
| `sia doctor` reports `TLS trust: certifi` on an inspected network | The `truststore` package is missing. Rerun `install.cmd`, or add `truststore` to the wheelhouse for an offline install. |
| Project folder is read-only | Copy the complete extracted folder to a writable local folder and open `install.cmd` there. |
| Python installation or execution is blocked | Give IT the displayed error and request an approved Python 3.11 or newer; rerun the same installer afterward. |
| Dependency installation fails | Restore download access or supply the complete wheelhouse. The previous selected runtime and user data are preserved. |
| Disk full, antivirus lock, or denied write | Resolve the specific error shown and reopen the installer. It can reuse a healthy runtime or retry with a fresh candidate. |
| Setup was interrupted | Reopen `install.cmd`. An unselected partial environment is never treated as an installed app. |

## Credentials on Windows

Prefer `/setup` or `/settings` to save credentials. Before writing secret bytes, SIA creates the temporary `.env` file
with a protected DACL granting access to the current Windows user, SYSTEM, and Administrators. Existing destination
permissions are secured before replacement, and the final file is checked. No additional package is needed.

If protection fails before saving, the terminal home automatically retains entered credentials for the current
session and explains that they were not saved. If replacement completed but final permission inspection failed, the
message explicitly says that the destination changed and its protection could not be confirmed. Run `/doctor` to
check the actual file permissions. Closing SIA discards session credentials.

### Hand-editing `.env` on Windows

`/setup` and `/settings` store a credential exactly as typed, so nothing below applies to them. If you do edit the
file by hand:

- Paste the secret unquoted. Backslashes are literal — `SIA_CLIENT_SECRET=p@ss\word` is the password `p@ss\word`,
  and a Vault user is `PVWA_USER=ACME\svc_sia`. Nothing is ever doubled.
- Quote the value only when it starts or ends with a space, or contains ` #` (which otherwise begins a comment).
  Quotes delimit and do not escape; the one special sequence inside them is a doubled quote, which writes one.
- Save as UTF-8. PowerShell's `>`, `Out-File` and `Set-Content` write UTF-16 unless you pass `-Encoding utf8`, and
  SIA reads UTF-8; a UTF-16 file is reported with the command that rewrites it. A Notepad byte-order mark is fine.
- `/doctor` reports any credential line whose quoting no longer means what an older SIA release stored.

A manually copied `.env` inherits its destination folder's permissions; run `/doctor` to check it. Windows
[`chmod` does not set a private ACL](https://docs.python.org/3/library/os.html#os.chmod), so a POSIX-style mode check
is not used as proof of protection. Network filesystems may not support the required ACL operations.

## Verification scope

The offline regression suite covers installer recovery decisions, environment publication, command quoting, and
credential failure handling. The Windows CI workflow additionally exercises actual CMD launchers, Windows file ACLs,
Windows PowerShell 5.1, and PowerShell 7 on x64 hosts. Check its run result for the exact revision being distributed;
the presence of the workflow alone is not a Windows test pass. No installer check authenticates to CyberArk or proves
that a target server is reachable.
