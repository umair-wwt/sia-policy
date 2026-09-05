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
[Python virtual environments are not portable](https://docs.python.org/3/library/venv.html#how-venvs-work).

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

The downloader uses Windows certificate trust; pip uses its configured trust and index settings. For a corporate
proxy or private package index, use IT's approved Python/pip configuration. Do not disable TLS checks. The app's
`[http] ca_bundle` applies to CyberArk traffic, not to the installer. WinGet uses Microsoft's documented
[installation options](https://learn.microsoft.com/en-us/windows/package-manager/winget/install), and the signed
fallback uses Python's documented [per-user installer options](https://docs.python.org/3/using/windows.html).

## When setup still needs help

| Message or symptom | Next action |
|---|---|
| Installer files are missing | Extract the entire ZIP; do not run a launcher from inside the archive. |
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

A manually copied `.env` inherits its destination folder's permissions; run `/doctor` to check it. Windows
[`chmod` does not set a private ACL](https://docs.python.org/3/library/os.html#os.chmod), so a POSIX-style mode check
is not used as proof of protection. Network filesystems may not support the required ACL operations.

## Verification scope

The offline regression suite covers installer recovery decisions, environment publication, command quoting, and
credential failure handling. The Windows CI workflow additionally exercises actual CMD launchers, Windows file ACLs,
Windows PowerShell 5.1, and PowerShell 7 on x64 hosts. Check its run result for the exact revision being distributed;
the presence of the workflow alone is not a Windows test pass. No installer check authenticates to CyberArk or proves
that a target server is reachable.
