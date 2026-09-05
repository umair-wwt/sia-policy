[CmdletBinding()]
param(
    [switch]$NoLaunch,
    [string]$PythonExecutable = "",
    [switch]$NoBootstrap
)

$ErrorActionPreference = "Stop"
$PreviousPythonUtf8 = $env:PYTHONUTF8
$PreviousPythonIoEncoding = $env:PYTHONIOENCODING
$PreviousConsoleOutputEncoding = [Console]::OutputEncoding
$PreviousLauncherEnvironment = @{}
foreach ($Name in @("PYTHON_MANAGER_AUTOMATIC_INSTALL", "PYLAUNCHER_ALLOW_INSTALL", "PYLAUNCHER_ALWAYS_INSTALL", "PYLAUNCHER_DRYRUN")) {
    $PreviousLauncherEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, "Process")
    [Environment]::SetEnvironmentVariable($Name, $null, "Process")
}
# Keep interpreter discovery read-only, including Python's newer install manager.
[Environment]::SetEnvironmentVariable("PYTHON_MANAGER_AUTOMATIC_INSTALL", "false", "Process")
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = $Utf8NoBom
$OutputEncoding = $Utf8NoBom
$ProjectRoot = $PSScriptRoot
$Backend = Join-Path $ProjectRoot "scripts\windows_install.py"
$PinnedPythonVersion = "3.14.7"

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Test-Python([string]$Candidate) {
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $null }
    if ($Candidate -match "\\WindowsApps\\python(3)?\.exe$") { return $null }
    try {
        $Result = & $Candidate -c "import sys,venv,ensurepip; print(str(sys.version_info[0])+'.'+str(sys.version_info[1])+'|'+sys.executable); raise SystemExit(0 if sys.version_info >= (3,11) else 7)" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $Result) { return $null }
        $Parts = ([string](@($Result)[-1])).Split("|", 2)
        if ($Parts.Count -ne 2 -or -not (Test-Path -LiteralPath $Parts[1] -PathType Leaf)) { return $null }
        return $Parts[1]
    } catch {
        return $null
    }
}

function Resolve-LauncherPython([string]$Selector) {
    try {
        $Result = & py $Selector -c "import sys; print(sys.executable); raise SystemExit(0 if sys.version_info >= (3,11) else 7)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $Result) {
            return Test-Python ([string](@($Result)[-1]))
        }
    } catch { }
    return $null
}

function Find-CompatiblePython {
    $PrimaryCandidates = New-Object System.Collections.Generic.List[string]
    if ($PythonExecutable) { [void]$PrimaryCandidates.Add($PythonExecutable) }

    $Pointer = Join-Path $ProjectRoot ".sia-python.path"
    if (Test-Path -LiteralPath $Pointer -PathType Leaf) {
        try { [void]$PrimaryCandidates.Add(([IO.File]::ReadAllText($Pointer, [Text.Encoding]::UTF8)).Trim()) } catch { }
    }
    [void]$PrimaryCandidates.Add((Join-Path $ProjectRoot ".venv\Scripts\python.exe"))
    $Seen = @{}
    foreach ($Candidate in $PrimaryCandidates) {
        if ([string]::IsNullOrWhiteSpace($Candidate)) { continue }
        $Key = $Candidate.ToLowerInvariant()
        if ($Seen.ContainsKey($Key)) { continue }
        $Seen[$Key] = $true
        $Resolved = Test-Python $Candidate
        if ($Resolved) { return $Resolved }
    }

    foreach ($Selector in @("-3.14", "-3.13", "-3.12", "-3.11", "-3")) {
        $Resolved = Resolve-LauncherPython $Selector
        if ($Resolved) { return $Resolved }
    }

    $Candidates = New-Object System.Collections.Generic.List[string]
    foreach ($Name in @("python.exe", "python3.exe", "python")) {
        try {
            $Command = Get-Command $Name -ErrorAction SilentlyContinue
            if ($Command -and $Command.Source) { [void]$Candidates.Add($Command.Source) }
        } catch { }
    }

    foreach ($Hive in @("HKCU:\Software\Python\PythonCore", "HKLM:\Software\Python\PythonCore", "HKLM:\Software\WOW6432Node\Python\PythonCore")) {
        if (-not (Test-Path $Hive)) { continue }
        foreach ($VersionKey in (Get-ChildItem $Hive -ErrorAction SilentlyContinue | Sort-Object PSChildName -Descending)) {
            try {
                $InstallKey = Get-Item (Join-Path $VersionKey.PSPath "InstallPath") -ErrorAction Stop
                $InstallPath = $InstallKey.GetValue("")
                if ($InstallPath) { [void]$Candidates.Add((Join-Path $InstallPath "python.exe")) }
            } catch { }
        }
    }

    if ($env:LOCALAPPDATA) {
        foreach ($Found in (Get-ChildItem (Join-Path $env:LOCALAPPDATA "Programs\Python\Python*\python.exe") -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
            [void]$Candidates.Add($Found.FullName)
        }
    }

    foreach ($Candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($Candidate)) { continue }
        $Key = $Candidate.ToLowerInvariant()
        if ($Seen.ContainsKey($Key)) { continue }
        $Seen[$Key] = $true
        $Resolved = Test-Python $Candidate
        if ($Resolved) { return $Resolved }
    }
    return $null
}

function Install-PythonWithWinget {
    try {
        $Winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if (-not $Winget) { return $false }
        Write-Step "Installing Python for this Windows user with winget"
        $Output = & $Winget.Source install --id Python.Python.3.14 --exact --source winget --scope user --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1
        $WingetExitCode = $LASTEXITCODE
        if ($Output) { $Output | ForEach-Object { Write-Host $_ } }
        return ($WingetExitCode -eq 0)
    } catch {
        Write-Warning "winget could not install Python; trying the signed python.org installer."
        return $false
    }
}

function Install-SignedPython {
    $Architecture = if ($env:PROCESSOR_ARCHITEW6432 -eq "ARM64" -or $env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
    $FileName = "python-$PinnedPythonVersion-$Architecture.exe"
    $Url = "https://www.python.org/ftp/python/$PinnedPythonVersion/$FileName"
    $Download = Join-Path ([IO.Path]::GetTempPath()) ("sia-" + [Guid]::NewGuid().ToString("N") + "-" + $FileName)
    try {
        Write-Step "Downloading the official Python $PinnedPythonVersion installer"
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $Downloaded = $false
        $LastDownloadError = ""
        foreach ($Attempt in 1..3) {
            Remove-Item -LiteralPath $Download -Force -ErrorAction SilentlyContinue
            try {
                Invoke-WebRequest -Uri $Url -OutFile $Download -UseBasicParsing -TimeoutSec 60
                $Downloaded = $true
                break
            } catch {
                $LastDownloadError = $_.Exception.Message
                if ($Attempt -lt 3) {
                    Write-Warning "Python download attempt $Attempt failed; retrying."
                    Start-Sleep -Seconds (2 * $Attempt)
                }
            }
        }
        if (-not $Downloaded) {
            throw "The official Python installer could not be downloaded after 3 attempts: $LastDownloadError"
        }
        $Signature = Get-AuthenticodeSignature -FilePath $Download
        if ($Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
            -not $Signature.SignerCertificate -or
            $Signature.SignerCertificate.Subject -notmatch "(^|,\s*)(CN|O)=Python Software Foundation(,|$)") {
            throw "The downloaded Python installer did not have a valid Python Software Foundation signature. It was not run."
        }
        Write-Step "Installing signed Python for this Windows user"
        $Process = Start-Process -FilePath $Download -ArgumentList @(
            "/quiet", "InstallAllUsers=0", "PrependPath=0", "Include_launcher=0",
            "Include_pip=1", "Include_test=0", "Shortcuts=0"
        ) -Wait -PassThru
        if ($Process.ExitCode -ne 0 -and $Process.ExitCode -ne 3010) {
            throw "The Python installer returned exit code $($Process.ExitCode)."
        }
    } finally {
        Remove-Item -LiteralPath $Download -Force -ErrorAction SilentlyContinue
    }
}

try {
    $FailureCode = 1
    if (-not (Test-Path -LiteralPath $Backend -PathType Leaf)) {
        throw "scripts\windows_install.py is missing. Extract the entire project folder and run install.cmd again."
    }
    Write-Host "SIA Policy Automation - Windows setup" -ForegroundColor White
    Write-Step "Looking for Python 3.11 or newer"
    $Python = Find-CompatiblePython
    if (-not $Python) {
        if ($NoBootstrap) {
            $FailureCode = 20
            throw "Python 3.11 or newer was not found and automatic Python installation is disabled."
        }
        $InstalledWithWinget = Install-PythonWithWinget
        if ($InstalledWithWinget) { $Python = Find-CompatiblePython }
        if (-not $Python) {
            Install-SignedPython
            $Python = Find-CompatiblePython
        }
        if (-not $Python) {
            $FailureCode = 20
            throw "Python was installed but Windows has not made it available yet. Restart Windows and run install.cmd again."
        }
    }
    Write-Host "Using $Python"
    Write-Step "Building and checking the SIA application"
    $Arguments = @($Backend, "--python", $Python)
    if ($NoLaunch) { $Arguments += "--no-launch" }
    & $Python @Arguments
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -eq 130) { exit 130 }
    if ($ExitCode -ne 0) { exit 10 }
} catch {
    Write-Host "`nInstallation could not finish: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Your configuration, inputs, and reports were preserved. You can safely run install.cmd again." -ForegroundColor Yellow
    exit $FailureCode
} finally {
    foreach ($Name in $PreviousLauncherEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($Name, $PreviousLauncherEnvironment[$Name], "Process")
    }
    [Environment]::SetEnvironmentVariable("PYTHONUTF8", $PreviousPythonUtf8, "Process")
    [Environment]::SetEnvironmentVariable("PYTHONIOENCODING", $PreviousPythonIoEncoding, "Process")
    [Console]::OutputEncoding = $PreviousConsoleOutputEncoding
}
