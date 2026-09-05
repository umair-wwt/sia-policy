[CmdletBinding()]
param(
    [string]$InstallerPath = (Join-Path $PSScriptRoot "..\install.ps1")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Assert-Equal($Expected, $Actual, [string]$Message) {
    if ($Expected -ne $Actual) {
        throw "ASSERTION FAILED: $Message (expected '$Expected', got '$Actual')"
    }
}

function Get-InstallerFunctionDefinitions([string]$Path) {
    $Tokens = $null
    $ParseErrors = $null
    $Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path -LiteralPath $Path).Path,
        [ref]$Tokens,
        [ref]$ParseErrors
    )
    if ($ParseErrors.Count -ne 0) {
        throw "install.ps1 has PowerShell parse errors: $($ParseErrors[0].Message)"
    }
    $Definitions = $Ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true)
    foreach ($Definition in $Definitions) {
        $Definition.Extent.Text
    }
}

foreach ($Definition in @(Get-InstallerFunctionDefinitions $InstallerPath)) {
    Invoke-Expression $Definition
}
$script:PinnedPythonVersion = "3.14.7"
$script:ProjectRoot = Split-Path -Parent (Resolve-Path -LiteralPath $InstallerPath).Path
$script:PythonExecutable = ""
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)

# An invalid signature, including a missing signer certificate, must stop before
# the downloaded executable can be launched.
$script:SignatureUnderTest = $null
$script:StartCount = 0
function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing, [int]$TimeoutSec)
    [IO.File]::WriteAllText($OutFile, "fake installer", $script:Utf8)
}
function Get-AuthenticodeSignature {
    param([string]$FilePath)
    return $script:SignatureUnderTest
}
function Start-Process {
    param([string]$FilePath, [object[]]$ArgumentList, [switch]$Wait, [switch]$PassThru)
    $script:StartCount += 1
    return [pscustomobject]@{ ExitCode = 0 }
}

foreach ($Signature in @(
    [pscustomobject]@{
        Status = [System.Management.Automation.SignatureStatus]::HashMismatch
        SignerCertificate = [pscustomobject]@{ Subject = "CN=Python Software Foundation" }
    },
    [pscustomobject]@{
        Status = [System.Management.Automation.SignatureStatus]::Valid
        SignerCertificate = $null
    },
    [pscustomobject]@{
        Status = [System.Management.Automation.SignatureStatus]::Valid
        SignerCertificate = [pscustomobject]@{ Subject = "CN=Unrelated Software Vendor" }
    }
)) {
    $script:SignatureUnderTest = $Signature
    $Rejected = $false
    try { Install-SignedPython } catch { $Rejected = $true }
    Assert-True $Rejected "an invalid or missing Python signer must be rejected"
}
Assert-Equal 0 $script:StartCount "an untrusted Python installer must never run"

# A persistent download failure stops after the third attempt without reaching
# either signature inspection or process launch.
$script:DownloadAttempts = 0
$script:SignatureChecks = 0
function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing, [int]$TimeoutSec)
    $script:DownloadAttempts += 1
    throw "persistent download failure"
}
function Start-Sleep { param([int]$Seconds) }
function Get-AuthenticodeSignature {
    param([string]$FilePath)
    $script:SignatureChecks += 1
    throw "signature inspection must not run after failed downloads"
}
$DownloadRejected = $false
try { Install-SignedPython } catch { $DownloadRejected = $true }
Assert-True $DownloadRejected "three failed downloads must stop bootstrap"
Assert-Equal 3 $script:DownloadAttempts "download retry count must be bounded"
Assert-Equal 0 $script:SignatureChecks "a missing download must not be signature checked"
Assert-Equal 0 $script:StartCount "a missing download must never be launched"

# Transient download errors are retried a bounded number of times. Signature
# validation must happen only after a successful download and before Start-Process.
$script:DownloadAttempts = 0
$script:SignatureChecks = 0
$script:SleepSeconds = @()
$script:StartedInstaller = $null
$script:StartedArguments = @()
function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing, [int]$TimeoutSec)
    $script:DownloadAttempts += 1
    if ($script:DownloadAttempts -lt 3) { throw "temporary download failure" }
    [IO.File]::WriteAllText($OutFile, "fake installer", $script:Utf8)
}
function Start-Sleep {
    param([int]$Seconds)
    $script:SleepSeconds += $Seconds
}
function Get-AuthenticodeSignature {
    param([string]$FilePath)
    $script:SignatureChecks += 1
    Assert-Equal 3 $script:DownloadAttempts "signature validation must follow the completed download"
    return [pscustomobject]@{
        Status = [System.Management.Automation.SignatureStatus]::Valid
        SignerCertificate = [pscustomobject]@{ Subject = "CN=Python Software Foundation" }
    }
}
function Start-Process {
    param([string]$FilePath, [object[]]$ArgumentList, [switch]$Wait, [switch]$PassThru)
    Assert-Equal 1 $script:SignatureChecks "the installer must be signature checked before execution"
    $script:StartedInstaller = $FilePath
    $script:StartedArguments = @($ArgumentList)
    Assert-True $Wait.IsPresent "the signed installer must be awaited"
    Assert-True $PassThru.IsPresent "the signed installer exit code must be available"
    return [pscustomobject]@{ ExitCode = 0 }
}

Install-SignedPython
Assert-Equal 3 $script:DownloadAttempts "the download must stop after the first successful retry"
Assert-Equal "2 4" ($script:SleepSeconds -join " ") "retry delays must stay bounded"
Assert-True (-not [string]::IsNullOrWhiteSpace($script:StartedInstaller)) "a trusted installer should run"
foreach ($RequiredArgument in @(
    "/quiet", "InstallAllUsers=0", "PrependPath=0", "Include_launcher=0",
    "Include_pip=1", "Include_test=0", "Shortcuts=0"
)) {
    Assert-True ($script:StartedArguments -contains $RequiredArgument) "missing safe install option $RequiredArgument"
}

# WinGet output is displayed but must not leak into the function's success
# pipeline, where the caller expects exactly one Boolean decision.
$script:WingetExit = 0
function Invoke-FakeWinget {
    $global:LASTEXITCODE = $script:WingetExit
    Write-Output "fake winget diagnostic"
}
function Get-Command {
    param([string]$Name, $ErrorAction)
    if ($Name -eq "winget.exe") {
        return [pscustomobject]@{ Source = "Invoke-FakeWinget" }
    }
    return $null
}

$WingetSuccess = @(Install-PythonWithWinget)
Assert-Equal 1 $WingetSuccess.Count "successful WinGet must return one pipeline value"
Assert-True ($WingetSuccess[0] -is [bool]) "WinGet result must be Boolean"
Assert-True $WingetSuccess[0] "zero WinGet exit code must report success"
$script:WingetExit = 9
$WingetFailure = @(Install-PythonWithWinget)
Assert-Equal 1 $WingetFailure.Count "failed WinGet must return one pipeline value"
Assert-True ($WingetFailure[0] -is [bool]) "failed WinGet result must remain Boolean"
Assert-True (-not $WingetFailure[0]) "nonzero WinGet exit code must report failure"

# Discovery gives the caller's explicit Python first priority, then falls back
# to the project's conventional .venv without reaching external discovery.
$script:PythonExecutable = "C:\CI\explicit-python.exe"
$script:DiscoveryCalls = @()
function Test-Python {
    param([string]$Candidate)
    $script:DiscoveryCalls += $Candidate
    if ($Candidate -eq $script:PythonExecutable) { return "C:\CI\resolved-python.exe" }
    return $null
}
function Resolve-LauncherPython { throw "launcher discovery should not run after an explicit match" }
$Explicit = Find-CompatiblePython
Assert-Equal "C:\CI\resolved-python.exe" $Explicit "explicit compatible Python should win"
Assert-Equal 1 $script:DiscoveryCalls.Count "explicit discovery should stop at its first match"

$DiscoveryRoot = Join-Path ([IO.Path]::GetTempPath()) ("sia-discovery-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $DiscoveryRoot | Out-Null
try {
    $script:ProjectRoot = $DiscoveryRoot
    $script:PythonExecutable = ""
    $ExpectedVenvPython = Join-Path $DiscoveryRoot ".venv\Scripts\python.exe"
    $script:DiscoveryCalls = @()
    function Test-Python {
        param([string]$Candidate)
        $script:DiscoveryCalls += $Candidate
        if ($Candidate -eq $ExpectedVenvPython) { return $ExpectedVenvPython }
        return $null
    }
    function Resolve-LauncherPython { throw "launcher discovery should not run after the .venv match" }
    $FromVenv = Find-CompatiblePython
    Assert-Equal $ExpectedVenvPython $FromVenv "the conventional project .venv should be automatic fallback"
    Assert-Equal 1 $script:DiscoveryCalls.Count ".venv discovery should stop at its match"
}
finally {
    Remove-Item -LiteralPath $DiscoveryRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Windows installer PowerShell smoke checks passed."
