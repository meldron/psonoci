param(
    [ValidateSet("x86_64-pc-windows-msvc", "x86_64-pc-windows-gnu")]
    [string]$Target = "x86_64-pc-windows-msvc"
)
$ErrorActionPreference = "Stop"

function Invoke-Checked([scriptblock]$Command, [switch]$AllowReboot) {
    & $Command
    if ($LASTEXITCODE -ne 0 -and -not ($AllowReboot -and $LASTEXITCODE -eq 3010)) {
        throw "Command failed with exit code $LASTEXITCODE"
    }
}

$toolVersions = ((Get-Content "sbom/tool-versions.env" | Where-Object {
    $_ -match "^[A-Z_][A-Z0-9_]*="
}) -join "`n") | ConvertFrom-StringData

# Bootstrap a declared interpreter on the disposable GitLab hosted runner.
# Chocolatey verifies package hashes; the build helper checks tool versions.
Invoke-Checked -AllowReboot { choco install python312 --version $toolVersions.GITLAB_PYTHON_VERSION --yes --no-progress }
if ($Target -eq "x86_64-pc-windows-gnu") {
    Invoke-Checked -AllowReboot { choco install mingw --version $toolVersions.GITLAB_MINGW_VERSION --yes --no-progress }
    if (-not (Get-Command perl -ErrorAction SilentlyContinue)) {
        Invoke-Checked -AllowReboot { choco install strawberryperl --yes --no-progress }
    }
}
$env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
    [Environment]::GetEnvironmentVariable("PATH", "User") + ";" + $env:PATH
$python = "C:\Python312\python.exe"
if (-not (Test-Path $python)) { throw "Pinned Python installation not found at $python" }
Invoke-Checked { & $python -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11+ required'" }
if ($Target -eq "x86_64-pc-windows-gnu") {
    $mingw = Join-Path $env:ProgramData "mingw64\mingw64\bin"
    if (-not (Test-Path (Join-Path $mingw "gcc.exe"))) { throw "Pinned MinGW installation not found" }
    $env:PATH = "$mingw;$env:PATH"
}

$env:RUSTUP_HOME = "C:\gitlabrunner\.rustup"
$env:CARGO_HOME = "C:\gitlabrunner\.cargo"
$env:PATH = "$env:CARGO_HOME\bin;$env:PATH"
$env:CARGO_AUDITABLE_VERSION = $toolVersions.CARGO_AUDITABLE_VERSION
Invoke-WebRequest https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe -OutFile rustup-init.exe
Invoke-Checked { .\rustup-init.exe -y --profile minimal --default-toolchain "${env:RUST_TOOLCHAIN}-x86_64-pc-windows-msvc" }
Invoke-Checked { rustup target add $Target }
Invoke-Checked { cargo install --locked cargo-auditable --version $toolVersions.CARGO_AUDITABLE_VERSION }
Invoke-Checked { & $python scripts/build-with-runtime-evidence.py --target $Target }
