$ErrorActionPreference = "Stop"

$env:RUSTUP_HOME = "C:\gitlabrunner\.rustup"
$env:CARGO_HOME = "C:\gitlabrunner\.cargo"

$toolVersions = Get-Content "sbom/tool-versions.env" | Where-Object {
    $_ -match "^[A-Z_]+="
} | ConvertFrom-StringData
$env:CARGO_AUDITABLE_VERSION = $toolVersions.CARGO_AUDITABLE_VERSION

wget https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe -outfile rustup-init.exe

./rustup-init.exe -y --profile minimal --default-toolchain "${env:RUST_TOOLCHAIN}-x86_64-pc-windows-msvc"

# remove config link
$filePath = ".cargo\config"
if (Test-Path -Path $filePath) {
    Remove-Item -Path $filePath -Force
}

# Set the PATH to include Cargo's bin directory for the current session
$env:PATH = "$env:CARGO_HOME\bin;$env:PATH"

# Embed the resolved dependency tree into the release executable.
& "$env:CARGO_HOME\bin\cargo.exe" install --locked cargo-auditable --version "$env:CARGO_AUDITABLE_VERSION"
& "$env:CARGO_HOME\bin\cargo.exe" auditable build --locked --release --target=x86_64-pc-windows-msvc
