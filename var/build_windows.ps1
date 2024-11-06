$ErrorActionPreference = "Stop"

$env:RUSTUP_HOME = "C:\gitlabrunner\.rustup"
$env:CARGO_HOME = "C:\gitlabrunner\.cargo"

wget https://static.rust-lang.org/rustup/dist/i686-pc-windows-gnu/rustup-init.exe -outfile rustup-init.exe

./rustup-init.exe -y --profile minimal --default-toolchain $RUST_TOOLCHAIN-x86_64-pc-windows-msvc

# remove config link
$filePath = ".cargo\config"
if (Test-Path -Path $filePath) {
    Remove-Item -Path $filePath -Force
}

# Set the PATH to include Cargo's bin directory for the current session
$env:PATH = "$env:CARGO_HOME\bin;$env:PATH"

# Run Cargo to build the project
& "$env:CARGO_HOME\bin\cargo.exe" build --release --target=x86_64-pc-windows-msvc
