# Builds pass-env-hello.exe the way the release workflow does: locked
# dependencies, pinned toolchain (rust-toolchain.toml), static CRT, no linker
# timestamps (/Brepro) and no local paths in the binary, so the same commit
# gives the same SHA-256 wherever it is built with the same toolchain.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE ".cargo" }
$flags = @(
	"-C", "link-arg=/Brepro",
	"-C", "target-feature=+crt-static",
	"--remap-path-prefix=$cargoHome=C:\cargo",
	"--remap-path-prefix=$PSScriptRoot=C:\src"
)
# The encoded form keeps paths with spaces intact.
$env:CARGO_ENCODED_RUSTFLAGS = $flags -join [char]0x1f
Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
cargo build --release --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$exe = Join-Path $PSScriptRoot "target\release\pass-env-hello.exe"
(Get-FileHash -Algorithm SHA256 $exe).Hash.ToLower() + "  pass-env-hello.exe"
