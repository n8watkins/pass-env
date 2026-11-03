#!/bin/sh
# Install pass-env from a GitHub release: picks the binary for this system,
# checks it against the release's SHA256SUMS (and its build provenance when gh
# is signed in), and puts it in ~/.local/bin.
#
#   curl -fsSL https://raw.githubusercontent.com/n8watkins/pass-env/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version v1.2.0 --dir /usr/local/bin
set -eu

REPO="n8watkins/pass-env"
version="${PASS_ENV_VERSION:-latest}"
dir="${PASS_ENV_INSTALL_DIR:-$HOME/.local/bin}"

usage() {
	cat <<EOF
Install pass-env from a GitHub release.

Options:
  --version <tag>   a release tag such as v1.2.0 (default: the latest release)
  --dir <folder>    where to put pass-env (default: ~/.local/bin)
  -h, --help        show this help

The same settings as environment variables: PASS_ENV_VERSION, PASS_ENV_INSTALL_DIR.
EOF
}

fail() { echo "pass-env install: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
		--version) [ $# -ge 2 ] || fail "--version needs a tag, e.g. v1.2.0"; version="$2"; shift 2 ;;
		--dir) [ $# -ge 2 ] || fail "--dir needs a folder"; dir="$2"; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) fail "unknown option $1 (see --help)" ;;
	esac
done

case "$(uname -s)" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) fail "pass-env runs on Linux and macOS (on Windows, install it inside WSL)" ;;
esac
case "$(uname -m)" in
	x86_64|amd64) arch=x64 ;;
	aarch64|arm64) arch=arm64 ;;
	*) fail "no pass-env binary for $(uname -m)" ;;
esac
asset="pass-env-$os-$arch"

if [ "$version" = latest ]; then
	base="https://github.com/$REPO/releases/latest/download"
else
	case "$version" in v*) ;; *) version="v$version" ;; esac
	base="https://github.com/$REPO/releases/download/$version"
fi

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsL --retry 2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	fail "needs curl or wget"
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	fail "needs sha256sum or shasum to check the download"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

fetch "$base/$asset" "$tmp/$asset" || fail "could not download $asset ($version); check the tag at https://github.com/$REPO/releases"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download SHA256SUMS ($version)"

expected="$(awk -v name="$asset" '$2 == name { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$expected" ] || fail "SHA256SUMS has no line for $asset"
[ "$(sha256 "$tmp/$asset")" = "$expected" ] || fail "checksum mismatch for $asset; nothing was installed"
checks="checksum ok"

# Build provenance proves the binary came from this repository's release
# workflow. It needs gh signed in; without it the checksum still applies.
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
	gh attestation verify "$tmp/$asset" --repo "$REPO" \
		--signer-workflow "$REPO/.github/workflows/release.yml" --deny-self-hosted-runners >/dev/null 2>&1 \
		|| fail "build provenance check failed for $asset; nothing was installed"
	checks="$checks, provenance ok"
else
	checks="$checks, provenance not checked (needs gh signed in)"
fi

mkdir -p "$dir"
chmod 755 "$tmp/$asset"
mv "$tmp/$asset" "$dir/pass-env"
installed="$("$dir/pass-env" version 2>/dev/null | head -n 1 || true)"
echo "Installed ${installed:-pass-env} to $dir/pass-env ($checks)."

case ":$PATH:" in
	*":$dir:"*) ;;
	*) echo "Add $dir to your PATH, e.g. echo 'export PATH=\"$dir:\$PATH\"' >> ~/.bashrc" ;;
esac
command -v pass >/dev/null 2>&1 || echo "pass-env needs pass and gpg: sudo apt install pass (macOS: brew install pass gnupg)."
echo "Next: pass-env doctor"
