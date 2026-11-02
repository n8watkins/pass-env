#!/usr/bin/env bash
# Hands-on check of Windows Hello unlock with the REAL helper and REAL
# Windows Hello prompts, in a throwaway sandbox: its own GNUPGHOME, store,
# config folder, helper folder and Windows Hello key name. Your real GPG
# setup, store and any real pass-env enrolment are never touched, and the
# throwaway Hello key is deleted at the end.
#
# Usage, in your own WSL terminal (not through an agent):
#   ./demo/hello-manual.sh [path/to/pass-env-hello.exe]
# With no path it uses hello/target/release/pass-env-hello.exe.
# Needs: bun, gpg, script (util-linux); pass is fetched without sudo if missing.
set -uo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
exe="${1:-$repo/hello/target/release/pass-env-hello.exe}"
[ -t 0 ] || { echo "Run this in your own terminal."; exit 2; }
[ -f "$exe" ] || { echo "No helper at $exe. Build it (hello/build-release.ps1) or pass its path."; exit 2; }
localappdata=$(wslpath -u "$(cd /mnt/c && cmd.exe /d /c 'echo %LOCALAPPDATA%' 2>/dev/null | tr -d '\r')")

work=$(mktemp -d)
helper_dir="$localappdata/pass-env-manual-test-$$"
key="pass-env-manual-test-$$"
pe=(bun "$repo/pass-env.ts")
cleanup() {
	PASS_ENV_HELLO_TEST_DIR="$helper_dir" PASS_ENV_HELLO_KEY="$key" "${pe[@]}" hello forget >/dev/null 2>&1 </dev/tty
	gpgconf --kill gpg-agent 2>/dev/null
	rm -rf "$work" "$helper_dir"
}
trap cleanup EXIT

if ! command -v pass >/dev/null; then
	(cd "$work" && apt-get download pass >/dev/null 2>&1 && dpkg-deb -x pass_*.deb pass-root) || { echo "Could not fetch pass; sudo apt install pass"; exit 1; }
	mkdir -p "$work/bin" && ln -s "$work/pass-root/usr/bin/pass" "$work/bin/pass"
	export PATH="$work/bin:$PATH"
fi

export GNUPGHOME="$work/gnupg" PASSWORD_STORE_DIR="$work/store" XDG_CONFIG_HOME="$work/config" XDG_STATE_HOME="$work/state"
export PASS_ENV_HELLO_TEST_DIR="$helper_dir" PASS_ENV_HELLO_KEY="$key" PASS_ENV_PINENTRY="$work/pinentry"
unset PASS_ENV_HELLO_HELPER
mkdir -m 700 "$GNUPGHOME"
# A throwaway passphrase, answered by a stand-in pinentry, so you never type one.
printf '#!/bin/sh\nFAKE_PIN=manual-test-pass exec %s/demo/fake-pinentry.sh "$@"\n' "$repo" > "$work/pinentry"
chmod +x "$work/pinentry"
printf 'allow-loopback-pinentry\npinentry-program %s\n' "$work/pinentry" > "$GNUPGHOME/gpg-agent.conf"
gpg --batch -q --pinentry-mode loopback --passphrase manual-test-pass --quick-gen-key manual-test@example.invalid default default never 2>/dev/null
pass init manual-test@example.invalid >/dev/null
"${pe[@]}" generate workstation/UNLOCK_CANARY >/dev/null
cd "$work"

results=()
ask() { # ask <step> <question>
	local answer
	read -r -p "    $2 [y/n] " answer </dev/tty
	results+=("$1: $([ "$answer" = y ] && echo PASS || echo FAIL)")
}
pause() { read -r -p "  Press Enter to $1 " _ </dev/tty; }
locked() { gpgconf --kill gpg-agent; }

echo "Sandbox: $work"
echo "Throwaway Windows Hello key: $key"
echo
echo "1. Install the helper (no prompt)"
"${pe[@]}" hello install "$exe" --yes
"${pe[@]}" hello status
ask "1 install+status" "Did status show 'Windows Hello available, TPM present'?"

echo
echo "2. Enrol: expect up to THREE Windows Hello prompts (create the key, use it, check it). Approve each."
pause "start"
"${pe[@]}" hello enrol
ask "2 enrol" "Did each prompt appear in front, and did it end with 'Saved'?"

echo
echo "3. Unlock with Windows Hello: expect ONE prompt. Approve it."
locked
pause "start"
"${pe[@]}" unlock --hello
ask "3 unlock" "Did it say 'Unlocked with Windows Hello'? Roughly how fast? (note it)"

echo
echo "4. Cancel: expect ONE prompt. CANCEL it."
locked
pause "start"
"${pe[@]}" unlock --hello
ask "4 cancel" "Did it say 'Windows Hello was cancelled', then 'Unlocked (checked with ...)' from the typed fallback (answered for you)?"

echo
echo "5. Locked Windows: after Enter you have 5 seconds to press Win+L. Unlock Windows again, then look here."
locked
pause "start the 5 second countdown"
sleep 5
"${pe[@]}" unlock --hello
ask "5 lock screen" "Did it either unlock after you signed back in, or fall back with a clear reason (no hang)?"

echo
echo "6. Forget: deletes the blob and the throwaway Hello key (no prompt expected)."
"${pe[@]}" hello forget
locked
"${pe[@]}" unlock --hello
ask "6 forget" "Did forget succeed, and did the last unlock say 'not enrolled yet' and fall back?"

echo
echo "Results (paste these back):"
printf '  %s\n' "${results[@]}"
echo "  Windows build: $(cmd.exe /d /c ver 2>/dev/null | tr -d '\r' | grep -o 'Version [0-9.]*')"
echo "  Helper SHA-256: $(sha256sum "$exe" | cut -c1-64)"
