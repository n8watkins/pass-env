#!/usr/bin/env bash
# End-to-end walk-through against real pass and GPG, with a passphrase-protected
# key, in a throwaway GNUPGHOME and store. Your real keys are never touched.
# Needs: bun, gpg, pass.
set -uo pipefail

cli="$(cd "$(dirname "$0")/.." && pwd)/pass-env.ts"
work=$(mktemp -d)
export GNUPGHOME="$work/gnupg" PASSWORD_STORE_DIR="$work/store"
trap 'gpgconf --kill gpg-agent 2>/dev/null; rm -rf "$work"' EXIT
mkdir -m 700 "$GNUPGHOME"
# Loopback lets this script stand in for the human typing the passphrase.
echo allow-loopback-pinentry > "$GNUPGHOME/gpg-agent.conf"
gpg --batch -q --pinentry-mode loopback --passphrase demo-pass --quick-gen-key demo@example.invalid default default never 2>/dev/null
pass init demo@example.invalid >/dev/null
gpgconf --kill gpg-agent # start locked
cd "$work"
pe() { bun "$cli" "$@"; }
step() { printf '\n== %s\n' "$1"; }

step "generate while locked (storing only encrypts)"
pe generate app/AUTH_SECRET
step "set from a pipe"
printf 'sk_test_synthetic\n' | pe set app/STRIPE_SECRET_KEY
step "check a .env.pass with one missing entry"
printf 'AUTH_SECRET=app/AUTH_SECRET\nSTRIPE_SECRET_KEY=app/STRIPE_SECRET_KEY\nWEBHOOK_SECRET=app/WEBHOOK_SECRET\n' > .env.pass
pe check; echo "exit=$?"
pe generate app/WEBHOOK_SECRET >/dev/null && pe check >/dev/null && echo "after generating it: all ok"
step "run while locked fails fast"
pe run -- sh -c 'echo should not run'; echo "exit=$?"
step "unlock refuses without a terminal (what an agent would hit)"
pe unlock </dev/null; echo "exit=$?"
step "the human unlocks (simulated with loopback)"
gpg --batch -q --pinentry-mode loopback --passphrase demo-pass -d "$PASSWORD_STORE_DIR/app/AUTH_SECRET.gpg" >/dev/null 2>&1 && echo unlocked
step "run after unlock"
pe run -- sh -c 'printf "AUTH_SECRET %s chars, STRIPE_SECRET_KEY %s chars (sk_test_synthetic is 17)\n" "${#AUTH_SECRET}" "${#STRIPE_SECRET_KEY}"'
step "rotate a generated secret"
before=$(pe run -- sh -c 'printf %s "$AUTH_SECRET"' | sha256sum | cut -c1-8)
pe generate app/AUTH_SECRET --force
after=$(pe run -- sh -c 'printf %s "$AUTH_SECRET"' | sha256sum | cut -c1-8)
echo "fingerprint $before -> $after"
step "pass still shows entries normally to the human"
pass show app/STRIPE_SECRET_KEY | head -c 8; echo "..."
