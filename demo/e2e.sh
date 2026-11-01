#!/usr/bin/env bash
# End-to-end walk-through against real pass and GPG, with a passphrase-protected
# key, in a throwaway GNUPGHOME and store. Your real keys are never touched.
# Needs: bun, gpg, pass.
set -uo pipefail

cli="$(cd "$(dirname "$0")/.." && pwd)/pass-env.ts"
# PASS_ENV_BIN runs the same walk-through with a compiled binary.
bin="${PASS_ENV_BIN:+$(cd "$(dirname "$PASS_ENV_BIN")" && pwd)/$(basename "$PASS_ENV_BIN")}"
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
pe() { if [ -n "$bin" ]; then "$bin" "$@"; else bun "$cli" "$@"; fi; }
step() { printf '\n== %s\n' "$1"; }
failures=0
expect() { # expect <description> <actual> <expected>
	if [ "$2" = "$3" ]; then echo "  ok: $1"; else echo "  FAILED: $1 (got: $2)"; failures=$((failures + 1)); fi
}

step "doctor checks the setup (no FAIL expected)"
pe doctor; expect "doctor exit" "$?" 0

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
step "pipe one secret into a command (stands in for gh secret set)"
pe pipe app/STRIPE_SECRET_KEY -- sh -c 'v=$(cat); printf "received %s chars\n" "${#v}"'
step "pass still shows entries normally to the human"
pass show app/STRIPE_SECRET_KEY | head -c 8; echo "..."

step "import an existing .env.local: dry run first, names only"
cat > .env.local <<'EOF'
# app settings
NEXT_PUBLIC_SITE_URL=https://example.invalid
export OPENAI_API_KEY="sk-synthetic-openai" # the key
DATABASE_URL=postgres://user:synthetic@localhost/app
PRIVATE_KEY="-----BEGIN SYNTHETIC KEY-----
abc123
-----END SYNTHETIC KEY-----"
DIRECT_URL=${DATABASE_URL}
EOF
original=$(cat .env.local)
out=$(pe import .env.local --prefix web --dry-run); printf '%s\n' "$out"
expect "dry run prints no values" "$(printf '%s' "$out" | grep -c synthetic)" 0
expect "dry run stores nothing" "$(pe list web/)" ""
step "import stores the secrets and writes .env.pass (GPG may be locked)"
gpgconf --kill gpg-agent
pe import .env.local --prefix web; expect "import exit" "$?" 0
cat .env.pass
expect ".env.local untouched" "$(cat .env.local)" "$original"
pe check >/dev/null; expect "check after import" "$?" 0
step "remove while locked refuses and changes nothing"
pe import .env.local --prefix web --remove; expect "remove while locked exits 1" "$?" 1
expect ".env.local still untouched" "$(cat .env.local)" "$original"
step "the human unlocks and tests the app"
gpg --batch -q --pinentry-mode loopback --passphrase demo-pass -d "$PASSWORD_STORE_DIR/web/OPENAI_API_KEY.gpg" >/dev/null 2>&1 && echo unlocked
pe run -- sh -c 'printf "OPENAI_API_KEY %s chars, PRIVATE_KEY %s lines\n" "${#OPENAI_API_KEY}" "$(printf "%s\n" "$PRIVATE_KEY" | wc -l)"'
expect "multi-line value round-trips exactly" "$(pe run -- sh -c 'printf %s "$PRIVATE_KEY"')" "$(printf -- '-----BEGIN SYNTHETIC KEY-----\nabc123\n-----END SYNTHETIC KEY-----')"
step "remove the secret lines after checking every value"
pe import .env.local --prefix web --remove; expect "remove exit" "$?" 0
cat .env.local
expect "secrets gone from .env.local" "$(grep -c synthetic .env.local)" 0
expect "public and skipped lines kept" "$(grep -c -e NEXT_PUBLIC_SITE_URL -e DIRECT_URL .env.local)" 2

step "result"
if [ "$failures" -eq 0 ]; then echo "all checks passed"; else echo "$failures checks failed"; exit 1; fi
