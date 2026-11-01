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
step "a second file in the same folder reuses entries with the same value (no --force)"
printf 'OPENAI_API_KEY=sk-synthetic-openai\nWORKER_TOKEN=synthetic-worker\n' > .dev.vars
pe import .dev.vars --prefix web; expect "second import exit" "$?" 0
step "remove the secret lines after checking every value"
pe import .env.local --prefix web --remove; expect "remove exit" "$?" 0
pe import .dev.vars --prefix web --remove; expect "remove .dev.vars exit" "$?" 0
expect ".dev.vars deleted" "$(test -e .dev.vars && echo present)" ""
cat .env.local
expect "secrets gone from .env.local" "$(grep -c synthetic .env.local)" 0
expect "public and skipped lines kept" "$(grep -c -e NEXT_PUBLIC_SITE_URL -e DIRECT_URL .env.local)" 2

step "scrub: count the secrets agents saved in their logs (fake logs in a temp HOME); counts only"
home="$work/home"
log="$home/.claude/projects/-demo/session.jsonl"
rollout="$home/.codex/sessions/2026/11/01/rollout.jsonl"
mkdir -p "$(dirname "$log")" "$(dirname "$rollout")"
body=$(printf 'Ab3dE5gH7j%.0s' 1 2 3 4)
ghtoken="gh""p_${body:0:36}" # split so no token-shaped text is committed
printf '{"type":"user","message":{"content":"my token is %s"}}\n' "$ghtoken" > "$log"
printf '{"type":"tool","output":"STRIPE_SECRET_KEY=sk_test_synthetic\\nDB_PASSWORD=Zk3mQ9pL2xV7nR4t"}\n' >> "$log"
printf '{"type":"assistant","text":"nothing secret here"}\n' >> "$log"
touch -d '1 hour ago' "$log"
printf '{"text":"%s"}\n' "$ghtoken" > "$rollout" # just written: an active session
secrets_in() { grep -c -e "$ghtoken" -e Zk3mQ9pL2xV7nR4t -e sk_test_synthetic "$@"; }
# The scan history goes to the temp HOME too, never your real ~/.local/state.
sc() { HOME="$home" XDG_STATE_HOME="$home/.local/state" pe scrub "$@"; }
out=$(sc); code=$?; printf '%s\n' "$out"
expect "dry run exits 1 when it finds something" "$code" 1
expect "dry run prints no secret" "$(printf '%s' "$out" | secrets_in)" 0
expect "dry run changes nothing" "$(secrets_in "$log")" 2
step "scrub --known while locked refuses"
gpgconf --kill gpg-agent
sc --known; expect "scrub --known while locked exits 1" "$?" 1
step "after unlock, --known also finds stored values no pattern knows (sk_test_synthetic is too short for the Stripe pattern)"
gpg --batch -q --pinentry-mode loopback --passphrase demo-pass -d "$PASSWORD_STORE_DIR/app/STRIPE_SECRET_KEY.gpg" >/dev/null 2>&1 && echo unlocked
out=$(sc --known); printf '%s\n' "$out"
expect "the stored Stripe value is found" "$(printf '%s' "$out" | grep -c 'session.jsonl: .*known-value 1')" 1
expect "--known prints no secret" "$(printf '%s' "$out" | secrets_in)" 0
step "scrub --fix rewrites the old log and skips the active one"
sc --known --fix; expect "fix exit" "$?" 0
cat "$log"
expect "secrets gone from the log" "$(secrets_in "$log")" 0
expect "every line is still JSON" "$(bun -e 'for (const line of require("fs").readFileSync(process.argv[1], "utf8").trim().split("\n")) JSON.parse(line); console.log("valid")' "$log")" valid
expect "the active file is untouched" "$(secrets_in "$rollout")" 1
step "scan history: the next run skips unchanged files and remembers what is still there"
out=$(sc --known); code=$?; printf '%s\n' "$out"
expect "2 unchanged files skipped" "$(printf '%s' "$out" | grep -c '^2 files unchanged since .*, skipped')" 1
expect "the active file's finding is remembered" "$(printf '%s' "$out" | grep -c 'rollout.jsonl: github-token 1 (unchanged since the scan on')" 1
expect "remembered findings still exit 1" "$code" 1
step "a log that only grew: just the new lines are read"
printf '{"type":"tool","output":"DB_PASSWORD=Zk3mQ9pL2xV7nR4t"}\n' >> "$log"
out=$(sc); printf '%s\n' "$out"
expect "only the new line is read" "$(printf '%s' "$out" | grep -c '^1 file only grew since the last scan')" 1
expect "the new secret is found once" "$(printf '%s' "$out" | grep -c 'session.jsonl: secret-assignment 1 (in use')" 1
expect "no secret printed" "$(printf '%s' "$out" | secrets_in)" 0
step "scrub --history: when each folder was checked and what was found (no secrets)"
out=$(sc --history); printf '%s\n' "$out"
expect "lists the Claude Code folder" "$(printf '%s' "$out" | grep -c '^~/.claude/projects$')" 1
expect "history prints no secret" "$(printf '%s' "$out" | secrets_in)" 0
state="$home/.local/state/pass-env/scrub.json"
expect "the history file is readable only by you" "$(bun -e 'console.log((require("fs").statSync(process.argv[1]).mode & 0o777).toString(8))' "$state")" 600
expect "the history file holds no secret" "$(secrets_in "$state")" 0

step "result"
if [ "$failures" -eq 0 ]; then echo "all checks passed"; else echo "$failures checks failed"; exit 1; fi
