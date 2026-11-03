#!/usr/bin/env bash
# Checks the npm packages the way users install them: builds them from a
# release's files, publishes them to a throwaway local registry (Verdaccio),
# then installs and runs pass-env with npm, pnpm, yarn and bun.
#   packaging/smoke-npm.sh <dist-folder>
# <dist-folder> holds a release's binaries and SHA256SUMS.
set -euo pipefail

dist="$(cd "$1" && pwd)"
here="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
port=4873
registry="http://127.0.0.1:$port"
# The registry runs in its own process group (setsid), so cleanup stops it and
# everything npx started for it, not just npx.
trap 'kill -- -"$verdaccio" 2>/dev/null || true; rm -rf "$work"' EXIT

node "$here/packaging/npm.mjs" "$dist" "$work/out" >/dev/null

mkdir -p "$work/registry"
cat >"$work/registry/config.yaml" <<EOF
storage: $work/registry/storage
uplinks: { npmjs: { url: https://registry.npmjs.org/ } }
packages:
  'pass-env*': { access: \$all, publish: \$all }
  '**': { access: \$all, proxy: npmjs }
max_body_size: 200mb
log: { type: stdout, format: pretty, level: error }
EOF
setsid npx -y verdaccio@6.1.6 --config "$work/registry/config.yaml" --listen "127.0.0.1:$port" >"$work/registry.log" 2>&1 &
verdaccio=$!
for _ in $(seq 60); do curl -sf "$registry/-/ping" >/dev/null && break; sleep 1; done
curl -sf "$registry/-/ping" >/dev/null || { cat "$work/registry.log"; echo "registry did not start"; exit 1; }

printf '//127.0.0.1:%s/:_authToken=smoke\n' "$port" >"$work/npmrc"
for package in "$work"/out/pass-env-* "$work/out/pass-env"; do
	(cd "$package" && npm publish --userconfig "$work/npmrc" --registry "$registry" >/dev/null 2>&1)
done

version="$(node -p "require('$work/out/pass-env/package.json').version")"
failed=0
check() {
	local name="$1" got="$2"
	if [[ "$got" == "pass-env $version"* ]]; then echo "ok    $name"; else echo "FAIL  $name: ${got:-no output}"; failed=1; fi
}
install_with() {
	local manager="$1" dir="$work/$1"
	mkdir -p "$dir" && cd "$dir"
	echo '{"name":"smoke","version":"0.0.0","private":true}' >package.json
	printf 'registry=%s\n' "$registry" >.npmrc
	case "$manager" in
		npm) npm install pass-env >/dev/null 2>&1 ;;
		pnpm) npx -y pnpm@10.20.0 add pass-env >/dev/null 2>&1 ;;
		yarn) npx -y yarn@1.22.22 add pass-env --registry "$registry" >/dev/null 2>&1 ;;
		bun) BUN_CONFIG_REGISTRY="$registry" bun add pass-env >/dev/null 2>&1 ;;
	esac
	check "$manager install" "$(node_modules/.bin/pass-env version 2>&1 | head -n 1)"
}

for manager in npm pnpm yarn bun; do
	if [[ "$manager" == bun ]] && ! command -v bun >/dev/null; then echo "skip  bun (not installed)"; continue; fi
	install_with "$manager"
done

cd "$work"
check "npx" "$(npx -y --registry "$registry" pass-env version 2>/dev/null | head -n 1)"
status=0; (cd "$work/npm" && node_modules/.bin/pass-env not-a-command >/dev/null 2>&1) || status=$?
[[ "$status" == 2 ]] && echo "ok    exit codes pass through" || { echo "FAIL  exit code: got $status, want 2"; failed=1; }

exit "$failed"
