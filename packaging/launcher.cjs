#!/usr/bin/env node
// The `pass-env` command from npm. The real program is a standalone binary in
// the package for this platform (pass-env-<os>-<arch>), which npm, pnpm, yarn
// and bun install as an optional dependency. This file only starts it.
"use strict";

const { spawnSync } = require("node:child_process");

const name = `pass-env-${process.platform}-${process.arch}`;
let binary;
try {
	binary = require.resolve(`${name}/bin/pass-env`);
} catch {
	const supported = ["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"];
	const here = `${process.platform}-${process.arch}`;
	console.error(supported.includes(here)
		? `pass-env: the ${name} package is missing. Reinstall without --no-optional / --omit=optional, or use the installer: https://github.com/n8watkins/pass-env#install`
		: `pass-env: no binary for ${here}; pass-env runs on Linux and macOS (on Windows, inside WSL).`);
	process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
	console.error(`pass-env: could not start ${binary}: ${result.error.message}`);
	process.exit(1);
}
if (result.signal) process.kill(process.pid, result.signal);
process.exit(result.status ?? 1);
