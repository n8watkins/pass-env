// Builds the npm packages for one release from the release's files:
//   node packaging/npm.mjs <dist-folder> <out-folder>
// <dist-folder> holds the binaries and SHA256SUMS the release workflow made.
// <out-folder> gets one folder per package, ready for `npm publish`:
// pass-env-<os>-<arch> (one binary each) and pass-env (the launcher), whose
// optionalDependencies pin every platform package to the same version.
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const [dist, out] = process.argv.slice(2);
if (!dist || !out) {
	console.error("usage: node packaging/npm.mjs <dist-folder> <out-folder>");
	process.exit(2);
}

const source = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const version = source.version;
const sums = new Map(readFileSync(join(dist, "SHA256SUMS"), "utf8").trim().split("\n").map((line) => {
	const [hash, file] = line.split(/\s+/);
	return [file, hash];
}));

const shared = {
	version,
	license: source.license,
	homepage: source.homepage,
	bugs: source.bugs,
	// npm checks provenance against this, so it must name the publishing repo.
	repository: source.repository,
	author: source.author,
};

const platforms = [
	["linux", "x64"], ["linux", "arm64"], ["darwin", "x64"], ["darwin", "arm64"],
];

rmSync(out, { recursive: true, force: true });
for (const [os, cpu] of platforms) {
	const name = `pass-env-${os}-${cpu}`;
	const file = join(dist, name);
	const hash = createHash("sha256").update(readFileSync(file)).digest("hex");
	if (sums.get(name) !== hash) throw new Error(`${name} does not match SHA256SUMS`);
	const dir = join(out, name);
	mkdirSync(join(dir, "bin"), { recursive: true });
	copyFileSync(file, join(dir, "bin", "pass-env"));
	chmodSync(join(dir, "bin", "pass-env"), 0o755);
	writeFileSync(join(dir, "package.json"), `${JSON.stringify({
		name,
		...shared,
		description: `The pass-env binary for ${os === "darwin" ? "macOS" : "Linux"} ${cpu}. Install pass-env instead.`,
		os: [os],
		cpu: [cpu],
		files: ["bin/pass-env"],
		preferUnplugged: true,
	}, null, 2)}\n`);
	writeFileSync(join(dir, "README.md"), `# ${name}\n\nThe pass-env binary for this platform. Install [\`pass-env\`](https://www.npmjs.com/package/pass-env) instead; it picks this package for you.\n`);
}

const main = join(out, "pass-env");
mkdirSync(join(main, "bin"), { recursive: true });
copyFileSync(join(root, "packaging", "launcher.cjs"), join(main, "bin", "pass-env.cjs"));
chmodSync(join(main, "bin", "pass-env.cjs"), 0o755);
for (const doc of ["README.md", "LICENSE", "CHANGES.md"]) copyFileSync(join(root, doc), join(main, doc));
writeFileSync(join(main, "package.json"), `${JSON.stringify({
	name: "pass-env",
	...shared,
	description: source.description,
	keywords: source.keywords,
	contributors: source.contributors,
	bin: { "pass-env": "bin/pass-env.cjs" },
	files: ["bin/pass-env.cjs", "README.md", "LICENSE", "CHANGES.md"],
	os: ["linux", "darwin"],
	optionalDependencies: Object.fromEntries(platforms.map(([os, cpu]) => [`pass-env-${os}-${cpu}`, version])),
}, null, 2)}\n`);

console.log(`npm packages for pass-env ${version} in ${out}: ${[...platforms.map(([os, cpu]) => `pass-env-${os}-${cpu}`), "pass-env"].join(", ")}`);
