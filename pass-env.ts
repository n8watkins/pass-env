#!/usr/bin/env bun
// pass-env: give programs and coding agents secrets from `pass` without
// showing them. Fork of misty-step/mistystack's bin/pass-env.ts (MIT).

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
	appendFileSync, chmodSync, closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, realpathSync, renameSync, rmSync,
	statSync, unlinkSync, utimesSync, writeFileSync, writeSync, type Stats,
} from "node:fs";
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";

class CliError extends Error {
	constructor(readonly code: string, message: string, readonly exitCode = 1) {
		super(message);
	}
}

type Mapping = { name: string; entry: string; multiline: boolean };
type Sources = { files: string[]; explicit: Mapping[] };
type Charset = "alnum" | "hex" | "base64url";
type Options =
	| { command: "help" }
	| { command: "list"; prefix: string; json: boolean }
	| ({ command: "run"; argv: string[] } & Sources)
	| ({ command: "check" } & Sources)
	| { command: "set"; entry: string; force: boolean }
	| { command: "generate"; entry: string; length: number; charset: Charset; force: boolean; copy: boolean }
	| { command: "copy"; entry: string; multiline: boolean }
	| { command: "pipe"; entry: string; multiline: boolean; argv: string[] }
	| { command: "unlock"; entry?: string }
	| ImportOptions
	| ScrubOptions
	| { command: "doctor" };
type ScrubOptions = { command: "scrub"; paths: string[]; known: boolean; fix: boolean; includeActive: boolean; all: boolean; history: boolean };
type ImportOptions = {
	command: "import"; file: string; prefix: string; skip: Set<string>; map: Map<string, string>; dryRun: boolean; force: boolean; remove: boolean;
};

const DEFAULT_FILE = ".env.pass";
const MULTILINE = "multiline:";
const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
// Frameworks compile these into the browser bundle, so they are not secret.
const PUBLIC_PREFIXES = ["NEXT_PUBLIC_", "VITE_", "PUBLIC_", "EXPO_PUBLIC_", "REACT_APP_"];
// Public names that still look like secrets, e.g. NEXT_PUBLIC_GEMINI_API_KEY.
const SECRET_LOOKING = /SECRET|PRIVATE|TOKEN|PASSWORD|(GEMINI|OPENAI|ANTHROPIC|GROQ|MISTRAL|RESEND|SENDGRID|TWILIO).*KEY/;
const PLACEHOLDER = /your|xxx|changeme|example|placeholder|replace/i;
const EXAMPLE_FILES = [".env.example", ".env.sample", ".dev.vars.example"];
const CHARSETS: Record<Charset, string> = {
	alnum: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	hex: "0123456789abcdef",
	base64url: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
};

function usage(): string {
	return `pass-env: use secrets from pass without printing them.

Store a secret
  pass-env set <entry> [--force]
      Paste a key you were given (hidden prompt), or pipe it in.
  pass-env generate <entry> [length] [--charset alnum|hex|base64url] [--copy] [--force]
      Make a random secret (default 48 alnum). Never printed.
      --copy also puts it on your clipboard to paste somewhere, cleared after 45s.
      --force replaces an existing one (rotation).

Use a secret
  pass-env run [-f file]... [-e NAME=entry]... -- command args...
      Start a command with secrets as environment variables.
      With no -f or -e, uses ./.env.pass.
  pass-env pipe <entry> [--multiline] -- command args...
      Send one secret to a command's input, e.g. gh secret set NAME.
  pass-env copy <entry> [--multiline]
      Put one secret on your clipboard, cleared after 45s.

Move an existing .env file into pass
  pass-env import <file> --prefix <prefix> [--dry-run] [--skip NAME,NAME] [--map NAME=entry]... [--force]
      Store each secret as <prefix>/<NAME> and add it to .env.pass next to
      the file. Public names (NEXT_PUBLIC_*, VITE_*, ...) and placeholders
      stay. The file is not changed. --dry-run shows the plan, names only.
      --map points a name at another entry, e.g. GEMINI_API_KEY=shared/GEMINI_API_KEY.
      An existing entry is reused if its value is the same (needs unlock).
  pass-env import <file> --prefix <prefix> [--skip ...] [--map ...] --remove
      After testing with run: check every stored value against the file,
      then delete those lines from it. Needs GPG unlocked.

Clean up keys agents already saw
  pass-env scrub [--path <file-or-folder>]... [--known] [--all]
      Coding agents keep chat logs (~/.claude, ~/.codex, ~/.pi, ~/.omp) with
      everything they saw. Count the secrets in them per file, by kind.
      Never prints them. Exits 1 if any are found. --known also finds the
      exact values in your store, even ones no pattern knows (needs unlock).
      Remembers what it checked (paths, times and counts only), so the next
      run skips unchanged files and reads only what was added to growing
      ones. --all reads every file again.
  pass-env scrub --fix [--include-active] [--path ...]... [--known] [--all]
      Replace each one with [REDACTED:<kind>] in place. JSONL lines stay
      valid. Skips files changed in the last 10 minutes (an agent may be
      writing them) unless --include-active. No backups, on purpose.
  pass-env scrub --history
      When each log folder was last checked, and what was found and fixed.

Check and set up
  pass-env doctor
      Check pass, GPG, the store and this folder, including env variables
      the code reads but nothing declares. Decrypts nothing.
  pass-env check [-f file]... [-e NAME=entry]...
      Show each mapping as ok or MISSING. Decrypts nothing.
  pass-env list [prefix] [--json]
      Show entry names. Decrypts nothing.
  pass-env unlock [entry]
      Type your GPG passphrase once per session. Terminal only.
  pass-env help

Reference files (.env.pass)
  One NAME=entry per line, full-line # comments allowed. Names only, safe
  to commit. A variable gets the entry's first line (pass's convention);
  write NAME=multiline:entry for PEM keys or JSON. No quotes, interpolation
  or inline comments. Later files override earlier ones; -e wins.

Examples
  pass-env set myapp/STRIPE_SECRET_KEY              # paste the key when asked
  pass-env generate myapp/AUTH_SECRET               # agent-safe, never shown
  pass-env generate myapp/WEBHOOK_SECRET --copy     # then paste it in a dashboard
  pass-env generate myapp/AUTH_SECRET --force       # rotate
  echo 'STRIPE_SECRET_KEY=myapp/STRIPE_SECRET_KEY' >> .env.pass
  pass-env check
  pass-env run -- pnpm dev
  pass-env pipe myapp/STRIPE_SECRET_KEY -- gh secret set STRIPE_SECRET_KEY
  pass-env pipe myapp/STRIPE_SECRET_KEY -- vercel env add STRIPE_SECRET_KEY production
  pass-env pipe myapp/STRIPE_SECRET_KEY -- npx wrangler secret put STRIPE_SECRET_KEY
  pass-env import .env.local --prefix myapp --dry-run

Notes
  The store is PASSWORD_STORE_DIR or ~/.password-store. Entry names are
  visible file names: never put a secret in a name.
  set and generate only encrypt, so they work while GPG is locked.
  Piped input with several lines is stored exactly, byte for byte.
  run, pipe and copy never prompt: if GPG is locked they say so.
  Clipboard clear time: PASSWORD_STORE_CLIP_TIME (default 45 seconds).
  pass-env never prints a secret, but the commands you run can, and
  anything running as you can decrypt while GPG is unlocked.`;
}

function validEntry(entry: string): boolean {
	return entry.length > 0 && !isAbsolute(entry) && !/[\\\x00-\x1f\x7f]/.test(entry)
		&& entry.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

function checkedEntry(entry: string | undefined, what = "entry"): string {
	if (!entry || entry.startsWith("-") || !validEntry(entry)) throw new CliError("USAGE", `invalid ${what} name`, 2);
	return entry;
}

function mapping(input: string, location: string): Mapping {
	const equals = input.indexOf("=");
	const name = input.slice(0, equals).trim();
	let entry = input.slice(equals + 1).trim();
	if (equals < 1 || !NAME.test(name)) {
		throw new CliError("USAGE", `${location}: expected NAME=entry`, 2);
	}
	const multiline = entry.startsWith(MULTILINE);
	if (multiline) entry = entry.slice(MULTILINE.length);
	if (!validEntry(entry)) throw new CliError("USAGE", `${location}: invalid entry for ${name}`, 2);
	return { name, entry, multiline };
}

function parseSources(args: string[], allowCommand: boolean): Sources & { argv?: string[] } {
	const files: string[] = [];
	const explicit: Mapping[] = [];
	for (let index = 0; index < args.length; index += 1) {
		const arg = args[index];
		if (arg === "--" && allowCommand) {
			const argv = args.slice(index + 1);
			if (!argv[0]) throw new CliError("USAGE", "run requires a command after --", 2);
			return { files, explicit, argv };
		}
		if (!["-e", "--env", "-f", "--env-file"].includes(arg)) throw new CliError("USAGE", `unexpected argument ${JSON.stringify(arg)}`, 2);
		const value = args[++index];
		if (!value || value === "--") throw new CliError("USAGE", `${arg} requires a value`, 2);
		if (arg === "-e" || arg === "--env") explicit.push(mapping(value, "--env"));
		else files.push(value);
	}
	if (allowCommand) throw new CliError("USAGE", "run requires -- command args...", 2);
	return { files, explicit };
}

function withDefaultFile(sources: Sources): Sources {
	if (sources.files.length || sources.explicit.length) return sources;
	if (!existsSync(DEFAULT_FILE)) {
		throw new CliError("USAGE", `no mappings: create ${DEFAULT_FILE} or pass -f file / -e NAME=entry`, 2);
	}
	return { files: [DEFAULT_FILE], explicit: [] };
}

function parseArgs(args: string[]): Options {
	const [command, ...rest] = args;
	if (!command || ["help", "--help", "-h"].includes(command) || rest.some((arg) => arg === "--help" || arg === "-h") && !rest.includes("--")) {
		return { command: "help" };
	}
	switch (command) {
		case "list": {
			let prefix: string | undefined;
			let json = false;
			for (const arg of rest) {
				if (arg === "--json") json = true;
				else if (prefix === undefined && !arg.startsWith("-")) prefix = arg;
				else throw new CliError("USAGE", "expected list [prefix] [--json]", 2);
			}
			if (prefix && !validEntry(prefix.endsWith("/") ? prefix.slice(0, -1) : prefix)) {
				throw new CliError("USAGE", "invalid entry prefix", 2);
			}
			return { command: "list", prefix: prefix ?? "", json };
		}
		case "run": {
			const parsed = parseSources(rest, true);
			return { command: "run", ...withDefaultFile(parsed), argv: parsed.argv! };
		}
		case "check":
			return { command: "check", ...withDefaultFile(parseSources(rest, false)) };
		case "set": {
			const force = rest.includes("--force");
			const positional = rest.filter((arg) => arg !== "--force");
			if (positional.length !== 1) throw new CliError("USAGE", "expected set <entry> [--force]", 2);
			return { command: "set", entry: checkedEntry(positional[0]), force };
		}
		case "generate": {
			let force = false;
			let copy = false;
			let charset: Charset = "alnum";
			const positional: string[] = [];
			for (let index = 0; index < rest.length; index += 1) {
				const arg = rest[index];
				if (arg === "--force") force = true;
				else if (arg === "--copy") copy = true;
				else if (arg === "--charset") {
					const value = rest[++index];
					if (!value || !Object.hasOwn(CHARSETS, value)) throw new CliError("USAGE", "--charset must be alnum, hex or base64url", 2);
					charset = value as Charset;
				} else if (arg.startsWith("-")) throw new CliError("USAGE", `unexpected argument ${JSON.stringify(arg)}`, 2);
				else positional.push(arg);
			}
			if (positional.length < 1 || positional.length > 2) {
				throw new CliError("USAGE", "expected generate <entry> [length] [--charset alnum|hex|base64url] [--copy] [--force]", 2);
			}
			const length = positional[1] === undefined ? 48 : Number(positional[1]);
			if (!Number.isInteger(length) || length < 16 || length > 512) throw new CliError("USAGE", "length must be a whole number from 16 to 512", 2);
			return { command: "generate", entry: checkedEntry(positional[0]), length, charset, force, copy };
		}
		case "copy": {
			const multiline = rest.includes("--multiline");
			const positional = rest.filter((arg) => arg !== "--multiline");
			if (positional.length !== 1) throw new CliError("USAGE", "expected copy <entry> [--multiline]", 2);
			return { command: "copy", entry: checkedEntry(positional[0]), multiline };
		}
		case "pipe": {
			const split = rest.indexOf("--");
			const before = split === -1 ? rest : rest.slice(0, split);
			const argv = split === -1 ? [] : rest.slice(split + 1);
			const multiline = before.includes("--multiline");
			const positional = before.filter((arg) => arg !== "--multiline");
			if (positional.length !== 1 || !argv[0]) throw new CliError("USAGE", "expected pipe <entry> [--multiline] -- command args...", 2);
			return { command: "pipe", entry: checkedEntry(positional[0]), multiline, argv };
		}
		case "unlock": {
			if (rest.length > 1) throw new CliError("USAGE", "expected unlock [entry]", 2);
			return { command: "unlock", entry: rest[0] === undefined ? undefined : checkedEntry(rest[0]) };
		}
		case "import":
			return parseImport(rest);
		case "scrub":
			return parseScrub(rest);
		case "doctor":
			if (rest.length) throw new CliError("USAGE", "expected doctor", 2);
			return { command: "doctor" };
		default:
			throw new CliError("USAGE", "unknown command; run pass-env help", 2);
	}
}

function parseImport(args: string[]): ImportOptions {
	const options: ImportOptions = { command: "import", file: "", prefix: "", skip: new Set(), map: new Map(), dryRun: false, force: false, remove: false };
	const expected = "expected import <file> --prefix <prefix> [--dry-run] [--skip NAME,NAME] [--map NAME=entry]... [--force] [--remove]";
	for (let index = 0; index < args.length; index += 1) {
		const arg = args[index];
		if (arg === "--dry-run") options.dryRun = true;
		else if (arg === "--force") options.force = true;
		else if (arg === "--remove") options.remove = true;
		else if (arg === "--prefix" || arg === "--skip" || arg === "--map") {
			const value = args[++index];
			if (!value || value.startsWith("-")) throw new CliError("USAGE", `${arg} requires a value`, 2);
			if (arg === "--prefix") options.prefix = checkedEntry(value.replace(/\/$/, ""), "prefix");
			else if (arg === "--map") {
				const item = mapping(value, "--map");
				options.map.set(item.name, item.entry);
			} else value.split(",").filter(Boolean).forEach((name) => options.skip.add(name));
		} else if (arg.startsWith("-") || options.file) throw new CliError("USAGE", expected, 2);
		else options.file = arg;
	}
	if (!options.file || !options.prefix) throw new CliError("USAGE", expected, 2);
	if (options.remove && (options.dryRun || options.force)) throw new CliError("USAGE", "--remove cannot be combined with --dry-run or --force", 2);
	return options;
}

function parseScrub(args: string[]): ScrubOptions {
	const options: ScrubOptions = { command: "scrub", paths: [], known: false, fix: false, includeActive: false, all: false, history: false };
	for (let index = 0; index < args.length; index += 1) {
		const arg = args[index];
		if (arg === "--known") options.known = true;
		else if (arg === "--fix") options.fix = true;
		else if (arg === "--include-active") options.includeActive = true;
		else if (arg === "--all") options.all = true;
		else if (arg === "--history") options.history = true;
		else if (arg === "--path") {
			const value = args[++index];
			if (!value) throw new CliError("USAGE", "--path requires a file or folder", 2);
			options.paths.push(value);
		} else throw new CliError("USAGE", "expected scrub [--path <file-or-folder>]... [--known] [--all] [--fix [--include-active]], or scrub --history", 2);
	}
	if (options.history && args.length > 1) throw new CliError("USAGE", "--history takes no other options", 2);
	if (options.includeActive && !options.fix) throw new CliError("USAGE", "--include-active only applies to --fix (a dry run already reads every file)", 2);
	return options;
}

function readText(path: string, what: string): string {
	try {
		if (!statSync(path).isFile()) throw new Error();
		return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(readFileSync(path));
	} catch {
		throw new CliError("REFERENCE_FILE", `${what}: cannot read regular UTF-8 file`);
	}
}

function referenceFile(path: string, location: string): Mapping[] {
	const items: Mapping[] = [];
	for (const [lineIndex, raw] of readText(path, location).split("\n").entries()) {
		const line = raw.trim();
		if (!line || line.startsWith("#")) continue;
		const item = mapping(line, `${location}, line ${lineIndex + 1}`);
		if (items.some((other) => other.name === item.name)) throw new CliError("USAGE", `${location}: duplicate mapping ${item.name}`, 2);
		items.push(item);
	}
	return items;
}

function readMappings(sources: Sources): Mapping[] {
	const result = new Map<string, Mapping>();
	for (let index = 0; index < sources.files.length; index += 1) {
		for (const item of referenceFile(sources.files[index], `reference file ${index + 1}`)) result.set(item.name, item);
	}
	for (const item of sources.explicit) result.set(item.name, item);
	if (!result.size) throw new CliError("USAGE", "no mappings found", 2);
	return [...result.values()];
}

function storePath(): string {
	const configured = process.env.PASSWORD_STORE_DIR;
	const home = process.env.HOME;
	if (!configured && !home) throw new CliError("STORE", "set PASSWORD_STORE_DIR or HOME");
	const root = resolve(configured || join(home!, ".password-store"));
	try {
		let current = parse(root).root;
		for (const part of relative(current, root).split(sep).filter(Boolean)) {
			current = join(current, part);
			if (!lstatSync(current).isDirectory()) throw new Error();
		}
	} catch {
		throw new CliError("STORE", "no password store found (it must be a real directory, not a symlink); create one with: pass init <your-gpg-id>");
	}
	return root;
}

function entryExists(root: string, entry: string): boolean {
	try {
		let current = root;
		const parts = `${entry}.gpg`.split("/");
		for (const [index, part] of parts.entries()) {
			current = join(current, part);
			const info = lstatSync(current);
			if (index === parts.length - 1 ? !info.isFile() : !info.isDirectory()) return false;
		}
		return true;
	} catch {
		return false;
	}
}

function listEntries(root: string, prefix: string): string[] {
	const entries: string[] = [];
	function visit(directory: string, base: string): void {
		for (const item of readdirSync(directory, { withFileTypes: true })) {
			if (item.name === ".git") continue;
			const entry = base ? `${base}/${item.name}` : item.name;
			if (!validEntry(entry)) continue;
			if (item.isDirectory()) visit(join(directory, item.name), entry);
			else if (item.isFile() && entry.endsWith(".gpg")) {
				const name = entry.slice(0, -4);
				if (validEntry(name) && name.startsWith(prefix)) entries.push(name);
			}
		}
	}
	try {
		visit(root, "");
	} catch {
		throw new CliError("STORE", "cannot list store entries");
	}
	return entries.sort();
}

// Turns pass/GPG stderr into a cause without ever echoing it.
function decryptFailure(name: string, stderr: string): CliError {
	if (/not in the password store/i.test(stderr)) return new CliError("ENTRY", `${name}: entry does not exist`);
	if (/no secret key/i.test(stderr)) return new CliError("DECRYPT", `${name}: encrypted for a GPG key this machine does not have`);
	if (/pinentry|inappropriate ioctl|operation cancelled|no passphrase|bad passphrase|cannot open|timeout/i.test(stderr)) {
		return new CliError("LOCKED", `${name}: GPG is locked; run pass-env unlock in your own terminal, then retry`);
	}
	return new CliError("DECRYPT", `${name}: pass could not decrypt this entry; try pass show in your own terminal`);
}

function guardSpawn<T>(start: () => T): T {
	try {
		return start();
	} catch {
		throw new CliError("PASS_MISSING", "pass is not installed; see https://www.passwordstore.org");
	}
}

async function decrypt(root: string, item: Mapping): Promise<string> {
	const backend = guardSpawn(() => Bun.spawn({
		cmd: ["pass", "show", "--", item.entry],
		env: { ...process.env, PASSWORD_STORE_DIR: root, PASSWORD_STORE_GPG_OPTS: "--batch --pinentry-mode error" },
		stdin: "ignore",
		stdout: "pipe",
		stderr: "pipe",
	}));
	const [output, errors, status] = await Promise.all([
		new Response(backend.stdout).arrayBuffer(),
		new Response(backend.stderr).text(),
		backend.exited,
	]);
	if (status !== 0) throw decryptFailure(item.name, errors);
	let value: string;
	try {
		value = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(output);
		if (value.includes("\0")) throw new Error();
	} catch {
		throw new CliError("VALUE", `${item.name}: entry must contain UTF-8 without NUL`);
	}
	if (item.multiline) return value;
	const end = value.indexOf("\n");
	return (end === -1 ? value : value.slice(0, end)).replace(/\r$/, "");
}

// pass stores single-line values as "value\n"; exact writes the bytes as given,
// so multiline: mappings get back exactly what was stored.
async function store(root: string, entry: string, value: string, force: boolean, exact = false): Promise<void> {
	if (!force && entryExists(root, entry)) {
		throw new CliError("EXISTS", `${entry} already exists; add --force to replace it`);
	}
	const backend = guardSpawn(() => Bun.spawn({
		cmd: ["pass", "insert", "--multiline", "--force", "--", entry],
		env: { ...process.env, PASSWORD_STORE_DIR: root },
		stdin: "pipe",
		stdout: "ignore",
		stderr: "pipe",
	}));
	backend.stdin.write(exact || value.endsWith("\n") ? value : `${value}\n`);
	await backend.stdin.end();
	const [errors, status] = await Promise.all([new Response(backend.stderr).text(), backend.exited]);
	if (status !== 0) {
		throw new CliError("STORE", /gpg-id|no public key|unusable public key/i.test(errors)
			? `could not encrypt ${entry}: check the store's .gpg-id (pass init <your-gpg-id>)`
			: `could not store ${entry}`);
	}
}

function randomSecret(length: number, charset: Charset): string {
	const alphabet = CHARSETS[charset];
	// Rejection sampling keeps every character equally likely.
	const limit = 256 - (256 % alphabet.length);
	let out = "";
	while (out.length < length) {
		for (const byte of crypto.getRandomValues(new Uint8Array(length * 2))) {
			if (byte < limit && out.length < length) out += alphabet[byte % alphabet.length];
		}
	}
	return out;
}

// Returns the number of lines stored from piped input (0 for the prompt).
async function setEntry(root: string, entry: string, force: boolean): Promise<number> {
	if (!process.stdin.isTTY) {
		// One line loses its trailing newline; several lines are kept exactly.
		const input = await Bun.stdin.text();
		const value = input.replace(/\r?\n$/, "");
		if (!value) throw new CliError("VALUE", "nothing was piped in");
		const multiline = /[\r\n]/.test(value);
		await store(root, entry, multiline ? input : value, force, multiline);
		return multiline ? value.split(/\r?\n|\r/).length : 1;
	}
	if (!force && entryExists(root, entry)) throw new CliError("EXISTS", `${entry} already exists; add --force to replace it`);
	// Interactive: pass shows its own hidden, confirmed prompt.
	const backend = guardSpawn(() => Bun.spawn({
		cmd: ["pass", "insert", "--force", "--", entry],
		env: { ...process.env, PASSWORD_STORE_DIR: root },
		stdin: "inherit",
		stdout: "inherit",
		stderr: "inherit",
	}));
	if (await backend.exited !== 0) throw new CliError("STORE", `${entry} was not stored`);
	return 0;
}

type Clipboard = { write: string[]; read?: string[] };

function isWsl(): boolean {
	if (process.env.WSL_DISTRO_NAME) return true;
	try { return /microsoft/i.test(readFileSync("/proc/version", "utf8")); } catch { return false; }
}

function clipboard(): Clipboard {
	const words = (value: string | undefined) => value?.split(" ").filter(Boolean);
	if (process.env.PASS_ENV_CLIPBOARD) {
		return { write: words(process.env.PASS_ENV_CLIPBOARD)!, read: words(process.env.PASS_ENV_CLIPBOARD_READ) };
	}
	if (isWsl() && Bun.which("clip.exe")) {
		return { write: ["clip.exe"], read: Bun.which("powershell.exe") ? ["powershell.exe", "-NoProfile", "-Command", "Get-Clipboard"] : undefined };
	}
	if (Bun.which("pbcopy")) return { write: ["pbcopy"], read: ["pbpaste"] };
	if (process.env.WAYLAND_DISPLAY && Bun.which("wl-copy")) return { write: ["wl-copy"], read: ["wl-paste", "--no-newline"] };
	if (process.env.DISPLAY && Bun.which("xclip")) {
		return { write: ["xclip", "-selection", "clipboard"], read: ["xclip", "-selection", "clipboard", "-o"] };
	}
	throw new CliError("CLIPBOARD", "no clipboard tool found (clip.exe, pbcopy, wl-copy or xclip)");
}

function clipSeconds(): number {
	const seconds = Number(process.env.PASSWORD_STORE_CLIP_TIME ?? 45);
	return Number.isInteger(seconds) && seconds > 0 ? seconds : 45;
}

async function copyToClipboard(board: Clipboard, value: string): Promise<number> {
	let writer;
	try {
		writer = Bun.spawn({ cmd: board.write, stdin: "pipe", stdout: "ignore", stderr: "ignore" });
	} catch {
		throw new CliError("CLIPBOARD", "could not start the clipboard tool");
	}
	writer.stdin.write(value);
	await writer.stdin.end();
	if (await writer.exited !== 0) throw new CliError("CLIPBOARD", "could not copy to the clipboard");
	// A detached shell clears the clipboard later, but only if it still holds
	// our value. The value travels over stdin, never argv.
	const seconds = clipSeconds();
	const quote = (parts: string[]) => parts.map((part) => `'${part.replace(/'/g, "'\\''")}'`).join(" ");
	const clear = `printf '' | ${quote(board.write)}`;
	const script = board.read
		? `expected=$(cat); sleep ${seconds}; current=$(${quote(board.read)} 2>/dev/null | tr -d '\\r'); [ "$current" = "$expected" ] && ${clear}`
		: `cat >/dev/null; sleep ${seconds}; ${clear}`;
	const clearer = spawn("sh", ["-c", script], { detached: true, stdio: ["pipe", "ignore", "ignore"] });
	await new Promise<void>((done) => clearer.stdin!.end(value, done));
	clearer.unref();
	return seconds;
}

function terminalTty(): string | undefined {
	if (process.env.GPG_TTY) return process.env.GPG_TTY;
	const result = Bun.spawnSync({ cmd: ["tty"], stdin: "inherit", stdout: "pipe", stderr: "ignore" });
	const name = result.stdout.toString().trim();
	return result.exitCode === 0 && name.startsWith("/") ? name : undefined;
}

async function unlock(root: string, entry: string | undefined): Promise<string> {
	const tty = process.stdin.isTTY ? terminalTty() : undefined;
	if (!tty) throw new CliError("TTY", "unlock needs your terminal; run it yourself, not through an agent", 2);
	let target = entry;
	if (!target && existsSync(DEFAULT_FILE)) target = readMappings({ files: [DEFAULT_FILE], explicit: [] })[0]?.entry;
	target ??= listEntries(root, "")[0];
	if (!target) throw new CliError("ENTRY", "the store is empty; add something first with pass-env set or generate");
	if (!entryExists(root, target)) throw new CliError("ENTRY", `${target}: entry does not exist`);
	const env: Record<string, string | undefined> = { ...process.env, PASSWORD_STORE_DIR: root, GPG_TTY: tty };
	delete env.PASSWORD_STORE_GPG_OPTS;
	const backend = guardSpawn(() => Bun.spawn({ cmd: ["pass", "show", "--", target], env, stdin: "inherit", stdout: "ignore", stderr: "pipe" }));
	const [errors, status] = await Promise.all([new Response(backend.stderr).text(), backend.exited]);
	if (status !== 0) throw decryptFailure(target, errors);
	return target;
}

// True when the terminal itself sends Ctrl-C/Ctrl-\ to our process group,
// which the child shares; forwarding as well would deliver them twice.
function terminalSignalsReachChild(): boolean {
	try {
		const stat = readFileSync("/proc/self/stat", "utf8");
		const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
		const [processGroup, foregroundGroup] = [fields[2], fields[5]];
		return Number(foregroundGroup) > 0 && foregroundGroup === processGroup;
	} catch {
		return Boolean(process.stdin.isTTY);
	}
}

async function runChild(argv: string[], env: NodeJS.ProcessEnv, input?: string): Promise<number> {
	let child: Bun.Subprocess<"inherit" | "pipe", "inherit", "inherit">;
	try {
		child = Bun.spawn({ cmd: argv, env, stdin: input === undefined ? "inherit" : "pipe", stdout: "inherit", stderr: "inherit" });
	} catch {
		throw new CliError("COMMAND", "could not start command");
	}
	if (input !== undefined) {
		const sink = child.stdin as import("bun").FileSink;
		sink.write(input);
		await sink.end();
	}
	const signals = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"] as const;
	const handlers = signals.map((signal) => {
		const handler = () => {
			if ((signal === "SIGINT" || signal === "SIGQUIT") && terminalSignalsReachChild()) return;
			child.kill(signal);
		};
		process.on(signal, handler);
		return handler;
	});
	let code: number;
	try {
		code = await child.exited;
	} finally {
		signals.forEach((signal, index) => process.removeListener(signal, handlers[index]));
	}
	if (child.signalCode) process.kill(process.pid, child.signalCode);
	return code;
}

// A dotenv line or quoted block: lines first..last of the file.
type DotenvRecord = { name: string; value: string; first: number; last: number; ambiguous: boolean };
type Dotenv = { lines: string[]; bom: boolean; records: DotenvRecord[] };
type Planned = {
	name: string; value: string; entry: string; multiline: boolean; action: "store" | "public" | "skip"; reason?: string; secretLooking?: boolean;
};
type PlanOptions = { prefix: string; skip: Set<string>; map: Map<string, string>; examples: Map<string, string> };

// Mirrors dotenv (used by Next.js, Vite and Wrangler). Errors name lines, never content.
function parseDotenv(text: string, label: string): Dotenv {
	const bom = text.startsWith("\uFEFF");
	const lines = (bom ? text.slice(1) : text).split("\n");
	const line = (index: number) => lines[index].replace(/\r$/, "");
	const records: DotenvRecord[] = [];
	for (let index = 0; index < lines.length; index += 1) {
		const raw = line(index);
		if (!raw.trim() || raw.trim().startsWith("#")) continue;
		const match = /^\s*(?:export\s+)?([\w.-]+)\s*=\s*(.*)$/.exec(raw);
		if (!match) throw new CliError("PARSE", `${label}, line ${index + 1}: expected NAME=value`);
		const [, name, rest] = match;
		const first = index;
		const quote = rest[0];
		if (quote !== '"' && quote !== "'" && quote !== "`") {
			// Unquoted: a # starts a comment only after whitespace; dotenv also cuts
			// at a bare #, so that case is flagged rather than guessed.
			const hash = rest.search(/(^|\s)#/);
			const value = (hash === -1 ? rest : rest.slice(0, hash)).trim();
			records.push({ name, value, first, last: index, ambiguous: value.includes("#") });
			continue;
		}
		let body = rest.slice(1);
		let value = "";
		for (;;) {
			const end = closingQuote(body, quote);
			if (end !== -1) {
				value += body.slice(0, end);
				break;
			}
			value += `${body}\n`;
			index += 1;
			if (index >= lines.length) throw new CliError("PARSE", `${label}, line ${first + 1}: quoted value is never closed`);
			body = line(index);
		}
		if (quote === '"') value = value.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
		records.push({ name, value, first, last: index, ambiguous: false });
	}
	return { lines, bom, records };
}

// The first quote followed by only whitespace or a comment; \" does not close "...".
function closingQuote(body: string, quote: string): number {
	for (let index = 0; index < body.length; index += 1) {
		if (quote === '"' && body[index] === "\\") index += 1;
		else if (body[index] === quote && /^\s*(#.*)?$/.test(body.slice(index + 1))) return index;
	}
	return -1;
}

function planImport(dotenv: Dotenv, { prefix, skip, map, examples }: PlanOptions): { items: Planned[]; duplicates: string[] } {
	const latest = new Map<string, DotenvRecord>();
	const duplicates = new Set<string>();
	for (const record of dotenv.records) {
		if (latest.has(record.name)) duplicates.add(record.name);
		latest.set(record.name, record);
	}
	const items = [...latest.values()].map((record): Planned => {
		const { name, value } = record;
		const plan = (action: Planned["action"], reason?: string): Planned => ({
			name, value, entry: map.get(name) ?? `${prefix}/${name}`, multiline: /[\r\n]/.test(value), action, reason,
		});
		if (skip.has(name)) return plan("skip", "--skip");
		const public_ = PUBLIC_PREFIXES.find((start) => name.startsWith(start));
		if (public_) return { ...plan("public"), secretLooking: Boolean(value) && SECRET_LOOKING.test(name.slice(public_.length)) };
		if (!NAME.test(name)) return plan("skip", "not a valid variable name");
		if (!value) return plan("skip", "empty value");
		if (record.ambiguous) return plan("skip", "unquoted # (quote the value)");
		if (PLACEHOLDER.test(value) || examples.get(name) === value) return plan("skip", "placeholder");
		// Next.js expands $NAME and ${NAME}, and turns \$ into $.
		if (/\$[{A-Za-z_]|\\\$/.test(value)) return plan("skip", "references another variable");
		return plan("store");
	});
	return { items, duplicates: [...duplicates] };
}

// Values from committed example files next to the file, to spot placeholders.
function exampleValues(directory: string): Map<string, string> {
	const values = new Map<string, string>();
	for (const name of EXAMPLE_FILES) {
		try {
			const path = join(directory, name);
			for (const record of parseDotenv(readText(path, path), path).records) values.set(record.name, record.value);
		} catch { /* Missing or unreadable: nothing to compare with. */ }
	}
	return values;
}

function git(directory: string, args: string[]): number | undefined {
	if (!Bun.which("git")) return undefined;
	return Bun.spawnSync({ cmd: ["git", ...args], cwd: directory, stdout: "ignore", stderr: "ignore" }).exitCode;
}

const gitTracked = (path: string) => git(dirname(path), ["ls-files", "--error-unmatch", "--", basename(path)]) === 0;

function publicSecretWarning(item: Planned): string {
	return `${item.name} looks like a secret, but public names are built into the browser bundle. If it holds a real key: rotate it, delete this line, and use it only on the server under a name without the public prefix`;
}

function readDotenv(options: ImportOptions): { dotenv: Dotenv; items: Planned[] } {
	if (gitTracked(options.file)) {
		throw new CliError("TRACKED", `${options.file} is committed to git, so it is shared config (deploys and teammates use it), not a local secret file; pass-env will not change it. If it holds real secrets, rotate them and git rm --cached it`);
	}
	const dotenv = parseDotenv(readText(options.file, options.file), options.file);
	const { items, duplicates } = planImport(dotenv, { ...options, examples: exampleValues(dirname(options.file)) });
	for (const name of duplicates) console.error(`warning: ${name} is set more than once in ${options.file}; the last value is used`);
	for (const item of items.filter((item) => item.secretLooking)) console.error(`warning: ${publicSecretWarning(item)}.`);
	return { dotenv, items };
}

function describePlan(items: Planned[], note: (item: Planned) => string = () => ""): string {
	const width = Math.max(...items.map((item) => item.name.length));
	return items.map((item) => {
		const what = item.action === "store" ? `stored as ${item.entry}${item.multiline ? " (multiline)" : ""}`
			: item.action === "public" ? `kept public${item.secretLooking ? " (but looks like a secret, see warning)" : ""}` : `skipped: ${item.reason}`;
		return `  ${item.name.padEnd(width)}  ${what}${note(item)}`;
	}).join("\n");
}

const sameMapping = (mapping: Mapping, item: Planned) => mapping.entry === item.entry && mapping.multiline === item.multiline;
const importFlags = (options: ImportOptions) => `--prefix ${options.prefix}${options.skip.size ? ` --skip ${[...options.skip].join(",")}` : ""}${
	[...options.map].map(([name, entry]) => ` --map ${name}=${entry}`).join("")}`;
const mappingLine = (item: Planned) => `${item.name}=${item.multiline ? MULTILINE : ""}${item.entry}`;
const shown = (path: string) => relative(process.cwd(), path) || ".";

// Where .gitignore rules hide the file: "pattern (source)", or undefined.
function gitIgnoreRule(path: string): string | undefined {
	if (!Bun.which("git")) return undefined;
	const result = Bun.spawnSync({ cmd: ["git", "check-ignore", "-v", "--", basename(path)], cwd: dirname(path), stdout: "pipe", stderr: "ignore" });
	if (result.exitCode !== 0) return undefined;
	// With -v, a matching !pattern is reported too; it means "not ignored".
	const match = /^(.+?):\d+:(.*)\t/.exec(result.stdout.toString());
	if (match?.[2].startsWith("!")) return undefined;
	return match ? `rule ${match[2]} in ${match[1]}` : "a .gitignore rule";
}

async function importFile(root: string, options: ImportOptions): Promise<number> {
	const { items } = readDotenv(options);
	const secrets = items.filter((item) => item.action === "store");
	const reference = join(dirname(options.file), DEFAULT_FILE);
	const existing = existsSync(reference) ? referenceFile(reference, shown(reference)) : [];
	const conflicts = secrets.filter((item) => existing.some((mapping) => mapping.name === item.name && !sameMapping(mapping, item)));
	const taken = new Set(secrets.filter((item) => entryExists(root, item.entry)).map((item) => item.name));
	if (!items.length) {
		console.log(`${options.file} has no variables.`);
		return 0;
	}
	if (options.dryRun) {
		console.log(`Plan for ${options.file} (dry run, nothing stored or changed):`);
		console.log(describePlan(items, (item) => taken.has(item.name) ? options.force ? " (replaces the existing entry)" : " (already exists: needs --force)" : ""));
		for (const item of conflicts) console.log(`problem: ${shown(reference)} already maps ${item.name} to another entry`);
		return 0;
	}
	if (conflicts.length) {
		throw new CliError("CONFLICT", `${shown(reference)} already maps ${conflicts.map((item) => item.name).join(", ")} to other entries; change those lines or use --skip`);
	}
	const same = options.force ? new Set<string>() : await sameValues(root, secrets.filter((item) => taken.has(item.name)));
	let count = 0;
	for (const item of secrets) {
		if (same.has(item.name)) continue;
		try {
			await store(root, item.entry, item.value, true, item.multiline);
		} catch (error) {
			const stored = count ? `; ${count} of ${secrets.length - same.size} were stored, so re-run with --force` : "";
			throw new CliError(error instanceof CliError ? error.code : "STORE", `${error instanceof CliError ? error.message : `could not store ${item.entry}`}${stored}`);
		}
		count += 1;
	}
	const added = secrets.filter((item) => !existing.some((mapping) => mapping.name === item.name));
	if (added.length) {
		const before = existsSync(reference) ? readFileSync(reference, "utf8") : "";
		const separator = before && !before.endsWith("\n") ? "\n" : "";
		appendFileSync(reference, `${separator}${before.trim() ? "\n" : ""}# Imported from ${basename(options.file)}\n${added.map(mappingLine).join("\n")}\n`);
	}
	console.log(`Imported ${options.file}:`);
	console.log(describePlan(items, (item) => same.has(item.name) ? " (already stored with the same value)" : ""));
	console.log(`\nStored ${count} ${count === 1 ? "entry" : "entries"}${same.size ? ` (${same.size} already had the same value)` : ""}; added ${added.length} ${added.length === 1 ? "line" : "lines"} to ${shown(reference)}. ${options.file} was not changed.`);
	const rule = gitIgnoreRule(reference);
	if (rule && secrets.length) console.error(`warning: git ignores ${shown(reference)} (${rule}). To commit it, add this line to .gitignore:\n  !.env.pass`);
	if (!secrets.length) return 0;
	const here = dirname(options.file) === "." ? "" : `cd ${dirname(options.file)} && `;
	const remove = `pass-env import ${options.file} ${importFlags(options)} --remove`;
	console.log(`\nNext:
  1. ${here}pass-env check
  2. ${here}pass-env run -- <your dev command>    (if it says LOCKED, run pass-env unlock first)
  3. ${remove}
     checks every stored value, then deletes those lines from ${options.file}`);
	if (isDevVars(options.file)) console.log(`\n${DEV_VARS_READERS} read ${basename(options.file)} instead of the environment until that file is gone; see --remove.`);
	return 0;
}

// Existing entries whose stored value equals the file's; any other existing entry needs --force.
async function sameValues(root: string, taken: Planned[]): Promise<Set<string>> {
	const same = new Set<string>();
	const differ: string[] = [];
	let locked = false;
	for (const item of taken) {
		try {
			if (!locked && await decrypt(root, item) === item.value) {
				same.add(item.name);
				continue;
			}
		} catch (error) {
			if (error instanceof CliError && error.code === "LOCKED") locked = true;
		}
		differ.push(item.entry);
	}
	if (!differ.length) return same;
	throw new CliError("EXISTS", locked
		? `already in the store: ${differ.join(", ")}; GPG is locked, so import cannot check whether the values are the same. Run pass-env unlock, or add --force to replace them`
		: `already in the store with a different value: ${differ.join(", ")}; add --force to replace them`);
}

const isDevVars = (file: string) => basename(file) === ".dev.vars" || basename(file).startsWith(".dev.vars.");
const DEV_VARS_READERS = "wrangler dev, the Cloudflare Vite plugin and OpenNext's next dev";

// Rewrites via a temporary file and rename, keeping the mode unless asked
// to drop group and other access.
function replaceFile(path: string, text: string, privateMode = false): void {
	const mode = (statSync(path).mode & 0o7777) & (privateMode ? ~0o077 : 0o7777);
	const temp = join(dirname(path), `.${basename(path)}.pass-env-${process.pid}.tmp`);
	try {
		writeFileSync(temp, text, { mode, flag: "wx" });
		chmodSync(temp, mode);
		renameSync(temp, path);
	} catch {
		rmSync(temp, { force: true });
		throw new CliError("WRITE", `could not rewrite ${path}; it was not changed`);
	}
}

async function removeImported(root: string, options: ImportOptions): Promise<number> {
	const { dotenv, items } = readDotenv(options);
	const secrets = items.filter((item) => item.action === "store");
	if (!secrets.length) {
		console.log(`${options.file} has no secret lines left to remove.`);
		return 0;
	}
	if (lstatSync(options.file).isSymbolicLink()) throw new CliError("USAGE", `${options.file} is a symlink; run this on the real file`, 2);
	const reference = join(dirname(options.file), DEFAULT_FILE);
	const existing = existsSync(reference) ? referenceFile(reference, shown(reference)) : [];
	const unmapped = secrets.filter((item) => !existing.some((mapping) => mapping.name === item.name && sameMapping(mapping, item)));
	if (unmapped.length) {
		throw new CliError("REFERENCE_FILE", `${shown(reference)} does not map ${unmapped.map((item) => `${item.name} to ${item.entry}`).join(", ")}; run the import without --remove first. Nothing was removed`);
	}
	const missing = secrets.filter((item) => !entryExists(root, item.entry));
	if (missing.length) throw new CliError("ENTRY", `not in the store: ${missing.map((item) => item.entry).join(", ")}; nothing was removed`);
	const differ: string[] = [];
	for (const item of secrets) {
		if (await decrypt(root, item) !== item.value) differ.push(item.name);
	}
	if (differ.length) {
		throw new CliError("MISMATCH", `the stored value differs from ${options.file} for ${differ.join(", ")}; nothing was removed. To store the file's values, run the import again with --force`);
	}
	const names = new Set(secrets.map((item) => item.name));
	const drop = new Set<number>();
	for (const record of dotenv.records) {
		if (names.has(record.name)) for (let index = record.first; index <= record.last; index += 1) drop.add(index);
	}
	const kept = dotenv.lines.filter((_, index) => !drop.has(index));
	const empty = kept.every((line) => !line.trim() || line.trim().startsWith("#"));
	console.log(`Checked ${secrets.length} stored ${secrets.length === 1 ? "value" : "values"} against ${options.file}: all match.`);
	if (empty) {
		unlinkSync(options.file);
		console.log(`Deleted ${options.file}: only comments and blank lines were left.`);
	} else {
		const shared = (statSync(options.file).mode & 0o077) !== 0;
		replaceFile(options.file, `${dotenv.bom ? "\uFEFF" : ""}${kept.join("\n")}`, true);
		console.log(`Removed ${secrets.map((item) => item.name).join(", ")} from ${options.file}.`);
		if (shared) console.log(`Made ${options.file} readable only by you (it was readable by other users).`);
		const left = items.filter((item) => item.action !== "store");
		if (left.length) console.log(`Still in ${options.file}:\n${describePlan(left)}`);
	}
	if (isDevVars(options.file)) {
		console.log(empty
			? `\n${DEV_VARS_READERS} can now read the environment, e.g. CLOUDFLARE_INCLUDE_PROCESS_ENV=true pass-env run -- npx wrangler dev`
			: `\n${DEV_VARS_READERS} ignore environment variables while ${basename(options.file)} exists, so pass-env run cannot reach them yet.
Move the remaining values into "vars" in wrangler.jsonc (or [vars] in wrangler.toml), then delete ${basename(options.file)}.`);
	}
	return 0;
}

type Check = { status: "ok" | "warn" | "FAIL"; text: string; fix?: string };
const ok = (text: string): Check => ({ status: "ok", text });
const warn = (text: string, fix: string): Check => ({ status: "warn", text, fix });
const fail = (text: string, fix: string): Check => ({ status: "FAIL", text, fix });
const DAY = 86_400;

function tilde(path: string): string {
	const home = process.env.HOME;
	return home && (path === home || path.startsWith(`${home}/`)) ? `~${path.slice(home.length)}` : path;
}

function installFix(what: string): string {
	return process.platform === "darwin" ? `brew install ${what === "pass" ? "pass gnupg" : "gnupg"}` : `sudo apt install ${what === "pass" ? "pass" : "gnupg"}`;
}

function toolChecks(): Check[] {
	// A compiled binary carries its own Bun runtime.
	const bun = Bun.main.startsWith("/$bunfs/") ? ok(`standalone binary (Bun ${Bun.version} built in)`) : ok(`Bun ${Bun.version}`);
	return [
		Bun.which("pass") ? ok("pass is installed") : fail("pass is not installed", installFix("pass")),
		Bun.which("gpg") ? ok("gpg is installed") : fail("gpg is not installed", installFix("gpg")),
		bun,
	];
}

function storeChecks(): Check[] {
	const configured = process.env.PASSWORD_STORE_DIR;
	const home = process.env.HOME;
	if (!configured && !home) return [fail("no password store: neither PASSWORD_STORE_DIR nor HOME is set", "export HOME, or PASSWORD_STORE_DIR=<store folder>")];
	const root = resolve(configured || join(home!, ".password-store"));
	if (isWsl() && /^\/mnt\/[a-z]\//i.test(`${root}/`)) {
		return [fail(`store ${root} is on the Windows drive, where Linux file permissions do not protect it`,
			"keep it inside WSL: unset PASSWORD_STORE_DIR, pass init <your-gpg-id>, then move the entries into ~/.password-store")];
	}
	try {
		storePath();
	} catch {
		return [fail(`no password store at ${tilde(root)} (it must be a real folder, not a symlink)`, "pass init <your-gpg-id>")];
	}
	const checks = [ok(`store ${tilde(root)}`)];
	let ids: string[];
	try {
		ids = readFileSync(join(root, ".gpg-id"), "utf8").split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
	} catch {
		ids = [];
	}
	if (!ids.length) return [...checks, fail("the store has no .gpg-id, so pass cannot encrypt", "pass init <your-gpg-id>")];
	if (!Bun.which("gpg")) return checks;
	const missing = ids.filter((id) => {
		const result = Bun.spawnSync({ cmd: ["gpg", "--batch", "--list-secret-keys", "--with-colons", "--", id], stdout: "pipe", stderr: "ignore" });
		return result.exitCode !== 0 || !/^sec:/m.test(result.stdout.toString());
	});
	checks.push(missing.length
		? fail(`no private key on this machine for ${missing.join(", ")} (from .gpg-id), so entries cannot be decrypted here`,
			"gpg --list-secret-keys shows the keys you have; import yours with gpg --import <key.asc>, or pass init <a key you have>")
		: ok(`private key for ${ids.join(", ")} is on this machine`));
	return checks;
}

function gpgChecks(): Check[] {
	const home = process.env.GNUPGHOME || (process.env.HOME ? join(process.env.HOME, ".gnupg") : undefined);
	const conf = home ? join(home, "gpg-agent.conf") : "gpg-agent.conf";
	let lines: string[] = [];
	try { lines = readFileSync(conf, "utf8").split("\n").map((line) => line.trim()); } catch { /* No config: GPG defaults. */ }
	const option = (name: string) => lines.filter((line) => line.split(/\s+/)[0] === name).map((line) => line.slice(name.length).trim()).pop();
	const checks: Check[] = [];
	const pinentry = option("pinentry-program");
	const curses = `echo 'pinentry-program ${Bun.which("pinentry-curses") ?? "/usr/bin/pinentry-curses"}' >> ${tilde(conf)} && gpgconf --kill gpg-agent`;
	if (pinentry && !existsSync(pinentry)) checks.push(fail(`pinentry-program ${pinentry} does not exist, so GPG cannot ask for your passphrase`, curses));
	else if (pinentry) checks.push(ok(`passphrase prompt: ${pinentry}`));
	else if (isWsl()) checks.push(warn("no pinentry-program set; on WSL the default prompt may never appear", curses));
	else checks.push(ok("passphrase prompt: GPG's default pinentry"));

	const profile = process.env.SHELL?.endsWith("zsh") ? "~/.zshrc" : "~/.bashrc";
	if (process.env.GPG_TTY) checks.push(ok("GPG_TTY is set"));
	else if (process.stdin.isTTY) checks.push(warn("GPG_TTY is not set, so a terminal passphrase prompt may not appear", `echo 'export GPG_TTY=$(tty)' >> ${profile}`));
	else checks.push(ok("GPG_TTY not checked (not run from a terminal)"));

	const ttl = (name: string, fallback: number) => {
		const value = Number(option(name));
		return Number.isInteger(value) && value >= 0 ? value : fallback;
	};
	const [cache, max] = [ttl("default-cache-ttl", 600), ttl("max-cache-ttl", 7200)];
	checks.push(cache > DAY || max > DAY
		? warn(`GPG stays unlocked too long (default-cache-ttl ${cache}s, max-cache-ttl ${max}s)`, `set default-cache-ttl 3600 and max-cache-ttl 28800 in ${tilde(conf)}, then gpgconf --kill gpg-agent`)
		: ok(`GPG unlock lasts ${cache}s after use, at most ${max}s`));
	return checks;
}

function clipboardCheck(): Check {
	try {
		return ok(`clipboard: ${clipboard().write[0]}`);
	} catch {
		const fix = process.platform === "darwin" ? "pbcopy ships with macOS" : process.env.WAYLAND_DISPLAY ? "sudo apt install wl-clipboard" : "sudo apt install xclip";
		return warn("no clipboard tool, so copy and --copy will not work (optional)", fix);
	}
}

function folderChecks(): Check[] {
	const checks: Check[] = [];
	const folder = basename(process.cwd());
	const prefix = /^[\w.-]+$/.test(folder) ? folder.toLowerCase() : "<project>";
	const plaintext = readdirSync(".").filter((name) => /^(\.env(\..+)?|\.dev\.vars(\..+)?)$/.test(name)
		&& name !== DEFAULT_FILE && !/\.(example|sample|template|dist)$/.test(name)
		&& lstatSync(name).isFile()).sort();
	const examples = exampleValues(".");
	const repository = git(".", ["rev-parse", "--is-inside-work-tree"]) === 0;
	for (const name of plaintext) {
		let items: Planned[];
		try {
			items = planImport(parseDotenv(readText(name, name), name), { prefix: "x", skip: new Set(), map: new Map(), examples }).items;
		} catch {
			checks.push(warn(`${name} could not be read as a dotenv file`, `check ${name} by hand`));
			continue;
		}
		for (const item of items.filter((item) => item.secretLooking)) {
			checks.push(warn(`${name}: ${item.name} looks like a secret under a public name (built into the browser bundle)`, "if it is a real key: rotate it and use it only on the server, without the public prefix"));
		}
		const secrets = items.filter((item) => item.action === "store").length;
		if (!secrets) {
			checks.push(ok(`${name} holds no secret-looking values`));
			continue;
		}
		const tracked = repository && gitTracked(resolve(name));
		const values = `${secrets} plaintext ${secrets === 1 ? "value" : "values"} that may be secret`;
		if (tracked) checks.push(warn(`${name} is committed to git and holds ${values}`, `if they are real secrets: rotate them, then git rm --cached ${name}`));
		else checks.push(warn(`${name} holds ${values}`, `pass-env import ${name} --prefix ${prefix} --dry-run`));
		const mode = statSync(name).mode & 0o777;
		if (mode & 0o077) checks.push(warn(`${name} can be read by other users (mode ${mode.toString(8)})`, `chmod 600 ${name}`));
		if (repository && !tracked && !gitIgnoreRule(resolve(name))) {
			checks.push(warn(`${name} is neither committed nor ignored by git, so git add . would commit it`, `echo '${name}' >> .gitignore`));
		}
	}
	if (!plaintext.length) checks.push(ok("no plaintext .env files in this folder"));
	const rule = gitIgnoreRule(resolve(DEFAULT_FILE));
	if (rule) checks.push(warn(`git ignores ${DEFAULT_FILE} (${rule}), so it will not be committed`, "echo '!.env.pass' >> .gitignore"));
	return checks;
}

function claudeCheck(): Check[] {
	const home = process.env.HOME;
	if (!home || !existsSync(join(home, ".claude"))) return [];
	let deny: unknown;
	try { deny = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8"))?.permissions?.deny; } catch { /* Missing or invalid. */ }
	const covered = Array.isArray(deny) && deny.some((rule) => typeof rule === "string" && /^Read\(.*\.env/.test(rule));
	return [covered ? ok("Claude Code is denied reading .env files") : warn("Claude Code may read .env files (hint)",
		`add to "permissions": { "deny": [...] } in ~/.claude/settings.json: "Read(**/.env)", "Read(**/.env.*)", "Read(**/.dev.vars)"`)];
}

// Env drift: variable names the code reads versus names the project declares.
const DRIFT_SKIP_DIRS = new Set([
	"node_modules", ".next", "dist", "build", ".git", ".worktrees", "out", "coverage",
	".venv", "venv", "__pycache__", ".wrangler", ".vercel", ".turbo", ".svelte-kit", ".output",
]);
const CODE_FILE = /\.(?:[cm]?[jt]sx?|py)$/;
const ENV_READS = [
	/\bprocess\.env\.([A-Za-z_]\w*)/g,
	/\bprocess\.env\[\s*["'`]([A-Za-z_]\w*)["'`]\s*\]/g,
	/\bimport\.meta\.env\.([A-Za-z_]\w*)/g,
	/\bBun\.env\.([A-Za-z_]\w*)/g,
	/\bDeno\.env\.get\(\s*["'`]([A-Za-z_]\w*)["'`]/g,
	/\bos\.environ\[\s*["']([A-Za-z_]\w*)["']\s*\]/g,
	/\bos\.(?:getenv|environ\.get)\(\s*["']([A-Za-z_]\w*)["']/g,
];
// const { A, B: b, C = "x" } = process.env
const ENV_DESTRUCTURE = /\{([^{}]*)\}\s*=\s*process\.env\b/g;
// Set by the runtime, the platform or the framework, so nobody declares them.
const RUNTIME_VARS = new Set([
	"NODE_ENV", "PORT", "HOST", "HOSTNAME", "CI", "HOME", "PATH", "PWD", "USER", "SHELL", "TERM", "TMPDIR", "TZ", "LANG", "DEBUG",
	"NEXT_RUNTIME", "NEXT_PHASE", "MODE", "DEV", "PROD", "SSR", "BASE_URL",
]);
const RUNTIME_PREFIXES = ["VERCEL", "GITHUB_", "CF_PAGES", "npm_"];
const DOTENV_NAME = /^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=/;
const DRIFT_MAX_FILES = 20_000;
const DRIFT_MAX_BYTES = 1_000_000;

type ProjectEnv = { used: Set<string>; declared: Set<string>; mapped: Set<string>; sources: number };

function readSmall(path: string): string | undefined {
	try {
		return statSync(path).size <= DRIFT_MAX_BYTES ? readFileSync(path, "utf8") : undefined;
	} catch {
		return undefined;
	}
}

// JSON with comments and trailing commas, as wrangler.jsonc allows.
function parseJsonc(text: string): unknown {
	let out = "";
	for (let index = 0; index < text.length; index += 1) {
		const char = text[index];
		if (char === '"') {
			const start = index;
			for (index += 1; index < text.length && text[index] !== '"'; index += 1) if (text[index] === "\\") index += 1;
			out += text.slice(start, index + 1);
		} else if (char === "/" && text[index + 1] === "/") {
			while (index < text.length && text[index] !== "\n") index += 1;
			out += "\n";
		} else if (char === "/" && text[index + 1] === "*") {
			const end = text.indexOf("*/", index + 2);
			index = end === -1 ? text.length : end + 1;
		} else out += char;
	}
	return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

function wranglerVars(name: string, text: string): string[] {
	if (name.endsWith(".toml")) {
		const names: string[] = [];
		let inVars = false;
		for (const raw of text.split("\n")) {
			const line = raw.trim();
			if (line.startsWith("[")) {
				inVars = /^\[\s*(?:env\.[^.\]]+\.)?vars\s*\]$/.test(line);
				continue;
			}
			const inline = /^vars\s*=\s*\{(.*)\}/.exec(line);
			if (inline) for (const match of inline[1].matchAll(/([A-Za-z_]\w*)\s*=/g)) names.push(match[1]);
			const key = inVars && /^["']?([A-Za-z_]\w*)["']?\s*=/.exec(line);
			if (key) names.push(key[1]);
		}
		return names;
	}
	try {
		const config = parseJsonc(text) as { vars?: object; env?: Record<string, { vars?: object }> };
		const objects = [config.vars, ...Object.values(config.env ?? {}).map((env) => env?.vars)];
		return objects.flatMap((vars) => vars && typeof vars === "object" ? Object.keys(vars) : []);
	} catch {
		return [];
	}
}

function codeReads(text: string, used: Set<string>): void {
	for (const pattern of ENV_READS) for (const match of text.matchAll(pattern)) used.add(match[1]);
	for (const match of text.matchAll(ENV_DESTRUCTURE)) {
		for (const part of match[1].split(",")) {
			const name = /^\s*([A-Za-z_]\w*)/.exec(part.trim().startsWith("...") ? "" : part);
			if (name) used.add(name[1]);
		}
	}
}

// One walk of the current folder: names read by code, and names declared in
// dotenv files, .env.pass, .dev.vars and Wrangler config.
function projectEnv(): ProjectEnv {
	const env: ProjectEnv = { used: new Set(), declared: new Set(), mapped: new Set(), sources: 0 };
	let budget = DRIFT_MAX_FILES;
	const visit = (directory: string): void => {
		let items;
		try { items = readdirSync(directory, { withFileTypes: true }); } catch { return; }
		for (const item of items) {
			if (budget <= 0) return;
			const path = directory === "." ? item.name : join(directory, item.name);
			if (item.isDirectory()) {
				if (!DRIFT_SKIP_DIRS.has(item.name)) visit(path);
				continue;
			}
			if (!item.isFile()) continue;
			budget -= 1;
			const dotenv = /^(\.env(\..+)?|\.dev\.vars(\..+)?)$/.test(item.name);
			const wrangler = /^wrangler\.(jsonc?|toml)$/.test(item.name);
			const code = CODE_FILE.test(item.name);
			if (!dotenv && !wrangler && !code && !item.name.endsWith(".prisma")) continue;
			const text = readSmall(path);
			if (text === undefined) continue;
			if (code) codeReads(text, env.used);
			else if (item.name.endsWith(".prisma")) for (const match of text.matchAll(/\benv\(\s*"([A-Za-z_]\w*)"\s*\)/g)) env.used.add(match[1]);
			else {
				env.sources += 1;
				const names = wrangler ? wranglerVars(item.name, text) : text.split("\n").map((line) => DOTENV_NAME.exec(line)?.[1]).filter((name) => name !== undefined);
				for (const name of names) {
					env.declared.add(name);
					if (item.name === DEFAULT_FILE) env.mapped.add(name);
				}
			}
		}
	};
	visit(".");
	return env;
}

function capped(names: string[], limit = 10): string {
	return names.length > limit ? `${names.slice(0, limit).join(", ")} and ${names.length - limit} more` : names.join(", ");
}

function driftChecks(): Check[] {
	const { used, declared, mapped, sources } = projectEnv();
	// Nothing to compare: no code reading the environment, or no declarations.
	if (!used.size || !sources) return [];
	const runtime = (name: string) => RUNTIME_VARS.has(name) || RUNTIME_PREFIXES.some((prefix) => name.startsWith(prefix));
	const undeclared = [...used].filter((name) => !declared.has(name) && !runtime(name)).sort();
	const unread = [...mapped].filter((name) => !used.has(name)).sort();
	const checks: Check[] = [];
	if (undeclared.length) {
		checks.push(warn(`env vars used in code but declared nowhere: ${capped(undeclared)}`,
			"add secrets to .env.pass and other values to .env.example, unless your platform sets them"));
	}
	if (unread.length) {
		checks.push(warn(`env vars in ${DEFAULT_FILE} but never read by the code: ${capped(unread)}`,
			"delete those lines if nothing uses them (tools such as Prisma or Auth.js can read variables your code does not)"));
	}
	if (!checks.length) checks.push(ok(`env vars: the code reads ${used.size}, all declared or set by the runtime`));
	return checks;
}

function doctor(): number {
	const checks = [...toolChecks(), ...storeChecks(), ...gpgChecks(), clipboardCheck(), ...folderChecks(), ...driftChecks(), ...claudeCheck()];
	for (const check of checks) {
		console.log(`${check.status.padEnd(4)}  ${check.text}`);
		if (check.fix) console.log(`      fix: ${check.fix}`);
	}
	const count = (status: Check["status"]) => checks.filter((check) => check.status === status).length;
	console.log(`\n${count("FAIL")} failed, ${count("warn")} ${count("warn") === 1 ? "warning" : "warnings"}, ${count("ok")} ok.`);
	return count("FAIL") ? 1 : 0;
}

// scrub: find and blank out secrets that coding agents already saved in
// their chat logs. Where each agent keeps its transcripts, relative to HOME:
// Claude Code (projects/**/*.jsonl, history.jsonl), Codex (sessions,
// archived_sessions, history.jsonl) and pi and its fork OMP (agent/sessions).
const AGENT_LOGS = [
	".claude/projects", ".claude/history.jsonl",
	".codex/sessions", ".codex/archived_sessions", ".codex/history.jsonl",
	".pi/agent/sessions", ".omp/agent/sessions",
];
const ACTIVE_MS = 10 * 60_000;
const CHUNK = 1 << 20;
// A raw PEM block over several lines is joined before matching, up to this many lines.
const PEM_MAX_LINES = 200;

// Each regex has two groups: text to keep, then the secret to replace.
// Adapted from Phaedrus Raznikov's redactor in misty-step/mistystack
// (agent-config/system-one/redaction.ts, MIT), with more providers, stricter
// lengths and checks against false positives, and JSON-escaped text in mind:
// in a JSONL log a newline is the two characters \n, so a token can follow
// "\n" and a PEM block is a single line.
// hint: a literal the text must contain, a cheap test before the regex.
type Pattern = { kind: string; regex: RegExp; check?: (secret: string) => boolean; boundary?: boolean; hint?: string };
const SEP = String.raw`(?:\s|\\+[rn])+`;
const PEM_KIND = String.raw`(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`;
// The marker, optional headers (Proc-Type: ...), then real base64, so code
// that merely mentions "-----BEGIN PRIVATE KEY-----" does not match.
const PEM_HEAD = String.raw`-----BEGIN ${PEM_KIND}${SEP}(?:[A-Za-z-]+: [^\n\\]*${SEP})*[A-Za-z0-9+/=]{40}`;
const PEM_OPEN_LINE = new RegExp(String.raw`-----BEGIN ${PEM_KIND}\s*$`);
const PEM_END = new RegExp(String.raw`-----END ${PEM_KIND}`);
const hasDigitAndLetter = (value: string) => /[0-9]/.test(value) && /[A-Za-z]/.test(value);
const mixedCase = (value: string) => /[0-9]/.test(value) && /[a-z]/.test(value) && /[A-Z]/.test(value);
// A value after "token=" and the like that looks like a real secret rather than code.
function plausibleSecret(value: string): boolean {
	return hasDigitAndLetter(value) && !PLACEHOLDER.test(value)
		&& !/^(?:[A-Za-z_$][\w$]*\.)+[A-Za-z_$][\w$]*!?$/.test(value) // process.env.API_KEY, config.token2
		&& !/^\$\{?[A-Za-z_]\w*\}?$/.test(value) // $API_KEY, ${API_KEY}
		&& !/^(?:\.{0,2}\/|~\/)/.test(value); // file paths
}
// boundary: the token must not continue a word ("risk-assessment" is not "sk-..."),
// except after an escaped \n, \r or \t. Checked outside the regex, which keeps
// each regex starting with a literal and so fast on long lines.
const pattern = (kind: string, source: string, options: Omit<Pattern, "kind" | "regex"> & { flags?: string } = {}): Pattern => (
	{ ...options, kind, regex: new RegExp(source, options.flags ?? "g") }
);
const token = (kind: string, source: string, check?: Pattern["check"]) => pattern(kind, `()(${source})`, { check, boundary: true });
const PATTERNS: Pattern[] = [
	pattern("private-key", String.raw`()(${PEM_HEAD}[\s\S]*?-----END ${PEM_KIND})`, { hint: "-----BEGIN " }),
	// No END marker (cut off): everything to the end of the string or line.
	pattern("private-key", String.raw`()(${PEM_HEAD}(?:\\.|[^"\\])*)`, { hint: "-----BEGIN " }),
	token("aws-access-key", String.raw`(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Za-z])`),
	token("github-token", String.raw`gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}`),
	token("anthropic-key", String.raw`sk-ant-[A-Za-z0-9_-]{32,}`, mixedCase),
	token("openai-key", String.raw`sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`, mixedCase),
	token("stripe-key", String.raw`[sr]k_(?:live|test)_[A-Za-z0-9]{20,}`, mixedCase),
	token("stripe-webhook-secret", String.raw`whsec_[A-Za-z0-9+/=]{24,}`, hasDigitAndLetter),
	token("slack-token", String.raw`xox[abposr]-[A-Za-z0-9-]{10,}`, (value) => /[0-9]/.test(value)),
	token("google-api-key", String.raw`AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])`),
	token("resend-key", String.raw`re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}`, hasDigitAndLetter),
	token("jwt", String.raw`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	pattern("bearer-token", String.raw`([Bb]earer\s+)([A-Za-z0-9._~+/-]{20,}=*)`, { check: hasDigitAndLetter, boundary: true }),
	// NAME=value, "name": "value", and the same inside JSON-escaped text. The
	// match starts at the keyword, so STRIPE_ in STRIPE_SECRET_KEY stays as is.
	pattern("secret-assignment", String.raw`((?:secret|token|password|passwd|api[_-]?key)[A-Za-z0-9_.-]{0,40}(?:\\*["'])?\s*[:=]\s*(?:\\*["'])?)([A-Za-z0-9_\-./+=~!@#$%^*]{12,})`, { check: plausibleSecret, flags: "gi" }),
];

const startsWord = (text: string, offset: number) => offset === 0 || !/[A-Za-z0-9]/.test(text[offset - 1]) || (offset > 1 && text[offset - 2] === "\\" && /[nrt]/.test(text[offset - 1]));

// The exact values in the store, raw and as they appear inside JSON strings.
function knownPattern(values: string[]): Pattern | undefined {
	const variants = new Set<string>();
	for (const value of values) {
		variants.add(value);
		variants.add(JSON.stringify(value).slice(1, -1));
	}
	if (!variants.size) return undefined;
	const escaped = [...variants].sort((a, b) => b.length - a.length).map((value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
	return { kind: "known-value", regex: new RegExp(`()(${escaped.join("|")})`, "g") };
}

function redact(text: string, patterns: Pattern[], counts: Map<string, number>): string {
	for (const { kind, regex, check, boundary, hint } of patterns) {
		if (hint && !text.includes(hint)) continue;
		text = text.replace(regex, (match: string, keep: string, secret: string, offset: number, whole: string) => {
			if ((check && !check(secret)) || (boundary && !startsWord(whole, offset))) return match;
			counts.set(kind, (counts.get(kind) ?? 0) + 1);
			return `${keep}[REDACTED:${kind}]`;
		});
	}
	return text;
}

const parsesAsJson = (text: string) => {
	try {
		JSON.parse(text);
		return true;
	} catch {
		return false;
	}
};

function addCounts(into: Map<string, number>, from: Map<string, number>): void {
	for (const [kind, count] of from) into.set(kind, (into.get(kind) ?? 0) + count);
}

// resume: where a later scan of the grown file starts when this one ended
// mid-line (the byte after the last newline), and what that partial line held.
// fullRescan: the file ended inside a raw PEM block, so only a full scan sees it whole.
// left: what was found on lines --fix had to leave as they were.
type Scanned = {
	counts: Map<string, number>; skippedLines: number; left: Map<string, number>;
	resume?: { offset: number; counts: Map<string, number> }; fullRescan: boolean;
};

// Streams a file line by line from byte start (a line start) up to byte end,
// writing the redacted text to output if given.
// Returns undefined for a file that is not UTF-8 text.
function scanFile(path: string, patterns: Pattern[], output?: number, start = 0, end?: number): Scanned | undefined {
	const result: Scanned = { counts: new Map(), skippedLines: 0, left: new Map(), fullRescan: false };
	let pending: string[] = [];
	let pendingSize = 0;
	const write = (text: string) => {
		if (output === undefined) return;
		pending.push(text);
		pendingSize += text.length;
		if (pendingSize >= CHUNK) flush();
	};
	const flush = () => {
		if (output !== undefined && pending.length) writeSync(output, pending.join(""));
		pending = [];
		pendingSize = 0;
	};
	const line = (text: string, newline: boolean) => {
		const counts = new Map<string, number>();
		const changed = redact(text, patterns, counts);
		// A replacement that would break a JSONL line leaves that line as it was.
		if (counts.size && output !== undefined && parsesAsJson(text) && !parsesAsJson(changed)) {
			result.skippedLines += 1;
			addCounts(result.left, counts);
			write(newline ? `${text}\n` : text);
			return;
		}
		addCounts(result.counts, counts);
		write(newline ? `${changed}\n` : changed);
	};
	// Lines of a raw (not JSON-escaped) PEM block, from its BEGIN line.
	let block: string[] = [];
	const endBlock = (newline: boolean, complete: boolean) => {
		const lines = block;
		block = [];
		if (complete) line(lines.join("\n"), newline);
		else lines.forEach((text, index) => line(text, index < lines.length - 1 || newline));
	};
	const handle = (text: string, newline: boolean) => {
		if (!block.length && !PEM_OPEN_LINE.test(text)) return line(text, newline);
		block.push(text);
		if (block.length > 1 && PEM_END.test(text)) endBlock(newline, true);
		else if (block.length >= PEM_MAX_LINES || !newline) endBlock(newline, false);
	};
	const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
	const buffer = Buffer.allocUnsafe(CHUNK);
	const input = openSync(path, "r");
	let partial: string[] = [];
	let position = start;
	// The byte after the last newline read so far.
	let lineEnd = start;
	try {
		for (;;) {
			const want = end === undefined ? CHUNK : Math.min(CHUNK, end - position);
			const bytes = want > 0 ? readSync(input, buffer, 0, want, position) : 0;
			if (bytes) {
				const newline = buffer.lastIndexOf(10, bytes - 1);
				if (newline !== -1) lineEnd = position + newline + 1;
				position += bytes;
			}
			let text: string;
			try {
				text = bytes ? decoder.decode(buffer.subarray(0, bytes), { stream: true }) : decoder.decode();
			} catch {
				return undefined;
			}
			if (text.includes("\0")) return undefined;
			let from = 0;
			for (let stop = text.indexOf("\n"); stop !== -1; stop = text.indexOf("\n", from)) {
				handle(partial.join("") + text.slice(from, stop), true);
				partial = [];
				from = stop + 1;
			}
			if (from < text.length) partial.push(text.slice(from));
			if (!bytes) break;
		}
		if (partial.length) {
			if (block.length) result.fullRescan = true;
			const before = new Map(result.counts);
			handle(partial.join(""), false);
			if (!result.fullRescan) result.resume = { offset: lineEnd, counts: difference(result.counts, before) };
		}
		if (block.length) {
			result.fullRescan = true;
			endBlock(false, false);
		}
		flush();
		return result;
	} finally {
		closeSync(input);
	}
}

const difference = (after: Map<string, number>, before: Map<string, number>) => new Map(
	[...after].map(([kind, count]): [string, number] => [kind, count - (before.get(kind) ?? 0)]).filter(([, count]) => count > 0),
);

// Every regular file under the given files and folders, with the location it
// was found in; symlinks inside are not followed.
function logFiles(locations: string[]): Map<string, string> {
	const files = new Map<string, string>();
	const visit = (path: string, location: string) => {
		let info: Stats;
		try { info = lstatSync(path); } catch { return; }
		if (info.isFile() && !/\.pass-env-\d+\.tmp$/.test(path)) {
			if (!files.has(path)) files.set(path, location);
		} else if (info.isDirectory()) {
			let names: string[];
			try { names = readdirSync(path); } catch { return; }
			for (const name of names) visit(join(path, name), location);
		}
	};
	for (const location of locations) visit(realpathSync(location), location);
	return new Map([...files].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

async function knownValues(): Promise<string[]> {
	const root = storePath();
	const values = new Set<string>();
	const failed: string[] = [];
	for (const entry of listEntries(root, "")) {
		try {
			const value = await decrypt(root, { name: entry, entry, multiline: false });
			if (value.length >= 12) values.add(value);
		} catch (error) {
			if (error instanceof CliError && error.code === "LOCKED") throw error;
			failed.push(entry);
		}
	}
	if (failed.length) console.error(`warning: could not decrypt ${capped(failed)}, so their values were not looked for`);
	return [...values];
}

// Changes whenever an entry is added, removed or rewritten; reads no secret.
function storeFingerprint(root: string): string {
	const hash = createHash("sha256").update(`${root}\n`);
	for (const entry of listEntries(root, "")) {
		let info: Stats;
		try { info = statSync(join(root, `${entry}.gpg`)); } catch { continue; }
		hash.update(`${entry}\0${info.size}\0${info.mtimeMs}\n`);
	}
	return hash.digest("hex").slice(0, 32);
}

const plural = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;
const describeCounts = (counts: Map<string, number>) => [...counts].sort(([a], [b]) => a.localeCompare(b)).map(([kind, count]) => `${kind} ${count}`).join(", ");
const total = (counts: Map<string, number>) => [...counts.values()].reduce((sum, count) => sum + count, 0);
const size = (bytes: number) => bytes < 1_000_000 ? `${Math.ceil(bytes / 1000)} KB` : `${(bytes / 1_000_000).toFixed(1)} MB`;

// Writes the redacted copy next to the file and renames it over the original,
// keeping mode and times. Gives up if the file changes meanwhile. Returns what
// was written, so the scan history can recognise the new file.
function rewriteFile(path: string, patterns: Pattern[], before: Stats): (Scanned & { written: Stats }) | "changed" | "failed" {
	const temp = join(dirname(path), `.${basename(path)}.pass-env-${process.pid}.tmp`);
	const mode = before.mode & 0o7777;
	let output: number | undefined;
	try {
		output = openSync(temp, "wx", mode);
		const result = scanFile(path, patterns, output);
		closeSync(output);
		output = undefined;
		const now = statSync(path);
		if (!result || now.mtimeMs !== before.mtimeMs || now.size !== before.size) {
			rmSync(temp, { force: true });
			return "changed";
		}
		chmodSync(temp, mode);
		utimesSync(temp, before.atime, before.mtime);
		const written = statSync(temp);
		renameSync(temp, path);
		return { ...result, written };
	} catch {
		if (output !== undefined) closeSync(output);
		rmSync(temp, { force: true });
		return "failed";
	}
}

// Scan history: which files scrub read, when, and what it found, so the next
// run skips unchanged files and reads only the new end of files that grew.
// It holds paths, sizes, times and counts only, never a secret.
// Bump PATTERNS_VERSION whenever PATTERNS or the way files are read changes,
// so every file is read again.
const PATTERNS_VERSION = 1;
type Counts = Record<string, number>;
type FileRecord = {
	location: string; dev: number; ino: number; size: number; mtime_ms: number; scanned_at: string; counts: Counts;
	fixed_at?: string;
	left?: number; // how many of the counts are on lines --fix had to leave
	known?: true; // scanned with --known against the store in store_fingerprint
	binary?: true; // not UTF-8 text
	stale?: true; // scanned with older patterns
	resume?: { offset: number; counts: Counts };
	full_rescan?: true;
};
type ScrubState = {
	version: 1; patterns_version: number; store_fingerprint?: string;
	locations: Record<string, { checked_at: string }>; files: Record<string, FileRecord>;
};

function historyPath(home: string): string {
	const state = process.env.XDG_STATE_HOME;
	return join(state && isAbsolute(state) ? state : join(home, ".local", "state"), "pass-env", "scrub.json");
}

const toCounts = (counts: Map<string, number>): Counts => Object.fromEntries([...counts].sort(([a], [b]) => a.localeCompare(b)));
const fromCounts = (counts: Counts) => new Map(Object.entries(counts));
const isCounts = (value: unknown): value is Counts => typeof value === "object" && value !== null && Object.values(value).every((count) => Number.isInteger(count));
const validRecord = (record: FileRecord) => typeof record === "object" && record !== null && typeof record.location === "string"
	&& [record.dev, record.ino, record.size, record.mtime_ms].every((value) => typeof value === "number") && typeof record.scanned_at === "string"
	&& isCounts(record.counts) && (record.resume === undefined || (typeof record.resume.offset === "number" && isCounts(record.resume.counts)));

function loadHistory(path: string): ScrubState {
	const empty: ScrubState = { version: 1, patterns_version: PATTERNS_VERSION, locations: {}, files: {} };
	let text: string;
	try { text = readFileSync(path, "utf8"); } catch { return empty; }
	try {
		const state = JSON.parse(text) as ScrubState;
		if (state.version !== 1 || typeof state.files !== "object" || typeof state.locations !== "object" || !state.files || !state.locations) throw new Error();
		for (const [file, record] of Object.entries(state.files)) if (!validRecord(record)) delete state.files[file];
		if (state.patterns_version !== PATTERNS_VERSION) {
			for (const record of Object.values(state.files)) record.stale = true;
			state.patterns_version = PATTERNS_VERSION;
		}
		return state;
	} catch {
		console.error(`warning: ${tilde(path)} is not a scan history this version can read, so every file is read again`);
		return empty;
	}
}

// Readable only by you, and replaced in one step so a crash never leaves half a file.
function saveHistory(path: string, state: ScrubState): void {
	const temp = `${path}.pass-env-${process.pid}.tmp`;
	try {
		mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
		rmSync(temp, { force: true });
		writeFileSync(temp, `${JSON.stringify(state)}\n`, { mode: 0o600, flag: "wx" });
		chmodSync(temp, 0o600);
		renameSync(temp, path);
	} catch {
		rmSync(temp, { force: true });
		console.error(`warning: could not save the scan history to ${tilde(path)}, so the next run reads every file again`);
	}
}

function when(iso: string): string {
	const date = new Date(iso);
	const two = (value: number) => String(value).padStart(2, "0");
	return `${date.getFullYear()}-${two(date.getMonth() + 1)}-${two(date.getDate())} ${two(date.getHours())}:${two(date.getMinutes())}`;
}

function byteAt(path: string, offset: number): number {
	let input: number | undefined;
	try {
		input = openSync(path, "r");
		const buffer = Buffer.alloc(1);
		return readSync(input, buffer, 0, 1, offset) === 1 ? buffer[0] : -1;
	} catch {
		return -1;
	} finally {
		if (input !== undefined) closeSync(input);
	}
}

type ScanPlan = { how: "same" } | { how: "append"; start: number } | { how: "full" };

// How much of a file to read, given what the last scan saw. A file that kept
// its inode and only grew is read from where the last scan stopped (a line
// start); anything else is read whole.
function scanPlan(path: string, info: Stats, record: FileRecord | undefined, known: boolean): ScanPlan {
	if (!record || record.stale || (known && !record.known) || record.dev !== info.dev || record.ino !== info.ino) return { how: "full" };
	if (info.size === record.size && info.mtimeMs === record.mtime_ms) return { how: "same" };
	if (info.size > record.size && info.mtimeMs > record.mtime_ms && !record.full_rescan && !record.binary) {
		const start = record.resume?.offset ?? record.size;
		if (start <= record.size && (start === 0 || byteAt(path, start - 1) === 10)) return { how: "append", start };
	}
	return { how: "full" };
}

// Whether --fix has something to do: not for lines it already had to leave,
// nor for exact store values when this run does not look for them.
const fixable = (record: FileRecord, known: boolean) =>
	Object.entries(record.counts).reduce((sum, [kind, count]) => sum + (known || kind !== "known-value" ? count : 0), 0) > (record.left ?? 0);

function scrubHistory(home: string): number {
	const path = historyPath(home);
	if (!existsSync(path)) {
		console.log("No scan history yet. Run pass-env scrub first.");
		return 0;
	}
	const state = loadHistory(path);
	const groups = new Map<string, FileRecord[]>();
	for (const record of Object.values(state.files)) groups.set(record.location, [...(groups.get(record.location) ?? []), record]);
	const checked = (location: string) => state.locations[location]?.checked_at
		?? (groups.get(location) ?? []).map((record) => record.scanned_at).sort().at(-1) ?? "";
	const locations = [...new Set([...Object.keys(state.locations), ...groups.keys()])].sort((a, b) => checked(b).localeCompare(checked(a)));
	console.log(`Scan history in ${tilde(path)} (paths, times and counts only), newest first:`);
	for (const location of locations) {
		const records = groups.get(location) ?? [];
		const found = records.filter((record) => Object.keys(record.counts).length);
		const counts = new Map<string, number>();
		for (const record of found) addCounts(counts, fromCounts(record.counts));
		const fixed = records.filter((record) => record.fixed_at).length;
		console.log(`\n${tilde(location)}\n  last checked ${checked(location) ? when(checked(location)) : "never"}: ${plural(records.length, "file")}, `
			+ `${found.length} with findings${found.length ? ` (${describeCounts(counts)})` : ""}, ${fixed} fixed`);
	}
	if (Object.values(state.files).some((record) => record.stale)) console.log("\nThe patterns changed since some of these scans; the next scrub reads those files again.");
	return 0;
}

async function scrub(options: ScrubOptions): Promise<number> {
	const home = process.env.HOME;
	if (!home) throw new CliError("USAGE", "HOME is not set, so the agent logs cannot be found", 2);
	if (options.history) return scrubHistory(home);
	for (const path of options.paths) {
		if (!existsSync(path)) throw new CliError("USAGE", `--path ${path}: no such file or folder`, 2);
	}
	const locations = [...AGENT_LOGS.map((path) => join(home, path)).filter((path) => existsSync(path)), ...options.paths.map((path) => resolve(path))];
	const shownLocations = locations.map(tilde).join(", ");
	if (!locations.length) {
		console.log("No agent logs found (looked in ~/.claude, ~/.codex, ~/.pi and ~/.omp). Add --path <file-or-folder> to scan somewhere else.");
		return 0;
	}
	const historyFile = historyPath(home);
	const state = loadHistory(historyFile);
	if (options.known) {
		const fingerprint = storeFingerprint(storePath());
		// The store changed, so earlier --known scans looked for other values.
		if (state.store_fingerprint !== fingerprint) for (const record of Object.values(state.files)) delete record.known;
		state.store_fingerprint = fingerprint;
	}
	const cutoff = Date.now() - ACTIVE_MS;
	let active = 0;
	const plans: { path: string; location: string; info: Stats; busy: boolean; record?: FileRecord; plan: ScanPlan }[] = [];
	for (const [path, location] of logFiles(locations)) {
		let info: Stats;
		try { info = statSync(path); } catch { continue; }
		const busy = info.mtimeMs > cutoff;
		if (options.fix && busy && !options.includeActive) {
			active += 1;
			continue;
		}
		const record = options.all ? undefined : state.files[path];
		plans.push({ path, location, info, busy, record, plan: scanPlan(path, info, record, options.known) });
	}
	// Decrypt only when some file has to be read.
	const reads = (item: (typeof plans)[number]) => item.plan.how !== "same" || (options.fix && fixable(item.record!, options.known));
	const known = options.known && plans.some(reads) ? knownPattern(await knownValues()) : undefined;
	const patterns = known ? [known, ...PATTERNS] : PATTERNS;
	const now = new Date().toISOString();
	const found = new Map<string, number>();
	const fixed = new Map<string, number>();
	let read = 0;
	let bytes = 0;
	let appended = 0;
	let unchanged = 0;
	let newest = "";
	let remembered = 0;
	let affected = 0;
	let notText = 0;
	let skippedLines = 0;
	const failed: string[] = [];
	for (const item of plans) {
		const { path, location, info, busy, record, plan } = item;
		const ids = (stats: Stats) => ({ location, dev: stats.dev, ino: stats.ino, size: stats.size, mtime_ms: stats.mtimeMs });
		const fixedAt = state.files[path]?.fixed_at;
		let counts: Map<string, number>;
		if (plan.how === "same" && !reads(item)) {
			unchanged += 1;
			if (record!.scanned_at > newest) newest = record!.scanned_at;
			record!.location = location;
			counts = fromCounts(record!.counts);
			if (!counts.size || options.fix) continue;
			remembered += 1;
		} else if (plan.how === "same") {
			// --fix on a file the last scan found secrets in: the rewrite reads it.
			counts = fromCounts(record!.counts);
		} else {
			const start = plan.how === "append" ? plan.start : 0;
			let scanned: Scanned | undefined;
			try {
				scanned = scanFile(path, patterns, undefined, start, info.size);
			} catch {
				notText += 1;
				delete state.files[path];
				continue;
			}
			read += 1;
			bytes += info.size - start;
			if (!scanned) {
				notText += 1;
				state.files[path] = { ...ids(info), scanned_at: now, counts: {}, binary: true };
				continue;
			}
			counts = scanned.counts;
			let left: number | undefined;
			if (plan.how === "append") {
				appended += 1;
				counts = fromCounts(record!.counts);
				for (const [kind, count] of fromCounts(record!.resume?.counts ?? {})) {
					if ((counts.get(kind) ?? 0) > count) counts.set(kind, counts.get(kind)! - count);
					else counts.delete(kind);
				}
				addCounts(counts, scanned.counts);
				left = record!.left;
			}
			state.files[path] = {
				...ids(info), scanned_at: now, counts: toCounts(counts),
				...(fixedAt && { fixed_at: fixedAt }), ...(left && { left }), ...(options.known && { known: true as const }),
				...(scanned.resume && { resume: { offset: scanned.resume.offset, counts: toCounts(scanned.resume.counts) } }),
				...(scanned.fullRescan && { full_rescan: true as const }),
			};
			if (!counts.size) continue;
		}
		if (!options.fix) {
			affected += 1;
			addCounts(found, counts);
			const notes = [plan.how === "same" && `unchanged since the scan on ${when(record!.scanned_at)}`, busy && "in use: --fix skips it"].filter(Boolean);
			console.log(`${tilde(path)}: ${describeCounts(counts)}${notes.length ? ` (${notes.join("; ")})` : ""}`);
			continue;
		}
		if (!fixable(state.files[path], options.known)) continue;
		if (plan.how === "same") {
			read += 1;
			bytes += info.size;
		}
		affected += 1;
		addCounts(found, counts);
		const result = rewriteFile(path, patterns, info);
		if (result === "changed" || result === "failed") {
			if (result === "changed") delete state.files[path];
			failed.push(tilde(path));
			console.log(`${tilde(path)}: ${result === "changed" ? "changed while scrubbing" : "could not be rewritten"}, so it was left as it was`);
			continue;
		}
		// Record the rewritten file, unless something changed it right after the rename.
		let after: Stats | undefined;
		try { after = statSync(path); } catch { after = undefined; }
		const { written } = result;
		if (after && after.ino === written.ino && after.size === written.size && after.mtimeMs === written.mtimeMs) {
			const left = total(result.left);
			state.files[path] = {
				...ids(written), scanned_at: now, counts: toCounts(result.left), fixed_at: now,
				...(left && { left }), ...(options.known && { known: true as const }), ...((result.resume || result.fullRescan) && { full_rescan: true as const }),
			};
		} else delete state.files[path];
		addCounts(fixed, result.counts);
		skippedLines += result.skippedLines;
		const skipped = result.skippedLines ? `; ${plural(result.skippedLines, "line")} left as is (would not stay valid JSON)` : "";
		console.log(`${tilde(path)}: redacted ${describeCounts(result.counts) || "nothing"}${skipped}`);
	}
	// Forget files that are gone, note when each location was checked, and save.
	for (const path of Object.keys(state.files)) if (!existsSync(path)) delete state.files[path];
	for (const location of locations) state.locations[location] = { checked_at: now };
	for (const location of Object.keys(state.locations)) if (!existsSync(location)) delete state.locations[location];
	saveHistory(historyFile, state);

	console.log(`${affected ? "\n" : ""}${read || !unchanged ? `Scanned ${plural(read, "file")} (${size(bytes)})` : "Nothing new to scan"} in ${shownLocations}.`);
	if (appended) console.log(`${plural(appended, "file")} only grew since the last scan, so only ${appended === 1 ? "its" : "their"} new lines were read.`);
	if (unchanged) console.log(`${plural(unchanged, "file")} unchanged since ${when(newest)}, skipped (--all reads everything again).`);
	if (notText) console.log(`Skipped ${plural(notText, "file")} that ${notText === 1 ? "is" : "are"} not UTF-8 text or could not be read.`);
	if (options.fix) {
		const count = total(fixed);
		const done = affected - failed.length;
		console.log(count ? `Redacted ${plural(count, "suspected secret")} in ${plural(done, "file")}: ${describeCounts(fixed)}.` : "No suspected secrets were redacted.");
		if (skippedLines) console.log(`Left ${plural(skippedLines, "line")} as ${skippedLines === 1 ? "it was" : "they were"}: redacting would have broken ${skippedLines === 1 ? "its" : "their"} JSON.`);
		if (active) console.log(`Skipped ${plural(active, "file")} changed in the last 10 minutes (an agent may be writing ${active === 1 ? "it" : "them"}); close the session or add --include-active.`);
		if (count) console.log("There are no backups: a backup would be one more plaintext copy. Rotate any real key that was found: blanking a log does not un-send it.");
		return failed.length ? 1 : 0;
	}
	const count = total(found);
	if (!count) {
		console.log("No suspected secrets found.");
		return 0;
	}
	const flags = [...options.paths.map((path) => ` --path ${path}`), options.known ? " --known" : ""].join("");
	console.log(`Found ${plural(count, "suspected secret")} in ${plural(affected, "file")}: ${describeCounts(found)}.`);
	if (remembered) console.log(`${remembered} of these files ${remembered === 1 ? "was" : "were"} not read again: unchanged since the scan that found ${remembered === 1 ? "it" : "them"}.`);
	console.log(`Nothing was changed. To replace them with [REDACTED:<kind>]: pass-env scrub --fix${flags}`);
	console.log("Rotate any real key in this list: it was also sent to the agent's model provider.");
	return 1;
}

async function main(args: string[]): Promise<number> {
	const options = parseArgs(args);
	if (options.command === "help") {
		console.log(usage());
		return 0;
	}
	if (options.command === "doctor") return doctor();
	if (options.command === "scrub") return scrub(options);
	const root = storePath();
	switch (options.command) {
		case "list": {
			const entries = listEntries(root, options.prefix);
			if (options.json) console.log(JSON.stringify(entries));
			else if (entries.length) console.log(entries.join("\n"));
			return 0;
		}
		case "check": {
			const items = readMappings(options);
			const width = Math.max(...items.map((item) => item.name.length));
			let missing = 0;
			for (const item of items) {
				const ok = entryExists(root, item.entry);
				if (!ok) missing += 1;
				console.log(`${ok ? "ok     " : "MISSING"}  ${item.name.padEnd(width)}  ${item.entry}${item.multiline ? " (multiline)" : ""}`);
			}
			if (missing) console.error(`${missing} missing; add with: pass-env set <entry>  or  pass-env generate <entry>`);
			return missing ? 1 : 0;
		}
		case "set": {
			const lines = await setEntry(root, options.entry, options.force);
			console.log(lines > 1 ? `Stored ${options.entry} exactly as piped (${lines} lines); map it with multiline:${options.entry}.` : `Stored ${options.entry}.`);
			return 0;
		}
		case "generate": {
			const board = options.copy ? clipboard() : undefined;
			const secret = randomSecret(options.length, options.charset);
			await store(root, options.entry, secret, options.force);
			const verb = options.force ? "Replaced" : "Generated";
			if (!board) {
				console.log(`${verb} ${options.entry}: ${options.length} random ${options.charset} characters. The value was not shown.`);
				return 0;
			}
			const seconds = await copyToClipboard(board, secret);
			console.log(`${verb} ${options.entry} and copied it to the clipboard; it clears in ${seconds}s.`);
			return 0;
		}
		case "copy":
		case "pipe": {
			if (!entryExists(root, options.entry)) throw new CliError("ENTRY", `${options.entry}: entry does not exist or is a symlink`);
			const board = options.command === "copy" ? clipboard() : undefined;
			const value = await decrypt(root, { name: options.entry, entry: options.entry, multiline: options.multiline });
			if (options.command === "pipe") return runChild(options.argv, process.env, value);
			const seconds = await copyToClipboard(board!, value);
			console.log(`Copied ${options.entry} to the clipboard; it clears in ${seconds}s.`);
			return 0;
		}
		case "import":
			return options.remove ? removeImported(root, options) : importFile(root, options);
		case "unlock": {
			const entry = await unlock(root, options.entry);
			console.log(`Unlocked (checked with ${entry}). Runs can decrypt until GPG's cache expires.`);
			return 0;
		}
		case "run": {
			const items = readMappings(options);
			for (const item of items) {
				if (!entryExists(root, item.entry)) throw new CliError("ENTRY", `${item.name}: entry does not exist or is a symlink; run pass-env check`);
			}
			const env: NodeJS.ProcessEnv = Object.assign(Object.create(null), process.env);
			const values = new Map<string, string>();
			for (const item of items) {
				const key = `${item.multiline ? "m" : "1"}:${item.entry}`;
				let value = values.get(key);
				if (value === undefined) {
					value = await decrypt(root, item);
					values.set(key, value);
				}
				env[item.name] = value;
			}
			return runChild(options.argv, env);
		}
	}
}

if (import.meta.main) {
	try {
		process.exitCode = await main(process.argv.slice(2));
	} catch (error) {
		const failure = error instanceof CliError ? error : new CliError("INTERNAL", "command failed");
		console.error(`${failure.code}: ${failure.message}`);
		process.exitCode = failure.exitCode;
	}
}
