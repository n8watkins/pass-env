#!/usr/bin/env bun
// pass-env: give programs and coding agents secrets from `pass` without
// showing them. Fork of misty-step/mistystack's bin/pass-env.ts (MIT).

import { spawn } from "node:child_process";
import { existsSync, lstatSync, readFileSync, readdirSync, statSync } from "node:fs";
import { isAbsolute, join, parse, relative, resolve, sep } from "node:path";

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
	| { command: "unlock"; entry?: string };

const DEFAULT_FILE = ".env.pass";
const MULTILINE = "multiline:";
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

Check and set up
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

Notes
  The store is PASSWORD_STORE_DIR or ~/.password-store. Entry names are
  visible file names: never put a secret in a name.
  set and generate only encrypt, so they work while GPG is locked.
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
	if (equals < 1 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
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
		default:
			throw new CliError("USAGE", "unknown command; run pass-env help", 2);
	}
}

function readMappings(sources: Sources): Mapping[] {
	const result = new Map<string, Mapping>();
	for (let index = 0; index < sources.files.length; index += 1) {
		const location = `reference file ${index + 1}`;
		let text: string;
		try {
			if (!statSync(sources.files[index]).isFile()) throw new Error();
			text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(readFileSync(sources.files[index]));
		} catch {
			throw new CliError("REFERENCE_FILE", `${location}: cannot read regular UTF-8 file`);
		}
		const seen = new Set<string>();
		for (const [lineIndex, raw] of text.split("\n").entries()) {
			const line = raw.trim();
			if (!line || line.startsWith("#")) continue;
			const item = mapping(line, `${location}, line ${lineIndex + 1}`);
			if (seen.has(item.name)) throw new CliError("USAGE", `${location}: duplicate mapping ${item.name}`, 2);
			seen.add(item.name);
			result.set(item.name, item);
		}
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

async function store(root: string, entry: string, value: string, force: boolean): Promise<void> {
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
	backend.stdin.write(value.endsWith("\n") ? value : `${value}\n`);
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

async function readStdin(): Promise<string> {
	const text = await Bun.stdin.text();
	return text.replace(/\r?\n$/, "");
}

async function setEntry(root: string, entry: string, force: boolean): Promise<void> {
	if (!process.stdin.isTTY) {
		const value = await readStdin();
		if (!value) throw new CliError("VALUE", "nothing was piped in");
		await store(root, entry, value, force);
		return;
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
}

type Clipboard = { write: string[]; read?: string[] };

function clipboard(): Clipboard {
	const words = (value: string | undefined) => value?.split(" ").filter(Boolean);
	if (process.env.PASS_ENV_CLIPBOARD) {
		return { write: words(process.env.PASS_ENV_CLIPBOARD)!, read: words(process.env.PASS_ENV_CLIPBOARD_READ) };
	}
	let wsl = false;
	try { wsl = /microsoft/i.test(readFileSync("/proc/version", "utf8")); } catch { /* Not Linux. */ }
	if (wsl && Bun.which("clip.exe")) {
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

async function main(args: string[]): Promise<number> {
	const options = parseArgs(args);
	if (options.command === "help") {
		console.log(usage());
		return 0;
	}
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
		case "set":
			await setEntry(root, options.entry, options.force);
			console.log(`Stored ${options.entry}.`);
			return 0;
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
