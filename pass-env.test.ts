import { afterEach, describe, expect, test } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

// PASS_ENV_BIN runs the whole suite against a compiled binary instead.
const cli = process.env.PASS_ENV_BIN ? resolve(process.env.PASS_ENV_BIN) : join(import.meta.dir, "pass-env.ts");
const launcher = process.env.PASS_ENV_BIN ? [cli] : [process.execPath, cli];
const roots: string[] = [];
type Fixture = { root: string; store: string; env: NodeJS.ProcessEnv; calls: string };

// A fake `pass` that stores plaintext, so tests can inspect what was written.
function fixture(entries: Record<string, string | Uint8Array> = { token: "synthetic-value" }): Fixture {
	const root = mkdtempSync(join(tmpdir(), "pass-env-test-"));
	roots.push(root);
	const store = join(root, ".password-store");
	const bin = join(root, "bin");
	const calls = join(root, "pass-called");
	mkdirSync(store);
	mkdirSync(bin);
	for (const [name, value] of Object.entries(entries)) {
		const file = join(store, `${name}.gpg`);
		mkdirSync(dirname(file), { recursive: true });
		writeFileSync(file, value);
	}
	writeFileSync(join(bin, "pass"), `#!${process.execPath}
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
const args = process.argv.slice(2);
appendFileSync(process.env.TEST_PASS_CALLS, args.join(" ") + "\\n");
const file = (entry) => join(process.env.PASSWORD_STORE_DIR, entry + ".gpg");
if (args[0] === "insert") {
  if (args.join(" ") !== "insert --multiline --force -- " + args[4] || args.length !== 5) process.exit(7);
  mkdirSync(dirname(file(args[4])), { recursive: true });
  writeFileSync(file(args[4]), await Bun.stdin.text());
  process.exit(0);
}
if (args[0] !== "show" || args[1] !== "--" || args.length !== 3) process.exit(7);
if (process.env.PASSWORD_STORE_GPG_OPTS !== "--batch --pinentry-mode error") process.exit(8);
if (process.env.TEST_PASS_LOCKED) {
  process.stderr.write("gpg: decryption failed: No pinentry synthetic-locked");
  process.exit(2);
}
// Deliberately drain backend stdin: the launcher must leave child stdin alone.
await Bun.stdin.text();
const failures = {
  broken: "synthetic-backend-stderr",
  locked: "gpg: public key decryption failed: Inappropriate ioctl for device synthetic-locked",
  nokey: "gpg: decryption failed: No secret key synthetic-nokey",
};
if (args[2] in failures) {
  process.stdout.write("synthetic-backend-plaintext");
  process.stderr.write(failures[args[2]]);
  process.exit(2);
}
process.stdout.write(readFileSync(file(args[2])));
`, { mode: 0o700 });
	// A fake clipboard backed by a file.
	writeFileSync(join(bin, "fakeclip"), `#!/bin/sh\ncat > "$CLIP_FILE"\n`, { mode: 0o700 });
	writeFileSync(join(bin, "fakepaste"), `#!/bin/sh\ncat "$CLIP_FILE"\n`, { mode: 0o700 });
	// A fake gpg that only answers doctor's secret-key question.
	writeFileSync(join(bin, "gpg"), `#!/bin/sh
for id; do :; done
case " $TEST_GPG_SECRET_KEYS " in *" $id "*) echo "sec:u:255:22:SYNTHETIC::::::::::"; exit 0;; esac
exit 2
`, { mode: 0o700 });
	return {
		root, store, calls,
		env: {
			...process.env, HOME: root, PASSWORD_STORE_DIR: store, PATH: `${bin}:${process.env.PATH}`, TEST_PASS_CALLS: calls,
			PASS_ENV_CLIPBOARD: "fakeclip", PASS_ENV_CLIPBOARD_READ: "fakepaste", CLIP_FILE: join(root, "clipboard"), PASSWORD_STORE_CLIP_TIME: "1",
		},
	};
}

function invoke(files: Fixture, args: string[], input = "") {
	const result = spawnSync(launcher[0], [...launcher.slice(1), ...args], {
		cwd: files.root, env: files.env, input, encoding: "utf8", timeout: 10_000,
	});
	if (result.error) throw result.error;
	return result;
}

function markerCommand(files: Fixture): string[] {
	return ["--", process.execPath, "-e", `require("node:fs").writeFileSync(${JSON.stringify(join(files.root, "child-started"))}, "started")`];
}

const stored = (files: Fixture, entry: string) => readFileSync(join(files.store, `${entry}.gpg`), "utf8");

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("run", () => {
	test("a missing later mapping starts neither backend lookup nor the child", () => {
		const files = fixture();
		const result = invoke(files, ["run", "-e", "FIRST=token", "-e", "SECOND=missing", ...markerCommand(files)]);
		expect(result.status).toBe(1);
		expect(result.stderr).toContain("SECOND");
		expect(result.stdout).toBe("");
		expect(existsSync(files.calls)).toBe(false);
		expect(existsSync(join(files.root, "child-started"))).toBe(false);
	});

	test("reference files are data, never shell programs", () => {
		const files = fixture();
		const injected = join(files.root, "injected");
		const reference = join(files.root, ".env.pass");
		writeFileSync(reference, `TOKEN=$(touch ${injected})\n`);
		const result = invoke(files, ["run", "-f", reference, ...markerCommand(files)]);
		expect(result.status).toBe(1);
		expect(existsSync(injected)).toBe(false);
		expect(existsSync(join(files.root, "child-started"))).toBe(false);
		expect(result.stderr).not.toContain("$(touch");
	});

	test("values are the entry's first line; multiline: gives the whole entry exactly", () => {
		const multi = "﻿ first line\r\n雪\nlast line\n\n";
		const files = fixture({ second: "second", last: "last\n", multi, empty: "", noted: "sk-abc\nuser: me\nurl: https://x\n" });
		const first = join(files.root, "first.pass");
		const second = join(files.root, "second.pass");
		writeFileSync(first, "# comment\n\nVALUE=missing-but-overridden\nFILE_ORDER=missing-but-overridden\nEMPTY=empty\n");
		writeFileSync(second, "VALUE=second\nFILE_ORDER=second\nFIRST=multi\nWHOLE=multiline:multi\nNOTED=noted\r\n");
		files.env.VALUE = "inherited";
		files.env.KEEP_ME = "untouched";
		const result = invoke(files, [
			"run", "-e", "VALUE=last", "-f", first, "--env-file", second,
			"--", process.execPath, "-e",
			'console.log(JSON.stringify(["VALUE","FILE_ORDER","FIRST","WHOLE","EMPTY","NOTED","KEEP_ME"].map((k) => process.env[k])))',
		]);
		expect(result.stderr).toBe("");
		expect(result.status).toBe(0);
		expect(JSON.parse(result.stdout)).toEqual(["last", "second", "﻿ first line", multi, "", "sk-abc", "untouched"]);
	});

	test("with no -f or -e, ./.env.pass is used", () => {
		const files = fixture();
		writeFileSync(join(files.root, ".env.pass"), "TOKEN=token\n");
		const result = invoke(files, ["run", "--", "printenv", "TOKEN"]);
		expect(result.status).toBe(0);
		expect(result.stdout).toBe("synthetic-value\n");
	});

	test("with no mappings and no ./.env.pass, it explains what to do", () => {
		const files = fixture();
		const result = invoke(files, ["run", ...markerCommand(files)]);
		expect(result.status).toBe(2);
		expect(result.stderr).toContain(".env.pass");
		expect(existsSync(join(files.root, "child-started"))).toBe(false);
	});

	test("prototype-like variable names are delivered as ordinary environment entries", () => {
		const files = fixture();
		const result = invoke(files, ["run", "-e", "__proto__=token", "--", "printenv", "__proto__"]);
		expect(result.status).toBe(0);
		expect(result.stdout).toBe("synthetic-value\n");
		expect(result.stderr).toBe("");
	});

	test("duplicate names within a reference file fail before execution", () => {
		const files = fixture();
		const reference = join(files.root, ".env.pass");
		writeFileSync(reference, "TOKEN=token\nTOKEN=token\n");
		const result = invoke(files, ["run", "-f", reference, ...markerCommand(files)]);
		expect(result.status).toBe(2);
		expect(existsSync(files.calls)).toBe(false);
		expect(existsSync(join(files.root, "child-started"))).toBe(false);
	});

	test("unsafe paths, symlinks, and directories cannot be mistaken for secret values", () => {
		const files = fixture({ "nested/token": "synthetic" });
		mkdirSync(join(files.store, "directory.gpg"));
		symlinkSync(join(files.store, "nested/token.gpg"), join(files.store, "alias.gpg"));
		symlinkSync(join(files.store, "nested"), join(files.store, "linked"));
		for (const entry of ["../escape", "/absolute", "nested/../nested/token", "alias", "linked/token", "directory"]) {
			const result = invoke(files, ["run", "-e", `TOKEN=${entry}`, ...markerCommand(files)]);
			expect(result.status).not.toBe(0);
		}
		const alias = join(files.root, "alias-store");
		symlinkSync(files.store, alias);
		files.env.PASSWORD_STORE_DIR = alias;
		expect(invoke(files, ["run", "-e", "TOKEN=nested/token", ...markerCommand(files)]).status).toBe(1);
		expect(existsSync(files.calls)).toBe(false);
		expect(existsSync(join(files.root, "child-started"))).toBe(false);
	});

	test("backend failures name a cause but never leak diagnostics or start the child", () => {
		const files = fixture({ broken: "x", locked: "x", nokey: "x", nul: "synthetic-nul\0value", invalid: new Uint8Array([0xff, 0xfe]) });
		const expected: Record<string, string> = { broken: "DECRYPT", locked: "LOCKED", nokey: "DECRYPT", nul: "VALUE", invalid: "VALUE" };
		for (const [entry, code] of Object.entries(expected)) {
			const result = invoke(files, ["run", "-e", `TOKEN=${entry}`, ...markerCommand(files)]);
			expect(result.status).toBe(1);
			expect(result.stdout).toBe("");
			expect(result.stderr).toStartWith(`${code}: TOKEN`);
			expect(result.stderr).not.toContain("synthetic-");
			expect(existsSync(join(files.root, "child-started"))).toBe(false);
		}
		expect(invoke(files, ["run", "-e", "TOKEN=locked", "--", "true"]).stderr).toContain("pass-env unlock");
		expect(invoke(files, ["run", "-e", "TOKEN=nokey", "--", "true"]).stderr).toContain("GPG key");
	});

	test("command cwd, argv, piped stdin, unfiltered output, and exit status are preserved", () => {
		const files = fixture();
		const result = invoke(files, [
			"run", "-e", "TOKEN=token", "--", process.execPath, "-e",
			'console.log(JSON.stringify([process.cwd(), process.argv.slice(1), await Bun.stdin.text(), process.env.TOKEN])); console.error("child-stderr"); process.exitCode = 37;',
			"--", "argument with spaces", "$(not evaluated)",
		], "child input\n");
		expect(result.status).toBe(37);
		expect(JSON.parse(result.stdout)).toEqual([files.root, ["argument with spaces", "$(not evaluated)"], "child input\n", "synthetic-value"]);
		expect(result.stderr).toBe("child-stderr\n");
	});

	test("a child killed by a signal leaves the launcher terminated by that signal", () => {
		const files = fixture();
		const result = invoke(files, ["run", "-e", "TOKEN=token", "--", process.execPath, "-e", 'process.kill(process.pid, "SIGTERM")']);
		expect(result.status).toBeNull();
		expect(result.signal).toBe("SIGTERM");
		expect(result.stdout).toBe("");
		expect(result.stderr).toBe("");
	});

	test("a signal sent to the launcher reaches its running child", async () => {
		const files = fixture();
		const child = spawn(launcher[0], [...launcher.slice(1), "run", "-e", "TOKEN=token", "--", process.execPath, "-e",
			'process.on("SIGTERM", () => process.exit(42)); process.stdin.resume(); console.log("ready");',
		], { cwd: files.root, env: files.env, detached: true, stdio: ["pipe", "pipe", "pipe"] });
		const { promise, resolve: accept, reject } = Promise.withResolvers<{ code: number | null; signal: NodeJS.Signals | null }>();
		const stop = () => {
			try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch { /* Already exited. */ }
		};
		const timer = setTimeout(() => { stop(); reject(new Error("launcher signal forwarding timed out")); }, 4000);
		child.once("error", reject);
		child.stdout!.once("data", () => child.kill("SIGTERM"));
		child.once("exit", (code, signal) => accept({ code, signal }));
		try {
			expect(await promise).toEqual({ code: 42, signal: null });
		} finally {
			clearTimeout(timer);
			stop();
		}
	});

	// Ctrl-C in a real terminal: the tty signals the whole foreground group,
	// so the launcher must not forward it a second time.
	test.skipIf(!Bun.which("script"))("one Ctrl-C in a terminal reaches the child once", async () => {
		const files = fixture();
		const ready = join(files.root, "ready");
		const count = join(files.root, "count");
		const childScript = join(files.root, "child.js");
		writeFileSync(childScript, `const fs = require("node:fs"); let n = 0;
process.on("SIGINT", () => { n += 1; });
fs.writeFileSync(${JSON.stringify(ready)}, "1");
setTimeout(() => { fs.writeFileSync(${JSON.stringify(count)}, String(n)); process.exit(0); }, 1500);`);
		const command = [...launcher, "run", "-e", "TOKEN=token", "--", process.execPath, childScript]
			.map((part) => `'${part}'`).join(" ");
		const term = spawn("script", ["-qec", command, "/dev/null"], { cwd: files.root, env: files.env, stdio: ["pipe", "ignore", "ignore"] });
		const deadline = Date.now() + 5000;
		while (!existsSync(ready) && Date.now() < deadline) await Bun.sleep(25);
		term.stdin!.write("\x03");
		await new Promise((done) => term.once("exit", done));
		expect(readFileSync(count, "utf8")).toBe("1");
	});
});

describe("check", () => {
	test("reports each mapping and fails on missing entries without decrypting", () => {
		const files = fixture({ "app/A": "x", "app/C": "x" });
		writeFileSync(join(files.root, ".env.pass"), "A=app/A\nB=app/B\nC=multiline:app/C\n");
		const result = invoke(files, ["check"]);
		expect(result.status).toBe(1);
		expect(result.stdout).toMatch(/ok\s+A\s+app\/A/);
		expect(result.stdout).toMatch(/MISSING\s+B\s+app\/B/);
		expect(result.stdout).toContain("app/C (multiline)");
		expect(result.stderr).toContain("1 missing");
		expect(existsSync(files.calls)).toBe(false);
		expect(invoke(files, ["check", "-e", "A=app/A"]).status).toBe(0);
	});
});

describe("generate", () => {
	test("stores a random secret, prints only a summary, and refuses to overwrite without --force", () => {
		const files = fixture({});
		const result = invoke(files, ["generate", "app/AUTH_SECRET"]);
		expect(result.status).toBe(0);
		const value = stored(files, "app/AUTH_SECRET");
		expect(value).toMatch(/^[A-Za-z0-9]{48}\n$/);
		expect(result.stdout).not.toContain(value.trim());
		expect(result.stdout).toContain("48 random alnum characters");

		const again = invoke(files, ["generate", "app/AUTH_SECRET"]);
		expect(again.status).toBe(1);
		expect(again.stderr).toContain("--force");
		expect(stored(files, "app/AUTH_SECRET")).toBe(value);

		expect(invoke(files, ["generate", "app/AUTH_SECRET", "--force"]).stdout).toContain("Replaced");
		expect(stored(files, "app/AUTH_SECRET")).not.toBe(value);
	});

	test("length and charset options are honoured and validated", () => {
		const files = fixture({});
		expect(invoke(files, ["generate", "a/HEX", "64", "--charset", "hex"]).status).toBe(0);
		expect(stored(files, "a/HEX")).toMatch(/^[0-9a-f]{64}\n$/);
		expect(invoke(files, ["generate", "a/B64", "--charset", "base64url", "20"]).status).toBe(0);
		expect(stored(files, "a/B64")).toMatch(/^[A-Za-z0-9_-]{20}\n$/);
		for (const bad of [["generate", "a/X", "8"], ["generate", "a/X", "--charset", "emoji"], ["generate", "a/X", "--charset", "toString"], ["generate", "../x"], ["generate"]]) {
			expect(invoke(files, bad).status).toBe(2);
		}
	});

	test("generated secrets round-trip through run without a trailing newline", () => {
		const files = fixture({});
		invoke(files, ["generate", "app/S"]);
		const result = invoke(files, ["run", "-e", "S=app/S", "--", "sh", "-c", 'printf %s "$S"']);
		expect(result.stdout).toBe(stored(files, "app/S").trimEnd());
	});
});

describe("clipboard", () => {
	const clip = (files: Fixture) => existsSync(files.env.CLIP_FILE!) ? readFileSync(files.env.CLIP_FILE!, "utf8") : "";

	test("generate --copy stores the secret, copies exactly it, never prints it, and clears it later", async () => {
		const files = fixture({});
		const result = invoke(files, ["generate", "app/WEBHOOK_SECRET", "--copy"]);
		expect(result.status).toBe(0);
		const value = stored(files, "app/WEBHOOK_SECRET").trimEnd();
		expect(clip(files)).toBe(value);
		expect(result.stdout).not.toContain(value);
		expect(result.stdout).toContain("clears in 1s");
		await Bun.sleep(1800);
		expect(clip(files)).toBe("");
	});

	test("copy puts the first line on the clipboard and does not clear something copied since", async () => {
		const files = fixture({ "app/KEY": "sk-synthetic\nuser: me\n" });
		const result = invoke(files, ["copy", "app/KEY"]);
		expect(result.status).toBe(0);
		expect(result.stdout).not.toContain("sk-synthetic");
		expect(clip(files)).toBe("sk-synthetic");
		writeFileSync(files.env.CLIP_FILE!, "something else");
		await Bun.sleep(1800);
		expect(clip(files)).toBe("something else");
	});

	test("copy fails clearly with no clipboard tool and for missing entries", () => {
		const files = fixture({ "app/KEY": "x" });
		expect(invoke(files, ["copy", "app/NOPE"]).stderr).toStartWith("ENTRY:");
		files.env.PASS_ENV_CLIPBOARD = "";
		files.env.PATH = join(files.root, "bin");
		files.env.DISPLAY = "";
		files.env.WAYLAND_DISPLAY = "";
		const result = invoke(files, ["generate", "app/NEW", "--copy"]);
		expect(result.stderr).toStartWith("CLIPBOARD:");
		expect(existsSync(join(files.store, "app/NEW.gpg"))).toBe(false);
	});
});

describe("pipe", () => {
	test("sends one secret to a command's stdin with no trailing newline and keeps its exit status", () => {
		const files = fixture({ "app/KEY": "sk-synthetic\n" });
		const result = invoke(files, ["pipe", "app/KEY", "--", process.execPath, "-e",
			'const v = await Bun.stdin.text(); console.log(JSON.stringify(v)); process.exitCode = 3']);
		expect(result.stdout).toBe('"sk-synthetic"\n');
		expect(result.status).toBe(3);
	});

	test("multiline sends the whole entry; missing entries and commands are rejected", () => {
		const files = fixture({ "app/PEM": "-----BEGIN-----\nabc\n-----END-----\n" });
		expect(invoke(files, ["pipe", "app/PEM", "--multiline", "--", "cat"]).stdout).toBe("-----BEGIN-----\nabc\n-----END-----\n");
		expect(invoke(files, ["pipe", "app/NOPE", "--", "cat"]).status).toBe(1);
		expect(invoke(files, ["pipe", "app/PEM"]).status).toBe(2);
		expect(invoke(files, ["pipe", "app/PEM", "--"]).status).toBe(2);
	});
});

describe("set", () => {
	test("stores piped input, dropping one trailing newline, and refuses to overwrite without --force", () => {
		const files = fixture({});
		const result = invoke(files, ["set", "app/KEY"], "sk-live-synthetic\n");
		expect(result.status).toBe(0);
		expect(result.stdout).toBe("Stored app/KEY.\n");
		expect(stored(files, "app/KEY")).toBe("sk-live-synthetic\n");
		expect(invoke(files, ["run", "-e", "K=app/KEY", "--", "sh", "-c", 'printf %s "$K"']).stdout).toBe("sk-live-synthetic");

		const again = invoke(files, ["set", "app/KEY"], "other\n");
		expect(again.status).toBe(1);
		expect(again.stderr).toContain("--force");
		expect(invoke(files, ["set", "app/KEY", "--force"], "other").status).toBe(0);
		expect(stored(files, "app/KEY")).toBe("other\n");
	});

	test("piped input with several lines is stored exactly and round-trips through multiline:", () => {
		const files = fixture({});
		const pem = "-----BEGIN SYNTHETIC-----\r\nabc\n-----END SYNTHETIC-----";
		const result = invoke(files, ["set", "app/PEM"], pem);
		expect(result.status).toBe(0);
		expect(result.stdout).toBe("Stored app/PEM exactly as piped (3 lines); map it with multiline:app/PEM.\n");
		expect(stored(files, "app/PEM")).toBe(pem);
		expect(invoke(files, ["set", "app/FILE"], `${pem}\n`).status).toBe(0);
		expect(stored(files, "app/FILE")).toBe(`${pem}\n`);
		const run = invoke(files, ["run", "-e", "PEM=multiline:app/PEM", "--", process.execPath, "-e", "process.stdout.write(JSON.stringify(process.env.PEM))"]);
		expect(JSON.parse(run.stdout)).toBe(pem);
	});

	test("empty input and bad names are rejected", () => {
		const files = fixture({});
		expect(invoke(files, ["set", "app/KEY"], "").status).toBe(1);
		expect(invoke(files, ["set", "../KEY"], "x").status).toBe(2);
		expect(invoke(files, ["set"], "x").status).toBe(2);
	});
});

describe("unlock and list", () => {
	test("unlock refuses to run without a terminal", () => {
		const files = fixture();
		const result = invoke(files, ["unlock"]);
		expect(result.status).toBe(2);
		expect(result.stderr).toContain("terminal");
		expect(existsSync(files.calls)).toBe(false);
	});

	test("list reports sorted names and literal prefixes without invoking pass or following symlinks", () => {
		const files = fixture({ "team/z": "not printed", "team/a": "not printed", other: "not printed" });
		mkdirSync(join(files.store, "directory.gpg"));
		symlinkSync(join(files.store, "other.gpg"), join(files.store, "alias.gpg"));
		symlinkSync(join(files.store, "team"), join(files.store, "linked-team"));
		const result = invoke(files, ["list", "--json"]);
		expect(result.status).toBe(0);
		expect(JSON.parse(result.stdout)).toEqual(["other", "team/a", "team/z"]);
		expect(invoke(files, ["list", "team/"]).stdout).toBe("team/a\nteam/z\n");
		expect(invoke(files, ["list", "team/*", "--json"]).stdout).toBe("[]\n");
		expect(existsSync(files.calls)).toBe(false);
	});

	test("help lists every command", () => {
		const files = fixture();
		const out = invoke(files, ["help"]).stdout;
		for (const command of ["run", "pipe", "copy", "check", "set", "generate", "unlock", "list", "import", "doctor"]) expect(out).toContain(`pass-env ${command}`);
	});
});

describe("import", () => {
	const lines = [
		"\uFEFF# Settings for the app",
		"NEXT_PUBLIC_SITE_URL=https://example.invalid",
		"export OPENAI_API_KEY=sk-synthetic-openai # the key",
		"SINGLE='literal-synthetic \\n kept #not-a-comment'",
		'ESCAPED="synthetic line one\\nline two"',
		'PEM="-----BEGIN SYNTHETIC-----',
		"abc",
		'-----END SYNTHETIC-----"',
		"EMPTY=",
		"REFERENCE=${OPENAI_API_KEY}/synthetic",
		"BARE_HASH=synthetic#def",
		"my.var=synthetic-dotted",
		"DUPLICATE=first-synthetic",
		"DUPLICATE=second-synthetic",
		"  SPACED  =  synthetic-spaced  ",
	];
	const sample = `${lines.join("\r\n")}\r\n`;
	const kept = "\uFEFF# Settings for the app\r\nNEXT_PUBLIC_SITE_URL=https://example.invalid\r\nEMPTY=\r\nREFERENCE=${OPENAI_API_KEY}/synthetic\r\nBARE_HASH=synthetic#def\r\nmy.var=synthetic-dotted\r\n";
	const secretFree = (text: string) => {
		for (const word of ["synthetic", "SYNTHETIC", "example.invalid", "line two"]) expect(text).not.toContain(word);
	};
	const setup = (entries: Record<string, string> = {}) => {
		const files = fixture(entries);
		writeFileSync(join(files.root, ".env.local"), sample);
		return files;
	};
	const read = (files: Fixture, name: string) => readFileSync(join(files.root, name), "utf8");
	// The error is the last stderr line; warnings may come first.
	const error = (stderr: string) => stderr.trimEnd().split("\n").pop()!;

	test("parses dotenv rules, stores secrets exactly, keeps public names and explains skips without printing values", () => {
		const files = setup();
		const result = invoke(files, ["import", ".env.local", "--prefix", "app"]);
		expect(result.status).toBe(0);
		secretFree(result.stdout + result.stderr);
		expect(stored(files, "app/OPENAI_API_KEY")).toBe("sk-synthetic-openai\n");
		expect(stored(files, "app/SINGLE")).toBe("literal-synthetic \\n kept #not-a-comment\n");
		expect(stored(files, "app/ESCAPED")).toBe("synthetic line one\nline two");
		expect(stored(files, "app/PEM")).toBe("-----BEGIN SYNTHETIC-----\nabc\n-----END SYNTHETIC-----");
		expect(stored(files, "app/DUPLICATE")).toBe("second-synthetic\n");
		expect(stored(files, "app/SPACED")).toBe("synthetic-spaced\n");
		for (const name of ["NEXT_PUBLIC_SITE_URL", "EMPTY", "REFERENCE", "BARE_HASH", "my.var"]) expect(existsSync(join(files.store, `app/${name}.gpg`))).toBe(false);
		expect(result.stdout).toMatch(/NEXT_PUBLIC_SITE_URL\s+kept public/);
		expect(result.stdout).toMatch(/PEM\s+stored as app\/PEM \(multiline\)/);
		expect(result.stdout).toMatch(/EMPTY\s+skipped: empty value/);
		expect(result.stdout).toMatch(/REFERENCE\s+skipped: references another variable/);
		expect(result.stdout).toMatch(/BARE_HASH\s+skipped: unquoted #/);
		expect(result.stdout).toMatch(/my\.var\s+skipped: not a valid variable name/);
		expect(result.stdout).toContain("pass-env import .env.local --prefix app --remove");
		expect(result.stderr).toContain("DUPLICATE is set more than once");
		expect(read(files, ".env.pass")).toBe("# Imported from .env.local\nOPENAI_API_KEY=app/OPENAI_API_KEY\nSINGLE=app/SINGLE\nESCAPED=multiline:app/ESCAPED\nPEM=multiline:app/PEM\nDUPLICATE=app/DUPLICATE\nSPACED=app/SPACED\n");
		expect(read(files, ".env.local")).toBe(sample);
	});

	test("multi-line values round-trip exactly through run", () => {
		const files = setup();
		invoke(files, ["import", ".env.local", "--prefix", "app"]);
		const result = invoke(files, ["run", "--", process.execPath, "-e", "process.stdout.write(JSON.stringify([process.env.PEM, process.env.ESCAPED, process.env.SINGLE]))"]);
		expect(JSON.parse(result.stdout)).toEqual(["-----BEGIN SYNTHETIC-----\nabc\n-----END SYNTHETIC-----", "synthetic line one\nline two", "literal-synthetic \\n kept #not-a-comment"]);
	});

	test("--dry-run prints names only and stores or writes nothing", () => {
		const files = setup({ "app/SPACED": "x" });
		const result = invoke(files, ["import", ".env.local", "--prefix", "app", "--dry-run", "--skip", "SINGLE,ESCAPED"]);
		expect(result.status).toBe(0);
		secretFree(result.stdout + result.stderr);
		expect(result.stdout).toContain("dry run");
		expect(result.stdout).toMatch(/SINGLE\s+skipped: --skip/);
		expect(result.stdout).toMatch(/SPACED\s+stored as app\/SPACED \(already exists: needs --force\)/);
		expect(existsSync(files.calls)).toBe(false);
		expect(existsSync(join(files.root, ".env.pass"))).toBe(false);
	});

	test("refuses before storing anything if an entry exists, and --force replaces", () => {
		const files = setup({ "app/PEM": "old" });
		const result = invoke(files, ["import", ".env.local", "--prefix", "app"]);
		expect(result.status).toBe(1);
		expect(error(result.stderr)).toStartWith("EXISTS: already in the store with a different value: app/PEM;");
		expect(readFileSync(files.calls, "utf8")).toBe("show -- app/PEM\n");
		expect(existsSync(join(files.root, ".env.pass"))).toBe(false);
		expect(invoke(files, ["import", ".env.local", "--prefix", "app", "--force"]).status).toBe(0);
		expect(stored(files, "app/PEM")).toBe("-----BEGIN SYNTHETIC-----\nabc\n-----END SYNTHETIC-----");
	});

	test("merges into an existing .env.pass and stops on a conflicting mapping", () => {
		const files = setup();
		writeFileSync(join(files.root, ".env.pass"), "# mine\nOTHER=shared/OTHER\nSPACED=app/SPACED");
		expect(invoke(files, ["import", ".env.local", "--prefix", "app"]).status).toBe(0);
		const merged = read(files, ".env.pass");
		expect(merged).toStartWith("# mine\nOTHER=shared/OTHER\nSPACED=app/SPACED\n\n# Imported from .env.local\nOPENAI_API_KEY=app/OPENAI_API_KEY\n");
		expect(merged.match(/SPACED=/g)).toHaveLength(1);

		const clash = setup();
		writeFileSync(join(clash.root, ".env.pass"), "PEM=app/PEM\n");
		const result = invoke(clash, ["import", ".env.local", "--prefix", "app"]);
		expect(result.status).toBe(1);
		expect(error(result.stderr)).toStartWith("CONFLICT: .env.pass already maps PEM");
		expect(existsSync(clash.calls)).toBe(false);
		expect(read(clash, ".env.pass")).toBe("PEM=app/PEM\n");
	});

	test("warns with the fix when git ignores .env.pass", () => {
		const files = setup();
		spawnSync("git", ["init", "-q"], { cwd: files.root });
		writeFileSync(join(files.root, ".gitignore"), ".env*\n");
		const result = invoke(files, ["import", ".env.local", "--prefix", "app"]);
		expect(result.status).toBe(0);
		expect(result.stderr).toContain("git ignores .env.pass (rule .env* in .gitignore)");
		expect(result.stderr).toContain("!.env.pass");
		writeFileSync(join(files.root, ".gitignore"), ".env*\n!.env.pass\n");
		expect(invoke(files, ["import", ".env.local", "--prefix", "app", "--force"]).stderr).not.toContain("git ignores");
	});

	test("--remove checks every value, then rewrites the file keeping comments, public and skipped lines, readable only by the owner", () => {
		const files = setup();
		invoke(files, ["import", ".env.local", "--prefix", "app"]);
		chmodSync(join(files.root, ".env.local"), 0o640);
		const result = invoke(files, ["import", ".env.local", "--prefix", "app", "--remove"]);
		expect(result.stderr).toContain("DUPLICATE is set more than once");
		expect(result.status).toBe(0);
		secretFree(result.stdout);
		expect(result.stdout).toContain("Checked 6 stored values against .env.local: all match.");
		expect(result.stdout).toMatch(/Still in \.env\.local:\n\s+NEXT_PUBLIC_SITE_URL\s+kept public/);
		expect(read(files, ".env.local")).toBe(kept);
		expect(statSync(join(files.root, ".env.local")).mode & 0o777).toBe(0o600);
		expect(result.stdout).toContain("readable only by you");
		expect(invoke(files, ["import", ".env.local", "--prefix", "app", "--remove"]).stdout).toContain("no secret lines left");
	});

	test("--remove changes nothing when a value differs, GPG is locked, or .env.pass lacks the mapping", () => {
		const files = setup();
		invoke(files, ["import", ".env.local", "--prefix", "app"]);
		writeFileSync(join(files.store, "app/SPACED.gpg"), "rotated-synthetic\n");
		const mismatch = invoke(files, ["import", ".env.local", "--prefix", "app", "--remove"]);
		expect(mismatch.status).toBe(1);
		expect(error(mismatch.stderr)).toStartWith("MISMATCH: the stored value differs from .env.local for SPACED; nothing was removed.");
		secretFree(mismatch.stdout + mismatch.stderr);
		expect(read(files, ".env.local")).toBe(sample);

		files.env.TEST_PASS_LOCKED = "1";
		const locked = invoke(files, ["import", ".env.local", "--prefix", "app", "--remove"]);
		expect(error(locked.stderr)).toStartWith("LOCKED:");
		expect(locked.stderr).toContain("pass-env unlock");
		expect(read(files, ".env.local")).toBe(sample);
		delete files.env.TEST_PASS_LOCKED;

		writeFileSync(join(files.root, ".env.pass"), "OTHER=shared/OTHER\n");
		const unmapped = invoke(files, ["import", ".env.local", "--prefix", "app", "--remove"]);
		expect(error(unmapped.stderr)).toStartWith("REFERENCE_FILE: .env.pass does not map OPENAI_API_KEY");
		expect(read(files, ".env.local")).toBe(sample);
	});

	test("--remove deletes a file left with only comments, and explains Wrangler for .dev.vars", () => {
		const files = fixture({});
		writeFileSync(join(files.root, ".dev.vars"), "# local\nAPI_KEY=synthetic-api\n\n");
		invoke(files, ["import", ".dev.vars", "--prefix", "worker"]);
		const result = invoke(files, ["import", ".dev.vars", "--prefix", "worker", "--remove"]);
		expect(result.status).toBe(0);
		expect(existsSync(join(files.root, ".dev.vars"))).toBe(false);
		expect(result.stdout).toContain("Deleted .dev.vars");
		expect(result.stdout).toContain("the Cloudflare Vite plugin and OpenNext's next dev can now read the environment");
		expect(result.stdout).toContain("CLOUDFLARE_INCLUDE_PROCESS_ENV=true pass-env run -- npx wrangler dev");

		mkdirSync(join(files.root, "sub"));
		writeFileSync(join(files.root, "sub/.dev.vars"), "API_KEY=synthetic-api\nPUBLIC_MODE=dev\n");
		const imported = invoke(files, ["import", "sub/.dev.vars", "--prefix", "worker", "--force"]);
		expect(imported.stdout).toContain("cd sub && pass-env check");
		expect(read(files, "sub/.env.pass")).toContain("API_KEY=worker/API_KEY");
		const partial = invoke(files, ["import", "sub/.dev.vars", "--prefix", "worker", "--remove"]);
		expect(partial.status).toBe(0);
		expect(read(files, "sub/.dev.vars")).toBe("PUBLIC_MODE=dev\n");
		expect(partial.stdout).toContain("wrangler dev, the Cloudflare Vite plugin and OpenNext's next dev ignore environment variables while .dev.vars exists");
		expect(partial.stdout).toContain('"vars" in wrangler.jsonc');
	});

	test("skips placeholders and warns about secrets under public names without storing them", () => {
		const files = fixture({});
		writeFileSync(join(files.root, ".env.example"), "STRIPE_KEY=sk_test_synthetic_sample\n");
		writeFileSync(join(files.root, ".env.local"), [
			"OPENAI_API_KEY=your-openai-key", "AUTH_SECRET=changeme", "STRIPE_KEY=sk_test_synthetic_sample",
			"NEXT_PUBLIC_GEMINI_API_KEY=AIza-synthetic", "NEXT_PUBLIC_SITE_URL=https://synthetic.invalid", "REAL=synthetic-real",
		].join("\n"));
		const dry = invoke(files, ["import", ".env.local", "--prefix", "app", "--dry-run"]);
		secretFree(dry.stdout + dry.stderr);
		for (const name of ["OPENAI_API_KEY", "AUTH_SECRET", "STRIPE_KEY"]) expect(dry.stdout).toMatch(new RegExp(`${name}\\s+skipped: placeholder`));
		expect(dry.stdout).toMatch(/NEXT_PUBLIC_GEMINI_API_KEY\s+kept public \(but looks like a secret, see warning\)/);
		expect(dry.stdout).toMatch(/NEXT_PUBLIC_SITE_URL\s+kept public\n/);
		expect(dry.stderr).toContain("warning: NEXT_PUBLIC_GEMINI_API_KEY looks like a secret");
		expect(dry.stderr).not.toContain("NEXT_PUBLIC_SITE_URL");
		expect(invoke(files, ["import", ".env.local", "--prefix", "app"]).status).toBe(0);
		expect(read(files, ".env.pass")).toBe("# Imported from .env.local\nREAL=app/REAL\n");
	});

	test("--map points a name at a shared entry, and an existing entry with the same value needs no --force", () => {
		const files = fixture({ "shared/GEMINI_API_KEY": "gemini-synthetic\n" });
		writeFileSync(join(files.root, ".env.local"), "GEMINI_API_KEY=gemini-synthetic\nAUTH_SECRET=auth-synthetic\n");
		writeFileSync(join(files.root, ".dev.vars"), "AUTH_SECRET=auth-synthetic\nGEMINI_API_KEY=gemini-synthetic\n");
		const map = ["--map", "GEMINI_API_KEY=shared/GEMINI_API_KEY"];
		const first = invoke(files, ["import", ".env.local", "--prefix", "web", ...map]);
		expect(first.status).toBe(0);
		expect(first.stdout).toMatch(/GEMINI_API_KEY\s+stored as shared\/GEMINI_API_KEY \(already stored with the same value\)/);
		expect(first.stdout).toContain("--prefix web --map GEMINI_API_KEY=shared/GEMINI_API_KEY --remove");
		expect(readFileSync(files.calls, "utf8")).not.toContain("insert --multiline --force -- shared/GEMINI_API_KEY");
		expect(read(files, ".env.pass")).toBe("# Imported from .env.local\nGEMINI_API_KEY=shared/GEMINI_API_KEY\nAUTH_SECRET=web/AUTH_SECRET\n");

		const second = invoke(files, ["import", ".dev.vars", "--prefix", "web", ...map]);
		expect(second.status).toBe(0);
		expect(second.stdout).toContain("Stored 0 entries (2 already had the same value); added 0 lines");
		expect(invoke(files, ["import", ".env.local", "--prefix", "web", ...map, "--remove"]).status).toBe(0);
		expect(invoke(files, ["import", ".dev.vars", "--prefix", "web", ...map, "--remove"]).status).toBe(0);
		expect(existsSync(join(files.root, ".env.local"))).toBe(false);
		expect(existsSync(join(files.root, ".dev.vars"))).toBe(false);

		writeFileSync(join(files.root, ".env.local"), "AUTH_SECRET=other-synthetic\n");
		expect(error(invoke(files, ["import", ".env.local", "--prefix", "web"]).stderr)).toStartWith("EXISTS: already in the store with a different value: web/AUTH_SECRET");
		writeFileSync(join(files.root, ".env.local"), "AUTH_SECRET=auth-synthetic\n");
		files.env.TEST_PASS_LOCKED = "1";
		const locked = error(invoke(files, ["import", ".env.local", "--prefix", "web"]).stderr);
		expect(locked).toStartWith("EXISTS: already in the store: web/AUTH_SECRET; GPG is locked");
		expect(locked).toContain("pass-env unlock");
		expect(invoke(files, ["import", ".env.local", "--prefix", "web", "--map", "bad name=x"]).status).toBe(2);
	});

	test("refuses to import or remove a file committed to git", () => {
		const files = setup();
		spawnSync("git", ["init", "-q"], { cwd: files.root });
		spawnSync("git", ["add", ".env.local"], { cwd: files.root });
		for (const extra of [[], ["--dry-run"], ["--remove"]]) {
			const result = invoke(files, ["import", ".env.local", "--prefix", "app", ...extra]);
			expect(result.status).toBe(1);
			expect(result.stderr).toStartWith("TRACKED: .env.local is committed to git, so it is shared config");
		}
		expect(existsSync(files.calls)).toBe(false);
		expect(read(files, ".env.local")).toBe(sample);
	});

	test("bad arguments and unparseable files fail clearly without echoing content", () => {
		const files = setup();
		for (const args of [["import", ".env.local"], ["import", ".env.local", "--prefix", "../x"], ["import", "--prefix", "app"],
			["import", ".env.local", "--prefix", "app", "--remove", "--force"], ["import", ".env.local", "--prefix", "app", "--remove", "--dry-run"]]) {
			expect(invoke(files, args).status).toBe(2);
		}
		writeFileSync(join(files.root, "broken.env"), "OK=1\nKEY=\"synthetic-unclosed\n");
		const broken = invoke(files, ["import", "broken.env", "--prefix", "app"]);
		expect(broken.status).toBe(1);
		expect(broken.stderr).toBe("PARSE: broken.env, line 2: quoted value is never closed\n");
		writeFileSync(join(files.root, "junk.env"), "synthetic-junk\n");
		expect(invoke(files, ["import", "junk.env", "--prefix", "app"]).stderr).toBe("PARSE: junk.env, line 1: expected NAME=value\n");
		expect(invoke(files, ["import", "missing.env", "--prefix", "app"]).stderr).toStartWith("REFERENCE_FILE: missing.env");
		expect(existsSync(files.calls)).toBe(false);
	});
});

describe("doctor", () => {
	// A healthy setup: store with a usable key, terminal prompt configured.
	const healthy = () => {
		const files = fixture();
		const gnupg = join(files.root, "gnupg");
		mkdirSync(gnupg);
		writeFileSync(join(files.store, ".gpg-id"), "synthetic@example.invalid\n");
		writeFileSync(join(gnupg, "gpg-agent.conf"), `pinentry-program ${join(files.root, "bin", "fakeclip")}\ndefault-cache-ttl 3600\nmax-cache-ttl 28800\n`);
		Object.assign(files.env, { GNUPGHOME: gnupg, GPG_TTY: "/dev/pts/synthetic", TEST_GPG_SECRET_KEYS: "synthetic@example.invalid" });
		return files;
	};
	const line = (out: string, status: string, text: string) => expect(out).toMatch(new RegExp(`^${status}\\s+.*${text}`, "m"));

	test("a healthy setup is all ok, and doctor never calls pass", () => {
		const files = healthy();
		const result = invoke(files, ["doctor"]);
		expect(result.stdout).not.toMatch(/^(warn|FAIL)/m);
		expect(result.status).toBe(0);
		line(result.stdout, "ok", "private key for synthetic@example.invalid");
		line(result.stdout, "ok", "no plaintext .env files");
		expect(result.stdout).toContain("0 failed, 0 warnings");
		expect(existsSync(files.calls)).toBe(false);
	});

	test("fails on a missing store, .gpg-id, private key, or prompt program", () => {
		const files = healthy();
		writeFileSync(join(files.env.GNUPGHOME!, "gpg-agent.conf"), "pinentry-program /nonexistent/pinentry\n");
		files.env.TEST_GPG_SECRET_KEYS = "someone-else";
		let result = invoke(files, ["doctor"]);
		expect(result.status).toBe(1);
		line(result.stdout, "FAIL", "no private key on this machine for synthetic@example.invalid");
		line(result.stdout, "FAIL", "pinentry-program /nonexistent/pinentry does not exist");
		expect(result.stdout).toContain("fix: gpg --list-secret-keys");

		rmSync(join(files.store, ".gpg-id"));
		line(invoke(files, ["doctor"]).stdout, "FAIL", "the store has no .gpg-id");
		files.env.PASSWORD_STORE_DIR = join(files.root, "nowhere");
		result = invoke(files, ["doctor"]);
		line(result.stdout, "FAIL", "no password store at");
		expect(result.stdout).toContain("fix: pass init <your-gpg-id>");
	});

	test("fails when pass and gpg are missing, and on a WSL store under /mnt", () => {
		const files = healthy();
		const empty = join(files.root, "empty-bin");
		mkdirSync(empty);
		files.env.PATH = empty;
		files.env.WSL_DISTRO_NAME = "synthetic";
		files.env.PASSWORD_STORE_DIR = "/mnt/c/Users/synthetic/store";
		const result = invoke(files, ["doctor"]);
		expect(result.status).toBe(1);
		line(result.stdout, "FAIL", "pass is not installed");
		line(result.stdout, "FAIL", "gpg is not installed");
		line(result.stdout, "FAIL", "on the Windows drive");
	});

	test("warns about long caches, WSL prompts, plaintext .env files, an ignored .env.pass and Claude Code rules", () => {
		const files = healthy();
		writeFileSync(join(files.env.GNUPGHOME!, "gpg-agent.conf"), "default-cache-ttl 600\nmax-cache-ttl 999999\n");
		files.env.WSL_DISTRO_NAME = "synthetic";
		writeFileSync(join(files.root, ".env.local"), "SECRET_KEY=synthetic-secret\nNEXT_PUBLIC_X=synthetic-public\n", { mode: 0o644 });
		chmodSync(join(files.root, ".env.local"), 0o644);
		writeFileSync(join(files.root, ".env"), "NEXT_PUBLIC_X=synthetic-public\n");
		writeFileSync(join(files.root, ".env.example"), "SECRET_KEY=synthetic-placeholder\n");
		spawnSync("git", ["init", "-q"], { cwd: files.root });
		writeFileSync(join(files.root, ".gitignore"), ".env*\n");
		mkdirSync(join(files.root, ".claude"));
		const result = invoke(files, ["doctor"]);
		expect(result.status).toBe(0);
		expect(result.stdout).not.toContain("synthetic-");
		line(result.stdout, "warn", "max-cache-ttl 999999s");
		line(result.stdout, "warn", "no pinentry-program set; on WSL");
		expect(result.stdout).toContain("pinentry-curses");
		line(result.stdout, "warn", ".env.local holds 1 plaintext value");
		expect(result.stdout).toMatch(/fix: pass-env import \.env\.local --prefix pass-env-test-\w+ --dry-run/);
		line(result.stdout, "ok", ".env holds no secret-looking values");
		expect(result.stdout).not.toContain(".env.example");
		line(result.stdout, "warn", "git ignores .env.pass");
		expect(result.stdout).toContain("fix: echo '!.env.pass' >> .gitignore");
		line(result.stdout, "warn", "Claude Code may read .env files");

		line(result.stdout, "warn", "\\.env\\.local can be read by other users \\(mode 644\\)");
		expect(result.stdout).toContain("fix: chmod 600 .env.local");

		writeFileSync(join(files.root, ".claude", "settings.json"), JSON.stringify({ permissions: { deny: ["Read(**/.env.*)"] } }));
		line(invoke(files, ["doctor"]).stdout, "ok", "Claude Code is denied reading .env files");
	});

	test("warns about secret-looking public names, and secret files git would commit or already tracks", () => {
		const files = healthy();
		spawnSync("git", ["init", "-q"], { cwd: files.root });
		writeFileSync(join(files.root, ".env.local"), "API_KEY=synthetic-key\n");
		chmodSync(join(files.root, ".env.local"), 0o600);
		writeFileSync(join(files.root, ".env.production"), "DB_PASSWORD=synthetic-password\nNEXT_PUBLIC_GEMINI_API_KEY=AIza-synthetic\n");
		chmodSync(join(files.root, ".env.production"), 0o600);
		spawnSync("git", ["add", ".env.production"], { cwd: files.root });
		const result = invoke(files, ["doctor"]);
		expect(result.status).toBe(0);
		expect(result.stdout).not.toContain("synthetic-");
		expect(result.stdout).not.toContain("other users");
		line(result.stdout, "warn", "\\.env\\.local is neither committed nor ignored by git");
		expect(result.stdout).toContain("fix: echo '.env.local' >> .gitignore");
		line(result.stdout, "warn", "\\.env\\.production is committed to git and holds 1 plaintext value");
		expect(result.stdout).toContain("git rm --cached .env.production");
		line(result.stdout, "warn", "\\.env\\.production: NEXT_PUBLIC_GEMINI_API_KEY looks like a secret under a public name");
	});
});

describe("doctor env drift", () => {
	const project = (files: Record<string, string>) => {
		const fx = fixture();
		for (const [name, text] of Object.entries(files)) {
			mkdirSync(dirname(join(fx.root, name)), { recursive: true });
			writeFileSync(join(fx.root, name), text);
		}
		return fx;
	};
	const doctorOut = (fx: Fixture) => invoke(fx, ["doctor"]).stdout;

	test("names read by code but declared nowhere, and .env.pass names the code never reads", () => {
		const fx = project({
			"src/app.ts": 'const a = process.env.APP_A; const b = process.env["APP_B"]; const n = process.env.NODE_ENV + process.env.VERCEL_URL;\nconst { APP_H, APP_I: renamed, APP_J = "x", ...rest } = process.env;',
			"src/client.tsx": "export const c = import.meta.env.VITE_C + import.meta.env.MODE;",
			"worker/edge.mjs": 'Deno.env.get("APP_D"); Bun.env.APP_K;',
			"tools/job.py": 'import os\nos.environ["APP_E"]\nos.getenv("APP_F")\nos.environ.get(\'APP_G\', "x")\n',
			"prisma/schema.prisma": 'datasource db {\n  url = env("DATABASE_URL")\n}\n',
			"node_modules/dep/index.js": "process.env.FROM_DEPENDENCY",
			".next/server.js": "process.env.FROM_BUILD",
			".env.pass": "APP_A=app/A\nUNUSED_KEY=app/UNUSED_KEY\nDATABASE_URL=app/DATABASE_URL\n",
			".env.example": "APP_B=\n",
			"wrangler.jsonc": '{\n  // comment\n  "vars": { "VITE_C": "x", }, /* block */\n  "env": { "staging": { "vars": { "APP_D": "y" } } },\n}\n',
			"worker/wrangler.toml": 'name = "w"\n[vars]\nAPP_E = "1"\n[env.prod.vars]\nAPP_F = "2"\n[build]\nAPP_K = "not vars"\n',
			"tools/.env.local": "export APP_G=\n",
		});
		const out = doctorOut(fx);
		expect(out).toMatch(/^warn\s+env vars used in code but declared nowhere: APP_H, APP_I, APP_J, APP_K$/m);
		expect(out).toMatch(/^warn\s+env vars in \.env\.pass but never read by the code: UNUSED_KEY$/m);
		for (const name of ["FROM_DEPENDENCY", "FROM_BUILD", "NODE_ENV", "VERCEL_URL", "MODE", "rest", "renamed"]) expect(out).not.toContain(name);
	});

	test("long lists are capped, a fully declared project is ok, and no declarations means no check", () => {
		const names = Array.from({ length: 13 }, (_, index) => `NAME_${String(index).padStart(2, "0")}`);
		const fx = project({ "index.js": names.map((name) => `process.env.${name};`).join("\n"), ".env.pass": "NAME_00=app/NAME_00\n" });
		expect(doctorOut(fx)).toMatch(/declared nowhere: NAME_01, .*, NAME_10 and 2 more$/m);

		const clean = project({ "index.js": "process.env.ONLY; process.env.PORT;", ".env.pass": "ONLY=app/ONLY\n" });
		const out = doctorOut(clean);
		expect(out).toMatch(/^ok\s+env vars: the code reads 2, all declared or set by the runtime$/m);
		expect(out).not.toMatch(/^warn\s+env/m);

		const bare = project({ "index.js": "process.env.ANYTHING;" });
		expect(doctorOut(bare)).not.toContain("env vars");
	});
});
