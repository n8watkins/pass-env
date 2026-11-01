import { afterEach, describe, expect, test } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const cli = join(import.meta.dir, "pass-env.ts");
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
import { dirname, join } from "node:path";
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
	return {
		root, store, calls,
		env: {
			...process.env, HOME: root, PASSWORD_STORE_DIR: store, PATH: `${bin}:${process.env.PATH}`, TEST_PASS_CALLS: calls,
			PASS_ENV_CLIPBOARD: "fakeclip", PASS_ENV_CLIPBOARD_READ: "fakepaste", CLIP_FILE: join(root, "clipboard"), PASSWORD_STORE_CLIP_TIME: "1",
		},
	};
}

function invoke(files: Fixture, args: string[], input = "") {
	const result = spawnSync(process.execPath, [cli, ...args], {
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
		const child = spawn(process.execPath, [cli, "run", "-e", "TOKEN=token", "--", process.execPath, "-e",
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
		const command = [process.execPath, cli, "run", "-e", "TOKEN=token", "--", process.execPath, childScript]
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
		for (const command of ["run", "pipe", "copy", "check", "set", "generate", "unlock", "list"]) expect(out).toContain(`pass-env ${command}`);
	});
});
