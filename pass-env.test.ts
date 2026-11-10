import { afterEach, describe, expect, test } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
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
if (args[0] === "init") {
  if (args[1] !== "--" || args.length !== 3) process.exit(7);
  mkdirSync(process.env.PASSWORD_STORE_DIR, { recursive: true });
  writeFileSync(join(process.env.PASSWORD_STORE_DIR, ".gpg-id"), args[2] + "\\n");
  process.exit(0);
}
if (args[0] === "insert") {
  if (args.join(" ") !== "insert --multiline --force -- " + args[4] || args.length !== 5) process.exit(7);
  mkdirSync(dirname(file(args[4])), { recursive: true });
  writeFileSync(file(args[4]), await Bun.stdin.text());
  process.exit(0);
}
if (args[0] !== "show" || args[1] !== "--" || args.length !== 3) process.exit(7);
// The typed unlock (no --pinentry-mode error): succeeds only when a test allows it.
if (process.env.PASSWORD_STORE_GPG_OPTS === undefined && process.env.TEST_PASS_ALLOW_TYPED) {
  appendFileSync(process.env.TEST_PASS_CALLS, "typed unlock\\n");
  writeFileSync(join(process.env.TEST_GPG_STATE, "unlocked"), "");
  process.exit(0);
}
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
	// A fake gpg: doctor's and init's secret-key questions, init's key creation
	// (passphrase on stdin), and the decrypts unlock --hello makes (unlocked yet?
	// / loopback with the passphrase on stdin).
	const state = join(root, "gpg-state");
	mkdirSync(state);
	writeFileSync(join(bin, "gpg"), `#!/bin/sh
case " $* " in
*" --pinentry-mode error "*) [ -e "$TEST_GPG_STATE/unlocked" ] && exit 0; echo "gpg: decryption failed: No secret key" >&2; exit 2;;
*" --quick-generate-key "*)
	IFS= read -r given
	if [ "$given" = "$TEST_GPG_PASSPHRASE" ]; then echo "keygen ok: $*" >> "$TEST_PASS_CALLS"; else echo "keygen got another passphrase" >> "$TEST_PASS_CALLS"; fi
	echo "[GNUPG:] KEY_CREATED B 0123456789ABCDEF0123456789ABCDEF01234567"; exit 0;;
*" --passphrase-fd 0 "*)
	IFS= read -r given
	if [ "$given" = "$TEST_GPG_PASSPHRASE" ]; then echo "loopback ok" >> "$TEST_PASS_CALLS"; : > "$TEST_GPG_STATE/unlocked"; exit 0; fi
	echo "loopback bad" >> "$TEST_PASS_CALLS"; echo "gpg: public key decryption failed: Bad passphrase" >&2; exit 2;;
esac
for id; do :; done
# With no key named, list every key: TEST_GPG_COLONS holds gpg's --with-colons lines.
if [ "$id" = "--with-colons" ]; then printf '%b' "\${TEST_GPG_COLONS:-}"; exit 0; fi
case " $TEST_GPG_SECRET_KEYS " in *" $id "*) if [ -n "\${TEST_GPG_COLONS:-}" ]; then printf '%b' "$TEST_GPG_COLONS"; else echo "sec:u:255:22:SYNTHETIC::::::::::"; fi; exit 0;; esac
exit 2
`, { mode: 0o700 });
	writeFileSync(join(bin, "gpgconf"), `#!/bin/sh\necho "gpgconf $*" >> "$TEST_PASS_CALLS"\nrm -f "$TEST_GPG_STATE/unlocked"\n`, { mode: 0o700 });
	return {
		root, store, calls,
		env: {
			// XDG_STATE_HOME keeps scrub's scan history inside the temp folder, never the real one.
			...process.env, HOME: root, XDG_STATE_HOME: join(root, ".local", "state"), PASSWORD_STORE_DIR: store, PATH: `${bin}:${process.env.PATH}`, TEST_PASS_CALLS: calls,
			PASS_ENV_CLIPBOARD: "fakeclip", PASS_ENV_CLIPBOARD_READ: "fakepaste", CLIP_FILE: join(root, "clipboard"), PASSWORD_STORE_CLIP_TIME: "1",
			XDG_CONFIG_HOME: join(root, ".config"), TEST_GPG_STATE: state, GNUPGHOME: join(root, "no-gnupg"),
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

describe("set at the prompt", () => {
	const ttyAvailable = Boolean(Bun.which("script"));
	// Types into pass-env in a pseudo-terminal, after the prompt is up, like a
	// person pasting. Each chunk is sent after a pause, so answers to a
	// follow-up question arrive after it is asked.
	const typed = (files: Fixture, args: string[], chunks: string[]) => {
		const command = [...launcher, ...args].map((part) => `'${part.replace(/'/g, "'\\''")}'`).join(" ");
		const feed = chunks.map((chunk) => `sleep 0.6; printf '%s' '${chunk.replace(/'/g, "'\\''")}'`).join("; ");
		const result = spawnSync("sh", ["-c", `{ ${feed}; sleep 1.5; } | script -qec "$0" /dev/null`, command], { cwd: files.root, env: files.env, encoding: "utf8", timeout: 20_000 });
		if (result.error) throw result.error;
		return { status: result.status, output: result.stdout.replace(/\r/g, "") };
	};

	test.skipIf(!ttyAvailable)("shows a * per character, never the value, and says how many were saved", () => {
		const files = fixture({});
		const value = "AQ.synthetic-key-0123456789";
		const result = typed(files, ["set", "app/KEY"], [`${value}\r`]);
		expect(result.status).toBe(0);
		expect(result.output).not.toContain(value);
		expect(result.output).toContain("*".repeat(value.length));
		expect(result.output).toContain(`Stored app/KEY: ${value.length} characters.`);
		expect(result.output).not.toContain("Retype");
		expect(stored(files, "app/KEY")).toBe(`${value}\n`);
	});

	test.skipIf(!ttyAvailable)("backspace removes a character and spaces around the value are trimmed", () => {
		const files = fixture({});
		const result = typed(files, ["set", "app/KEY"], [" synthetic-valueX\x7f \r"]);
		expect(result.status).toBe(0);
		expect(result.output).toContain("Removed the spaces");
		expect(result.output).toContain("Stored app/KEY: 15 characters.");
		expect(stored(files, "app/KEY")).toBe("synthetic-value\n");
	});

	test.skipIf(!ttyAvailable)("a 1-character paste asks first, and saves nothing on no", () => {
		const files = fixture({});
		const result = typed(files, ["set", "app/KEY"], ["v\r", "n\r"]);
		expect(result.status).toBe(1);
		expect(result.output).toContain("That is only 1 character");
		expect(result.output).toContain("nothing was saved");
		expect(existsSync(join(files.store, "app", "KEY.gpg"))).toBe(false);
	});

	test.skipIf(!ttyAvailable)("a short value is saved when confirmed", () => {
		const files = fixture({});
		const result = typed(files, ["set", "app/PIN"], ["1234\r", "y\r"]);
		expect(result.status).toBe(0);
		expect(result.output).toContain("Stored app/PIN: 4 characters.");
		expect(stored(files, "app/PIN")).toBe("1234\n");
	});

	test.skipIf(!ttyAvailable)("Ctrl-C cancels without saving and gives the terminal back", () => {
		const files = fixture({});
		const result = typed(files, ["set", "app/KEY"], ["synthetic\x03"]);
		expect(result.status).toBe(1);
		expect(result.output).toContain("cancelled; nothing was saved");
		expect(existsSync(join(files.store, "app", "KEY.gpg"))).toBe(false);
	});

	test.skipIf(!ttyAvailable)("an empty Enter saves nothing", () => {
		const files = fixture({});
		const result = typed(files, ["set", "app/KEY"], ["\r"]);
		expect(result.status).toBe(1);
		expect(result.output).toContain("nothing was pasted");
	});
});

describe("set", () => {
	test("stores piped input, dropping one trailing newline, and refuses to overwrite without --force", () => {
		const files = fixture({});
		const result = invoke(files, ["set", "app/KEY"], "sk-live-synthetic\n");
		expect(result.status).toBe(0);
		expect(result.stdout).toBe("Stored app/KEY: 17 characters.\n");
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
		const empty = invoke(files, ["set", "app/KEY"], "");
		expect(empty.status).toBe(1);
		expect(empty.stderr).toContain("run pass-env set in your own terminal");
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
		for (const command of ["run", "pipe", "copy", "check", "set", "generate", "unlock", "list", "import", "scrub", "doctor"]) expect(out).toContain(`pass-env ${command}`);
	});

	test("no arguments prints a short overview that points at the full help", () => {
		const files = fixture();
		const result = invoke(files, []);
		expect(result.status).toBe(0);
		expect(result.stdout.trim().split("\n").length).toBeLessThan(15);
		expect(result.stdout).toContain("pass-env help <command>");
	});

	test("help <command> and <command> --help print only that command", () => {
		const files = fixture();
		for (const args of [["help", "generate"], ["generate", "--help"], ["generate", "x", "-h"]]) {
			const out = invoke(files, args).stdout;
			expect(out).toContain("pass-env generate <entry>");
			expect(out).not.toContain("pass-env run");
		}
		const passthrough = invoke(files, ["run", "-e", "A=missing", "--", "sh", "--help"]);
		expect(passthrough.stdout).not.toContain("pass-env: use secrets");
	});

	test("a usage error names the help to read", () => {
		const files = fixture();
		const run = invoke(files, ["run"]);
		expect(run.status).toBe(2);
		expect(run.stderr).toContain("pass-env run -- npm run dev");
		expect(run.stderr).toContain("See pass-env help run");
		const unknown = invoke(files, ["frob"]);
		expect(unknown.stderr).toContain('unknown command "frob"');
		expect(unknown.stderr).toContain("See pass-env help\n");
		expect(invoke(files, ["help", "nope"]).status).toBe(2);
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
		expect(result.stdout).toContain("fix: pass-env init");
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

describe("scrub", () => {
	// Built at runtime so no realistic-looking key is ever committed to this repo.
	const body = "Ab3dE5gH7jK9mN1pQ3sT5vW7xY9zA1bC3dE5fG7h";
	const pem = `-----BEGIN ${"PRIVATE"} KEY-----\n${"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ".repeat(2)}\nQ2xpZW50IGtleQ==\n-----END PRIVATE KEY-----`;
	const samples: Record<string, string> = {
		"aws-access-key": `${"AK"}IAQ3XAMPL7ZZ9W2XY4`,
		"github-token": `${"gh"}p_${body.slice(0, 36)}`,
		"anthropic-key": `${"sk"}-ant-api03-${body}`,
		"openai-key": `${"sk"}-proj-${body}`,
		"stripe-key": `${"sk"}_live_${body.slice(0, 24)}`,
		"stripe-webhook-secret": `${"wh"}sec_${body.slice(0, 32)}`,
		"slack-token": `${"xo"}xb-123456789012-1234567890123-${body.slice(0, 24)}`,
		"google-api-key": `${"AI"}za${body.slice(0, 35)}`,
		"resend-key": `${"re"}_${body.slice(0, 8)}_${body.slice(8, 32)}`,
		jwt: `${"ey"}JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
	};
	const contexts: Record<string, [string, string]> = {
		"bearer-token": ["curl -H 'Authorization: Bearer ", "Zk3mQ9pL2xV7nR4tY8wB1cD6'"],
		"secret-assignment": ["DB_PASSWORD=", "Zk3mQ9pL2xV7nR4t"],
	};
	const secretTexts = [...Object.values(samples), pem.split("\n")[1], "Zk3mQ9pL2xV7nR4t"];
	// Things that look close but are not secrets, and must not be touched.
	const decoys = [
		"risk-assessment-framework-docs-version-two", "const apiKey = process.env.OPENAI_API_KEY_2;", 'if (pem.startsWith("-----BEGIN PRIVATE KEY-----")) {',
		"password=your-password-12345", "token: ${API_TOKEN_2}", "secret_file=/etc/app/secret2.txt", "Bearer authentication_middleware_layer",
		"re_render_component_after_update_x", "sk-short", `${"AK"}IAlowercase0123456789`, "task-dispatcher-for-background-jobs-queue", "max_tokens: 123456789012345",
	];
	const old = (path: string) => utimesSync(path, new Date(Date.now() - 3600_000), new Date(Date.now() - 3600_000));
	const session = (fx: Fixture, lines: string[], name = ".claude/projects/-home-me-app/session.jsonl") => {
		const path = join(fx.root, name);
		mkdirSync(dirname(path), { recursive: true });
		writeFileSync(path, `${lines.join("\n")}\n`);
		old(path);
		return path;
	};
	const noSecrets = (text: string) => {
		for (const secret of secretTexts) expect(text).not.toContain(secret);
	};

	test("finds every kind, also JSON-escaped and inside escaped JSON, and prints only counts", () => {
		const fx = fixture({});
		const lines = [
			...Object.values(samples).map((secret) => JSON.stringify({ type: "user", message: { content: `here:\n${secret} and more` } })),
			...Object.values(contexts).map(([before, secret]) => JSON.stringify({ type: "tool", output: `${before}${secret}` })),
			JSON.stringify({ type: "tool", output: `cat key.pem\n${pem}\n` }),
			JSON.stringify({ text: JSON.stringify({ config: JSON.stringify({ private_key: pem }) }) }),
		];
		session(fx, lines);
		session(fx, [JSON.stringify({ display: `export STRIPE_SECRET_KEY=${samples["stripe-key"]}` })], ".claude/history.jsonl");
		const result = invoke(fx, ["scrub"]);
		expect(result.status).toBe(1);
		noSecrets(result.stdout + result.stderr);
		const kinds = Object.keys({ ...samples, ...contexts }).sort().map((kind) => `${kind} 1`);
		const projectLine = result.stdout.split("\n").find((line) => line.startsWith("~/.claude/projects/"))!;
		expect(projectLine).toBe(`~/.claude/projects/-home-me-app/session.jsonl: ${[...kinds, "private-key 2"].sort().join(", ")}`);
		expect(result.stdout).toContain("~/.claude/history.jsonl: stripe-key 1\n");
		expect(result.stdout).toContain("Found 15 suspected secrets in 2 files");
		expect(result.stdout).toContain("Nothing was changed. To replace them with [REDACTED:<kind>]: pass-env scrub --fix");
	});

	test("also scans ~/.claude/projects-archive", () => {
		const fx = fixture({});
		session(fx, [JSON.stringify({ text: `token ${samples["github-token"]}` })], ".claude/projects-archive/-home-me-old/session.jsonl");
		const result = invoke(fx, ["scrub"]);
		expect(result.status).toBe(1);
		noSecrets(result.stdout + result.stderr);
		expect(result.stdout).toContain("~/.claude/projects-archive/-home-me-old/session.jsonl: github-token 1\n");
		expect(result.stdout).toContain("in ~/.claude/projects-archive");
	});

	test("lookalikes do not match, and a clean scan exits 0", () => {
		const fx = fixture({});
		const path = session(fx, decoys.map((text) => JSON.stringify({ type: "assistant", text })));
		session(fx, [JSON.stringify({ usage: { input_tokens: 123456, output_tokens: 99 } })], ".codex/sessions/2026/11/01/rollout.jsonl");
		const before = readFileSync(path, "utf8");
		const result = invoke(fx, ["scrub"]);
		expect(result.stdout).toContain("Scanned 2 files");
		expect(result.stdout).toContain("No suspected secrets found.");
		expect(result.status).toBe(0);
		expect(invoke(fx, ["scrub", "--fix"]).status).toBe(0);
		expect(readFileSync(path, "utf8")).toBe(before);
	});

	test("--fix redacts in place, keeps JSONL valid, mode and times, and leaves a line it cannot fix", () => {
		const fx = fixture({});
		// A PEM BEGIN in one JSON field and END in another: redacting would break the line.
		const broken = JSON.stringify({ a: pem.split("-----END")[0], list: ["x", "-----END PRIVATE KEY-----"] });
		const lines = [JSON.stringify({ text: `token ${samples["github-token"]}` }), broken, JSON.stringify({ text: `cat\n${pem}` }), "not json DB_PASSWORD=Zk3mQ9pL2xV7nR4t"];
		const path = session(fx, lines);
		chmodSync(path, 0o600);
		old(path);
		const mtime = statSync(path).mtimeMs;
		const result = invoke(fx, ["scrub", "--fix"]);
		expect(result.status).toBe(0);
		noSecrets(result.stdout + result.stderr);
		expect(result.stdout).toContain("session.jsonl: redacted github-token 1, private-key 1, secret-assignment 1; 1 line left as is (would not stay valid JSON)");
		expect(result.stdout).toContain("Left 1 line as it was: redacting would have broken its JSON.");
		expect(result.stdout).toContain("There are no backups");
		const after = readFileSync(path, "utf8").split("\n");
		expect(after[0]).toBe(JSON.stringify({ text: "token [REDACTED:github-token]" }));
		expect(after[1]).toBe(broken);
		expect(after[2]).toBe(JSON.stringify({ text: "cat\n[REDACTED:private-key]" }));
		expect(after[3]).toBe("not json DB_PASSWORD=[REDACTED:secret-assignment]");
		expect(after[4]).toBe("");
		for (const line of after.slice(0, 3)) expect(() => JSON.parse(line)).not.toThrow();
		expect(statSync(path).mode & 0o777).toBe(0o600);
		expect(statSync(path).mtimeMs).toBe(mtime);
		expect(readFileSync(path, "utf8")).not.toContain(".pass-env-");
		// Running again remembers the line it could not fix, and --all reads it again.
		const again = invoke(fx, ["scrub"]);
		expect(again.stdout).toContain("session.jsonl: private-key 1 (unchanged since the scan on ");
		expect(again.stdout).toContain("1 of these files was not read again");
		expect(again.status).toBe(1);
		const all = invoke(fx, ["scrub", "--all"]);
		expect(all.stdout).toContain("session.jsonl: private-key 1\n");
		expect(all.status).toBe(1);
	});

	test("skips files changed in the last 10 minutes unless --include-active", () => {
		const fx = fixture({});
		const path = session(fx, [JSON.stringify({ text: samples["openai-key"] })]);
		utimesSync(path, new Date(), new Date());
		const dry = invoke(fx, ["scrub"]);
		expect(dry.stdout).toContain("session.jsonl: openai-key 1 (in use: --fix skips it)");
		const fix = invoke(fx, ["scrub", "--fix"]);
		expect(fix.status).toBe(0);
		expect(fix.stdout).toContain("Skipped 1 file changed in the last 10 minutes");
		expect(fix.stdout).toContain("--include-active");
		expect(readFileSync(path, "utf8")).toContain(samples["openai-key"]);
		expect(invoke(fx, ["scrub", "--fix", "--include-active"]).stdout).toContain("redacted openai-key 1");
		expect(readFileSync(path, "utf8")).toBe(`${JSON.stringify({ text: "[REDACTED:openai-key]" })}\n`);
	});

	test("--path adds files and folders, joins a raw PEM block over lines, and skips binary files", () => {
		const fx = fixture({});
		const outside = join(fx.root, "elsewhere");
		mkdirSync(join(outside, "deep"), { recursive: true });
		writeFileSync(join(outside, "deep", "notes.txt"), `before\n${pem}\nafter`);
		writeFileSync(join(outside, "image.bin"), new Uint8Array([0, 1, 2, 0xff]));
		const single = join(fx.root, "one.log");
		writeFileSync(single, `${samples.jwt}\r\n`);
		for (const path of [join(outside, "deep", "notes.txt"), join(outside, "image.bin"), single]) old(path);
		const result = invoke(fx, ["scrub", "--path", "elsewhere", "--path", "one.log"]);
		expect(result.status).toBe(1);
		expect(result.stdout).toContain("elsewhere/deep/notes.txt: private-key 1");
		expect(result.stdout).toContain("one.log: jwt 1");
		expect(result.stdout).toContain("Skipped 1 file that is not UTF-8 text or could not be read.");
		expect(result.stdout).toContain("pass-env scrub --fix --path elsewhere --path one.log");
		expect(invoke(fx, ["scrub", "--fix", "--path", "elsewhere", "--path", "one.log"]).status).toBe(0);
		expect(readFileSync(join(outside, "deep", "notes.txt"), "utf8")).toBe("before\n[REDACTED:private-key]\nafter");
		expect(readFileSync(single, "utf8")).toBe("[REDACTED:jwt]\r\n");
	});

	test("--known finds exact store values no pattern knows, raw and JSON-escaped; it needs GPG unlocked", () => {
		const custom = 'plain"words\\no-pattern-knows';
		const fx = fixture({ "app/CUSTOM": `${custom}\nuser: me\n`, "app/SHORT": "tiny-value\n", nokey: "x" });
		const path = session(fx, [JSON.stringify({ text: `value is ${custom} here` }), "raw tiny-value", JSON.stringify({ text: "nothing" })]);
		writeFileSync(join(fx.root, "raw.txt"), `copy: ${custom}\n`);
		old(join(fx.root, "raw.txt"));
		expect(invoke(fx, ["scrub"]).status).toBe(0);
		const result = invoke(fx, ["scrub", "--known", "--path", "raw.txt"]);
		expect(result.status).toBe(1);
		expect(result.stdout + result.stderr).not.toContain("no-pattern-knows");
		expect(result.stdout).toContain("session.jsonl: known-value 1");
		expect(result.stdout).toContain("raw.txt: known-value 1");
		expect(result.stderr).toBe("warning: could not decrypt nokey, so their values were not looked for\n");
		expect(invoke(fx, ["scrub", "--known", "--fix", "--path", "raw.txt"]).status).toBe(0);
		expect(readFileSync(path, "utf8")).toBe(`${JSON.stringify({ text: "value is [REDACTED:known-value] here" })}\nraw tiny-value\n${JSON.stringify({ text: "nothing" })}\n`);
		expect(readFileSync(join(fx.root, "raw.txt"), "utf8")).toBe("copy: [REDACTED:known-value]\n");

		fx.env.TEST_PASS_LOCKED = "1";
		// Nothing changed since the last --known scan, so nothing needs decrypting.
		const remembered = invoke(fx, ["scrub", "--known", "--path", "raw.txt"]);
		expect(remembered.status).toBe(0);
		expect(remembered.stdout).toContain("2 files unchanged since");
		const locked = invoke(fx, ["scrub", "--known", "--all"]);
		expect(locked.status).toBe(1);
		expect(locked.stderr).toStartWith("LOCKED:");
		expect(locked.stderr).toContain("pass-env unlock");
		expect(locked.stdout).toBe("");
	});

	describe("scan history", () => {
		const historyFile = (fx: Fixture) => join(fx.root, ".local", "state", "pass-env", "scrub.json");
		const history = (fx: Fixture) => JSON.parse(readFileSync(historyFile(fx), "utf8"));
		const at = (path: string, minutesAgo: number) => utimesSync(path, new Date(Date.now() - minutesAgo * 60_000), new Date(Date.now() - minutesAgo * 60_000));
		const line = (text: string) => `${JSON.stringify({ type: "tool", output: text })}\n`;

		test("skips unchanged files, reads changed ones, and keeps only paths, times and counts in a file only you can read", () => {
			const fx = fixture({});
			const one = session(fx, [JSON.stringify({ text: samples["github-token"] })]);
			const two = session(fx, [JSON.stringify({ text: "nothing" })], ".codex/sessions/2026/11/01/rollout.jsonl");
			const first = invoke(fx, ["scrub"]);
			expect(first.stdout).toContain("Scanned 2 files");
			expect(first.status).toBe(1);
			const again = invoke(fx, ["scrub"]);
			expect(again.stdout).toContain("Nothing new to scan in ~/.claude/projects, ~/.codex/sessions.");
			expect(again.stdout).toMatch(/2 files unchanged since \d{4}-\d\d-\d\d \d\d:\d\d, skipped \(--all reads everything again\)\./);
			expect(again.stdout).toContain("session.jsonl: github-token 1 (unchanged since the scan on ");
			expect(again.status).toBe(1);
			writeFileSync(two, `${JSON.stringify({ text: samples.jwt })}\n`);
			old(two);
			const changed = invoke(fx, ["scrub"]);
			expect(changed.stdout).toContain("Scanned 1 file");
			expect(changed.stdout).toContain("rollout.jsonl: jwt 1\n");
			expect(changed.stdout).toContain("1 file unchanged since");
			expect(invoke(fx, ["scrub", "--all"]).stdout).toContain("Scanned 2 files");

			const state = history(fx);
			expect(statSync(historyFile(fx)).mode & 0o777).toBe(0o600);
			expect(statSync(dirname(historyFile(fx))).mode & 0o777).toBe(0o700);
			expect(Object.keys(state.files).sort()).toEqual([one, two].sort());
			expect(state.files[one]).toMatchObject({ location: join(fx.root, ".claude/projects"), size: statSync(one).size, counts: { "github-token": 1 } });
			noSecrets(readFileSync(historyFile(fx), "utf8"));
		});

		test("a newer pattern version reads every file again", () => {
			const fx = fixture({});
			session(fx, [JSON.stringify({ text: "nothing" })]);
			invoke(fx, ["scrub"]);
			const state = history(fx);
			state.patterns_version = 0;
			writeFileSync(historyFile(fx), JSON.stringify(state));
			expect(invoke(fx, ["scrub", "--history"]).stdout).toContain("The patterns changed since some of these scans");
			const result = invoke(fx, ["scrub"]);
			expect(result.stdout).toContain("Scanned 1 file");
			expect(result.stdout).not.toContain("unchanged");
			expect(invoke(fx, ["scrub"]).stdout).toContain("1 file unchanged since");
		});

		test("--known reads files again when the store changes, and a plain scan does not count for --known", () => {
			const value = "only-the-store-knows-this-value";
			const fx = fixture({ "app/A": "something-else-entirely\n" });
			session(fx, [JSON.stringify({ text: `here ${value}` })]);
			expect(invoke(fx, ["scrub"]).status).toBe(0);
			const first = invoke(fx, ["scrub", "--known"]);
			expect(first.stdout).toContain("Scanned 1 file");
			expect(first.status).toBe(0);
			expect(invoke(fx, ["scrub", "--known"]).stdout).toContain("1 file unchanged since");
			writeFileSync(join(fx.store, "app", "B.gpg"), `${value}\n`);
			const changed = invoke(fx, ["scrub", "--known"]);
			expect(changed.stdout).toContain("Scanned 1 file");
			expect(changed.stdout).toContain("session.jsonl: known-value 1\n");
			expect(changed.stdout + changed.stderr).not.toContain(value);
			expect(changed.status).toBe(1);
			// The fingerprint is names, sizes and times: no value reaches the history.
			expect(readFileSync(historyFile(fx), "utf8")).not.toContain(value);
			// --fix without --known cannot redact a known value, so it leaves the file alone.
			const plain = invoke(fx, ["scrub", "--fix"]);
			expect(plain.stdout).toContain("1 file unchanged since");
			expect(plain.stdout).toContain("No suspected secrets were redacted.");
			expect(invoke(fx, ["scrub", "--known", "--fix"]).stdout).toContain("session.jsonl: redacted known-value 1");
			expect(invoke(fx, ["scrub", "--known"]).status).toBe(0);
		});

		test("a file that only grew is read from where the last scan stopped, also mid-line", () => {
			const fx = fixture({});
			const filler = line("x".repeat(200_000));
			const path = session(fx, [JSON.stringify({ text: samples["github-token"] })]);
			writeFileSync(path, filler, { flag: "a" });
			at(path, 60);
			expect(invoke(fx, ["scrub"]).stdout).toContain("session.jsonl: github-token 1\n");
			writeFileSync(path, line(`key ${samples["openai-key"]}`), { flag: "a" });
			at(path, 50);
			const grown = invoke(fx, ["scrub"]);
			expect(grown.stdout).toContain("session.jsonl: github-token 1, openai-key 1\n");
			expect(grown.stdout).toContain("Scanned 1 file (1 KB)");
			expect(grown.stdout).toContain("1 file only grew since the last scan, so only its new lines were read.");
			// A line still being written: its start is read again once it is finished.
			writeFileSync(path, `{"text":"${samples.jwt.slice(0, 30)}`, { flag: "a" });
			at(path, 40);
			expect(invoke(fx, ["scrub"]).stdout).toContain("session.jsonl: github-token 1, openai-key 1\n");
			writeFileSync(path, `${samples.jwt.slice(30)} and ${samples["stripe-key"]}"}\n`, { flag: "a" });
			at(path, 30);
			const finished = invoke(fx, ["scrub"]);
			expect(finished.stdout).toContain("session.jsonl: github-token 1, jwt 1, openai-key 1, stripe-key 1\n");
			expect(finished.stdout).toContain("Scanned 1 file (1 KB)");
			expect(invoke(fx, ["scrub", "--all"]).stdout).toContain("session.jsonl: github-token 1, jwt 1, openai-key 1, stripe-key 1\n");
		});

		test("a replaced file (new inode) or one that shrank is read whole", () => {
			const fx = fixture({});
			const path = session(fx, [JSON.stringify({ text: samples["github-token"] })]);
			at(path, 60);
			invoke(fx, ["scrub"]);
			const temp = `${path}.new`;
			writeFileSync(temp, `${readFileSync(path, "utf8")}${line(samples["openai-key"])}`);
			renameSync(temp, path);
			at(path, 50);
			const replaced = invoke(fx, ["scrub"]);
			expect(replaced.stdout).not.toContain("only grew");
			expect(replaced.stdout).toContain("session.jsonl: github-token 1, openai-key 1\n");
			writeFileSync(path, line(samples.jwt));
			at(path, 40);
			const shrank = invoke(fx, ["scrub"]);
			expect(shrank.stdout).toContain("session.jsonl: jwt 1\n");
			expect(shrank.stdout).not.toContain("only grew");
		});

		test("--fix records the rewritten file, so the next run skips it; deleted files are forgotten", () => {
			const fx = fixture({});
			const path = session(fx, [JSON.stringify({ text: samples["github-token"] })]);
			const gone = session(fx, [JSON.stringify({ text: "nothing" })], ".claude/projects/-home-me-app/other.jsonl");
			const inode = statSync(path).ino;
			expect(invoke(fx, ["scrub", "--fix"]).stdout).toContain("session.jsonl: redacted github-token 1");
			expect(statSync(path).ino).not.toBe(inode);
			const after = invoke(fx, ["scrub"]);
			expect(after.stdout).toContain("2 files unchanged since");
			expect(after.stdout).toContain("No suspected secrets found.");
			expect(after.status).toBe(0);
			const again = invoke(fx, ["scrub", "--fix"]);
			expect(again.stdout).toContain("2 files unchanged since");
			expect(again.stdout).toContain("No suspected secrets were redacted.");
			expect(history(fx).files[path]).toMatchObject({ counts: {}, size: statSync(path).size, mtime_ms: statSync(path).mtimeMs });
			expect(history(fx).files[path].fixed_at).toBeString();
			rmSync(gone);
			invoke(fx, ["scrub"]);
			expect(Object.keys(history(fx).files)).toEqual([path]);
		});

		test("--history lists each location, newest first, with counts and fixes but no secret", () => {
			const fx = fixture({});
			expect(invoke(fx, ["scrub", "--history"]).stdout).toBe("No scan history yet. Run pass-env scrub first.\n");
			session(fx, [JSON.stringify({ text: samples["github-token"] }), JSON.stringify({ text: samples.jwt })]);
			session(fx, [JSON.stringify({ text: samples["openai-key"] })], ".claude/projects/-home-me-app/two.jsonl");
			session(fx, [JSON.stringify({ text: "nothing" })], ".codex/sessions/2026/11/01/rollout.jsonl");
			writeFileSync(join(fx.root, "notes.txt"), `DB_PASSWORD=Zk3mQ9pL2xV7nR4t\n`);
			old(join(fx.root, "notes.txt"));
			invoke(fx, ["scrub", "--path", "notes.txt"]);
			invoke(fx, ["scrub", "--fix", "--path", "notes.txt"]);
			const state = history(fx);
			state.locations[join(fx.root, "notes.txt")].checked_at = "2026-01-02T03:04:00.000Z";
			writeFileSync(historyFile(fx), JSON.stringify(state));
			const result = invoke(fx, ["scrub", "--history"]);
			expect(result.status).toBe(0);
			noSecrets(result.stdout + result.stderr);
			expect(result.stdout).toStartWith("Scan history in ~/.local/state/pass-env/scrub.json (paths, times and counts only), newest first:\n");
			expect(result.stdout).toMatch(/~\/\.claude\/projects\n {2}last checked \d{4}-\d\d-\d\d \d\d:\d\d: 2 files, 0 with findings, 2 fixed\n/);
			expect(result.stdout).toMatch(/~\/\.codex\/sessions\n {2}last checked [^:]+:\d\d: 1 file, 0 with findings, 0 fixed\n/);
			expect(result.stdout).toMatch(/~\/notes\.txt\n {2}last checked 2026-01-0\d \d\d:\d\d: 1 file, 0 with findings, 1 fixed\n$/);
			for (const args of [["scrub", "--history", "--all"], ["scrub", "--fix", "--history"]]) expect(invoke(fx, args).status).toBe(2);
		});

		test("an unreadable history starts over with a warning", () => {
			const fx = fixture({});
			session(fx, [JSON.stringify({ text: "nothing" })]);
			mkdirSync(dirname(historyFile(fx)), { recursive: true });
			writeFileSync(historyFile(fx), "not json");
			const result = invoke(fx, ["scrub"]);
			expect(result.stderr).toBe("warning: ~/.local/state/pass-env/scrub.json is not a scan history this version can read, so every file is read again\n");
			expect(result.stdout).toContain("Scanned 1 file");
			expect(invoke(fx, ["scrub"]).stdout).toContain("1 file unchanged since");
		});
	});

	test("usage errors exit 2, and no logs at all is fine", () => {
		const fx = fixture({});
		for (const args of [["scrub", "--include-active"], ["scrub", "--path"], ["scrub", "--path", "missing"], ["scrub", "--bogus"]]) {
			expect(invoke(fx, args).status).toBe(2);
		}
		const none = invoke(fx, ["scrub"]);
		expect(none.status).toBe(0);
		expect(none.stdout).toContain("No agent logs found");
	});
});

describe("Windows Hello unlock (fake helper)", () => {
	const PASSPHRASE = "synthetic-gpg-passphrase";
	const fakeHelper = join(import.meta.dir, "demo", "fake-hello-helper.ts");
	const fakePinentry = join(import.meta.dir, "demo", "fake-pinentry.sh");
	const ttyAvailable = Boolean(Bun.which("script"));

	// A store that is set up and locked, with the fake helper and pinentry.
	const hello = (mode = "ok") => {
		const files = fixture({ token: "synthetic-value" });
		writeFileSync(join(files.store, ".gpg-id"), "synthetic@example.invalid\n");
		Object.assign(files.env, {
			PASS_ENV_HELLO_HELPER: fakeHelper, PASS_ENV_HELLO_HELPER_UNPINNED: "1", FAKE_HELLO_MODE: mode, FAKE_HELLO_LOG: join(files.root, "helper-calls"),
			PASS_ENV_PINENTRY: fakePinentry, FAKE_PIN: PASSPHRASE, TEST_GPG_PASSPHRASE: PASSPHRASE,
			TEST_GPG_SECRET_KEYS: "synthetic@example.invalid", TEST_PASS_ALLOW_TYPED: "1", WSL_DISTRO_NAME: "Synthetic-WSL",
		});
		delete files.env.SSH_CONNECTION;
		delete files.env.SSH_TTY;
		return files;
	};
	const blob = (files: Fixture) => join(files.root, ".config", "pass-env", "hello.blob");
	const helperCalls = (files: Fixture) => existsSync(files.env.FAKE_HELLO_LOG!) ? readFileSync(files.env.FAKE_HELLO_LOG!, "utf8") : "";
	const passCalls = (files: Fixture) => existsSync(files.calls) ? readFileSync(files.calls, "utf8") : "";
	const unlocked = (files: Fixture) => existsSync(join(files.env.TEST_GPG_STATE!, "unlocked"));
	// Runs pass-env inside a pseudo-terminal, like a person in their own terminal.
	const inTty = (files: Fixture, args: string[]) => {
		const command = [...launcher, ...args].map((part) => `'${part.replace(/'/g, "'\\''")}'`).join(" ");
		const result = spawnSync("script", ["-qec", command, "/dev/null"], { cwd: files.root, env: files.env, input: "", encoding: "utf8", timeout: 20_000 });
		if (result.error) throw result.error;
		const output = result.stdout.replace(/\r/g, "");
		expect(output).not.toContain(PASSPHRASE);
		return { status: result.status, output };
	};
	const enrolled = (mode = "ok") => {
		const files = hello();
		expect(inTty(files, ["hello", "enrol"]).status).toBe(0);
		Bun.spawnSync({ cmd: ["rm", "-f", join(files.env.TEST_GPG_STATE!, "unlocked"), files.calls, files.env.FAKE_HELLO_LOG!] });
		files.env.FAKE_HELLO_MODE = mode;
		return files;
	};

	test("unlock --hello and hello enrol refuse without a terminal, and never start the helper", () => {
		const files = hello();
		for (const args of [["unlock", "--hello"], ["hello", "enrol"], ["hello", "forget"]]) {
			const result = invoke(files, args);
			expect(result.status).toBe(2);
			expect(result.stderr).toContain("TTY:");
		}
		expect(helperCalls(files)).toBe("");
		expect(passCalls(files)).toBe("");
	});

	test.skipIf(!ttyAvailable)("enrol checks the passphrase, then saves an encrypted blob readable only by you", () => {
		const files = hello();
		const result = inTty(files, ["hello", "enrol"]);
		expect(result.status).toBe(0);
		expect(result.output).toContain("Passphrase checked");
		expect(result.output).toContain("Saved");
		expect(passCalls(files)).toContain("gpgconf --reload gpg-agent\nloopback ok\n");
		expect(helperCalls(files)).toMatch(/^check\nenrol --from Synthetic-WSL: /);
		const saved = readFileSync(blob(files));
		expect(saved.subarray(0, 4).toString()).toBe("PEH1");
		expect(saved.includes(Buffer.from(PASSPHRASE))).toBe(false);
		expect(statSync(blob(files)).mode & 0o777).toBe(0o600);
		expect(statSync(dirname(blob(files))).mode & 0o777).toBe(0o700);
	});

	test.skipIf(!ttyAvailable)("PASS_ENV_HELLO_KEY picks another Windows Hello key, kept in the blob", () => {
		const files = hello();
		files.env.PASS_ENV_HELLO_KEY = "pass-env-test-1";
		expect(inTty(files, ["hello", "enrol"]).status).toBe(0);
		expect(helperCalls(files)).toContain("enrol --from Synthetic-WSL: ");
		expect(helperCalls(files)).toContain(" --key pass-env-test-1\n");
		expect(readFileSync(blob(files)).subarray(6, 21).toString()).toBe("pass-env-test-1");
		rmSync(join(files.env.TEST_GPG_STATE!, "unlocked"));
		expect(inTty(files, ["unlock", "--hello"]).output).toContain("Unlocked with Windows Hello");
		files.env.PASS_ENV_HELLO_KEY = "bad/name";
		expect(invoke(files, ["hello", "status"]).stderr).toContain("USAGE: PASS_ENV_HELLO_KEY must be");
	});

	test.skipIf(!ttyAvailable)("enrol refuses a wrong or cancelled passphrase and saves nothing", () => {
		const files = hello();
		files.env.FAKE_PIN = "not-it";
		let result = inTty(files, ["hello", "enrol"]);
		expect(result.status).toBe(1);
		expect(result.output).toContain("PASSPHRASE: that passphrase does not open token; nothing was saved");
		expect(helperCalls(files)).toBe("check\n");
		files.env.FAKE_PIN_CANCEL = "1";
		result = inTty(files, ["hello", "enrol"]);
		expect(result.output).toContain("CANCELLED:");
		expect(existsSync(blob(files))).toBe(false);
	});

	test.skipIf(!ttyAvailable)("enrol needs pass, GPG and a store with an entry first, and Hello available", () => {
		let files = hello();
		rmSync(join(files.store, ".gpg-id"));
		let result = inTty(files, ["hello", "enrol"]);
		expect(result.output).toContain("FAIL  the store has no .gpg-id");
		expect(result.output).toContain("SETUP: set up pass and GPG first: run pass-env doctor");
		files = hello();
		rmSync(join(files.store, "token.gpg"));
		result = inTty(files, ["hello", "enrol"]);
		expect(result.output).toContain("ENTRY: the store is empty; add something first");
		files = hello("unavailable");
		result = inTty(files, ["hello", "enrol"]);
		expect(result.output).toContain("HELLO: Windows Hello is not usable here (hello unsupported");
		expect(passCalls(files)).toBe("");
		expect(existsSync(blob(files))).toBe(false);
	});

	test.skipIf(!ttyAvailable)("unlock --hello unlocks through the helper and gpg loopback, with no typed prompt", () => {
		const files = enrolled();
		const result = inTty(files, ["unlock", "--hello"]);
		expect(result.status).toBe(0);
		expect(result.output).toContain("Unlocked with Windows Hello (checked with token)");
		expect(result.output).toContain("fake-hello: request from Synthetic-WSL: ");
		expect(passCalls(files)).toBe("loopback ok\n");
		expect(unlocked(files)).toBe(true);
		// Already unlocked: no prompt at all.
		const again = inTty(files, ["unlock", "--hello"]);
		expect(again.output).toContain("GPG is already unlocked");
		expect(helperCalls(files).match(/unwrap/g)?.length).toBe(1);
	});

	test.skipIf(!ttyAvailable)("every Hello failure falls back to the typed passphrase and says why", () => {
		const cases: Record<string, string> = {
			cancel: "Windows Hello was cancelled",
			unavailable: "Windows Hello is not available for pass-env",
			locked: "Windows Hello or the Windows session is locked",
			corrupt: "the saved passphrase does not open with this Windows Hello key; run pass-env hello enrol",
			other: "Windows Hello failed",
			wrong: "the passphrase saved with Windows Hello no longer opens GPG (was it changed?); run pass-env hello enrol",
		};
		for (const [mode, reason] of Object.entries(cases)) {
			const files = enrolled(mode);
			const result = inTty(files, ["unlock", "--hello"]);
			expect(result.status).toBe(0);
			expect(result.output).toContain(`Windows Hello not used: ${reason}`);
			expect(result.output).toContain("falling back to your typed GPG passphrase");
			expect(result.output).toContain("Unlocked (checked with token)");
			expect(passCalls(files)).toEndWith("typed unlock\n");
		}
	}, 30_000);

	test.skipIf(!ttyAvailable)("no blob, a corrupt blob, or SSH: the helper is never started", () => {
		let files = hello();
		let result = inTty(files, ["unlock", "--hello"]);
		expect(result.output).toContain("not enrolled yet (pass-env hello enrol)");
		files = enrolled();
		writeFileSync(blob(files), "PEH1\x02junk");
		result = inTty(files, ["unlock", "--hello"]);
		expect(result.output).toContain("the saved blob is not valid (format version 2 is not supported)");
		files = enrolled();
		files.env.SSH_CONNECTION = "192.0.2.1 22 192.0.2.2 22";
		result = inTty(files, ["unlock", "--hello"]);
		expect(result.output).toContain("this is an SSH session");
		for (const output of [result.output]) expect(output).toContain("Unlocked (checked with token)");
		expect(helperCalls(files)).toBe("");
	});

	test.skipIf(!ttyAvailable)("a helper whose hash changed since install is not run", () => {
		const files = enrolled();
		const dir = join(files.root, "windows-local", "pass-env");
		mkdirSync(dir, { recursive: true });
		const helper = join(dir, "pass-env-hello.exe");
		writeFileSync(helper, readFileSync(fakeHelper), { mode: 0o700 });
		const digest = (path: string) => new Bun.CryptoHasher("sha256").update(readFileSync(path)).digest("hex");
		writeFileSync(join(files.root, ".config", "pass-env", "hello-helper.json"),
			JSON.stringify({ path: helper, sha256: digest(helper), version: "0.0.0-fake", installed: "2026-11-02T00:00:00.000Z" }), { mode: 0o600 });
		delete files.env.PASS_ENV_HELLO_HELPER;
		files.env.PASS_ENV_HELLO_TEST_DIR = join(files.root, "windows-local");
		let result = inTty(files, ["unlock", "--hello"]);
		// A release build pins the real helper's hash, which the fake can never match.
		const pinned = invoke(files, ["version"]).stdout.includes("pins pass-env-hello.exe SHA-256");
		expect(result.output).toContain(pinned ? "the installed helper is not the one pass-env" : "Unlocked with Windows Hello");
		if (pinned) return;
		writeFileSync(helper, `${readFileSync(fakeHelper, "utf8")}\n// tampered\n`);
		Bun.spawnSync({ cmd: ["rm", "-f", join(files.env.TEST_GPG_STATE!, "unlocked"), files.env.FAKE_HELLO_LOG!] });
		result = inTty(files, ["unlock", "--hello"]);
		expect(result.output).toContain("changed since it was installed (SHA-256 mismatch), so it was not run");
		expect(result.output).toContain("Unlocked (checked with token)");
		expect(helperCalls(files)).toBe("");
		const status = invoke(files, ["hello", "status"]);
		expect(status.status).toBe(1);
		expect(status.stdout).toMatch(/^FAIL\s+the helper at .* changed since it was installed/m);
	});

	test("a release build refuses PASS_ENV_HELLO_HELPER unless PASS_ENV_HELLO_HELPER_UNPINNED=1, and it warns when used", () => {
		const files = hello();
		const status = invoke(files, ["hello", "status"]);
		expect(status.stderr).toContain(`pass-env: using PASS_ENV_HELLO_HELPER=${fakeHelper}, which is not hash-checked`);
		delete files.env.PASS_ENV_HELLO_HELPER_UNPINNED;
		const pinned = invoke(files, ["version"]).stdout.includes("pins pass-env-hello.exe SHA-256");
		const result = invoke(files, ["hello", "status"]);
		if (pinned) expect(result.stdout).toMatch(/^FAIL\s+PASS_ENV_HELLO_HELPER is set, but this pass-env release pins its helper/m);
		else expect(result.status).toBe(0);
	});

	test("a FIFO or symlink in place of the blob is refused at once, never read", () => {
		const files = hello();
		const dir = join(files.root, ".config", "pass-env");
		mkdirSync(dir, { recursive: true, mode: 0o700 });
		expect(spawnSync("mkfifo", [join(dir, "hello.blob")]).status).toBe(0);
		let result = invoke(files, ["hello", "status"]);
		expect(result.stdout).toMatch(/^FAIL\s+.*hello\.blob must be a regular file/m);
		rmSync(join(dir, "hello.blob"));
		symlinkSync(join(files.root, "elsewhere"), join(dir, "hello.blob"));
		writeFileSync(join(files.root, "elsewhere"), "PEH1");
		result = invoke(files, ["hello", "status"]);
		expect(result.stdout).toMatch(/^FAIL\s+.*hello\.blob must be a regular file, not a symlink/m);
	});

	test("hello install rejects files that are not Windows programs, and needs a terminal or --yes", () => {
		const files = hello();
		files.env.PASS_ENV_HELLO_TEST_DIR = join(files.root, "windows-local");
		const fake = join(files.root, "not-a-program.exe");
		writeFileSync(fake, "#!/bin/sh\n");
		expect(invoke(files, ["hello", "install", fake]).stderr).toContain("TTY:");
		const result = invoke(files, ["hello", "install", fake, "--yes"]);
		expect(result.status).toBe(1);
		expect(result.stderr).toContain("not a Windows program; nothing was installed");
		expect(existsSync(join(files.root, ".config", "pass-env", "hello-helper.json"))).toBe(false);
	});

	test.skipIf(!ttyAvailable)("hello status, doctor and forget", () => {
		const files = enrolled();
		const status = invoke(files, ["hello", "status"]);
		expect(status.status).toBe(0);
		expect(status.stdout).toMatch(/^ok\s+Windows Hello helper 0\.0\.0-fake \(set by PASS_ENV_HELLO_HELPER, not hash-checked\)/m);
		expect(status.stdout).toMatch(/^ok\s+Windows Hello available, TPM present, pass-env key present \(TPM-attested\)/m);
		expect(status.stdout).toMatch(/^ok\s+enrolled: .*hello\.blob is well-formed \(key pass-env\)/m);
		expect(invoke(files, ["doctor"]).stdout).toContain("Windows Hello helper 0.0.0-fake");
		chmodSync(blob(files), 0o644);
		expect(invoke(files, ["hello", "status"]).stdout).toMatch(/^warn\s+.*hello\.blob can be read by other users/m);
		writeFileSync(blob(files), "junk");
		expect(invoke(files, ["hello", "status"]).stdout).toMatch(/^FAIL\s+.*hello\.blob is not valid \(not a pass-env Hello blob\)/m);
		const forget = inTty(files, ["hello", "forget"]);
		expect(forget.status).toBe(0);
		expect(forget.output).toContain("No pass-env Windows Hello key is left.");
		expect(existsSync(blob(files))).toBe(false);
		expect(helperCalls(files)).toEndWith("forget\n");
	});

	test("doctor stays quiet about Hello until it is used, and flags the helper as pinentry", () => {
		const files = hello();
		delete files.env.PASS_ENV_HELLO_HELPER;
		expect(invoke(files, ["doctor"]).stdout).not.toContain("Windows Hello");
		mkdirSync(files.env.GNUPGHOME!);
		writeFileSync(join(files.env.GNUPGHOME!, "gpg-agent.conf"), "pinentry-program /mnt/c/x/pass-env-hello.exe\ndefault-cache-ttl 86400\nmax-cache-ttl 86400\n");
		const result = invoke(files, ["doctor"]);
		expect(result.stdout).toMatch(/^FAIL\s+pinentry-program is the Windows Hello helper/m);
		expect(result.stdout).toMatch(/^ok\s+GPG unlock lasts 24h after use, at most 24h/m);
	});

	test("version matches package.json and the helper's Cargo.toml", () => {
		const files = hello();
		const version = invoke(files, ["version"]).stdout.split("\n")[0];
		const pkg = JSON.parse(readFileSync(join(import.meta.dir, "package.json"), "utf8")).version;
		const cargo = readFileSync(join(import.meta.dir, "hello", "Cargo.toml"), "utf8").match(/^version = "(.+)"$/m)?.[1];
		expect(version).toBe(`pass-env ${pkg}`);
		expect(cargo).toBe(pkg);
		expect(invoke(files, ["--version"]).stdout.split("\n")[0]).toBe(version);
	});
});

describe("init", () => {
	const PASSPHRASE = "synthetic-test-passphrase";
	const fakePinentry = join(import.meta.dir, "demo", "fake-pinentry.sh");
	const ttyAvailable = Boolean(Bun.which("script"));
	const NEW_KEY = "0123456789ABCDEF0123456789ABCDEF01234567";
	const OLD_KEY = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";

	// No store yet, and a fake pinentry that gives the answers in order.
	const setup = (answers: string[]) => {
		const files = fixture({});
		rmSync(files.store, { recursive: true });
		const seq = join(files.root, "pin-answers");
		writeFileSync(seq, answers.map((answer) => `${answer}\n`).join(""));
		Object.assign(files.env, {
			PASS_ENV_PINENTRY: fakePinentry, FAKE_PIN_SEQ: seq, FAKE_PIN_LOG: join(files.root, "pin-log"), TEST_GPG_PASSPHRASE: PASSPHRASE,
		});
		return files;
	};
	const shown = (files: Fixture) => existsSync(files.env.FAKE_PIN_LOG!) ? readFileSync(files.env.FAKE_PIN_LOG!, "utf8") : "";
	const calls = (files: Fixture) => existsSync(files.calls) ? readFileSync(files.calls, "utf8") : "";
	const inTty = (files: Fixture, args: string[]) => {
		const command = [...launcher, ...args].map((part) => `'${part.replace(/'/g, "'\\''")}'`).join(" ");
		const result = spawnSync("script", ["-qec", command, "/dev/null"], { cwd: files.root, env: files.env, input: "", encoding: "utf8", timeout: 20_000 });
		if (result.error) throw result.error;
		const output = result.stdout.replace(/\r/g, "");
		expect(output).not.toContain(PASSPHRASE);
		return { status: result.status, output };
	};

	test("refuses without a terminal, before asking anything", () => {
		const files = setup([PASSPHRASE, PASSPHRASE]);
		const result = invoke(files, ["init", "--name", "Synthetic", "--email", "synthetic@example.invalid"]);
		expect(result.status).toBe(2);
		expect(result.stderr).toContain("TTY: init needs your terminal");
		expect(calls(files)).toBe("");
		expect(existsSync(join(files.store, ".gpg-id"))).toBe(false);
	});

	test("rejects --key together with --name or --email", () => {
		const result = invoke(setup([]), ["init", "--key", OLD_KEY, "--name", "Synthetic"]);
		expect(result.status).toBe(2);
		expect(result.stderr).toContain("--key uses an existing key");
	});

	test.skipIf(!ttyAvailable)("shows the rules, names what was wrong, then makes the key and the store", () => {
		const files = setup(["short1", "lettersonlyhere", PASSPHRASE, "synthetic-other-passphrase", PASSPHRASE, PASSPHRASE]);
		const result = inTty(files, ["init", "--name", "Synthetic Person", "--email", "synthetic@example.invalid"]);
		expect(result.status).toBe(0);
		const log = shown(files);
		// The rules are in the prompt itself, before any mistake.
		expect(log.split("\n")[0]).toContain("Rules: at least 12 characters, with at least one digit or symbol.");
		expect(log).toContain("SETERROR Too short: that was 6 characters, and at least 12 are needed.");
		expect(log).toContain("SETERROR Add at least one digit or symbol; that was letters only.");
		expect(log).toContain("SETDESC Type the same passphrase again");
		expect(log).toContain("SETERROR The two entries did not match.");
		expect(log).not.toContain(PASSPHRASE);
		// The passphrase went to gpg on stdin, never in its arguments.
		expect(calls(files)).toContain("keygen ok: --batch --no-tty --pinentry-mode loopback --passphrase-fd 0 --status-fd 1 --quick-generate-key -- Synthetic Person <synthetic@example.invalid> future-default default never");
		expect(calls(files)).not.toContain(PASSPHRASE);
		// The store records the fingerprint, not the email.
		expect(readFileSync(join(files.store, ".gpg-id"), "utf8")).toBe(`${NEW_KEY}\n`);
		expect(result.output).toContain(`Created your GPG key ${NEW_KEY} (Synthetic Person <synthetic@example.invalid>).`);
		expect(result.output).toContain("Created the store");
	});

	test.skipIf(!ttyAvailable)("cancelling the prompt creates nothing", () => {
		const files = setup([]);
		files.env.FAKE_PIN_CANCEL = "1";
		const result = inTty(files, ["init", "--name", "Synthetic", "--email", ""]);
		expect(result.status).not.toBe(0);
		expect(result.output).toContain("CANCELLED");
		expect(calls(files)).not.toContain("keygen");
		expect(existsSync(join(files.store, ".gpg-id"))).toBe(false);
	});

	test.skipIf(!ttyAvailable)("--key uses a key you already have, without a passphrase prompt", () => {
		const files = setup([]);
		Object.assign(files.env, {
			TEST_GPG_SECRET_KEYS: OLD_KEY,
			TEST_GPG_COLONS: `sec:u:255:22:F4BE65B3D6E82D5C:1762700000:::u:::scESC:::+:::23::0:\\nfpr:::::::::${OLD_KEY}:\\nuid:u::::1::X::Synthetic Owner <synthetic@example.invalid>::::::::::0:\\nssb:u:255:18:2DF604CBEF434726:1762700000:::::e:::+:::23:\\nfpr:::::::::AD57D968D058DA245840C6812DF604CBEF434726:\\n`,
		});
		const result = inTty(files, ["init", "--key", OLD_KEY]);
		expect(result.status).toBe(0);
		expect(shown(files)).toBe("");
		expect(calls(files)).not.toContain("keygen");
		expect(readFileSync(join(files.store, ".gpg-id"), "utf8")).toBe(`${OLD_KEY}\n`);
		expect(result.output).toContain(`for your key ${OLD_KEY} (Synthetic Owner <synthetic@example.invalid>)`);
	});

	test.skipIf(!ttyAvailable)("leaves a store that is already set up alone", () => {
		const files = setup([PASSPHRASE, PASSPHRASE]);
		mkdirSync(files.store);
		writeFileSync(join(files.store, ".gpg-id"), "synthetic@example.invalid\n");
		const result = inTty(files, ["init", "--name", "Synthetic", "--email", ""]);
		expect(result.status).not.toBe(0);
		expect(result.output).toContain("is already set up (for synthetic@example.invalid); nothing to do");
		expect(calls(files)).not.toContain("keygen");
		expect(readFileSync(join(files.store, ".gpg-id"), "utf8")).toBe("synthetic@example.invalid\n");
	});
});
