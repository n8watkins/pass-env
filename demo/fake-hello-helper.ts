#!/usr/bin/env bun
// A stand-in for pass-env-hello.exe, for tests and demo/e2e.sh on any OS.
// It speaks the same stdin/stdout/exit-code protocol but has NO security:
// its "encryption" is a fixed XOR. FAKE_HELLO_MODE picks the outcome:
// ok (default), cancel, unavailable, locked, corrupt, wrong, other.
// FAKE_HELLO_LOG gets one line per call (arguments only, never input).
import { appendFileSync } from "node:fs";

const [command, ...rest] = process.argv.slice(2);
const mode = process.env.FAKE_HELLO_MODE ?? "ok";
if (process.env.FAKE_HELLO_LOG) appendFileSync(process.env.FAKE_HELLO_LOG, `${[command, ...rest].join(" ")}\n`);
const codes: Record<string, number> = { unavailable: 3, cancel: 4, locked: 5, corrupt: 6, other: 7 };
const header = (name: Buffer) => Buffer.concat([Buffer.from("PEH1"), Buffer.from([1, name.length]), name, Buffer.alloc(32, 1), Buffer.alloc(12, 2)]);
const xorHeader = (key: string) => header(Buffer.from(key));
const xor = (bytes: Uint8Array) => Buffer.from(bytes.map((byte) => byte ^ 0x5a));

if (command === "version") {
	console.log("pass-env-hello 0.0.0-fake");
	process.exit(0);
}
if (command === "check") {
	const available = mode !== "unavailable";
	console.log(JSON.stringify({ helper: "pass-env-hello", version: "0.0.0-fake", protocol: 1, hello: available ? "available" : "unsupported", tpm: "present", key: "present", attestation: "tpm" }));
	process.exit(available ? 0 : 3);
}
if (command === "forget") process.exit(0);
const keyFlag = rest.indexOf("--key");
const keyName = keyFlag === -1 ? "pass-env" : rest[keyFlag + 1];
if ((command !== "enrol" && command !== "unwrap") || rest[0] !== "--from" || (rest.length !== 2 && !(command === "enrol" && rest.length === 4 && keyFlag === 2))) process.exit(2);
const input = Buffer.from(await Bun.stdin.arrayBuffer());
console.error(`fake-hello: request from ${rest[1]}`);
if (mode in codes) process.exit(codes[mode]);
if (command === "enrol") {
	process.stdout.write(Buffer.concat([xorHeader(keyName), xor(input), Buffer.alloc(16)]));
	process.exit(0);
}
const blobKey = input.subarray(6, 6 + (input[5] ?? 0)).toString("latin1");
const expected = xorHeader(blobKey);
if (!input.subarray(0, expected.length).equals(expected) || input.length < expected.length + 17) process.exit(6);
process.stdout.write(mode === "wrong" ? Buffer.from("not-the-passphrase") : xor(input.subarray(expected.length, input.length - 16)));
