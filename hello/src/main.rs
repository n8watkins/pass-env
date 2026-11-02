#![cfg_attr(not(windows), allow(dead_code, unused_imports))]
//! pass-env-hello: the Windows side of `pass-env unlock --hello`.
//!
//! Stateless: input on stdin, result on stdout, fixed messages on stderr,
//! never a file. Exit codes are the protocol with pass-env; see
//! docs/windows-hello.md. No secret is ever put in a message.

use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use pass_env_hello::{Error, SignerError, MAX_BLOB, MAX_SECRET};
use zeroize::Zeroizing;

#[cfg(windows)]
mod hello;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL: u32 = 1;
const KEY_NAME: &str = "pass-env";

const OK: u8 = 0;
const USAGE: u8 = 2;
const UNAVAILABLE: u8 = 3;
const CANCELLED: u8 = 4;
const LOCKED: u8 = 5;
const BAD_BLOB: u8 = 6;
const OTHER: u8 = 7;

fn usage() -> ExitCode {
	eprintln!("usage: pass-env-hello version | check | enrol --from <who> | unwrap --from <who> | forget");
	eprintln!("Run by pass-env (pass-env hello enrol, pass-env unlock --hello), not by hand.");
	ExitCode::from(USAGE)
}

fn fail(code: u8, message: &str) -> ExitCode {
	eprintln!("pass-env-hello: {message}");
	ExitCode::from(code)
}

fn error_exit(error: Error) -> ExitCode {
	match error {
		Error::Malformed(what) => fail(
			BAD_BLOB,
			&format!("the stored blob is not valid ({what}); run pass-env hello enrol"),
		),
		Error::Decrypt => fail(
			BAD_BLOB,
			"the stored blob does not open with this Windows Hello key; run pass-env hello enrol",
		),
		Error::BadSecret => fail(USAGE, "the passphrase must be 1 to 4096 bytes without NUL"),
		Error::NotDeterministic => fail(
			OTHER,
			"Windows Hello signatures are not repeatable on this machine, so they cannot protect a passphrase",
		),
		Error::Random => fail(OTHER, "could not get random bytes from Windows"),
		Error::Signer(SignerError::Cancelled) => fail(CANCELLED, "Windows Hello was cancelled"),
		Error::Signer(SignerError::Unavailable) => fail(
			UNAVAILABLE,
			"Windows Hello is not available for pass-env (run pass-env hello status)",
		),
		Error::Signer(SignerError::Locked) => fail(LOCKED, "Windows Hello is locked (security device or session locked)"),
		Error::Signer(SignerError::Other) => fail(OTHER, "Windows Hello failed"),
	}
}

/// Reads at most `limit` bytes; more than that is an error, never truncated.
/// The buffer is preallocated so it is never reallocated (and copied).
fn read_stdin(limit: usize) -> Result<Zeroizing<Vec<u8>>, ()> {
	let mut buffer = Zeroizing::new(Vec::with_capacity(limit + 64));
	std::io::stdin().take(limit as u64 + 1).read_to_end(&mut buffer).map_err(|_| ())?;
	if buffer.len() > limit {
		return Err(());
	}
	Ok(buffer)
}

/// Who asked, for the notice: printable ASCII only, at most 200 characters.
fn sanitize(from: &str) -> String {
	let clean: String = from.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(200).collect();
	if clean.is_empty() {
		"an unknown caller".into()
	} else {
		clean
	}
}

fn from_argument(args: &[String]) -> Option<String> {
	match args {
		[] => Some("an unknown caller".into()),
		[flag, value] if flag == "--from" => Some(sanitize(value)),
		_ => None,
	}
}

fn notice(from: &str, what: &str) {
	eprintln!("pass-env-hello: Windows Hello request to {what}, from {from}.");
	eprintln!("pass-env-hello: approve it only if you just started this yourself; otherwise cancel.");
}

fn main() -> ExitCode {
	let args: Vec<String> = std::env::args().skip(1).collect();
	let Some((command, rest)) = args.split_first() else {
		return usage();
	};
	match command.as_str() {
		"version" | "--version" if rest.is_empty() => {
			println!("pass-env-hello {VERSION}");
			ExitCode::from(OK)
		}
		"check" if rest.is_empty() => check(),
		"enrol" => match from_argument(rest) {
			Some(from) => enrol(&from),
			None => usage(),
		},
		"unwrap" => match from_argument(rest) {
			Some(from) => unwrap(&from),
			None => usage(),
		},
		"forget" if rest.is_empty() => forget(),
		_ => usage(),
	}
}

#[cfg(not(windows))]
fn check() -> ExitCode {
	println!("{{\"helper\":\"pass-env-hello\",\"version\":\"{VERSION}\",\"protocol\":{PROTOCOL},\"hello\":\"unsupported\",\"tpm\":\"unknown\",\"key\":\"unknown\",\"attestation\":\"unknown\"}}");
	ExitCode::from(UNAVAILABLE)
}

#[cfg(windows)]
fn check() -> ExitCode {
	let status = hello::status(KEY_NAME);
	println!(
		"{{\"helper\":\"pass-env-hello\",\"version\":\"{VERSION}\",\"protocol\":{PROTOCOL},\"hello\":\"{}\",\"tpm\":\"{}\",\"key\":\"{}\",\"attestation\":\"{}\"}}",
		status.hello, status.tpm, status.key, status.attestation,
	);
	ExitCode::from(if status.usable() { OK } else { UNAVAILABLE })
}

fn refuse_terminal_stdout() -> Option<ExitCode> {
	std::io::stdout()
		.is_terminal()
		.then(|| fail(USAGE, "refusing to write a secret to a terminal; pass-env reads it through a pipe"))
}

fn write_stdout(bytes: &[u8]) -> ExitCode {
	let mut out = std::io::stdout().lock();
	if out.write_all(bytes).and_then(|()| out.flush()).is_err() {
		return fail(OTHER, "could not write the result");
	}
	ExitCode::from(OK)
}

#[cfg(not(windows))]
fn enrol(_from: &str) -> ExitCode {
	fail(UNAVAILABLE, "pass-env-hello only runs on Windows")
}

#[cfg(windows)]
fn enrol(from: &str) -> ExitCode {
	if let Some(code) = refuse_terminal_stdout() {
		return code;
	}
	let Ok(secret) = read_stdin(MAX_SECRET) else {
		return fail(USAGE, "the passphrase must be at most 4096 bytes");
	};
	notice(
		from,
		"save your GPG passphrase (up to three prompts: create the key, use it, check it)",
	);
	let signer = match hello::open_or_create(KEY_NAME) {
		Ok(signer) => signer,
		Err(error) => return error_exit(Error::Signer(error)),
	};
	match pass_env_hello::wrap(&signer, KEY_NAME, &secret) {
		Ok(blob) => write_stdout(&blob),
		Err(error) => error_exit(error),
	}
}

#[cfg(not(windows))]
fn unwrap(_from: &str) -> ExitCode {
	fail(UNAVAILABLE, "pass-env-hello only runs on Windows")
}

#[cfg(windows)]
fn unwrap(from: &str) -> ExitCode {
	if let Some(code) = refuse_terminal_stdout() {
		return code;
	}
	let Ok(blob) = read_stdin(MAX_BLOB) else {
		return error_exit(Error::Malformed("too long"));
	};
	// Parse before any prompt: a bad blob never shows a Hello dialog.
	let key_name = match pass_env_hello::parse(&blob) {
		Ok(parsed) => parsed.key_name.to_owned(),
		Err(error) => return error_exit(error),
	};
	notice(from, "unlock GPG for pass-env");
	let signer = match hello::open(&key_name) {
		Ok(signer) => signer,
		Err(error) => return error_exit(Error::Signer(error)),
	};
	match pass_env_hello::unwrap(&signer, &blob) {
		Ok(secret) => write_stdout(&secret),
		Err(error) => error_exit(error),
	}
}

#[cfg(not(windows))]
fn forget() -> ExitCode {
	fail(UNAVAILABLE, "pass-env-hello only runs on Windows")
}

#[cfg(windows)]
fn forget() -> ExitCode {
	match hello::delete(KEY_NAME) {
		Ok(()) => {
			eprintln!("pass-env-hello: deleted the Windows Hello key {KEY_NAME}");
			ExitCode::from(OK)
		}
		Err(error) => error_exit(Error::Signer(error)),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn notice_text_is_sanitized() {
		assert_eq!(sanitize("Ubuntu: /home/me\u{1b}[2J\nproj"), "Ubuntu: /home/me[2Jproj");
		assert_eq!(sanitize(""), "an unknown caller");
		assert_eq!(sanitize(&"a".repeat(500)).len(), 200);
	}

	#[test]
	fn from_flag_is_strict() {
		assert_eq!(from_argument(&[]), Some("an unknown caller".into()));
		assert_eq!(from_argument(&["--from".into(), "x".into()]), Some("x".into()));
		assert_eq!(from_argument(&["--from".into()]), None);
		assert_eq!(from_argument(&["x".into(), "y".into()]), None);
	}
}
