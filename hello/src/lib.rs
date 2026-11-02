//! Blob format and crypto for pass-env-hello.
//!
//! Pure Rust and platform independent, so it is unit tested and fuzzed on
//! Linux as well as Windows. The Windows Hello key only appears behind the
//! `Signer` trait. See docs/windows-hello.md for the design and threat model.

#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 4] = b"PEH1";
pub const FORMAT_VERSION: u8 = 1;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const MAX_KEY_NAME: usize = 64;
pub const MAX_SECRET: usize = 4096;
/// The largest well-formed blob; readers never need more than this.
pub const MAX_BLOB: usize = MAGIC.len() + 2 + MAX_KEY_NAME + SALT_LEN + NONCE_LEN + MAX_SECRET + TAG_LEN;
pub const HKDF_INFO: &[u8] = b"pass-env-hello v1 aes-256-gcm";
/// Prefix of what Windows Hello signs, so a signature made for pass-env is
/// never the same as one another program asks the same key for.
pub const SIGN_CONTEXT: &[u8] = b"pass-env-hello v1 unwrap key\0";
/// Smallest RSA-2048 signature we accept as key material.
const MIN_SIGNATURE: usize = 256;

/// Why a Windows Hello signature could not be made. Maps to exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerError {
	Unavailable,
	Cancelled,
	Locked,
	Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
	/// The blob is not well formed. The message never contains blob bytes.
	Malformed(&'static str),
	/// The tag did not verify: tampered, or another key or salt.
	Decrypt,
	/// The secret to wrap is empty, too long, or contains NUL.
	BadSecret,
	/// The signer gave a different result the second time.
	NotDeterministic,
	Random,
	Signer(SignerError),
}

impl From<SignerError> for Error {
	fn from(error: SignerError) -> Self {
		Error::Signer(error)
	}
}

/// Signs data after a user gesture. Windows Hello in the binary, fakes in tests.
pub trait Signer {
	fn sign(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignerError>;
}

/// A parsed blob. Borrowed from the input; holds no secret.
#[derive(Debug, PartialEq, Eq)]
pub struct Blob<'a> {
	pub key_name: &'a str,
	pub salt: &'a [u8],
	pub nonce: &'a [u8],
	/// Everything before the ciphertext: the GCM associated data.
	pub header: &'a [u8],
	pub ciphertext: &'a [u8],
}

pub fn valid_key_name(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= MAX_KEY_NAME
		&& name
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Strict parser: exact magic and version, bounded lengths, no trailing bytes.
pub fn parse(bytes: &[u8]) -> Result<Blob<'_>, Error> {
	if bytes.len() > MAX_BLOB {
		return Err(Error::Malformed("too long"));
	}
	let mut rest = bytes;
	let mut take = |count: usize, what: &'static str| -> Result<&[u8], Error> {
		if rest.len() < count {
			return Err(Error::Malformed(what));
		}
		let (head, tail) = rest.split_at(count);
		rest = tail;
		Ok(head)
	};
	if take(MAGIC.len(), "magic")? != MAGIC {
		return Err(Error::Malformed("magic"));
	}
	if take(1, "version")?[0] != FORMAT_VERSION {
		return Err(Error::Malformed("version"));
	}
	let name_len = take(1, "key name length")?[0] as usize;
	if name_len == 0 || name_len > MAX_KEY_NAME {
		return Err(Error::Malformed("key name length"));
	}
	let key_name = core::str::from_utf8(take(name_len, "key name")?).map_err(|_| Error::Malformed("key name"))?;
	if !valid_key_name(key_name) {
		return Err(Error::Malformed("key name"));
	}
	let salt = take(SALT_LEN, "salt")?;
	let nonce = take(NONCE_LEN, "nonce")?;
	let header_len = bytes.len() - rest.len();
	let ciphertext = rest;
	if ciphertext.len() < TAG_LEN + 1 || ciphertext.len() > MAX_SECRET + TAG_LEN {
		return Err(Error::Malformed("ciphertext length"));
	}
	Ok(Blob {
		key_name,
		salt,
		nonce,
		header: &bytes[..header_len],
		ciphertext,
	})
}

fn header(key_name: &str, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
	let mut out = Vec::with_capacity(MAGIC.len() + 2 + key_name.len() + SALT_LEN + NONCE_LEN);
	out.extend_from_slice(MAGIC);
	out.push(FORMAT_VERSION);
	out.push(key_name.len() as u8);
	out.extend_from_slice(key_name.as_bytes());
	out.extend_from_slice(salt);
	out.extend_from_slice(nonce);
	out
}

/// What Windows Hello signs: context, key name, NUL, salt.
pub fn signed_message(key_name: &str, salt: &[u8]) -> Vec<u8> {
	let mut message = Vec::with_capacity(SIGN_CONTEXT.len() + key_name.len() + 1 + salt.len());
	message.extend_from_slice(SIGN_CONTEXT);
	message.extend_from_slice(key_name.as_bytes());
	message.push(0);
	message.extend_from_slice(salt);
	message
}

fn cipher(signer: &dyn Signer, key_name: &str, salt: &[u8]) -> Result<Aes256Gcm, Error> {
	let signature = signer.sign(&signed_message(key_name, salt))?;
	if signature.len() < MIN_SIGNATURE {
		return Err(Error::Signer(SignerError::Other));
	}
	let mut key = Zeroizing::new([0u8; 32]);
	Hkdf::<Sha256>::new(Some(salt), &signature)
		.expand(HKDF_INFO, key.as_mut())
		.map_err(|_| Error::Signer(SignerError::Other))?;
	// Aes256Gcm zeroizes its round keys on drop (the "zeroize" feature).
	Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| Error::Signer(SignerError::Other))
}

/// Encrypts with a given salt and nonce. Callers use `wrap`; tests use this
/// for known answers.
pub fn seal(signer: &dyn Signer, key_name: &str, secret: &[u8], salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>, Error> {
	if !valid_key_name(key_name) {
		return Err(Error::Malformed("key name"));
	}
	if secret.is_empty() || secret.len() > MAX_SECRET || secret.contains(&0) {
		return Err(Error::BadSecret);
	}
	let aad = header(key_name, salt, nonce);
	let ciphertext = cipher(signer, key_name, salt)?
		.encrypt(Nonce::from_slice(nonce), Payload { msg: secret, aad: &aad })
		.map_err(|_| Error::Decrypt)?;
	let mut blob = aad;
	blob.extend_from_slice(&ciphertext);
	Ok(blob)
}

/// Opens a blob. The returned secret is wiped when dropped.
pub fn unwrap(signer: &dyn Signer, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
	let blob = parse(bytes)?;
	let cipher = cipher(signer, blob.key_name, blob.salt)?;
	// decrypt allocates the plaintext once; it goes straight into Zeroizing.
	cipher
		.decrypt(
			Nonce::from_slice(blob.nonce),
			Payload {
				msg: blob.ciphertext,
				aad: blob.header,
			},
		)
		.map(Zeroizing::new)
		.map_err(|_| Error::Decrypt)
}

/// Constant-time equality for secrets of public length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
	core::hint::black_box(diff) == 0
}

/// Wraps a secret with fresh random salt and nonce, then opens the result
/// again and compares, so a blob that cannot be opened is never returned.
pub fn wrap(signer: &dyn Signer, key_name: &str, secret: &[u8]) -> Result<Vec<u8>, Error> {
	let mut salt = [0u8; SALT_LEN];
	let mut nonce = [0u8; NONCE_LEN];
	getrandom::getrandom(&mut salt).map_err(|_| Error::Random)?;
	getrandom::getrandom(&mut nonce).map_err(|_| Error::Random)?;
	let blob = seal(signer, key_name, secret, &salt, &nonce)?;
	let check = match unwrap(signer, &blob) {
		Ok(check) => check,
		Err(Error::Decrypt) => return Err(Error::NotDeterministic),
		Err(error) => return Err(error),
	};
	if !ct_eq(&check, secret) {
		return Err(Error::NotDeterministic);
	}
	Ok(blob)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::cell::Cell;

	/// Deterministic fake: HMAC-like stand-in, 256 bytes derived from a seed.
	struct FakeSigner {
		seed: u8,
		calls: Cell<u32>,
	}

	impl FakeSigner {
		fn new(seed: u8) -> Self {
			FakeSigner { seed, calls: Cell::new(0) }
		}
	}

	impl Signer for FakeSigner {
		fn sign(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignerError> {
			self.calls.set(self.calls.get() + 1);
			let mut out = Vec::with_capacity(256);
			for index in 0..256usize {
				out.push(self.seed ^ data[index % data.len()] ^ (index as u8));
			}
			Ok(Zeroizing::new(out))
		}
	}

	/// Different output on every call, like a randomized signature scheme.
	struct RandomizedSigner(Cell<u8>);
	impl Signer for RandomizedSigner {
		fn sign(&self, _data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignerError> {
			self.0.set(self.0.get().wrapping_add(1));
			Ok(Zeroizing::new(vec![self.0.get(); 256]))
		}
	}

	struct FailingSigner(SignerError);
	impl Signer for FailingSigner {
		fn sign(&self, _data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignerError> {
			Err(self.0)
		}
	}

	struct ShortSigner;
	impl Signer for ShortSigner {
		fn sign(&self, _data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignerError> {
			Ok(Zeroizing::new(vec![7; 32]))
		}
	}

	const SECRET: &[u8] = b"correct horse battery staple";

	#[test]
	fn round_trip_and_layout() {
		let signer = FakeSigner::new(1);
		let blob = wrap(&signer, "pass-env", SECRET).unwrap();
		assert_eq!(signer.calls.get(), 2, "wrap signs once to seal and once to check");
		assert_eq!(&blob[..4], MAGIC);
		assert_eq!(blob[4], FORMAT_VERSION);
		assert_eq!(blob[5] as usize, "pass-env".len());
		assert_eq!(blob.len(), 4 + 2 + 8 + SALT_LEN + NONCE_LEN + SECRET.len() + TAG_LEN);
		let parsed = parse(&blob).unwrap();
		assert_eq!(parsed.key_name, "pass-env");
		assert_eq!(&*unwrap(&signer, &blob).unwrap(), SECRET);
		assert!(
			!blob.windows(SECRET.len()).any(|window| window == SECRET),
			"plaintext must not appear in the blob"
		);
	}

	#[test]
	fn fresh_salt_and_nonce_every_time() {
		let signer = FakeSigner::new(1);
		let a = wrap(&signer, "pass-env", SECRET).unwrap();
		let b = wrap(&signer, "pass-env", SECRET).unwrap();
		assert_ne!(parse(&a).unwrap().salt, parse(&b).unwrap().salt);
		assert_ne!(parse(&a).unwrap().nonce, parse(&b).unwrap().nonce);
	}

	#[test]
	fn known_answer_is_stable() {
		// Pins the format: HKDF info, AAD layout and cipher must not drift.
		let blob = seal(&FakeSigner::new(9), "k", b"x", &[1; SALT_LEN], &[2; NONCE_LEN]).unwrap();
		let hex: String = blob.iter().map(|byte| format!("{byte:02x}")).collect();
		assert_eq!(
			hex,
			concat!(
				"50454831",
				"01",
				"01",
				"6b",
				"0101010101010101010101010101010101010101010101010101010101010101",
				"020202020202020202020202",
				"e0",
				"69e29a0ba446d60fa899ddee14a5054a",
			)
		);
		assert_eq!(&*unwrap(&FakeSigner::new(9), &blob).unwrap(), b"x");
	}

	#[test]
	fn every_tampered_byte_is_rejected() {
		let signer = FakeSigner::new(3);
		let blob = wrap(&signer, "pass-env", SECRET).unwrap();
		for index in 0..blob.len() {
			let mut bad = blob.clone();
			bad[index] ^= 0x01;
			assert!(unwrap(&signer, &bad).is_err(), "flipping byte {index} must fail");
		}
	}

	#[test]
	fn swapped_header_fields_are_rejected() {
		let signer = FakeSigner::new(3);
		let a = wrap(&signer, "pass-env", SECRET).unwrap();
		let b = wrap(&signer, "pass-env", SECRET).unwrap();
		let pa = parse(&a).unwrap();
		let pb = parse(&b).unwrap();
		// a's ciphertext with b's nonce, then with b's salt.
		let mut mixed = a.clone();
		let nonce_at = pa.header.len() - NONCE_LEN;
		mixed[nonce_at..pa.header.len()].copy_from_slice(pb.nonce);
		assert_eq!(unwrap(&signer, &mixed), Err(Error::Decrypt));
		let mut mixed = a.clone();
		let salt_at = nonce_at - SALT_LEN;
		mixed[salt_at..nonce_at].copy_from_slice(pb.salt);
		assert_eq!(unwrap(&signer, &mixed), Err(Error::Decrypt));
		// Same secret and key, different key name in the header.
		let renamed = seal(&signer, "pass-envX", SECRET, &[5; SALT_LEN], &[6; NONCE_LEN]).unwrap();
		let original = seal(&signer, "pass-env1", SECRET, &[5; SALT_LEN], &[6; NONCE_LEN]).unwrap();
		let mut swapped = original.clone();
		swapped[6..15].copy_from_slice(b"pass-envX");
		assert_ne!(swapped, renamed);
		assert_eq!(unwrap(&signer, &swapped), Err(Error::Decrypt));
	}

	#[test]
	fn wrong_key_is_rejected() {
		let blob = wrap(&FakeSigner::new(1), "pass-env", SECRET).unwrap();
		assert_eq!(unwrap(&FakeSigner::new(2), &blob), Err(Error::Decrypt));
	}

	#[test]
	fn non_deterministic_signer_is_caught_at_wrap() {
		assert_eq!(
			wrap(&RandomizedSigner(Cell::new(0)), "pass-env", SECRET),
			Err(Error::NotDeterministic)
		);
	}

	#[test]
	fn signer_errors_pass_through() {
		for error in [
			SignerError::Cancelled,
			SignerError::Unavailable,
			SignerError::Locked,
			SignerError::Other,
		] {
			assert_eq!(wrap(&FailingSigner(error), "pass-env", SECRET), Err(Error::Signer(error)));
		}
		let blob = wrap(&FakeSigner::new(1), "pass-env", SECRET).unwrap();
		assert_eq!(
			unwrap(&FailingSigner(SignerError::Cancelled), &blob),
			Err(Error::Signer(SignerError::Cancelled))
		);
		assert_eq!(wrap(&ShortSigner, "pass-env", SECRET), Err(Error::Signer(SignerError::Other)));
	}

	#[test]
	fn secrets_and_names_are_checked() {
		let signer = FakeSigner::new(1);
		assert_eq!(wrap(&signer, "pass-env", b""), Err(Error::BadSecret));
		assert_eq!(wrap(&signer, "pass-env", b"a\0b"), Err(Error::BadSecret));
		assert_eq!(wrap(&signer, "pass-env", &vec![b'a'; MAX_SECRET + 1]), Err(Error::BadSecret));
		assert!(wrap(&signer, "pass-env", &vec![b'a'; MAX_SECRET]).is_ok());
		for name in ["", "a/b", "a b", "ä", &"a".repeat(MAX_KEY_NAME + 1)] {
			assert!(wrap(&signer, name, SECRET).is_err(), "{name:?}");
		}
		assert_eq!(
			signer.calls.get(),
			2,
			"bad input never reaches the signer except the one valid wrap"
		);
	}

	#[test]
	fn parser_is_strict() {
		let blob = wrap(&FakeSigner::new(1), "pass-env", SECRET).unwrap();
		let mut trailing = blob.clone();
		trailing.push(0);
		assert!(unwrap(&FakeSigner::new(1), &trailing).is_err());
		for length in 0..blob.len() {
			let result = parse(&blob[..length]);
			// Truncation inside the ciphertext still parses but fails the tag.
			if result.is_ok() {
				assert_eq!(unwrap(&FakeSigner::new(1), &blob[..length]), Err(Error::Decrypt));
			}
		}
		let mut version = blob.clone();
		version[4] = 2;
		assert_eq!(parse(&version), Err(Error::Malformed("version")));
		let mut name_len = blob.clone();
		name_len[5] = 0;
		assert_eq!(parse(&name_len), Err(Error::Malformed("key name length")));
		assert_eq!(parse(&vec![0; MAX_BLOB + 1]), Err(Error::Malformed("too long")));
		assert_eq!(parse(b"PEH1"), Err(Error::Malformed("version")));
	}

	#[test]
	fn parse_never_calls_the_signer_on_garbage() {
		let signer = FakeSigner::new(1);
		for garbage in [&b""[..], b"hello", &[0xff; 300]] {
			assert!(matches!(unwrap(&signer, garbage), Err(Error::Malformed(_))));
		}
		assert_eq!(signer.calls.get(), 0);
	}

	/// Records what it was asked to sign.
	struct Recording(std::cell::RefCell<Vec<Vec<u8>>>);
	impl Signer for Recording {
		fn sign(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignerError> {
			self.0.borrow_mut().push(data.to_vec());
			Ok(Zeroizing::new(vec![3; 256]))
		}
	}

	#[test]
	fn hello_signs_a_domain_separated_message_not_the_bare_salt() {
		let signer = Recording(Default::default());
		let blob = seal(&signer, "k1", b"x", &[4; SALT_LEN], &[5; NONCE_LEN]).unwrap();
		let signed = signer.0.borrow()[0].clone();
		assert_eq!(signed, [SIGN_CONTEXT, b"k1\0", &[4; SALT_LEN]].concat());
		assert!(unwrap(&signer, &blob).is_ok());
		assert_eq!(signer.0.borrow()[1], signed);
	}

	#[test]
	fn ct_eq_works() {
		assert!(ct_eq(b"abc", b"abc"));
		assert!(!ct_eq(b"abc", b"abd"));
		assert!(!ct_eq(b"abc", b"ab"));
	}
}
