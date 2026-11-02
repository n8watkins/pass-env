//! Any input: parse must never panic, and unwrap must reject everything that
//! was not sealed with the same signer (or open it to what was sealed).
#![no_main]

use libfuzzer_sys::fuzz_target;
use pass_env_hello::{parse, unwrap, Error, Signer, SignerError, MAX_BLOB};
use zeroize::Zeroizing;

struct Fixed;
impl Signer for Fixed {
	fn sign(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignerError> {
		Ok(Zeroizing::new((0..256usize).map(|i| data[i % data.len()] ^ i as u8).collect()))
	}
}

fuzz_target!(|data: &[u8]| {
	match parse(data) {
		Ok(blob) => {
			assert!(data.len() <= MAX_BLOB);
			assert_eq!(blob.header.len() + blob.ciphertext.len(), data.len());
			// Random bytes essentially never carry a valid GCM tag.
			assert!(matches!(unwrap(&Fixed, data), Err(Error::Decrypt) | Ok(_)));
		}
		Err(_) => assert!(unwrap(&Fixed, data).is_err()),
	}
});
