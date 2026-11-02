//! Windows Hello through KeyCredentialManager. Windows only.
//!
//! The 25H2 create workaround (probe with OpenAsync first) and the focus
//! workaround (bring "Credential Dialog Xaml Host" to the front) come from
//! github.com/312-dev/wsl-hello-sudo (MIT, Copyright 2017 Takaya Saeki).

use std::sync::mpsc;
use std::time::Duration;

use pass_env_hello::{Signer, SignerError};
use windows::core::{w, Interface, HSTRING, PCWSTR};
use windows::Security::Credentials::{
	KeyCredential, KeyCredentialAttestationStatus, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;
use windows::Win32::Security::Cryptography::{
	NCryptFreeObject, NCryptOpenStorageProvider, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_HANDLE, NCRYPT_PROV_HANDLE,
};
use windows::Win32::System::WinRT::IBufferByteAccess;
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};
use zeroize::{Zeroize, Zeroizing};

pub struct Status {
	pub hello: &'static str,
	pub tpm: &'static str,
	pub key: &'static str,
	pub attestation: &'static str,
}

impl Status {
	pub fn usable(&self) -> bool {
		self.hello == "available" && self.tpm == "present" && self.attestation != "software"
	}
}

fn supported() -> bool {
	KeyCredentialManager::IsSupportedAsync().and_then(|op| op.join()).unwrap_or(false)
}

/// True when the TPM's platform crypto provider opens.
fn tpm_present() -> bool {
	let mut provider = NCRYPT_PROV_HANDLE::default();
	// SAFETY: provider is a valid out pointer; the handle is freed below.
	unsafe {
		if NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0).is_err() {
			return false;
		}
		let _ = NCryptFreeObject(NCRYPT_HANDLE(provider.0));
	}
	true
}

fn status_error(status: KeyCredentialStatus) -> SignerError {
	match status {
		KeyCredentialStatus::NotFound => SignerError::Unavailable,
		KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => SignerError::Cancelled,
		KeyCredentialStatus::SecurityDeviceLocked => SignerError::Locked,
		_ => SignerError::Other,
	}
}

fn other(_: windows::core::Error) -> SignerError {
	SignerError::Other
}

/// "tpm", "software", "unavailable" (temporary or unknown failure).
fn attestation(key: &KeyCredential) -> &'static str {
	match key
		.GetAttestationAsync()
		.and_then(|op| op.join())
		.and_then(|result| result.Status())
	{
		Ok(KeyCredentialAttestationStatus::Success) => "tpm",
		Ok(KeyCredentialAttestationStatus::NotSupported) => "software",
		_ => "unavailable",
	}
}

fn open_existing(name: &str) -> Result<Option<KeyCredential>, SignerError> {
	let result = KeyCredentialManager::OpenAsync(&HSTRING::from(name))
		.and_then(|op| op.join())
		.map_err(other)?;
	match result.Status().map_err(other)? {
		KeyCredentialStatus::Success => Ok(Some(result.Credential().map_err(other)?)),
		KeyCredentialStatus::NotFound => Ok(None),
		status => Err(status_error(status)),
	}
}

pub fn status(name: &str) -> Status {
	let hello = if supported() { "available" } else { "unsupported" };
	let tpm = if tpm_present() { "present" } else { "absent" };
	let (key, attestation) = if hello != "available" {
		("unknown", "unknown")
	} else {
		match open_existing(name) {
			Ok(Some(key)) => ("present", attestation(&key)),
			Ok(None) => ("absent", "n/a"),
			Err(_) => ("error", "unknown"),
		}
	};
	Status {
		hello,
		tpm,
		key,
		attestation,
	}
}

pub struct HelloSigner {
	key: KeyCredential,
}

/// Refuses keys that are not backed by a TPM: no platform provider, or an
/// attestation answer of NotSupported (a software key).
fn checked(key: KeyCredential) -> Result<HelloSigner, SignerError> {
	if !tpm_present() || attestation(&key) == "software" {
		return Err(SignerError::Unavailable);
	}
	Ok(HelloSigner { key })
}

fn require_hello() -> Result<(), SignerError> {
	if supported() {
		Ok(())
	} else {
		Err(SignerError::Unavailable)
	}
}

pub fn open(name: &str) -> Result<HelloSigner, SignerError> {
	require_hello()?;
	checked(open_existing(name)?.ok_or(SignerError::Unavailable)?)
}

pub fn open_or_create(name: &str) -> Result<HelloSigner, SignerError> {
	require_hello()?;
	if !tpm_present() {
		return Err(SignerError::Unavailable);
	}
	// Windows 11 25H2 throws NCrypt 0x80098044 from RequestCreateAsync(FailIfExists)
	// even for new names, so probe first and only create when really absent.
	if let Some(key) = open_existing(name)? {
		return checked(key);
	}
	let focus = focus_hello_window();
	let created = KeyCredentialManager::RequestCreateAsync(&HSTRING::from(name), KeyCredentialCreationOption::ReplaceExisting)
		.and_then(|op| op.join());
	drop(focus);
	let created = created.map_err(other)?;
	match created.Status().map_err(other)? {
		KeyCredentialStatus::Success => checked(created.Credential().map_err(other)?),
		status => Err(status_error(status)),
	}
}

pub fn delete(name: &str) -> Result<(), SignerError> {
	require_hello()?;
	if open_existing(name)?.is_none() {
		return Ok(());
	}
	KeyCredentialManager::DeleteAsync(&HSTRING::from(name))
		.and_then(|op| op.join())
		.map_err(other)
}

/// Copies a WinRT buffer into a wiped-on-drop Vec, then zeroes the buffer.
fn take_buffer(buffer: &IBuffer) -> Result<Zeroizing<Vec<u8>>, SignerError> {
	let length = buffer.Length().map_err(other)? as usize;
	let access: IBufferByteAccess = buffer.cast().map_err(other)?;
	// SAFETY: Buffer() points at `length` bytes owned by `buffer`, which
	// outlives this function; nothing else touches it meanwhile.
	unsafe {
		let data = access.Buffer().map_err(other)?;
		if data.is_null() {
			return Err(SignerError::Other);
		}
		let bytes = std::slice::from_raw_parts_mut(data, length);
		let copy = Zeroizing::new(bytes.to_vec());
		bytes.zeroize();
		Ok(copy)
	}
}

impl Signer for HelloSigner {
	fn sign(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignerError> {
		let input = CryptographicBuffer::CreateFromByteArray(data).map_err(other)?;
		let focus = focus_hello_window();
		let result = self.key.RequestSignAsync(&input).and_then(|op| op.join());
		drop(focus);
		let result = result.map_err(other)?;
		match result.Status().map_err(other)? {
			KeyCredentialStatus::Success => take_buffer(&result.Result().map_err(other)?),
			status => Err(status_error(status)),
		}
	}
}

/// Hello's dialog can open behind the terminal. Until the returned sender is
/// dropped, look for it and bring it to the front once.
fn focus_hello_window() -> mpsc::SyncSender<()> {
	let (stop, stopped) = mpsc::sync_channel::<()>(0);
	std::thread::spawn(move || loop {
		// SAFETY: constant, NUL-terminated class name; null window name.
		if let Ok(window) = unsafe { FindWindowW(w!("Credential Dialog Xaml Host"), PCWSTR::null()) } {
			if !window.is_invalid() {
				// SAFETY: window is a handle FindWindowW just returned.
				let _ = unsafe { SetForegroundWindow(window) };
				return;
			}
		}
		match stopped.recv_timeout(Duration::from_millis(200)) {
			Err(mpsc::RecvTimeoutError::Timeout) => continue,
			_ => return,
		}
	});
	stop
}
