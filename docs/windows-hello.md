# Windows Hello unlock (experimental)

Status: **experimental and opt-in**, Windows 11 + WSL only.
Nothing changes for anyone who does not run `pass-env hello install` and `pass-env hello enrol`.
The typed GPG passphrase always keeps working, so nobody can be locked out by this feature.

This is the design record for the feature: what it does, how it is built, what it protects against and what it does not.
The owner's hands-on checklist is [windows-hello-manual-test.md](windows-hello-manual-test.md).

## Goal

Unlock GPG for pass-env with a fingerprint, face or Windows Hello PIN instead of typing the GPG passphrase every day, without weakening what pass-env already guarantees:

- An agent without a terminal still cannot start an unlock.
- No secret is ever printed, logged, put in argv or the environment, or written to disk in plaintext.
- GPG stays the only thing that holds the store's key; Hello only replaces the typing.

## Owner decisions (2026-11-02)

- Explicit command only: `pass-env unlock --hello`.
  The helper is never installed as gpg-agent's `pinentry-program`, so `pass show` or `gpg` run by an agent can never raise a Hello prompt.
  `doctor` warns if it finds the helper configured that way.
- The TTY requirement of `unlock` stays, for `--hello` too.
- The owner keeps a memorable GPG passphrase, saved offline, as the always-available typed fallback.
- `pass-env hello enrol` requires an existing, working GPG key and passphrase: it checks pass, GPG and the store first, and proves the passphrase works before wrapping it.
- The gpg-agent cache window stays 24 hours for now (`default-cache-ttl 86400`, `max-cache-ttl 86400`); `doctor` only warns above one day.
- Shipped in the public repository, labelled experimental, until the owner completes the manual test.
- Security must not rely on secrecy: assume attackers read this document and the source, and that the release channel can be attacked.

## How it works

```
WSL (Linux)                                    Windows
-----------                                    -------
pass-env unlock --hello   (needs a TTY)
  |  checks: WSL, interop, not SSH, helper hash
  |  stdin: hello.blob  ---------------------> pass-env-hello.exe unwrap
  |                                              KeyCredentialManager.OpenAsync("pass-env")
  |                                              RequestSignAsync(salt)  <-- Hello prompt (gesture)
  |                                              HKDF-SHA256(signature) -> AES-256-GCM key
  |                                              decrypt blob, zeroize
  |  stdout: passphrase  <--------------------  (pipe, never disk)
  v
gpg --batch --pinentry-mode loopback --passphrase-fd 3 --decrypt <canary entry>
  -> gpg-agent caches the passphrase under its normal TTL
  -> pass-env run / pipe / copy work as after a typed unlock
```

### The Windows helper: `pass-env-hello.exe`

A small Rust program (`hello/` in this repository) using the official `windows` crate.
It is stateless: it reads its input on stdin, writes its result on stdout, prints short fixed messages on stderr, and never writes a file.

| Subcommand | Input | Output | Prompts? |
| --- | --- | --- | --- |
| `version` | none | `pass-env-hello <version>` | No |
| `check` | none | one JSON line: version, protocol, Hello availability, TPM, key presence | No |
| `enrol --from <context>` | the passphrase on stdin | the blob on stdout | Yes (creates the key if missing, then signs) |
| `unwrap --from <context>` | the blob on stdin | the passphrase on stdout | Yes |
| `forget` | none | none | No (deletes the Hello key) |

`--from` is the WSL distro and folder pass-env runs in; the helper prints it on stderr just before the Hello prompt, with a reminder to approve only a prompt you just started.

Exit codes are the protocol between pass-env and the helper:

| Code | Meaning | pass-env does |
| --- | --- | --- |
| 0 | Success | Continues |
| 2 | Usage error | Typed fallback |
| 3 | Hello unavailable: not supported, not set up, no TPM-backed key, or the key is missing | Typed fallback, suggests `hello status` |
| 4 | The user cancelled the prompt | Typed fallback |
| 5 | The security device or session is locked | Typed fallback |
| 6 | The blob is malformed, tampered with, or belongs to another key | Typed fallback, suggests `hello enrol` |
| 7 | Any other error | Typed fallback |

### Crypto

- **Key**: a Windows Hello key created with `KeyCredentialManager.RequestCreateAsync("pass-env")`.
  It is an RSA-2048 key held by the Microsoft Passport key storage provider; on a machine with a TPM it lives in the TPM and cannot be exported.
  Every use needs a live Hello gesture (face, fingerprint or PIN).
- **Windows 11 25H2**: `RequestCreateAsync(FailIfExists)` throws NCrypt `0x80098044` even for a new name, so the helper probes with `OpenAsync` first and only creates (with `ReplaceExisting`) when the key is really absent.
  This workaround and the focus workaround below come from [312-dev/wsl-hello-sudo](https://github.com/312-dev/wsl-hello-sudo) (MIT).
- **Focus**: Hello's dialog can open behind the terminal; a short-lived thread finds the `Credential Dialog Xaml Host` window and brings it to the front.
- **TPM check**: before creating or using the key the helper checks `KeyCredentialManager.IsSupportedAsync()`, that the TPM platform crypto provider opens, and asks the key for a TPM attestation (`GetAttestationAsync`).
  An attestation answer of `NotSupported` means a software key, and the helper refuses it (exit 3).
  A temporary attestation failure (for example no network for the attestation certificate) is reported by `check` and `hello status` but does not block use while the TPM provider is present.
- **Wrapping**: enrol picks a random 32-byte salt and asks Hello to sign it.
  `RequestSignAsync` uses RSA PKCS#1 v1.5 with SHA-256, which is deterministic: the same key signing the same salt gives the same signature every time.
  `HKDF-SHA256(ikm = signature, salt = salt, info = "pass-env-hello v1 aes-256-gcm")` gives a 256-bit key, and AES-256-GCM with a random 96-bit nonce encrypts the passphrase.
  Enrol then runs a full unwrap (a second gesture) and compares the result with the passphrase before saving anything, so a non-deterministic signer can never leave a blob that cannot be opened.
- **Blob**, binary, at `${XDG_CONFIG_HOME:-~/.config}/pass-env/hello.blob`, mode 600, folder mode 700:

  | Bytes | Field |
  | --- | --- |
  | 4 | Magic `PEH1` |
  | 1 | Format version, `1` |
  | 1 | Key name length `n`, 1 to 64 |
  | n | Key name, ASCII `[A-Za-z0-9._-]` |
  | 32 | Salt |
  | 12 | Nonce |
  | 17 to 4112 | Ciphertext and 16-byte GCM tag (passphrase of 1 to 4096 bytes) |

  Everything before the ciphertext is the GCM associated data, so changing the version, key name, salt or nonce makes decryption fail.
  The parser is strict: exact magic and version, length limits on every field, no trailing bytes, and it rejects anything else before any Hello call.
  The blob is ciphertext only; on its own it is useless without the TPM key and a gesture.

### pass-env commands

| Command | What it does |
| --- | --- |
| `pass-env hello install [<file>] [--yes]` | Copies `pass-env-hello.exe` to `%LOCALAPPDATA%\pass-env\` and records its SHA-256 in `~/.config/pass-env/hello-helper.json`. With no file it downloads the helper of the same release as this pass-env, checks it against the hash pinned in this pass-env and, when `gh` is installed, verifies its GitHub build provenance with `gh attestation verify`. Replacing a helper with a different hash shows both hashes and asks first (`--yes` skips the question). Never runs on its own: there is no auto-update. |
| `pass-env hello enrol` | Needs a TTY. Checks pass, GPG, the store and the private key (pointing at `pass-env doctor` and the setup docs if anything is missing), asks for the GPG passphrase through pinentry, proves it decrypts a store entry, then has the helper wrap it and writes the blob. |
| `pass-env hello status` | Shows the helper's path, version and hash check, what Windows reports about Hello and the TPM (no prompt), and whether the blob is present and well-formed. |
| `pass-env hello forget` | Deletes the blob and asks the helper to delete the Hello key. The typed passphrase is unaffected. |
| `pass-env unlock --hello [entry]` | Needs a TTY. If GPG is already unlocked, says so and stops. Otherwise runs the helper, feeds the passphrase to `gpg --pinentry-mode loopback --passphrase-fd 3` decrypting the canary entry (the same entry plain `unlock` uses), and forgets it. On any failure it explains why and falls back to the typed unlock. |

`PASS_ENV_HELLO_HELPER=<path>` points pass-env at another helper; tests use it with a fake helper, and it skips the WSL and hash checks, so only set it yourself.

### Canary entry

The decrypt that warms the cache uses the same entry plain `unlock` uses: the one given on the command line, else the first mapping in `./.env.pass`, else the first entry in the store.
Its plaintext goes to `/dev/null`.

### Passphrase handling in pass-env

- Read from the helper's stdout into a `Uint8Array`, never converted to a string, and written once to gpg on file descriptor 3, then overwritten with zeros.
- The enrol prompt uses pinentry (the `pinentry-program` from `gpg-agent.conf`, else `pinentry-curses`) over its Assuan protocol, so it looks and behaves like GPG's own prompt; the reply is decoded straight into a byte buffer.
- Before the Hello and enrol paths pass-env marks itself non-dumpable (`prctl(PR_SET_DUMPABLE, 0)` through `bun:ffi`, best effort), which also stops other processes of the same user from attaching a debugger to it.
- The JavaScript runtime may still keep copies it does not expose (for example inside stream buffers); this is a limit of the runtime, noted under "Memory disclosure" below.

## Threat model

Assumptions: the attacker can read this document and all source code; the attacker may control a dependency, a GitHub Actions runner image or the release download; the owner's Windows account and TPM are not already compromised at the kernel level.
The asset is the GPG passphrase (permanent) and, through it, every secret in the store.
The existing baseline: while gpg-agent's cache is warm, anything running as the user can decrypt (see the README); this feature does not change that window.

| Threat | Mitigation | What it covers | What it cannot cover |
| --- | --- | --- | --- |
| Same-user WSL process (for example a prompt-injected agent) reads files | The blob is ciphertext; the key never leaves the TPM; the helper needs a live gesture | Reading `hello.blob`, the config or the helper gives nothing | A process that can replace `~/.local/bin/pass-env`, the helper, the config, or your shell can wait for you to unlock and capture the passphrase, typed or Hello. Same-user code execution is out of scope for any local secret tool; run untrusted agents as another user or in a container |
| Same-user WSL process starts an unlock | `unlock --hello` and `hello enrol` refuse without a TTY; the helper is never a pinentry | An agent's `pass-env unlock --hello`, `pass show` and `gpg` cannot raise a prompt | An agent can run `pass-env-hello.exe unwrap` directly: see "prompt phishing" |
| Prompt phishing: something else triggers a Hello prompt and you approve it out of habit | The helper prints who asked (distro and folder) in the terminal that started it; pass-env tells you a prompt is coming; docs say to approve only prompts you just started | Makes an unexpected prompt noticeable | Windows' Hello dialog cannot show a custom message, and the caller controls the `--from` text. If you approve a prompt you did not start, the caller gets the passphrase. Cancel any unexpected prompt and run `pass-env hello status` |
| Same-user Windows process | None beyond Windows itself | Nothing specific | It can read `\\wsl.localhost\...`, replace `%LOCALAPPDATA%\pass-env\pass-env-hello.exe` between the hash check and the start, and read the helper's memory. Out of scope, as for every user-level tool |
| Tampered helper binary on disk | pass-env hashes the file before every run and compares it with the hash pinned in the pass-env release (or, for the script, the hash recorded by `hello install`); mismatch means no run and a typed fallback | Corruption, a stale or swapped copy, a downgrade, a write by another principal | A same-user attacker who rewrites both the helper and pass-env (or the record). Time-of-check to time-of-use between hashing and starting is narrowed by hashing immediately before the start, not eliminated |
| Malicious or compromised release | Built only by GitHub Actions from a tag on `main`; SHA-256 sums; Sigstore build provenance (`actions/attest-build-provenance`); `hello install` verifies the pinned hash and runs `gh attestation verify` with the workflow identity when `gh` exists; no auto-update | A tampered download, a release asset swapped after publishing, an artifact not built by this repository's workflow | A compromise of the repository itself (a malicious commit merged to `main`) or of GitHub. Branch protection and required reviews are the owner's controls here |
| Compromised dependency | Few dependencies, exact versions, committed `Cargo.lock`, `cargo-deny` (licenses, sources, advisories, bans) and `cargo-audit` in CI, crates.io only | Known advisories, unexpected sources, version drift | A malicious release of a pinned crate that nobody has reported yet. Dependencies are the `windows` crates and RustCrypto (`aes-gcm`, `hkdf`, `sha2`, `zeroize`, `getrandom`) |
| Tampered blob | Strict parser, AES-GCM tag, header bound as associated data | Bit flips, swapped fields, a blob from another key or salt, truncation | Deleting the blob (denial of service only: the typed unlock still works) |
| Replay | A blob only opens with this machine's TPM key and a gesture; re-enrol uses a fresh salt and nonce | An old blob restored by an attacker still needs a gesture and yields only an old passphrase, which gpg rejects if it changed | The signature over a salt is a stable secret: anyone who once read it from the helper's memory can open that blob forever. Re-enrol after any suspected compromise, and change the GPG passphrase |
| Memory disclosure | Rust: `zeroize` on the signature, derived key and plaintext, no copies into `String`, `panic = "abort"`. pass-env: byte buffers wiped after use, non-dumpable process | Leftovers in freed memory and core dumps of pass-env | A live same-user debugger on Windows, pages swapped to disk, and copies inside the JavaScript runtime that cannot be wiped |
| Logs and crash dumps | No secret in argv, env, error messages or stderr; helper messages are fixed strings; pass-env never prints helper stdout; abort on panic with no message containing data | Terminal scrollback, agent transcripts, shell history, CI logs | Windows Error Reporting full dumps if you configured `LocalDumps` yourself |
| Lock-out | The typed passphrase is never removed; every failure falls back to it | Lost TPM, reset Windows Hello, new PC, broken helper | A forgotten typed passphrase: keep it offline, as decided |
| Remote sessions | `unlock --hello` skips Hello when `SSH_CONNECTION` or `SSH_TTY` is set | A prompt appearing on a desktop nobody is at | Other remote tools that do not set these variables |

### Why not the simpler options

- **`UserConsentVerifier` only** shows a Hello prompt and returns "verified", but the passphrase would then sit next to it in a file or DPAPI, and anything running as the user can skip the prompt and read it.
- **DPAPI or Credential Manager** decrypt for any process of the user without a gesture.
- **The helper as gpg-agent's `pinentry-program`** would let any `gpg` call, including an agent's, raise a Hello prompt.

## Fallback and recovery

- Every failure of `unlock --hello` (no WSL interop, SSH, helper missing or hash mismatch, Hello cancelled or unavailable, Windows locked, bad blob, passphrase rejected by gpg) prints one line saying why, then runs the normal typed unlock in the same terminal.
- Changed the GPG passphrase: the stored one is rejected by gpg; run `pass-env hello enrol` again.
- New PC, reset Hello, new TPM or a lost blob: the typed unlock works; enrol again.
- To turn it off: `pass-env hello forget`, and optionally delete `%LOCALAPPDATA%\pass-env`.

## Release and supply chain

- `.github/workflows/release.yml` runs on a `v*` tag, first checking that the tagged commit is on `main`.
- A `windows-latest` job runs `cargo test`, `cargo deny check` and `cargo audit`, builds `pass-env-hello.exe` twice in two folders and requires identical hashes (a reproducibility check), and uploads it with its SHA-256.
- The Linux job pins that hash into `pass-env.ts` (`PINNED_HELPER_SHA256`), checks the pin was applied exactly once, builds the binaries from the pinned file, runs the tests, attaches the pinned `pass-env.ts`, the binaries, `pass-env-hello.exe` and `SHA256SUMS`, and creates build provenance attestations for all of them.
- Third-party actions are pinned to commit SHAs.
- Forks: without a release, nothing about Hello runs; `hello install <file>` with a self-built helper records its hash locally.

### How a user verifies a release

```sh
gh release download v1.2.0 --repo n8watkins/pass-env --pattern 'pass-env-hello.exe' --pattern SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify pass-env-hello.exe --repo n8watkins/pass-env \
  --signer-workflow n8watkins/pass-env/.github/workflows/release.yml --source-ref refs/tags/v1.2.0 --deny-self-hosted-runners
```

`pass-env hello install` does the same checks itself, and `pass-env hello status` shows the hash it expects and the one on disk.

## Testing

- Rust unit tests (`cargo test` in `hello/`, Linux and Windows): blob round trip, every tampered field rejected, wrong key rejected, length limits, trailing bytes, a fake signer trait, and a non-deterministic signer caught by enrol's check.
- A fuzz target for the blob parser (`hello/fuzz`, `cargo fuzz run parse_blob`), run for a short time in CI.
- Bun tests with `PASS_ENV_HELLO_HELPER` pointing at a fake helper: success, cancel, unavailable, locked, corrupt blob, wrong passphrase, already unlocked, no TTY, SSH, hash mismatch, and each falling back to the typed unlock; enrol's prerequisites and passphrase check; status, forget and doctor output.
- `demo/e2e.sh` runs enrol and `unlock --hello` against real GPG in a throwaway `GNUPGHOME`, with the fake helper and a fake pinentry, in a pseudo-terminal.
- CI on `windows-latest` builds the helper and runs `pass-env-hello.exe check`, covering the "Hello unsupported" path of a machine without Hello.
- Real Hello prompts cannot be automated; the owner runs [windows-hello-manual-test.md](windows-hello-manual-test.md).

## Resource impact

- The helper runs only during `unlock --hello`, `hello enrol`, `hello status`, `hello forget` and `doctor`, for well under a second plus the time you take at the prompt, using a few MB of memory. Nothing runs in the background, nothing is scheduled, no service or tray app is involved.
- Disk: the helper is under 1 MB in `%LOCALAPPDATA%\pass-env`, the blob under 5 KB, the record under 1 KB.
- gpg-agent is unchanged: it already runs (socket-activated by systemd) with a few MB of memory and idle CPU; Hello only changes how the passphrase reaches it.

## Risks

- Windows API changes, as 25H2 already showed with key creation; covered by the probe-first workaround and the typed fallback.
- The unpackaged-app identity Windows uses to scope the Hello key could change with the helper's path or signature, making the key unreachable; re-enrol fixes it.
- Prompt phishing cannot be fully solved without a Windows API for a custom prompt message.
- The JavaScript runtime cannot guarantee that every copy of the passphrase is wiped.

## Effort

About two days of focused work: the helper and its tests, the pass-env commands and tests, CI and release changes, documentation, a security review, and the owner's manual test.
