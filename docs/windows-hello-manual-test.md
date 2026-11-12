# Windows Hello unlock: owner's manual test

Windows Hello prompts (face, fingerprint, PIN) cannot be automated, so this is the part a person has to do.
Everything else is covered by automated tests; see "What was already verified" at the end.
Windows Hello unlock stays **experimental** until this checklist passes.

There are two parts.
Part A takes about two minutes and needs no setup at all: it runs in a throwaway sandbox.
Part B is the real setup, for when you have done the one-time pass and GPG setup.

## Part A: the sandbox run (about 2 minutes, no setup)

It uses its own throwaway GPG key, store, config folder, helper folder and Windows Hello key name, answers the GPG passphrase for you, and deletes the throwaway Hello key at the end.
Your real `~/.gnupg`, store and any future real enrolment are never touched.

1. Get the helper.
   After the release: download `pass-env-hello.exe` from the release page into `~/Downloads`, or build it from the repository on Windows:

   ```sh
   cd ~/projects/tools/pass-env
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w hello/build-release.ps1)"
   ```

2. Run the sandbox in your own WSL terminal (not through an agent):

   ```sh
   ./demo/hello-manual.sh /mnt/c/Users/natha/Downloads/pass-env-hello.exe   # or no argument for the one you built
   ```

3. Follow it.
   It pauses before each step and asks a yes/no question after it:

   | Step | You do | You should see |
   | --- | --- | --- |
   | 1. Install and status | Nothing | `Windows Hello available, TPM present, pass-env key absent` |
   | 2. Enrol | Approve up to three Hello prompts | Each prompt comes to the front; it ends with `Saved ... hello.blob` |
   | 3. Unlock | Approve one prompt | `Unlocked with Windows Hello (checked with workstation/UNLOCK_CANARY)` |
   | 4. Cancel | Cancel the prompt | `Windows Hello not used: Windows Hello was cancelled`, then `Unlocked (checked with ...)` from the typed fallback (answered for you in the sandbox) |
   | 5. Lock screen | Press Win+L within 5 seconds, sign back in | Either it unlocks once you are back, or it falls back with a clear reason. It must not hang |
   | 6. Forget | Nothing | The blob and the throwaway key are deleted; the next unlock says `not enrolled yet` and falls back |

4. Paste the "Results" block it prints at the end back into the chat, plus anything that looked off (a prompt behind other windows, slow steps, confusing text).

If something fails half way, the script still deletes the sandbox and the throwaway Hello key when it exits.

## Part B: the real setup (after the one-time pass setup)

Prerequisites: the steps in `SECURITY-TODO.md`, Phase 2, are done: `pass` installed, your GPG key with the memorable passphrase you saved offline, `pass init`, and `pass-env doctor` shows no FAIL.

1. **Install the helper** (no prompt).

   ```sh
   pass-env hello install
   ```

   Expect: it downloads `pass-env-hello.exe` from the release matching your pass-env, checks it against the hash pinned in that release, verifies its build provenance when `gh` is installed, copies it to `%LOCALAPPDATA%\pass-env\`, and prints `Installed pass-env-hello 1.2.0` and its SHA-256.

2. **Status** (no prompt).

   ```sh
   pass-env hello status
   ```

   Expect: `ok` for the helper (hash matches the one pinned in pass-env), `Windows Hello available, TPM present, pass-env key absent`, and `warn not enrolled`.

3. **Enrol** (up to three prompts).

   ```sh
   pass-env hello enrol
   ```

   Expect: GPG's usual curses passphrase prompt (type your real passphrase), `Passphrase checked`, then up to three Hello prompts, then `Saved ~/.config/pass-env/hello.blob`.
   A wrong passphrase must stop with `that passphrase does not open ...; nothing was saved`.

4. **Unlock** (one prompt).

   ```sh
   gpgconf --reload gpg-agent          # lock
   pass-env unlock --hello
   pass-env run -- true                # works without typing anything
   ```

   Expect: `Unlocked with Windows Hello`.
   Running `pass-env unlock --hello` again says `GPG is already unlocked` with no prompt.

5. **Cancel**: lock again, run `pass-env unlock --hello`, cancel the prompt.
   Expect: `Windows Hello was cancelled`, then GPG's own passphrase prompt; typing it unlocks as before.

6. **Lock screen**: lock, run `sleep 5; pass-env unlock --hello`, press Win+L, sign back in.
   Expect: an unlock or a clear fallback, never a hang.

7. **Agent check**: ask an agent to run `pass-env unlock --hello`.
   Expect: `TTY: unlock --hello needs your terminal`, and no Hello prompt appears.

8. **Unexpected prompt drill**: if a Hello prompt ever appears that you did not start, cancel it and run `pass-env hello status`; tell Claude what was running.

9. **Forget** (no prompt): `pass-env hello forget`.
   Expect: the blob and the Hello key are deleted, and `pass-env unlock` (typed) still works.
   Run `pass-env hello enrol` again to keep using Hello.

## How to report

Paste into the chat:

- The "Results" block from Part A, or for Part B the step numbers that did not match "Expect".
- `pass-env hello status` output (it never contains a secret).
- Your Windows build (`winver`), and anything odd: prompt behind the terminal, timings, wording.

Do not paste your passphrase, the contents of `hello.blob`, or a screenshot of a passphrase prompt with text in it.

## What was already verified without you

- Rust: blob format with a known-answer test, every tampered byte and swapped header field rejected, wrong key rejected, non-repeatable signatures caught, strict parser limits, flag parsing; plus 60 seconds of fuzzing of the parser (about 9 million inputs, no crash).
- `cargo deny` (advisories, licences, sources) and `cargo audit` clean; the release build is byte-for-byte reproducible across folders.
- pass-env with a fake helper (Bun tests and `demo/e2e.sh` against real GPG): enrol, unlock, already-unlocked, cancel, unavailable, locked, corrupt blob, a passphrase GPG rejects, SSH, no terminal, hash mismatch, status, doctor, forget, and that the passphrase never appears in any output.
- On this PC with the real `pass-env-hello.exe` in a sandbox (throwaway GPG key, store, config and helper folder, and Hello key name `pass-env-sandbox-test`, which was never created): install through WSL interop with the hash record, `check` (Hello available, TPM present), doctor and status, a well-formed blob for a key that does not exist (the real helper answers "unavailable" without any prompt and pass-env falls back), a corrupt blob, a tampered helper (hash mismatch, not run), forget, and the no-terminal refusals.
- Not verified, needs you: real key creation, real signing, the prompt coming to the front, cancel, and the lock-screen case. That is Part A.
