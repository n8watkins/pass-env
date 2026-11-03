# Owner to-do

Things only the maintainer can do for pass-env on their own machine: the one-time pass and GPG setup, and the tests that need a person.
Agents keep this list current; tick an item by changing `[ ]` to `[x]` and adding the date.
No secrets go in this file.
The maintainer's cross-project list of keys to rotate is `SECURITY-TODO.md` in the private [secret-handling-review](https://github.com/n8watkins/secret-handling-review/blob/main/SECURITY-TODO.md) repo.

Last checked: 2026-11-02.
Already done on this machine (2026-11-01): pass-env is at `~/.local/bin/pass-env`, `~/.gnupg/gpg-agent.conf` uses `pinentry-curses`, and `~/.zshrc` exports `GPG_TTY`.
`pass` is not installed yet.

## 1. One-time setup: pass and a GPG key (about 20 minutes)

- [ ] `pass-env doctor` shows no FAIL, and the GPG key and passphrase are backed up.

**What.**
Install pass, create the GPG key that encrypts the store, and back both up.

**Steps.**
Run these in a new terminal of your own (not through an agent), so the passphrase prompt reaches you:

1. Install pass:

   ```sh
   sudo apt install -y pass
   ```

2. Create the key (default type, your email, a passphrase you can type daily and will not forget):

   ```sh
   gpg --full-generate-key
   ```

3. Create the store with that key's email:

   ```sh
   pass init <your-email>
   ```

4. Reload the agent so it picks up `gpg-agent.conf`:

   ```sh
   gpgconf --reload gpg-agent
   ```

5. Check the setup and fix anything it flags:

   ```sh
   pass-env doctor
   ```

6. Back up the private key offline, then delete the export:

   ```sh
   gpg --export-secret-keys --armor <your-email> > /mnt/c/Users/natha/Downloads/gpg-key-backup.asc
   ```

   Move the file to a USB stick or another place you trust, then delete it from Downloads.
7. Write the passphrase down somewhere safe (a password manager, or paper kept with the key backup).

**Why.**
pass-env stores every secret in pass, encrypted to this GPG key.
Lose the key or the passphrase and every stored secret is gone, so steps 6 and 7 are not optional.

**Unblocks.**
Every project's `pass-env run`, `pipe` and `import` (for example TL;DW's `shared/GEMINI_API_KEY` smoke test, and the Cloudflare token for pr-post-private), the key migration in SECURITY-TODO.md, and item 2 Part B below.

## 2. Windows Hello manual test

- [ ] Part A (sandbox) passed.
- [ ] Part B (real setup) passed.

**What.**
Run the checklist in [docs/windows-hello-manual-test.md](docs/windows-hello-manual-test.md).

**Steps.**
Follow that file; it is the source for this test.
Part A takes about two minutes and needs no setup; Part B needs item 1 done first.
Report the result (or the first step that failed) to Claude.

**Why.**
Windows Hello prompts (face, fingerprint, PIN) cannot be automated, so a person has to approve them.

**Unblocks.**
Dropping the "experimental" label from `unlock --hello`, and using Hello instead of typing the passphrase every day.

## 3. Turn on npm and Homebrew publishing (about 15 minutes)

- [ ] npm: an account with two-factor authentication, the `NPM_TOKEN` secret for the first publish, and the repository variable `NPM_PUBLISH=true`.
- [x] Homebrew: tap, deploy key and `HOMEBREW_TAP=true` set up by an agent (2026-11-03).
- [ ] After the first release reaches npm: switch the five packages to trusted publishing and delete the token.

**What.**
The release workflow publishes pass-env to npm (so `npm`, `pnpm`, `yarn` and `bun` can install it) once npm is set up; Homebrew is already on.

**Steps.**
[`docs/publishing.md`](docs/publishing.md) has each step.
The installer (`install.sh`) already works without any of this.
