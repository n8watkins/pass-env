# Changes from upstream

Upstream: `bin/pass-env.ts` in [misty-step/mistystack](https://github.com/misty-step/mistystack) at commit `6d51473` (2026-09-16).
The first commit in this repository is that file unchanged.

## Fixed

- **Trailing newline in values.**
  `pass insert` and `pass generate` store `value\n`, and upstream passed the whole decrypted file, so programs received the key with a newline on the end.
  Values are now the entry's first line, matching the convention of `pass`, QtPass and browser extensions.
  `NAME=multiline:entry` keeps the old whole-entry behaviour for PEM keys and JSON.
- **Notes became part of the value.**
  Entries with extra lines (`user:`, `url:`) leaked those lines into the variable; first-line values fix this too.
- **One Ctrl-C reached the child twice.**
  The terminal signals the whole foreground process group and upstream forwarded the signal again, so tools that treat a second Ctrl-C as "force quit" skipped their clean shutdown.
  SIGINT and SIGQUIT are no longer forwarded when the terminal already delivers them (detected from `/proc/self/stat`, falling back to "stdin is a TTY").
  SIGTERM and SIGHUP are still forwarded.
  Covered by a test that types Ctrl-C into a real pseudo-terminal.

- **Multi-line values gained a newline.**
  Values were always stored with a newline added, so a `multiline:` value without one came back changed.
  Piped `set` input with several lines, and multi-line values from `import`, are now stored exactly.

## Added

- `set <entry>`: store a pasted (hidden, confirmed prompt) or piped value.
- `generate <entry> [length] [--charset] [--copy]`: store a random secret without printing it, unlike `pass generate`, which prints the new password. `--copy` also puts it on the clipboard for a human to paste.
- `pipe <entry> -- command`: send one secret to a command's stdin, replacing `sh -c 'printf %s "$V" | ...'`.
- `copy <entry>`: put one secret on the clipboard. Like `pass -c`, it is cleared after `PASSWORD_STORE_CLIP_TIME` seconds (default 45), but only if the clipboard still holds it. Uses `clip.exe` on WSL, then `pbcopy`, `wl-copy` or `xclip`.
- `unlock [entry]`: one place to type the GPG passphrase; refuses without a terminal so an agent cannot trigger a prompt.
- `check`: report each mapping as ok or missing without decrypting.
- `import <file> --prefix <prefix>`: move the secrets in a `.env` file into pass and write `.env.pass`, in two steps. `--dry-run` shows the plan (names only); `--remove` deletes the imported lines only after every stored value matches the file.
  It skips placeholders, warns about secrets under public names such as `NEXT_PUBLIC_GEMINI_API_KEY`, refuses files committed to git, and with `--map NAME=entry` can point a name at a shared entry; an existing entry with the same value is reused without `--force`.
- `doctor`: check pass, GPG, the store, the passphrase prompt (and that the Hello helper is never the pinentry), cache times (a warning only above one day), the clipboard and the current folder (plaintext secrets, file permissions, git status), without decrypting.
  It also reports env drift: variable names the code reads that nothing declares, and names in `.env.pass` the code never reads (names only).
- `scrub`: find the secrets coding agents already saved in their chat logs (Claude Code, Codex, pi and OMP), counted per file by kind, without printing them; `--fix` replaces each with `[REDACTED:<kind>]` in place, keeping JSONL lines valid, file modes and times, and skipping files an agent may still be writing.
  `--known` also matches the exact values in the store.
  A scan history (`${XDG_STATE_HOME:-~/.local/state}/pass-env/scrub.json`, mode 600, paths, sizes, times and counts only) lets later runs skip unchanged files and read only the new lines of logs that grew; `--all` reads everything again and `--history` reports when each location was checked, what was found and what was fixed.
  The patterns started from Phaedrus Raznikov's redactor in mistystack (`agent-config/system-one/redaction.ts` before commit `b483332`, MIT), extended with more providers, stricter lengths, checks against false positives, JSON-escaped text, and regexes that stay fast on log lines of many megabytes.
- `unlock --hello` and `hello install | enrol | status | forget` (experimental, WSL on Windows): unlock GPG with Windows Hello. A small Rust helper, `pass-env-hello.exe`, wraps the passphrase with a TPM-backed Windows Hello key (HKDF over a deterministic RSA signature, AES-256-GCM); the typed passphrase stays the fallback. See `docs/windows-hello.md`.
  The 25H2 key-creation and dialog-focus workarounds come from [312-dev/wsl-hello-sudo](https://github.com/312-dev/wsl-hello-sudo) (MIT).
- `version`.
- Standalone binaries for Linux and macOS (x64 and arm64), built with `bun build --compile` by a release workflow on each `v*` tag. CI runs the tests and the e2e walk-through against a compiled binary.
- `run` and `check` default to `./.env.pass`.
- Errors name a cause (`LOCKED`, `ENTRY`, `DECRYPT` for a missing key) by classifying GPG's stderr, which is still never printed.

## Unchanged

Strict data-only reference files, no symlinks in the store, no prompting during `run`, no secret output from the launcher, exit status and stdio passed through.
