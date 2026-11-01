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

## Added

- `set <entry>`: store a pasted (hidden, confirmed prompt) or piped value.
- `generate <entry> [length] [--charset]`: store a random secret without printing it, unlike `pass generate`, which prints the new password.
- `unlock [entry]`: one place to type the GPG passphrase; refuses without a terminal so an agent cannot trigger a prompt.
- `check`: report each mapping as ok or missing without decrypting.
- `run` and `check` default to `./.env.pass`.
- Errors name a cause (`LOCKED`, `ENTRY`, `DECRYPT` for a missing key) by classifying GPG's stderr, which is still never printed.

## Unchanged

Strict data-only reference files, no symlinks in the store, no prompting during `run`, no secret output from the launcher, exit status and stdio passed through.
