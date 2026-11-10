# Roadmap

Each step keeps the existing rule: pass-env never prints a secret value.

## Done

- **`import`**: move an existing `.env` file into pass in two steps, `--dry-run` first and `--remove` after testing.
  See "Migrate an existing project" in the README.
- **`doctor`**: check the setup without decrypting anything.
  See "Troubleshooting" in the README.
- **Standalone binaries** built with `bun build --compile` for Linux and macOS (x64 and arm64).
  A `v*` tag runs `.github/workflows/release.yml`, which tests the compiled binary with the full test suite and the e2e walk-through before attaching all four to a GitHub release.
- **Multi-line values stored exactly**, so `multiline:` mappings round-trip byte for byte.
- **`scrub`**: find and blank out keys that coding agents already saved in their chat logs.
  See "Clean up keys agents already saw" in the README.
- **Env drift in `doctor`**: names the code reads but nothing declares, and `.env.pass` names the code never reads.
- **Scan history for `scrub`**: skip unchanged files, read only the new end of growing logs, and `scrub --history`.
  See "Scan history" in the README.

- **Masked output for `run` and `pipe`** (owner decision, 2026-11-10): every copy of a value pass-env handed over is shown as `***`.
  It closes the gap the hook cannot see: an agent edits a named script (`npm run test`) to print a key, then runs it with `pass-env run`.
  See "What run and pipe print" in the README for what is and is not caught.
  `--no-mask` turns it off only for the owner at a terminal, after a yes typed there; without a terminal (an agent) it refuses and runs nothing.
  **Measured cost** (the owner's condition; 2026-11-10, WSL2 on 8 CPUs, five fake values including a 27-line PEM key).
  pass-env's own peak memory (VmHWM of the pass-env process, not the command's) and wall time, for v1.4.0, this build with `--no-mask`, and this build masked; medians of 5 runs, 2 for the test suite:

  | Command | v1.4.0 | new, `--no-mask` | new, masked |
  | --- | --- | --- | --- |
  | `true` (startup) | 0.19 s, 51.9 MB | 0.08 s, 28.5 MB | 0.06 s, 31.3 MB |
  | 100k separate lines, 1 in 1000 with a value, to a pipe | 1.16 s, 52.1 MB | 1.13 s, 29.4 MB | 1.06 s, 47.6 MB |
  | the same, to a terminal | 2.91 s, 51.9 MB | 2.56 s, 29.9 MB | 2.44 s, 46.4 MB |
  | 50 MB in large writes, to a pipe | 0.39 s, 51.7 MB | 0.24 s, 28.6 MB | 0.42 s, 56.2 MB |
  | pass-env's test suite (`bun test`), to a pipe | 65.0 s, 51.5 MB | 80.0 s, 29.4 MB | 50.4 s, 32.4 MB |
  | the same, to a terminal | 45.7 s, 51.5 MB | 46.0 s, 28.7 MB | 84.0 s, 32.1 MB |

  Latency is not noticeable: chatty output arrives as fast as unmasked (the same as piping it through `cat`), bulk output costs about 0.2 s per 50 MB, and the test suite's own spread (46 to 84 s, in both directions) hides any difference; a rerun alternating masked and unmasked in a terminal gave 65.8 and 74.4 s masked against 65.9 and 61.4 s unmasked.
  Memory is not the "few kilobytes" first expected: a real long command peaks 3 MB above unmasked, and very heavy output up to 28 MB above, as garbage collected after; it stays below what v1.4.0 used for anything, because the move to Bun 1.4.4 saves 23 MB.

- **Windows Hello unlock** (experimental): `pass-env unlock --hello`, see `docs/windows-hello.md`.
  Leaves experimental once the owner's manual test (`docs/windows-hello-manual-test.md`) passes.

### Decisions that differ from the original plan

- An unquoted value containing `#` with no space before it (`KEY=abc#def`) is skipped with a reason.
  dotenv cuts the value at any `#`, other loaders only at ` #`, so pass-env asks you to quote it instead of guessing.
- Values containing `\$` are skipped like `$OTHER`, because Next.js turns `\$` into `$` and the stored value would differ from what the app saw.
- A name that is not a valid variable name (`my.var`) is skipped, because `.env.pass` cannot map it.
- A line that is not `NAME=value`, or a quote that is never closed, stops the import with the line number, instead of being ignored as dotenv does.
- `--remove` also requires that `.env.pass` maps each name to `<prefix>/<NAME>`, so removing a line can never leave the app without the variable.
- `--remove` cannot be combined with `--dry-run` or `--force`.
- From the audit of real projects: placeholders are skipped, secret-looking public names get a warning, files committed to git are refused, `--map NAME=entry` points a name at a shared entry, and an existing entry with the same value is reused without `--force`.
  The same-value check needs GPG unlocked; while locked, an existing entry still needs `--force`, and `--dry-run` never decrypts, so it only says the entry exists.
- `doctor` reports file permissions and "neither committed nor ignored" only for dotenv files that hold secret-looking values, so a plain `.env` of public defaults stays quiet.
- `scrub` scans every UTF-8 text file in the agent log folders, not only `.jsonl`, so transcripts saved in other formats are covered; binary files are skipped and counted.
- pi and OMP are covered through their session folders (`~/.pi/agent/sessions`, `~/.omp/agent/sessions`); other agent data such as Codex's SQLite databases is left to `--path` or not scanned, since it cannot be rewritten line by line.
- An assigned value (`token=...`) must contain letters and digits and must not look like code, a path or a placeholder, so passwords made only of words are missed; `--known` finds those.
- A dry run reads files an agent is still writing and marks them "in use", while `--fix` skips them, so the dry run shows everything there is.
- `--fix` keeps each file's modification time, so tools that sort sessions by time (such as `claude --resume`) keep their order, and gives up on a file that changes while it is being rewritten.
- A line that would stop being valid JSON is left whole rather than partly redacted; the summary counts it, and a later dry run still reports it.
- The scan history records the patterns version and the store fingerprint per run, and marks a record stale or no longer checked against the store when they change, so a location left out of one run is never trusted with results from older patterns or another store.
- A dry run that skips an unchanged file still reports what the last scan found in it and exits with 1; `--fix` skips a file whose remaining findings are only lines it already had to leave (they would not stay valid JSON).
- A file that was not UTF-8 text is remembered too, so it is not read again until it changes.
- The pseudo-terminal carries only the command's output: stdin stays the real terminal, so the command keeps its controlling terminal and Ctrl-C, Ctrl-Z, prompts and `sudo` work as before.
  Bun's own `Bun.Terminal` was not used: it puts stdin, stdout and stderr on one pty that is not the command's controlling terminal, so Ctrl-C typed into it does nothing, stderr cannot stay separate, and `pipe` would have to type the secret into it.
  The pty comes from `openpty` in the C library through `bun:ffi`, with output processing off so bytes reach the terminal exactly as written; without it (or with Bun before 1.4.4) pass-env falls back to pipes, losing colors but still masking.
- Output that could be the start of a value is held for at most 0.1 seconds, so prompts are not held back; a value printed in pieces further apart than that is not caught.
- When stdout and stderr are the same file (a terminal, or the one log file coding agents use), the command gets one channel for both, so their order is kept.
- After the command exits, output from background processes it left is passed on until they are quiet for 0.1 seconds; later output is dropped, never shown unmasked.
- The drift check also reads `Bun.env.X`, `const { X } = process.env` and Prisma's `env("X")`, skips Python virtual environments and common build folders besides the requested ones, and runs only when there is a declaration file to compare with.

## Next

Nothing from the audit of real projects was skipped.

1. **Windows Hello out of experimental** after the manual test.
2. **npm package `pass-env`.** The name is free.
   Install would be `bun add -g pass-env` or `bunx pass-env`.
   It still needs Bun at runtime, and the owner has to log in to npm once to publish.

## Not planned

- **Shell tab completion.** Small benefit for the extra code; `pass-env list` covers it.
- **A GUI.** QtPass already browses the same store.
- **Syncing or team sharing.** `pass` already supports a git-backed store with several GPG recipients.
