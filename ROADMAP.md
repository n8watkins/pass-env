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
