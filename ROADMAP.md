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

## Next

Nothing from the audit of real projects was skipped.

1. **Publish the first release.**
   The owner pushes a tag (`git tag v1.1.0 && git push origin v1.1.0`); the workflow does the rest.
2. **npm package `pass-env`.** The name is free.
   Install would be `bun add -g pass-env` or `bunx pass-env`.
   It still needs Bun at runtime, and the owner has to log in to npm once to publish.

## Not planned

- **Shell tab completion.** Small benefit for the extra code; `pass-env list` covers it.
- **A GUI.** QtPass already browses the same store.
- **Syncing or team sharing.** `pass` already supports a git-backed store with several GPG recipients.
