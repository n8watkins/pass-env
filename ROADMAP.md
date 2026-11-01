# Roadmap

Planned next steps, in order.
Each one keeps the existing rule: pass-env never prints a secret value.

## 1. `import`: move an existing .env file into pass

```sh
pass-env import .env.local --prefix myapp            # step 1: store secrets, write .env.pass
pass-env run -- pnpm dev                             # test the app
pass-env import .env.local --prefix myapp --remove   # step 2: delete the secret lines from .env.local
```

### What step 1 does

1. **Reads the file with normal dotenv rules.**
   `KEY=value`, an optional `export ` prefix, single quotes (literal), double quotes (with `\n` escapes and real line breaks), unquoted values with a trailing ` # comment`, Windows line endings.
   If a name appears twice, the last one wins, as in Next.js, and pass-env warns.
2. **Decides what to store.**
   Everything is treated as secret except names that are public by design: `NEXT_PUBLIC_*`, `VITE_*`, `PUBLIC_*`, `EXPO_PUBLIC_*`, `REACT_APP_*`.
   Those stay in the file, because the framework compiles them into the browser bundle anyway.
   Treating everything else as secret is the safe default: a URL stored in pass costs nothing, a secret left in plain text costs a lot.
3. **Skips what it cannot move safely, and says so.**
   - Empty values.
   - Values that reference other variables (`$OTHER` or `${OTHER}`), because Next.js expands those when it loads the file.
   - Anything named with `--skip NAME,NAME`.
4. **Checks before writing anything.**
   If any `<prefix>/<NAME>` entry already exists, it stops before storing a single key, unless `--force` is given.
5. **Stores each secret** as `<prefix>/<NAME>`.
   Values that span lines are stored exactly and mapped with `multiline:`.
6. **Writes `.env.pass`** next to the file.
   It adds new lines and keeps existing ones.
   It stops if a name already points somewhere else.
7. **Warns if git would ignore `.env.pass`.**
   Patterns like `.env*` in `.gitignore` hide it, and it prints the one-line fix (`!.env.pass`).
8. **Leaves the original file untouched** and prints the next steps.

`--dry-run` shows the plan without storing anything: each name, and whether it will be stored as an entry, kept as public, or skipped and why.
Names only, never values.

### What step 2 (`--remove`) does

1. Decrypts each imported entry and compares it with the file's value.
   This needs GPG unlocked, and you will have unlocked it to test the app anyway.
2. Only if every value matches, it rewrites the file without the imported lines.
   Comments, public values and skipped lines stay.
   The rewrite is atomic (temporary file, then rename) and keeps the file's permissions.
3. If only comments and blank lines are left, it deletes the file.
4. **Cloudflare Workers:** Wrangler ignores environment variables while a `.dev.vars` file exists.
   So for `.dev.vars`, it tells you to move any remaining public values into `wrangler.jsonc` `vars` so the file can go.

### Why two steps

- **You can't lose a key.** Nothing plaintext is deleted until you have run the app through pass-env and every stored value has been checked against the original.
- **No backup copy.** A backup of the file would be one more plaintext copy, which is the thing this tool exists to remove.

### Agents

An agent can run both steps.
Values go straight from the file into pass without being printed.
`--remove` only works while you have GPG unlocked.

### Small fix needed first

`store()` adds a trailing newline to every value.
That's harmless for single-line values, since only the first line is read, but multi-line values would come back with an extra newline.
Store `multiline:` values exactly.

### Tests

- The parser cases above.
- Classification, and `--dry-run` printing no values.
- Refusing existing entries.
- Merging into an existing `.env.pass`, and the `.gitignore` warning.
- `--remove` only after every value matches, and keeping comments and public lines.
- Multi-line values round-tripping exactly.
- The `.dev.vars` message.

## 2. `doctor`: check the setup

One command for first-time setup and "why doesn't it work".
It decrypts nothing.

| Check | Fix it prints |
| --- | --- |
| `pass`, `gpg` and Bun are installed | Install command for the OS |
| Store exists, is a real folder, and is not under `/mnt/c` on WSL | `pass init <id>`, or move it |
| The store's `.gpg-id` key has a private key on this machine | `gpg --list-secret-keys` explanation |
| A passphrase prompt is configured; on WSL, `pinentry-curses` | Line for `gpg-agent.conf` |
| `GPG_TTY` is set in your shell | Line for your shell profile |
| GPG cache times are not longer than a day | Suggested values |
| A clipboard tool exists | Which one to install (optional) |
| In this folder: plaintext `.env` files with secrets | `pass-env import ...` |
| In this folder: `.env.pass` is ignored by git | `!.env.pass` line |
| If `~/.claude` exists: Claude Code deny rules for `.env` files | The JSON to add (hint only) |

Each line is ok, a warning, or a failure, plus one fix command.
The exit code is 1 if anything failed.

## 3. Easier install

1. **Standalone binaries on GitHub releases**, built with `bun build --compile` for Linux and macOS (x64 and arm64).
   Install is one download, and users don't need Bun.
   A tag push runs a release workflow.
   This needs a test that the compiled binary behaves the same (process signals, `import.meta.main`).
2. **npm package `pass-env`.** The name is free.
   Install would be `bun add -g pass-env` or `bunx pass-env`.
   It still needs Bun at runtime, and the owner has to log in to npm once to publish.

## Not planned

- **Shell tab completion.** Small benefit for the extra code; `pass-env list` covers it.
- **A GUI.** QtPass already browses the same store.
- **Syncing or team sharing.** `pass` already supports a git-backed store with several GPG recipients.
