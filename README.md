# pass-env

Use secrets from [`pass`](https://www.passwordstore.org/) in your apps, your deploys and your AI coding agents, without the secrets ever showing up in files, terminals or chat transcripts.

> **Created by Phaedrus Raznikov ([@moomooskycow](https://github.com/moomooskycow)) at [Misty Step](https://github.com/misty-step).**
> pass-env started as part of his agent toolkit, [mistystack](https://github.com/misty-step/mistystack) (MIT).
> This fork, maintained by [Nathan Watkins](https://github.com/n8watkins), adds import, generate, doctor, scrub and other commands, and fixes three bugs; see [CHANGES.md](CHANGES.md).

```sh
pass-env set myapp/STRIPE_SECRET_KEY                      # paste the key once, it gets encrypted
echo 'STRIPE_SECRET_KEY=myapp/STRIPE_SECRET_KEY' >> .env.pass
pass-env run -- pnpm dev                                  # your app gets the key, nothing prints it
```

Each project keeps a `.env.pass` file that lists **names only**.
It is safe to commit and safe for agents to read.
The real values stay encrypted in your `pass` store.

## Why

Coding agents (Claude Code, Codex, Cursor and others) read files and run commands as you.
A plaintext `.env.local` is one `cat` away from being copied into an agent's transcript, and from there into logs and caches.
That is how real keys leak.
pass-env takes plaintext secrets out of the places agents look, while still letting agents run your app, create new secrets and push secrets to production without seeing them.

**What it does not do:** stop a determined attacker.
While GPG is unlocked, anything running as your user can decrypt, including an agent that runs `pass-env run -- printenv KEY` on purpose.
For a hard boundary, run agents as a different OS user or in a container, and keep production keys in your hosting platform.

## Install

Needs `gpg` and `pass`.
Works on Linux, macOS and Windows through WSL.

```sh
# pass and a GPG key (skip what you already have)
sudo apt install pass                 # macOS: brew install pass gnupg
gpg --full-generate-key               # choose a passphrase you can type daily
pass init you@example.com             # the email on that key
```

Then install pass-env one of two ways.

**A standalone binary** (no Bun needed), from the [releases page](https://github.com/n8watkins/pass-env/releases) once a release is published.
Pick the file for your system: `pass-env-linux-x64`, `pass-env-linux-arm64`, `pass-env-darwin-x64` (Intel Mac) or `pass-env-darwin-arm64` (Apple silicon).

```sh
mkdir -p ~/.local/bin
curl -fsSL https://github.com/n8watkins/pass-env/releases/latest/download/pass-env-linux-x64 -o ~/.local/bin/pass-env
chmod +x ~/.local/bin/pass-env
```

To check that a binary was built by this repository's release workflow from that tag (recommended, and required for trusting Windows Hello's pinned helper), with [gh](https://cli.github.com):

```sh
gh attestation verify ~/.local/bin/pass-env --repo n8watkins/pass-env \
  --signer-workflow n8watkins/pass-env/.github/workflows/release.yml --deny-self-hosted-runners
```

**The script**, if you have [Bun](https://bun.sh):

```sh
mkdir -p ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/n8watkins/pass-env/main/pass-env.ts -o ~/.local/bin/pass-env
chmod +x ~/.local/bin/pass-env
```

Each release also attaches an attested `pass-env.ts` (verify it the same way); the copy on `main` above is the latest code and is not attested.

Make sure `~/.local/bin` is on your `PATH`.
Then check the setup:

```sh
pass-env doctor
```

It prints one line per check (ok, warn or FAIL) and a command to fix each problem.
Back up your GPG private key once (`gpg --export-secret-keys --armor you@example.com > key.asc`), store it offline, and delete the file.
Lose that key and every stored secret is gone.

## All commands

| Command | What it does | Needs unlock? |
| --- | --- | --- |
| `pass-env set <entry>` | Store a key you were given. Paste it at the hidden prompt, or pipe it in | No |
| `pass-env generate <entry>` | Make a random secret and store it. Never printed | No |
| `pass-env generate <entry> --copy` | Same, and put it on your clipboard to paste somewhere (cleared after 45s) | No |
| `pass-env run -- <command>` | Run a command with the secrets from `./.env.pass` as environment variables | Yes |
| `pass-env pipe <entry> -- <command>` | Send one secret to a command's input, for example `gh secret set` | Yes |
| `pass-env copy <entry>` | Put one stored secret on your clipboard (cleared after 45s) | Yes |
| `pass-env check` | Show each line of `./.env.pass` as ok or MISSING | No |
| `pass-env list [prefix]` | Show the names in your store | No |
| `pass-env import <file> --prefix <prefix>` | Move the secrets in a `.env` file into pass and write `.env.pass`. The file is not changed | No |
| `pass-env import <file> --prefix <prefix> --remove` | After testing: check every stored value, then delete those lines from the file | Yes |
| `pass-env scrub` | Count the secrets coding agents already saved in their chat logs, per file. Prints none of them | Only with `--known` |
| `pass-env scrub --fix` | Replace those secrets in the logs with `[REDACTED:<kind>]` | Only with `--known` |
| `pass-env scrub --history` | Show when each log folder was last checked, what was found and what was fixed. Prints no secret | No |
| `pass-env doctor` | Check pass, GPG, the store and the current folder, including env variables the code reads but nothing declares. Decrypts nothing | No |
| `pass-env unlock` | Type your GPG passphrase for this session. Only works in your own terminal | |
| `pass-env unlock --hello` | Experimental, WSL on Windows: unlock with face, fingerprint or PIN; falls back to typing | |
| `pass-env hello install`, `enrol`, `status`, `forget` | Experimental: set up, check or remove Windows Hello unlock (see below) | |
| `pass-env version` | Print the version | |
| `pass-env help` | Everything here, with examples | |

Options:
- `--force` on `set` or `generate` replaces an existing entry (rotation).
- `generate <entry> 64 --charset hex` sets the length (16 to 512, default 48) and characters (`alnum`, `hex`, `base64url`).
- `--multiline` on `pipe` or `copy` uses the whole entry instead of its first line.
- `run -f file` or `run -e NAME=entry` uses other mappings instead of `./.env.pass`.
- `--dry-run` on `import` shows the plan, names only.
- `--skip NAME,NAME` on `import` leaves those names in the file, and `--force` replaces existing entries.
- `--map NAME=entry` on `import` (repeatable) stores a name in an existing or shared entry, such as `--map GEMINI_API_KEY=shared/GEMINI_API_KEY`.
- `--path <file-or-folder>` on `scrub` (repeatable) scans more places; `--known` also looks for the exact values in your store (needs unlock); `--include-active` lets `--fix` rewrite files changed in the last 10 minutes; `--all` reads every file again instead of skipping the ones unchanged since the last scan.

An **entry** is just a name you choose, like `myapp/STRIPE_SECRET_KEY`.
Names are visible file names, so never put a secret in a name.

## Common tasks

### Store a key a provider gave you

```sh
pass-env set myapp/OPENAI_API_KEY
```

Paste it, then paste it again to confirm.
Nothing is echoed or saved in your shell history.

For a value that spans lines, such as a PEM key or JSON, pipe it in:

```sh
pass-env set myapp/FIREBASE_ADMIN_KEY < service-account.json
```

Piped input with several lines is stored exactly, byte for byte.
Map it with `multiline:` (see below).
Piped input with one line loses its trailing newline, so `echo` works.

### Make up a new secret

For values you invent rather than receive: `AUTH_SECRET`, session keys, cron tokens, your own webhook secrets.
There are two ways, depending on who needs it.

**You need to paste it somewhere** (a dashboard field, another machine):

```sh
pass-env generate myapp/WEBHOOK_SECRET --copy
```

It is stored and on your clipboard. Paste it within 45 seconds.

**An agent or script needs to use it** (nobody sees it):

```sh
pass-env generate myapp/WEBHOOK_SECRET
pass-env pipe myapp/WEBHOOK_SECRET -- gh secret set WEBHOOK_SECRET
```

### Use secrets in your app

List what the project needs in `.env.pass`:

```sh
# variable name = entry name
OPENAI_API_KEY=myapp/OPENAI_API_KEY
AUTH_SECRET=myapp/AUTH_SECRET
GEMINI_API_KEY=shared/GEMINI_API_KEY
FIREBASE_ADMIN_KEY=multiline:myapp/FIREBASE_ADMIN_KEY
```

Then:

```sh
pass-env check                # anything missing?
pass-env unlock               # once per session, in your terminal
pass-env run -- pnpm dev
```

Each variable gets the first line of its entry, the same convention `pass` and its apps use.
Use `multiline:` for values that span lines, such as PEM keys or JSON.
Lines are data only: no quotes, `export`, interpolation or comments after a value.

Put it in your scripts so nobody has to remember:

```json
"scripts": {
  "dev": "pass-env run -- next dev",
  "db:migrate": "pass-env run -- drizzle-kit migrate"
}
```

### Send a secret to production

```sh
pass-env pipe myapp/STRIPE_SECRET_KEY -- gh secret set STRIPE_SECRET_KEY                    # GitHub Actions
pass-env pipe myapp/STRIPE_SECRET_KEY -- vercel env add STRIPE_SECRET_KEY production        # Vercel
pass-env pipe myapp/STRIPE_SECRET_KEY -- npx wrangler secret put STRIPE_SECRET_KEY          # Cloudflare Workers
```

### Paste a stored secret into a website

```sh
pass-env copy myapp/STRIPE_SECRET_KEY
```

### Rotate a secret

| The secret is | Rotate it with |
| --- | --- |
| One you made up (`AUTH_SECRET`, cron token, your own webhook secret) | `pass-env generate <entry> --force` (add `--copy` if you must paste it somewhere) |
| One a provider issued (Stripe, OpenAI, Resend, Clerk, Stripe's `whsec_` webhook secret) | Roll it in the provider's dashboard, then `pass-env set <entry> --force` |

Then update every copy: run the production `pipe` command again, and update the other side of anything shared (a webhook secret is checked by the receiver and known by the sender).
Local projects pick up the new value on their next run.
Rotating `AUTH_SECRET` signs everyone out.

## Does it work with my setup?

pass-env sets ordinary environment variables, so anything that reads them works unchanged.

| Setup | Works? | Notes |
| --- | --- | --- |
| Next.js, Vite | Yes | Real environment variables win over `.env` files, so no code changes. Browser-visible values (`NEXT_PUBLIC_*`, `VITE_*`) are public by design; keep them in a normal `.env` |
| Node, Bun, Python, Go, Ruby, Rust | Yes | |
| Prisma, Drizzle, Convex, Supabase and other CLIs | Yes | Run them through `pass-env run` |
| Cloudflare Workers (`wrangler dev`) | One setting | Wrangler reads `.dev.vars`, not the environment. Delete `.dev.vars` and run `CLOUDFLARE_INCLUDE_PROCESS_ENV=true pass-env run -- npx wrangler dev` |
| Docker | With flags | Name the variables: `pass-env run -- docker run -e STRIPE_SECRET_KEY image` |
| Tools that want a key file (Google credentials JSON, SSH keys, certificates) | Not directly | Use the tool's environment-variable option if it has one |
| Editor run buttons, debuggers, GUI apps, cron | Only when started through pass-env | They don't inherit your terminal |
| Hosting (Vercel, Cloudflare, GitHub Actions) | No, by design | Send values once with `pass-env pipe` |

## With AI coding agents

Paste this into `CLAUDE.md`, `AGENTS.md` or your agent's equivalent:

```markdown
## Secrets
- Never open .env, .env.*, .dev.vars or ~/.password-store, and never print secret variables (env, printenv, echo).
- Each project lists its secrets by name in .env.pass. Run things with `pass-env run -- <command>`; check with `pass-env check`.
- To create a secret we control: `pass-env generate <project>/<NAME>`, then add `NAME=<project>/<NAME>` to .env.pass.
- To move a plaintext .env file into pass: `pass-env import <file> --prefix <project> --dry-run`, then without --dry-run; after I have tested the app, the same command with --remove.
- To send a secret somewhere: `pass-env pipe <entry> -- <command that reads stdin>`.
- To rotate one we control: `pass-env generate <entry> --force`, re-send it to production with pipe, then tell me every other place that still holds the old value.
- For keys a provider issues (Stripe, OpenAI, Resend...), ask me to run `pass-env set <entry>`. Never ask me to paste a key into chat.
- If you see LOCKED, ask me to run `pass-env unlock`; you cannot unlock it.
```

For Claude Code, also block reads of secret files in `~/.claude/settings.json`:

```json
{ "permissions": { "deny": ["Read(**/.env)", "Read(**/.env.*)", "Read(**/.dev.vars)", "Read(~/.password-store/**)"] } }
```

Keep GPG's unlock short. In `~/.gnupg/gpg-agent.conf`:

```
default-cache-ttl 3600
max-cache-ttl 28800
```

## Clean up keys agents already saw

Coding agents save everything they see in chat logs on your machine.
Claude Code keeps them in `~/.claude/projects/` and `~/.claude/history.jsonl`, Codex in `~/.codex/sessions/`, `~/.codex/archived_sessions/` and `~/.codex/history.jsonl`, and pi and OMP in `~/.pi/agent/sessions/` and `~/.omp/agent/sessions/`.
Any key an agent ever printed or read stays there in plain text, where any program running as you can find it.
pass-env stops new leaks; `scrub` finds and blanks out the ones already saved.
It is a command you run on your own machine, not in CI.

```sh
pass-env scrub          # look first: counts per file, never the secrets
pass-env scrub --fix    # replace each one with [REDACTED:<kind>]
```

```
~/.claude/projects/-home-me-myapp/0b6f2c1e.jsonl: github-token 2, private-key 1
~/.claude/history.jsonl: stripe-key 1

Scanned 214 files (183.0 MB) in ~/.claude/projects, ~/.claude/history.jsonl, ~/.codex/sessions.
Found 4 suspected secrets in 2 files: github-token 2, private-key 1, stripe-key 1.
```

It finds private keys (PEM blocks, also when written inside JSON as `\n` text), AWS access keys, GitHub tokens (`ghp_`, `gho_`, `github_pat_` and the other prefixes), OpenAI and Anthropic `sk-` keys, Stripe `sk_live_`, `sk_test_` and `rk_` keys and `whsec_` webhook secrets, Slack `xox` tokens, Google `AIza` keys, Resend `re_` keys, `Bearer` tokens, JWTs, and assignments such as `DB_PASSWORD=...` or `"api_key": "..."`.
To keep false positives low, each pattern needs a realistic length, and an assigned value needs letters and digits and must not look like code (`process.env.API_KEY`), a path or a placeholder.
`--known` also looks for the exact current value of every entry in your store (its first line, if 12 characters or longer), which catches keys no pattern recognises.
It decrypts, so it needs GPG unlocked; the values are only held in memory.

The dry run exits with 1 if it found anything and 0 if not, so scripts can use it.
Add `--path <file-or-folder>` (repeatable) to scan other places as well.
Files are read line by line, so logs of hundreds of megabytes are fine.

### Scan history

`scrub` remembers which files it checked, when, and how many suspected secrets of each kind it found, so later runs are fast.
A file whose inode, size and modification time are unchanged is skipped, and the summary says so (`401 files unchanged since 2026-11-01 09:59, skipped`).
A file that only grew, such as `~/.claude/history.jsonl` or a session log, is read from the line where the last scan stopped.
Anything else, a newer version of the patterns, or a change to the store for `--known`, means the file is read whole again.
Remembered findings still count: the dry run lists them with "unchanged since the scan on ..." and still exits with 1.
The history is `${XDG_STATE_HOME:-~/.local/state}/pass-env/scrub.json`, readable only by you, and holds paths, sizes, times and counts, never a secret.
For `--known` it keeps a fingerprint of the store made from entry names, sizes and times, without decrypting anything.
Files that no longer exist are forgotten.
`pass-env scrub --history` shows each location, newest first, with when it was last checked, how many files were checked, which kinds were found and how many files were fixed.
`--all` ignores the history and reads every file again.

`--fix` rewrites each affected file in place:

- A line that was valid JSON stays valid JSON. If a replacement would break a line, that line is left as it was and counted as skipped.
- Each file is replaced through a temporary file and a rename, keeping its permissions and its modification time, so session lists keep their order.
- Files changed in the last 10 minutes are skipped, because an agent may still be writing them. Close the session first, or add `--include-active`.
- There is no backup on purpose: a backup would be one more plaintext copy.

Blanking a log does not un-leak a key, because the agent already sent it to its model provider.
Rotate every real key it finds (see "Rotate a secret").
Other places agents keep data, such as Codex's SQLite databases or Claude Code's `file-history` folder, are not scanned by default; add text folders with `--path`.

## Windows (WSL)

Install and use everything inside WSL.
Keep the store and `~/.gnupg` on the Linux side; under `/mnt/c` file permissions do not apply.
Use the terminal passphrase prompt (`pinentry-program /usr/bin/pinentry-curses` in `gpg-agent.conf`) and add `export GPG_TTY=$(tty)` to your shell profile.
`--copy` and `copy` use the Windows clipboard (`clip.exe`), so you can paste straight into a browser.
For a GUI to browse entries, QtPass runs inside WSL (`sudo apt install qtpass`) and uses the same store.

### Windows Hello unlock (experimental, opt-in)

Instead of typing the GPG passphrase, unlock with face, fingerprint or Windows Hello PIN.
It needs Windows 11 (or 10) with Windows Hello and a TPM, and WSL.
Nothing changes until you run these, and the typed passphrase always keeps working, so you cannot be locked out.

```sh
pass-env hello install        # puts pass-env-hello.exe in %LOCALAPPDATA%\pass-env, checks its hash and build provenance
pass-env hello enrol          # type your passphrase once; it is checked, then saved encrypted with a TPM-backed Hello key
pass-env unlock --hello       # in your terminal: one Hello prompt instead of typing
```

`pass-env hello status` shows the setup without any prompt, and `pass-env hello forget` removes it.
Like `unlock`, `unlock --hello` only works in your own terminal, so an agent cannot start a prompt; never set the helper as gpg-agent's `pinentry-program` (`doctor` flags it).
Approve a Hello prompt only right after you started one yourself.
The saved passphrase is ciphertext in `~/.config/pass-env/hello.blob` (mode 600); opening it needs the TPM key and a live Hello gesture.
Any problem (cancelled, unavailable, locked screen, SSH, a changed helper, a changed passphrase) prints why and falls back to the typed prompt.
Design, threat model and release verification: [docs/windows-hello.md](docs/windows-hello.md).
It stays experimental until the [manual test](docs/windows-hello-manual-test.md) passes.

## Migrate an existing project

`import` moves the secrets in an existing `.env.local` (or `.env`, `.dev.vars`) into pass in two steps.
No value is ever printed.

**1. Look at the plan.**

```sh
pass-env import .env.local --prefix myapp --dry-run
```

```
Plan for .env.local (dry run, nothing stored or changed):
  NEXT_PUBLIC_SITE_URL  kept public
  OPENAI_API_KEY        stored as myapp/OPENAI_API_KEY
  DATABASE_URL          stored as myapp/DATABASE_URL
  PRIVATE_KEY           stored as myapp/PRIVATE_KEY (multiline)
  DIRECT_URL            skipped: references another variable
```

Everything is stored except names that are public by design (`NEXT_PUBLIC_*`, `VITE_*`, `PUBLIC_*`, `EXPO_PUBLIC_*`, `REACT_APP_*`).
Empty values and values that use `$OTHER` or `${OTHER}` are skipped, and so is an unquoted value containing `#` (dotenv would cut it there; quote it and re-run).
Placeholders are skipped too: values containing `your`, `xxx`, `changeme`, `example`, `placeholder` or `replace`, and values equal to the same name in a `.env.example` or `.env.sample` next to the file.
Add `--skip NAME,NAME` to leave other names in the file.

A public name that looks like a secret, such as `NEXT_PUBLIC_GEMINI_API_KEY`, gets a warning and is not stored.
Anything with a public prefix is built into the browser bundle, so if it holds a real key, rotate it, delete the line, and use the key only on the server under a name without the prefix.

A file that is committed to git (a shared `.env` with defaults, say) is refused: deploys and teammates use it, so it is not a local secret file.

**2. Store the secrets.**

```sh
pass-env import .env.local --prefix myapp
```

This stores each secret as `myapp/<NAME>` and adds the mappings to `.env.pass` next to the file.
It stops before storing anything if `.env.pass` already maps a name somewhere else, or if an entry already exists with a different value (add `--force` to replace it).
An existing entry with the same value is simply reused, which needs GPG unlocked to compare.
So you can import `.env.local` and then `.dev.vars` from the same folder, and point a key several projects share at one entry with `--map GEMINI_API_KEY=shared/GEMINI_API_KEY`.
It warns if git ignores `.env.pass` and prints the line to add to `.gitignore`.
`.env.local` is not changed.

**3. Test the app.**

```sh
pass-env check
pass-env unlock
pass-env run -- pnpm dev
```

**4. Remove the plaintext secrets.**

```sh
pass-env import .env.local --prefix myapp --remove
```

This decrypts each stored value and compares it with the file.
Only if every value matches, it rewrites the file without those lines, keeping comments, public values and skipped lines.
If nothing but comments is left, it deletes the file.
If the file was readable by other users, it also makes it readable only by you.
A value left in the file that refers to a removed one, like `DIRECT_URL=${DATABASE_URL}?pgbouncer=true`, keeps working when the app runs through `pass-env run`, because Next.js and other dotenv loaders fill `${DATABASE_URL}` in from the real environment.
There is no backup copy on purpose: it would be one more plaintext copy of your secrets.

For Cloudflare Workers, `wrangler dev`, the Cloudflare Vite plugin and OpenNext's `next dev` ignore environment variables while `.dev.vars` exists.
Move any values left in it into `vars` in `wrangler.jsonc`, delete it, and start Wrangler with `CLOUDFLARE_INCLUDE_PROCESS_ENV=true pass-env run -- npx wrangler dev`.

An agent can run all of this.
Values go from the file into pass without being printed, and `--remove` only works while you have GPG unlocked.

## Troubleshooting

Start with `pass-env doctor`.
It checks that `pass`, `gpg` and Bun are installed, that the store exists (and on WSL is not under `/mnt/c`), that this machine has the private key for the store's `.gpg-id`, the passphrase prompt (`pinentry-curses` on WSL), `GPG_TTY`, GPG's cache times and the clipboard.
In the current folder it looks for plaintext `.env` files that hold secrets, and warns if such a file can be read by other users (fix: `chmod 600`), is committed to git, or is neither committed nor ignored (so `git add .` would commit it).
It also warns about secret-looking public names such as `NEXT_PUBLIC_GEMINI_API_KEY`, and about a `.env.pass` that git ignores.
If you use Claude Code, it also checks that `~/.claude/settings.json` blocks reading `.env` files.

It also compares the environment variables the code reads with the names the project declares, and warns about names used in code but declared nowhere, and names in `.env.pass` that the code never reads.
Reads are found in `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs` and `.py` files (`process.env.X`, `process.env["X"]`, `const { X } = process.env`, `import.meta.env.X`, `Bun.env.X`, `Deno.env.get("X")`, `os.environ["X"]`, `os.getenv("X")`, `os.environ.get("X")`) and in Prisma schemas (`env("X")`).
It skips `node_modules`, `.next`, `dist`, `build`, `out`, `coverage`, `.git`, `.worktrees`, Python virtual environments (`.venv`, `venv`, `__pycache__`) and the build folders of Wrangler, Vercel, Turborepo, SvelteKit and Nuxt.
Declared names come from `.env.pass`, `.env`, `.env.*` (including `.env.example` and `.env.sample`), `.dev.vars` and `vars` in `wrangler.jsonc` or `wrangler.toml`; only names are read.
Names that the runtime or platform sets are ignored: `NODE_ENV`, `PORT`, `HOST`, `HOSTNAME`, `CI`, `HOME`, `PATH`, `PWD`, `USER`, `SHELL`, `TERM`, `TMPDIR`, `TZ`, `LANG`, `DEBUG`, `NEXT_RUNTIME`, `NEXT_PHASE`, Vite's `MODE`, `DEV`, `PROD`, `SSR` and `BASE_URL`, and names starting with `VERCEL`, `GITHUB_`, `CF_PAGES` or `npm_`.
The check runs only when the code reads at least one variable and the folder has a file to compare with, and each warning lists at most 10 names.
Libraries and tools can read variables your code never mentions (Prisma's CLI, Auth.js), so a "never read" warning is a hint, not an error.

It decrypts nothing and exits with 1 if any check failed.

## Errors

Errors are one line, start with a code, and never include secret values or GPG output.

| Code | Meaning |
| --- | --- |
| `LOCKED` | GPG needs your passphrase: run `pass-env unlock` |
| `ENTRY` | The entry does not exist: `pass-env check` shows which |
| `EXISTS` | Already stored: add `--force` to replace it |
| `DECRYPT` | This machine's GPG key cannot open the entry |
| `CLIPBOARD` | No clipboard tool found (`clip.exe`, `pbcopy`, `wl-copy` or `xclip`) |
| `TTY` | `unlock` was run without a terminal (for example by an agent) |
| `MISMATCH` | `import --remove` found a stored value that differs from the file, so it removed nothing |
| `CONFLICT` | `import` found a name that `.env.pass` already maps to another entry |
| `PARSE` | `import` could not read a line of the file (the line number is given) |
| `TRACKED` | `import` was given a file committed to git; it only moves local secret files |
| `REFERENCE_FILE`, `WRITE` | A file could not be read, or could not be rewritten |
| `USAGE`, `STORE`, `PASS_MISSING` | Wrong arguments, no store yet (`pass init`), or `pass` not installed |
| `HELLO`, `SETUP`, `PASSPHRASE`, `PINENTRY`, `CANCELLED`, `CONFIG`, `DOWNLOAD` | Windows Hello setup: the helper or Hello is not usable, pass and GPG are not set up yet, the typed passphrase did not open the store, no pinentry, you cancelled, a pass-env config file is wrong, or a download failed |

## Tests

```sh
bun test           # 76 tests with a fake pass, gpg, clipboard and Windows Hello helper, including real-terminal tests
./demo/e2e.sh      # walk-through against real pass and GPG in a temp folder, including import, --remove, scrub, its scan history and Hello unlock
cd hello && cargo test   # the Windows helper's blob format and crypto (runs on Linux too)
```

Set `PASS_ENV_BIN=path/to/binary` to run both against a compiled binary.
CI does this on every push.

## Credits

pass-env was written by Phaedrus Raznikov at [Misty Step](https://github.com/misty-step) as part of [mistystack](https://github.com/misty-step/mistystack) (MIT).
This fork fixes three bugs and adds `set`, `generate`, `pipe`, `copy`, `unlock`, `check`, `import`, `scrub` and `doctor`.
`scrub`'s patterns started from Phaedrus's redactor in mistystack (`agent-config/system-one/redaction.ts`, MIT).
See [CHANGES.md](CHANGES.md).
