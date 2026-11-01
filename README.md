# pass-env

Use secrets from [`pass`](https://www.passwordstore.org/) in your apps, your deploys and your AI coding agents, without the secrets ever showing up in files, terminals or chat transcripts.

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

**The script**, if you have [Bun](https://bun.sh):

```sh
mkdir -p ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/n8watkins/pass-env/main/pass-env.ts -o ~/.local/bin/pass-env
chmod +x ~/.local/bin/pass-env
```

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
| `pass-env doctor` | Check pass, GPG, the store and the current folder. Decrypts nothing | No |
| `pass-env unlock` | Type your GPG passphrase for this session. Only works in your own terminal | |
| `pass-env help` | Everything here, with examples | |

Options:
- `--force` on `set` or `generate` replaces an existing entry (rotation).
- `generate <entry> 64 --charset hex` sets the length (16 to 512, default 48) and characters (`alnum`, `hex`, `base64url`).
- `--multiline` on `pipe` or `copy` uses the whole entry instead of its first line.
- `run -f file` or `run -e NAME=entry` uses other mappings instead of `./.env.pass`.
- `--dry-run` on `import` shows the plan, names only.
- `--skip NAME,NAME` on `import` leaves those names in the file, and `--force` replaces existing entries.

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

## Windows (WSL)

Install and use everything inside WSL.
Keep the store and `~/.gnupg` on the Linux side; under `/mnt/c` file permissions do not apply.
Use the terminal passphrase prompt (`pinentry-program /usr/bin/pinentry-curses` in `gpg-agent.conf`) and add `export GPG_TTY=$(tty)` to your shell profile.
`--copy` and `copy` use the Windows clipboard (`clip.exe`), so you can paste straight into a browser.
For a GUI to browse entries, QtPass runs inside WSL (`sudo apt install qtpass`) and uses the same store.

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
Add `--skip NAME,NAME` to leave other names in the file.

**2. Store the secrets.**

```sh
pass-env import .env.local --prefix myapp
```

This stores each secret as `myapp/<NAME>` and adds the mappings to `.env.pass` next to the file.
It stops before storing anything if an entry already exists (add `--force` to replace) or if `.env.pass` already maps a name somewhere else.
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
There is no backup copy on purpose: it would be one more plaintext copy of your secrets.

For Cloudflare Workers, Wrangler ignores environment variables while `.dev.vars` exists.
Move any values left in it into `vars` in `wrangler.jsonc`, delete it, and start Wrangler with `CLOUDFLARE_INCLUDE_PROCESS_ENV=true pass-env run -- npx wrangler dev`.

An agent can run all of this.
Values go from the file into pass without being printed, and `--remove` only works while you have GPG unlocked.

## Troubleshooting

Start with `pass-env doctor`.
It checks that `pass`, `gpg` and Bun are installed, that the store exists (and on WSL is not under `/mnt/c`), that this machine has the private key for the store's `.gpg-id`, the passphrase prompt (`pinentry-curses` on WSL), `GPG_TTY`, GPG's cache times and the clipboard.
In the current folder it looks for plaintext `.env` files that hold secrets and for a `.env.pass` that git ignores.
If you use Claude Code, it also checks that `~/.claude/settings.json` blocks reading `.env` files.
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
| `REFERENCE_FILE`, `WRITE` | A file could not be read, or could not be rewritten |
| `USAGE`, `STORE`, `PASS_MISSING` | Wrong arguments, no store yet (`pass init`), or `pass` not installed |

## Tests

```sh
bun test           # 42 tests with a fake pass, gpg and clipboard, including a real-terminal Ctrl-C test
./demo/e2e.sh      # walk-through against real pass and GPG in a temp folder, including import and --remove
```

Set `PASS_ENV_BIN=path/to/binary` to run both against a compiled binary.
CI does this on every push.

## Credits

pass-env was written by Phaedrus Raznikov at [Misty Step](https://github.com/misty-step) as part of [mistystack](https://github.com/misty-step/mistystack) (MIT).
This fork fixes three bugs and adds `set`, `generate`, `pipe`, `copy`, `unlock`, `check`, `import` and `doctor`.
See [CHANGES.md](CHANGES.md).
