# pass-env

Run programs with secrets from [`pass`](https://www.passwordstore.org/), without the secrets landing in files, terminals or AI agent transcripts.

```sh
pass-env set myapp/STRIPE_SECRET_KEY        # paste the key once; it is encrypted
echo 'STRIPE_SECRET_KEY=myapp/STRIPE_SECRET_KEY' >> .env.pass
pass-env run -- pnpm dev                    # your app gets the key, nothing prints it
```

Your project keeps a `.env.pass` file that lists **names only**, never values.
It is safe to commit and safe for coding agents to read.
The real keys stay encrypted in your `pass` store and are decrypted only into the one program you start.

## Why

Coding agents (Claude Code, Codex, Cursor and others) read files and run commands as you.
A plaintext `.env.local` is one `cat` away from being copied into an agent's transcript, and from there into logs, caches and provider requests.
That is how real keys leak.
pass-env removes plaintext secrets from the places agents look by habit, while still letting agents run your app, generate new secrets and push secrets to production without seeing them.

### What it does not do

pass-env prevents accidents, not a determined attacker.
Once you unlock GPG, anything running as your user can decrypt until GPG's cache expires, including an agent that runs `pass-env run -- printenv KEY` on purpose.
For a hard boundary, run agents as a different OS user or in a container, and keep production keys in your hosting platform rather than on your laptop.

## Install

Needs [Bun](https://bun.sh), `gpg` and `pass`.
Works on Linux, macOS and Windows through WSL.

```sh
# 1. pass and a GPG key (skip what you already have)
sudo apt install pass            # macOS: brew install pass gnupg
gpg --full-generate-key          # pick a passphrase you can type daily
pass init you@example.com        # the email on that key

# 2. pass-env
mkdir -p ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/n8watkins/pass-env/main/pass-env.ts -o ~/.local/bin/pass-env
chmod +x ~/.local/bin/pass-env
pass-env help
```

Make sure `~/.local/bin` is on your `PATH`.

Back up your GPG private key once (`gpg --export-secret-keys --armor you@example.com > key.asc`), keep it somewhere offline, then delete the file.
If you lose it, every stored secret is gone.

## Everyday use

### Add a key you got from a provider

```sh
pass-env set myapp/OPENAI_API_KEY
```

Paste the key when prompted, then paste it again to confirm.
Nothing is echoed or saved in shell history.
The text after `set` is the **name** you choose, not the key.
Names are visible file names, so never put a secret in a name.

You can also pipe a value in: `pbpaste | pass-env set myapp/OPENAI_API_KEY`.

### Make up a secret you control

For values you invent rather than receive, such as `AUTH_SECRET`, session keys, cron tokens or your own webhook secrets:

```sh
pass-env generate myapp/AUTH_SECRET                    # 48 random letters and digits
pass-env generate myapp/WEBHOOK_SECRET 64 --charset hex
```

The value is never printed, so an agent can do this for you safely.
Storing never needs your passphrase, because it only encrypts.

### Tell the project which keys it needs

`.env.pass` in the project folder:

```sh
# variable name = name in pass
OPENAI_API_KEY=myapp/OPENAI_API_KEY
AUTH_SECRET=myapp/AUTH_SECRET
GEMINI_API_KEY=shared/GEMINI_API_KEY
FIREBASE_ADMIN_KEY=multiline:myapp/FIREBASE_ADMIN_KEY
```

Each variable gets the first line of its entry, the same convention `pass`, QtPass and browser extensions use.
Use `multiline:` for keys that span lines, such as PEM private keys or JSON.

Check it any time; this decrypts nothing:

```sh
pass-env check
```

### Run your app

```sh
pass-env unlock          # once per session, in your own terminal: type your passphrase
pass-env run -- pnpm dev
```

`run` uses `./.env.pass` unless you pass `-f file` or `-e NAME=entry`.
It never prompts: if GPG is locked it stops at once with `LOCKED: ... run pass-env unlock`.

Add scripts so nobody has to remember the prefix:

```json
"scripts": {
  "dev": "pass-env run -- next dev",
  "db:migrate": "pass-env run -- drizzle-kit migrate"
}
```

### Send a key to production without showing it

```sh
# GitHub Actions
pass-env run -e V=myapp/STRIPE_SECRET_KEY -- sh -c 'printf %s "$V" | gh secret set STRIPE_SECRET_KEY'
# Vercel
pass-env run -e V=myapp/STRIPE_SECRET_KEY -- sh -c 'printf %s "$V" | vercel env add STRIPE_SECRET_KEY production'
# Cloudflare Workers
pass-env run -e V=myapp/STRIPE_SECRET_KEY -- sh -c 'printf %s "$V" | npx wrangler secret put STRIPE_SECRET_KEY'
```

### Rotate a key

| Kind of secret | How to rotate |
| --- | --- |
| One you generated (`AUTH_SECRET`, cron token, your own webhook secret) | `pass-env generate myapp/AUTH_SECRET --force` |
| One a provider issued (Stripe, OpenAI, Resend, Clerk, Stripe webhook `whsec_...`) | Roll it in the provider's dashboard, then `pass-env set myapp/STRIPE_SECRET_KEY --force` |

Then update every place that holds a copy: re-run the production command above, and for shared secrets (a webhook secret both sides check) update the other side too.
Every local project that points at the entry picks up the new value on its next run.
Rotating `AUTH_SECRET` signs everyone out, which is usually the point.

## Commands

| Command | What it does |
| --- | --- |
| `pass-env run [-f file]... [-e NAME=entry]... -- cmd` | Start `cmd` with the secrets in its environment. Defaults to `./.env.pass` |
| `pass-env check [-f file]...` | List each mapping as ok or MISSING. Decrypts nothing |
| `pass-env set <entry> [--force]` | Store a pasted or piped value |
| `pass-env generate <entry> [length] [--charset alnum\|hex\|base64url] [--force]` | Store a new random secret (16 to 512 chars, default 48 alnum). Never printed |
| `pass-env unlock [entry]` | Type your passphrase so runs can decrypt. Refuses without a terminal |
| `pass-env list [prefix] [--json]` | Show entry names. Decrypts nothing |
| `pass-env help` | All of the above with examples |

Errors are short codes with a cause, and never include secret values or GPG output: `ENTRY`, `LOCKED`, `DECRYPT`, `EXISTS`, `STORE`, `USAGE`, `TTY`, `PASS_MISSING`.

## Does it work with my setup?

pass-env sets normal environment variables, so anything that reads `process.env` (or `os.environ`, `ENV`, and so on) works unchanged.

| Setup | Works? | Notes |
| --- | --- | --- |
| Next.js | Yes | Real environment variables win over `.env*` files. `NEXT_PUBLIC_*` values are compiled into the browser bundle, so they are public anyway; keep those in a normal `.env` |
| Vite | Yes | Existing environment variables win over `.env` files. Only `VITE_*` reaches the browser, and that is public too |
| Node, Bun, Python, Go, Rust, Ruby scripts | Yes | |
| Prisma, Drizzle, Convex, Supabase CLIs | Yes | Run them through `pass-env run` |
| Cloudflare Workers (`wrangler dev`) | With one setting | Wrangler reads `.dev.vars`, not the environment. Delete `.dev.vars` and run `CLOUDFLARE_INCLUDE_PROCESS_ENV=true pass-env run -- npx wrangler dev` |
| Docker | With flags | List the names: `pass-env run -- docker run -e STRIPE_SECRET_KEY -e AUTH_SECRET image` |
| Tools that want a key **file** (`GOOGLE_APPLICATION_CREDENTIALS`, SSH keys, certificates) | Not directly | Prefer the tool's env-var option (many accept the JSON or PEM text). Otherwise `sh -c 'printf %s "$KEY" > /dev/shm/k && tool --key /dev/shm/k; rm /dev/shm/k'` |
| Editor run buttons, debuggers, GUI apps, cron, systemd | Only if started through pass-env | They don't inherit your terminal. Start them from a terminal with `pass-env run`, or wrap the command in their config |
| Production hosting (Vercel, Cloudflare, GitHub Actions) | No, by design | They don't have your store. Push the values once with the commands above |

## Using it with AI coding agents

Paste this into your `CLAUDE.md`, `AGENTS.md` or equivalent:

```markdown
## Secrets
- Never open .env, .env.*, .dev.vars, or anything in ~/.password-store, and never run env, printenv or echo on secret variables.
- Each project lists its secrets by name in .env.pass. Run anything that needs them with `pass-env run -- <command>`; check with `pass-env check`.
- To create a secret we control (AUTH_SECRET, cron or webhook secrets we define): `pass-env generate <project>/<NAME>`, then add `NAME=<project>/<NAME>` to .env.pass.
- To rotate one of those: `pass-env generate <entry> --force`, push it to production with `pass-env run -e V=<entry> -- sh -c 'printf %s "$V" | <platform> ...'`, then tell me every other place that still holds the old value.
- For keys a provider issues (Stripe, OpenAI, Resend...), ask me to run `pass-env set <entry>` myself. Never ask me to paste a key into chat.
- If you see LOCKED, ask me to run `pass-env unlock`; you cannot unlock it yourself.
```

For Claude Code, also block reads of secret files in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": ["Read(**/.env)", "Read(**/.env.*)", "Read(**/.dev.vars)", "Read(~/.password-store/**)"]
  }
}
```

Keep GPG's cache short so an unlocked session does not stay open all day.
In `~/.gnupg/gpg-agent.conf`:

```
default-cache-ttl 3600
max-cache-ttl 28800
```

## Windows (WSL)

Install and use everything inside WSL.
Keep the store and `~/.gnupg` on the Linux side; under `/mnt/c` file permissions do not apply.
For the passphrase prompt, use the terminal one (`pinentry-program /usr/bin/pinentry-curses` in `gpg-agent.conf`) and add `export GPG_TTY=$(tty)` to your shell profile.
If you want a GUI to browse entries, QtPass runs inside WSL (`sudo apt install qtpass`) and shows up as a normal window; it uses the same store, and pass-env reads its entries correctly because it only takes the first line.

## Migrating from .env files

For each secret in an existing `.env.local`:

```sh
pass-env set myapp/STRIPE_SECRET_KEY      # paste the value from the old file
echo 'STRIPE_SECRET_KEY=myapp/STRIPE_SECRET_KEY' >> .env.pass
```

Then `pass-env check`, run the app once, and delete the old file.
Keep public, non-secret settings in a committed `.env`.

## Tests

```sh
bun test           # 22 tests with a fake pass, including a real-terminal Ctrl-C test
./demo/e2e.sh      # full walk-through against real pass and GPG in a temp dir
```

## Credits

pass-env was written by Phaedrus Raznikov at [Misty Step](https://github.com/misty-step) as part of [mistystack](https://github.com/misty-step/mistystack) (MIT).
This fork adds `set`, `generate`, `unlock` and `check`, first-line values with `multiline:` opt-in, a default `.env.pass`, clearer errors, and a fix for Ctrl-C reaching the child twice.
See [CHANGES.md](CHANGES.md).
