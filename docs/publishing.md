# Publishing pass-env

How a release reaches each install channel, and the one-time setup each needs.
Everything ships from one tag, which [release-kit](https://github.com/n8watkins/release-kit) cuts (`npm run release -- --push`); `.github/workflows/release.yml` does the rest.

| Channel | Built by | Turned on by |
| --- | --- | --- |
| GitHub Release (binaries, `pass-env.ts`, `SHA256SUMS`, build provenance) | `build` and `publish` jobs | Always on |
| `install.sh` | Reads the latest release | Always on |
| npm (`pass-env` plus `pass-env-<os>-<arch>`) | `npm` job, from the release's files | Repository variable `NPM_PUBLISH=true` |
| Homebrew (`n8watkins/tap/pass-env`) | `homebrew` job, writes `Formula/pass-env.rb` in `n8watkins/homebrew-tap` | Repository variable `HOMEBREW_TAP=true` and secret `HOMEBREW_TAP_DEPLOY_KEY` (both set) |

The npm and Homebrew jobs run only after the GitHub Release is published, and use the exact files it published, checked against `SHA256SUMS` again.
A failed npm or Homebrew job never undoes the release; fix the cause and re-run the job (npm skips versions already published).

## Releasing

1. On an up-to-date `main`, preview with `npm run release -- --dry-run`, then run `npm run release -- --push`.
   release-kit picks the version from the Conventional Commits since the last tag, bumps it in `package.json`, `pass-env.ts` (`const VERSION`), `hello/Cargo.toml` and `hello/Cargo.lock` (`.release.json`), writes the `CHANGELOG.md` section, and lands the release commit and tag through a release pull request (main is protected).
2. The tag starts the release workflow: it checks the tag is on `main` and the versions match, builds and tests everything, publishes the GitHub Release with the `CHANGELOG.md` section as its notes, then npm and Homebrew if they are on.
3. `CHANGES.md` (what this fork changed from upstream) is still edited by hand when a change is worth listing there.

## One-time setup: npm

1. Create an npm account (or use yours) and turn on two-factor authentication for publishing.
2. First publish, with a token (npm only lets you set up trusted publishing for packages that exist):
   create a granular access token that can publish new packages, add it as the repository secret `NPM_TOKEN`, and set the repository variable `NPM_PUBLISH` to `true`.
3. After the first release reaches npm: for each of the five packages (`pass-env`, `pass-env-linux-x64`, `pass-env-linux-arm64`, `pass-env-darwin-x64`, `pass-env-darwin-arm64`), open its settings on npmjs.com, add a trusted publisher (GitHub Actions, repository `n8watkins/pass-env`, workflow `release.yml`), and set "require two-factor authentication and disallow tokens".
4. Delete the `NPM_TOKEN` secret and revoke the token. From then on the workflow publishes with short-lived OIDC credentials and nothing long-lived exists to leak.

## Homebrew (set up)

The tap is `n8watkins/homebrew-tap`, shared by pass-env and devguard.
The release workflow pushes the formula with an SSH deploy key that can write to that one repository and nothing else: its public half is a deploy key on the tap ("release workflows: pass-env, devguard"), its private half the `HOMEBREW_TAP_DEPLOY_KEY` secret here and in the other repo.
To rotate it, generate a new key pair, replace the deploy key on the tap, and set the secret again in both repos (`gh secret set HOMEBREW_TAP_DEPLOY_KEY < key`), then delete the private key file.
The repository variable `HOMEBREW_TAP=true` turns the job on; set it to anything else to pause it.

## Checking changes to packaging

`.github/workflows/packaging.yml` runs on any pull request that changes `install.sh`, `packaging/` or the release workflow:
it runs the installer on Linux x64, Linux arm64 and macOS, publishes the npm packages to a throwaway local registry and installs them with npm, pnpm, yarn, bun and npx, and installs, tests and audits the Homebrew formula on macOS, all from the latest release's files.
Locally: `packaging/smoke-npm.sh <folder with a release's files>`.
