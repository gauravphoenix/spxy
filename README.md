# SPXY (Secure Package Proxy)

A Cloudflare Worker that acts as a paranoid npm registry proxy. It inspects
package metadata for signs of supply-chain compromise before letting
`npm install` proceed. All configuration lives in the registry URL — no
config files, no build plugins, no lockfile modifications.

Works out of the box with the npm CLI. Just update your `.npmrc` and point
to the proxy hosted on Cloudflare. Designed to be no/low cost — fits
comfortably in Cloudflare's free Workers tier for typical team use
(100k requests/day). No KV, D1, or other paid services required.

Authentication is **enabled by default**. You must set an `AUTH_TOKEN`
secret (or set `AUTH_MODE=off` to disable it).

```bash
npm --registry https://your-proxy.workers.dev/ install axios
```

---

## Quick Start

**1. Deploy the worker:**

```bash
npx wrangler deploy
# => Deployed to https://spxy.your-subdomain.workers.dev
```

**2. Set an auth token** (required by default):

```bash
npx wrangler secret put AUTH_TOKEN
# Enter a secret token when prompted, e.g.: my-secret-token-123
```

**3. Configure `.npmrc`** in your project (or `~/.npmrc` for global):

```ini
registry=https://your-proxy.workers.dev/
//your-proxy.workers.dev/:_authToken=my-secret-token-123
```

The first line sets the registry. The second line (note the `//` prefix)
tells npm which token to send to that host. The token must match what you
set in step 2.

**4. Install as usual:**

```bash
npm install express
```

---

## FAQ

- [How does it work?](#how-does-it-work)
- [What checks does it run?](#what-checks-does-it-run)
- [What's the URL format?](#whats-the-url-format)
- [What's the difference between block and warn mode?](#whats-the-difference-between-block-and-warn-mode)
- [Can I run only specific checks?](#can-i-run-only-specific-checks)
- [A package is being blocked. How do I bypass it?](#a-package-is-being-blocked-how-do-i-bypass-it)
- [What does a block look like?](#what-does-a-block-look-like)
- [What real attacks would this catch?](#what-real-attacks-would-this-catch)
- [How does authentication work?](#how-does-authentication-work)
- [What about the GitHub API rate limit?](#what-about-the-github-api-rate-limit)
- [How do I update the suspicious email list?](#how-do-i-update-the-suspicious-email-list)
- [What does the structured logging look like?](#what-does-the-structured-logging-look-like)
- [Limitations](#limitations)
- [How fast is it?](#how-fast-is-it)

---

### How does it work?

The proxy sits between `npm` and the registry. When npm fetches a packument
(package metadata), the proxy inspects the `latest` version for metadata
anomalies — missing git hashes, dropped provenance signatures, suspicious
publisher changes, etc. If anything looks off, it either blocks the install
(403) or attaches warning headers.

Tarballs, audit requests, and non-GET requests pass through untouched.

### What checks does it run?

18 checks organized by severity. CRITICAL and HIGH block in block mode.
MEDIUM only produces warning headers.

| #   | Name                       | Severity | Detects                                             |
| --- | -------------------------- | -------- | --------------------------------------------------- |
| 1   | missing-githead            | CRITICAL | No `gitHead` and no provenance signatures           |
| 2   | githead-verification       | MEDIUM   | gitHead commit doesn't exist in the repo            |
| 3   | trusted-publisher-dropped  | CRITICAL | Prior version used OIDC trusted publishing, this one doesn't |
| 101 | suspicious-publisher-email | HIGH     | Publisher email is a disposable/anonymous provider   |
| 102 | publisher-changed          | HIGH     | Publisher changed from CI bot to human               |
| 103 | signatures-dropped         | HIGH     | Provenance signatures present before, gone now       |
| 104 | install-scripts-added      | HIGH     | preinstall/install/postinstall scripts added         |
| 105 | missing-git-tag            | MEDIUM   | No git tag for this version                          |
| 106 | repo-url-changed           | MEDIUM   | Repository owner changed between versions            |
| 107 | bin-field-added            | HIGH     | New executable bin entries added                     |
| 108 | license-removed            | HIGH     | License field was removed                            |
| 109 | tarball-host-suspicious    | HIGH     | Tarball hosted outside trusted registries            |
| 110 | publisher-not-maintainer   | HIGH     | Publisher not in maintainers list (CI bots excluded) |
| 111 | native-bindings-added      | HIGH     | Native bindings (gypfile) added                      |
| 201 | publisher-email-changed    | MEDIUM   | Publisher email address changed                      |
| 202 | new-dependencies           | MEDIUM   | New dependencies added                               |
| 203 | unverifiable-repo          | MEDIUM   | Repo URL points to an unrecognized host              |
| 204 | missing-repository         | MEDIUM*  | No repository field                                  |

*Check 204 elevates to HIGH when the package also has no gitHead and no
provenance signatures — the combination is a much stronger signal.

### What's the URL format?

```
https://your-proxy.workers.dev/<mode?>/<check-numbers...>/<check-allow...>/<npm-path>
```

Segments are parsed left to right until something doesn't look like
configuration:

| Segment       | Meaning                                          |
| ------------- | ------------------------------------------------ |
| `block`       | Block mode (default if omitted)                  |
| `warn`        | Warn mode — findings become headers, never 403   |
| `101`         | Enable only check #101 (repeat for multiple)     |
| `101-allow`   | Bypass check #101 — won't contribute to blocking |

### What's the difference between block and warn mode?

**Block mode** (default): CRITICAL and HIGH findings return a 403 with a
detailed error message. MEDIUM findings pass through with warning headers.

**Warn mode**: All findings pass through with warning headers. Nothing is
ever blocked.

```bash
npm --registry https://your-proxy.workers.dev/warn/ install axios
```

### Can I run only specific checks?

Yes. Put check numbers in the URL:

```bash
# Fast preset — no git API calls, no rate limit concerns
npm --registry https://your-proxy.workers.dev/1/3/101/102/103/104/107/108/109/110/111/ install axios
```

If no check numbers are specified, all 18 checks run.

### A package is being blocked. How do I bypass it?

Every block message includes a bypass hint:

```
  To bypass a specific check (use with caution):
    npm --registry https://your-proxy.workers.dev/106-allow/ i ms
```

Use the `<number>-allow` syntax directly on the command line — no need
to modify your `.npmrc`:

```bash
# You see this block:
#   [HIGH] #106 repo-url-changed: Repo URL changed from .../zeit/ms to .../vercel/ms
#
# Override it for a one-off install:
npm --registry https://your-proxy.workers.dev/106-allow/ install ms

# Bypass multiple checks:
npm --registry https://your-proxy.workers.dev/106-allow/105-allow/ install typescript

# Combine with auth token if authentication is enabled:
npm --registry https://your-proxy.workers.dev/106-allow/ \
    --//your-proxy.workers.dev/:_authToken=YOUR_TOKEN \
    install ms
```

The `--registry` flag overrides your `.npmrc` for that single command.
Your `.npmrc` stays unchanged — next time you run `npm install`, the
full checks apply again.

If you want a permanent bypass, add it to `.npmrc` instead:

```ini
registry=https://your-proxy.workers.dev/106-allow/
//your-proxy.workers.dev/:_authToken=YOUR_TOKEN
```

This is intentionally visible in `.npmrc` so it's auditable — you can see
exactly which checks your team has chosen to bypass.

### What does a block look like?

```
npm error 403 ══════════════════════════════════════════════════════════════
npm error 403   BLOCKED by SPXY
npm error 403 ══════════════════════════════════════════════════════════════
npm error 403
npm error 403   Package:  example-pkg@2.0.0
npm error 403   Checks:   1,2,3,101,102,103,104,105,106,107,108,109,110,111,201,202,203,204
npm error 403
npm error 403   Findings:
npm error 403     [CRITICAL] #1 missing-githead: Published without gitHead ...
npm error 403     [HIGH] #104 install-scripts-added: Install lifecycle scripts added: postinstall
npm error 403
npm error 403   To bypass a specific check (use with caution):
npm error 403     npm --registry https://your-proxy.workers.dev/1-allow/104-allow/ i example-pkg
npm error 403
npm error 403 ══════════════════════════════════════════════════════════════
```

### What real attacks would this catch?

| Attack                          | Year | Caught? | Key signals                              |
| ------------------------------- | ---- | ------- | ---------------------------------------- |
| ua-parser-js (account hijack)   | 2021 | Yes     | #1 missing-githead, #104 install-scripts |
| coa + rc (account hijack)       | 2021 | Yes     | #1 missing-githead, #104 install-scripts |
| colors/faker (insider sabotage) | 2022 | No      | Insider used legitimate tooling          |
| event-stream (social eng.)      | 2018 | Partial | #102 publisher-changed, #202 new-deps    |
| @ledgerhq/connect-kit (phish)   | 2023 | Yes     | #1 missing-githead, #3 trusted-publisher-dropped, #103 signatures-dropped |

The insider sabotage case (colors/faker) is undetectable via metadata.
This is an inherent limitation of any metadata-based approach.

### Limitations

- **Only checks `latest` dist-tag** — the proxy can't tell from a packument
  request which version npm will ultimately install. Checking all dist-tags
  caused too many false positives on dev/RC/insiders tags.
- **Cannot catch insider attacks** — if a legitimate maintainer publishes
  malicious code through legitimate tooling, there are no metadata anomalies
  to detect.
- **Git checks are best-effort** — checks #2 and #105 depend on git host
  APIs. On rate limit or downtime, they return inconclusive (MEDIUM warning)
  rather than falsely blocking.

### How does authentication work?

Authentication is **on by default**. Every request (packuments and
tarballs) must include a valid token. Without it, the proxy returns 401.

**Production setup:**

```bash
# 1. Set the token the proxy will accept
npx wrangler secret put AUTH_TOKEN

# 2. Add to your project's .npmrc (or ~/.npmrc for global)
```

```ini
registry=https://your-proxy.workers.dev/
//your-proxy.workers.dev/:_authToken=my-secret-token-123
```

The `.npmrc` needs two lines. The first sets the registry. The second
(starting with `//`) tells npm which token to send to that host.
The token value must match what you set via `wrangler secret put`.

**Local development setup:**

Create `.dev.vars` in the proxy project directory:

```
AUTH_TOKEN=test-token
GITHUB_TOKEN=ghp_xxx
```

And in the project where you run `npm install`, create `.npmrc`:

```ini
registry=http://localhost:8787/
//localhost:8787/:_authToken=test-token
```

**To disable authentication:**

Set `AUTH_MODE` to `off` — either in `.dev.vars` for local dev or as
a secret for production:

```bash
# Local dev — add to .dev.vars
AUTH_MODE=off

# Production
npx wrangler secret put AUTH_MODE   # enter: off
```

If `AUTH_MODE` is not set, it defaults to `on`. If auth is on but no
`AUTH_TOKEN` is configured, the proxy returns a 500 with setup
instructions.

**Auth-exempt paths:** Requests to `/-/npm/` paths are exempt from
authentication. This covers npm internal endpoints like the
vulnerability audit (`POST /-/npm/v1/security/advisories/bulk`).
All other requests — packuments and tarballs — require a valid token.

### What about the GitHub API rate limit?

Without a token: 60 requests/hour (exhausted quickly).
With a token: 5,000 requests/hour.

```bash
# Production
npx wrangler secret put GITHUB_TOKEN

# Local dev — add to .dev.vars
GITHUB_TOKEN=ghp_xxx
```

A fine-grained token with zero permissions works for public repos.

If the rate limit is hit, checks #2 and #105 return "inconclusive" (MEDIUM
warning) rather than falsely blocking. The package passes through.

Verification results are cached for 30 days via the CF Cache API, so
repeated installs of the same package don't make additional API calls.

### How do I update the suspicious email list?

Edit the text files in `src/data/` — one domain per line:

- **`disposable-domains.txt`** — 5,359 disposable email domains, sourced
  from [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) (CC0 license)
- **`suspicious-domains.txt`** — privacy-focused providers that are
  legitimate but unusual for npm publishing (protonmail, tutanota, etc.)

Both are merged at build time. No code changes needed — edit the files
and run `npx wrangler deploy`.

### What does the structured logging look like?

Every action is logged as JSON (viewable via `wrangler tail`):

```json
{
  "ts": "2025-04-01T12:34:56.789Z",
  "action": "block",
  "pkg": "evil-pkg@1.0.0",
  "mode": "block",
  "checks": [0],
  "findings": [
    { "severity": "CRITICAL", "check": "missing-githead", "num": 1,
      "message": "Published without gitHead and without provenance signatures" }
  ],
  "blockedVersions": ["1.0.0"]
}
```

`checks: [0]` means all checks were enabled. Otherwise it lists the
specific check IDs. `action` is one of: `pass`, `warn`, `block`, `skip`.

To stream logs from your deployed worker:

```bash
wrangler tail --format json
```

### How fast is it?

Adds ~100–400 ms on first install of a package (metadata inspection +
optional git API calls). Subsequent installs of the same version are
faster thanks to CF Cache API caching of git verification results (30-day
TTL). Tarballs and non-GET requests pass through with no added latency.

---

## .npmrc Examples

```ini
# All checks, block mode (strictest)
registry=https://your-proxy.workers.dev/
//your-proxy.workers.dev/:_authToken=YOUR_TOKEN

# All checks, warn mode (monitor without blocking)
registry=https://your-proxy.workers.dev/warn/
//your-proxy.workers.dev/:_authToken=YOUR_TOKEN

# Fast preset — no git API calls, no rate limit concerns
registry=https://your-proxy.workers.dev/1/3/101/102/103/104/107/108/109/110/111/
//your-proxy.workers.dev/:_authToken=YOUR_TOKEN

# Bypass a noisy check
registry=https://your-proxy.workers.dev/106-allow/
//your-proxy.workers.dev/:_authToken=YOUR_TOKEN
```

---

## Project Structure

```
src/
  index.js            Entry point — URL parser + fetch handler
  constants.js        Static data — check IDs, regexes, headers
  checks.js           All 18 security checks
  handlers.js         Packument processing (small, large, corgi)
  responses.js        Response builders (block, warn, passthrough)
  utils.js            Helpers — semver compare, severity, logging
  git.js              Git host verification + CF cache
  data/
    disposable-domains.txt   5,359 disposable email domains
    suspicious-domains.txt   Privacy email domains suspicious for npm
wrangler.toml         Cloudflare Worker config
```

---

## Testing

```bash
npx wrangler dev

# Basic install
npm --registry http://localhost:8787 install axios

# View packument with checks
npm --registry http://localhost:8787 view axios

# Warn mode
npm --registry http://localhost:8787/warn/ install axios

# Specific checks
npm --registry http://localhost:8787/1/3/101/ view axios

# See what the proxy is doing in real time
wrangler tail --format json
```
