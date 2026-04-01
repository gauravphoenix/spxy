# Refactor: Split `src/index.js` into Logical Modules

**Date:** 2026-04-01
**Status:** Approved

## Goal

`src/index.js` is ~1050 lines. Break it into focused modules that are each short enough to read in one sitting, with no circular dependencies and no behavior changes.

## Constraints

- Cloudflare Worker deployed via Wrangler — ESM `import`/`export` is fully supported; Wrangler bundles at deploy time.
- No behavior changes. This is a pure refactor.
- `wrangler.toml` `main = "src/index.js"` stays unchanged.

## File Structure

```
src/
  constants.js   ~50 lines
  utils.js       ~60 lines
  git.js         ~130 lines
  checks.js      ~230 lines
  responses.js   ~120 lines
  handlers.js    ~200 lines
  index.js       ~40 lines
```

## Module Responsibilities

### `src/constants.js`
All static data. No imports.

Exports: `UPSTREAM`, `GITHUB_API`, `GITLAB_API`, `BITBUCKET_API`, `CODEBERG_API`,
`SOURCEHUT_API`, `CACHE_ORIGIN`, `CACHE_VERSION`, `VERIFY_CACHE_TTL`,
`ALL_CHECK_IDS`, `GITHEAD_RE`, `CI_PUBLISHER_RE`, `MAX_PACKUMENT_BYTES`,
`SUSPICIOUS_EMAIL_DOMAINS`, `TRUSTED_TARBALL_HOSTS`,
`GH_HEADERS`, `DEFAULT_HEADERS`, `CORGI_HEADERS`, `SEV`

### `src/utils.js`
Pure utility functions. Imports `SEV` from constants.

Exports: `compareSemver()`, `highestSeverity()`, `hasValidGitHead()`,
`hasProvenanceSignatures()`, `log()`

### `src/git.js`
Git host URL parsing, commit/tag verification, and the Cloudflare Cache API
caching layer. Imports from constants + utils.

Exports: `normalizeRepoUrl()`, `parseRepoUrl()`, `extractRepoUrl()`,
`commitUrl()`, `tagUrl()`, `verifyCommit()`, `verifyTag()`,
`cachedVerify()`, `cachedVerifyCommit()`, `cachedVerifyTag()`

### `src/checks.js`
All security check logic. Imports from constants + utils + git.

Exports: `sevForCheck()`, `isCriticalOrHigh()`, `finding()`, `runChecks()`

### `src/responses.js`
All `Response` construction. No project imports (uses only Web APIs).

Exports: `copyHeaders()`, `warningHeaders()`, `passthrough()`,
`rawResponse()`, `rawResponseDirect()`, `jsonResponse()`,
`blockResponse()`, `blockResponseMulti()`

### `src/handlers.js`
Request routing and orchestration. Imports from checks + git + responses +
constants + utils.

Exports: `checkViaCorgi()`, `handleSmallPayload()`,
`handleLargePackument()`, `handleLargePackumentFallback()`

### `src/index.js`
Entry point only. Imports handlers + constants.

Contains: `parseProxyUrl()` (small, tightly coupled to the entry point),
`export default { fetch }`

## Dependency Graph

```
index.js
  └── handlers.js
        ├── checks.js
        │     ├── git.js
        │     │     ├── constants.js
        │     │     └── utils.js
        │     ├── constants.js
        │     └── utils.js
        ├── responses.js
        ├── constants.js
        └── utils.js
```

No circular dependencies.

## What Does NOT Change

- All function signatures and return types
- All check logic and severity rules
- All response shapes, headers, and status codes
- `wrangler.toml`
- The structured JSON logging added previously
