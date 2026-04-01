# Split `src/index.js` Into Modules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Break `src/index.js` (~1050 lines) into 7 focused ESM modules with no behavior changes.

**Architecture:** Create six new files (`constants`, `utils`, `git`, `checks`, `responses`, `handlers`) containing code moved verbatim from index.js, then rewrite index.js as a thin entry point (~40 lines) that imports from them. Each new file is created in full before index.js is touched — so existing behavior is unaffected until Task 7.

**Tech Stack:** Cloudflare Workers, Wrangler (bundles ESM automatically), plain JS (no test framework in this repo).

---

## File Map

| File | Status | Responsibility |
|------|--------|----------------|
| `src/constants.js` | Create | All static data: URLs, sets, regexes, header objects |
| `src/utils.js` | Create | Pure helpers: semver sort, severity, gitHead checks, log() |
| `src/git.js` | Create | Repo URL parsing, commit/tag verification, CF cache layer |
| `src/checks.js` | Create | All security check logic: runChecks(), finding(), severity |
| `src/responses.js` | Create | All Response construction: block, warn, pass, passthrough |
| `src/handlers.js` | Create | Orchestration: checkViaCorgi(), handleSmall/Large packument |
| `src/index.js` | Rewrite | Entry point only: parseProxyUrl() + export default { fetch } |

---

## Task 1: Create `src/constants.js`

**Files:**
- Create: `src/constants.js`

- [ ] **Step 1: Create the file**

```js
export const UPSTREAM = "https://registry.npmjs.org";
export const GITHUB_API = "https://api.github.com";
export const GITLAB_API = "https://gitlab.com/api/v4";
export const BITBUCKET_API = "https://api.bitbucket.org/2.0";
export const CODEBERG_API = "https://codeberg.org/api/v1";
export const SOURCEHUT_API = "https://git.sr.ht/api";

export const CACHE_ORIGIN = "https://githead-guard.internal";
export const CACHE_VERSION = "v2";
export const VERIFY_CACHE_TTL = 86400 * 30;

export const ALL_CHECK_IDS = new Set([
  // CRITICAL (1–99)
  1, 2, 3,
  // HIGH (100–199)
  101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
  // MEDIUM (200–299)
  201, 202, 203, 204,
]);

export const GITHEAD_RE = /^[0-9a-f]{7,40}$/i;
export const CI_PUBLISHER_RE = /github actions|gitlab|circleci|buildkite|jenkins/i;

export const MAX_PACKUMENT_BYTES = 8 * 1024 * 1024;

export const SUSPICIOUS_EMAIL_DOMAINS = new Set([
  "proton.me", "protonmail.com", "protonmail.ch",
  "tutanota.com", "tutamail.com", "tuta.io",
  "guerrillamail.com", "guerrillamail.de", "grr.la",
  "mailinator.com", "tempmail.com", "throwaway.email",
  "yopmail.com", "sharklasers.com", "guerrillamailblock.com",
  "maildrop.cc", "dispostable.com",
]);

export const TRUSTED_TARBALL_HOSTS = new Set([
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "npm.pkg.github.com",
  "registry.npmmirror.com",
]);

export const GH_HEADERS = Object.freeze({
  "User-Agent": "npm-githead-guard/1.0",
  Accept: "application/vnd.github+json",
});
export const DEFAULT_HEADERS = Object.freeze({
  "User-Agent": "npm-githead-guard/1.0",
});
export const CORGI_HEADERS = Object.freeze({
  "User-Agent": "npm-githead-guard/1.0",
  Accept: "application/vnd.npm.install.v1+json",
});

export const SEV = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
```

- [ ] **Step 2: Commit**

```bash
git add src/constants.js
git commit -m "refactor: extract constants module"
```

---

## Task 2: Create `src/utils.js`

**Files:**
- Create: `src/utils.js`

- [ ] **Step 1: Create the file**

```js
import { SEV, ALL_CHECK_IDS, GITHEAD_RE } from "./constants.js";

export function hasValidGitHead(meta) {
  return meta && typeof meta.gitHead === "string" && GITHEAD_RE.test(meta.gitHead);
}

export function hasProvenanceSignatures(meta) {
  return meta?.dist?.signatures?.length > 0;
}

export function highestSeverity(findings) {
  let max = 0;
  for (let i = 0; i < findings.length; i++) {
    const s = SEV[findings[i].severity] || 0;
    if (s > max) max = s;
    if (max === 4) return "CRITICAL";
  }
  return max >= 3 ? "HIGH" : max >= 2 ? "MEDIUM" : "LOW";
}

export function compareSemver(a, b) {
  const dashA = a.indexOf("-");
  const dashB = b.indexOf("-");
  const coreA = dashA === -1 ? a : a.slice(0, dashA);
  const coreB = dashB === -1 ? b : b.slice(0, dashB);

  let ai = 0, bi = 0;
  for (let part = 0; part < 3; part++) {
    let an = 0, bn = 0;
    while (ai < coreA.length && coreA[ai] !== ".") { an = an * 10 + (coreA.charCodeAt(ai) - 48); ai++; }
    while (bi < coreB.length && coreB[bi] !== ".") { bn = bn * 10 + (coreB.charCodeAt(bi) - 48); bi++; }
    ai++; bi++;
    if (an !== bn) return an - bn;
  }

  const preA = dashA !== -1;
  const preB = dashB !== -1;
  if (preA && !preB) return -1;
  if (!preA && preB) return 1;
  if (preA && preB) {
    const partsA = a.slice(dashA + 1).split(".");
    const partsB = b.slice(dashB + 1).split(".");
    const len = Math.max(partsA.length, partsB.length);
    for (let i = 0; i < len; i++) {
      if (i >= partsA.length) return -1;
      if (i >= partsB.length) return 1;
      const ia = partsA[i];
      const ib = partsB[i];
      const na = /^\d+$/.test(ia) ? parseInt(ia, 10) : null;
      const nb = /^\d+$/.test(ib) ? parseInt(ib, 10) : null;
      if (na !== null && nb !== null) {
        if (na !== nb) return na - nb;
      } else if (na !== null) {
        return -1;
      } else if (nb !== null) {
        return 1;
      } else {
        if (ia < ib) return -1;
        if (ia > ib) return 1;
      }
    }
  }

  return 0;
}

export function log(action, pkg, mode, enabledChecks, extra = {}) {
  const entry = {
    ts: new Date().toISOString(),
    action,
    pkg,
    mode,
    checks: enabledChecks === ALL_CHECK_IDS ? [0] : [...enabledChecks].sort((a, b) => a - b),
  };
  if (extra.findings?.length) entry.findings = extra.findings;
  if (extra.blockedVersions) entry.blockedVersions = extra.blockedVersions;
  if (extra.reason) entry.reason = extra.reason;
  console.log(JSON.stringify(entry));
}
```

- [ ] **Step 2: Commit**

```bash
git add src/utils.js
git commit -m "refactor: extract utils module"
```

---

## Task 3: Create `src/git.js`

**Files:**
- Create: `src/git.js`

- [ ] **Step 1: Create the file**

```js
import {
  CACHE_ORIGIN, CACHE_VERSION, VERIFY_CACHE_TTL,
  GH_HEADERS, DEFAULT_HEADERS,
  GITHUB_API, GITLAB_API, BITBUCKET_API, CODEBERG_API, SOURCEHUT_API,
} from "./constants.js";

export function normalizeRepoUrl(raw) {
  if (!raw) return "";
  let url = raw.trim();
  url = url.replace(/^git\+/, "");
  url = url.replace(/^git:\/\//, "https://");
  url = url.replace(/\.git\/?$/, "");
  url = url.replace(/\/+$/, "");
  return url;
}

export function parseRepoUrl(repoUrl) {
  if (!repoUrl) return null;
  const url = normalizeRepoUrl(repoUrl);

  const gh = url.match(/github\.com[/:]([^/]+)\/([^/.#]+)/);
  if (gh) return { host: "github", owner: gh[1], repo: gh[2] };

  const gl = url.match(/gitlab\.com[/:](.+?)$/);
  if (gl) {
    const project = gl[1].replace(/\/$/, "");
    return { host: "gitlab", project, owner: project, repo: project };
  }

  const bb = url.match(/bitbucket\.org[/:]([^/]+)\/([^/.#]+)/);
  if (bb) return { host: "bitbucket", owner: bb[1], repo: bb[2] };

  const cb = url.match(/codeberg\.org[/:]([^/]+)\/([^/.#]+)/);
  if (cb) return { host: "codeberg", owner: cb[1], repo: cb[2] };

  const sh = url.match(/git\.sr\.ht[/:]([^/]+)\/([^/.#]+)/);
  if (sh) return { host: "sourcehut", owner: sh[1], repo: sh[2] };

  return { host: null };
}

export function extractRepoUrl(obj) {
  const repo = obj.repository;
  if (!repo) return "";
  const raw = typeof repo === "string" ? repo : repo.url || "";
  return normalizeRepoUrl(raw);
}

export function commitUrl(p, sha) {
  switch (p.host) {
    case "github":    return `${GITHUB_API}/repos/${p.owner}/${p.repo}/git/commits/${sha}`;
    case "gitlab":    return `${GITLAB_API}/projects/${encodeURIComponent(p.project)}/repository/commits/${sha}`;
    case "bitbucket": return `${BITBUCKET_API}/repositories/${p.owner}/${p.repo}/commit/${sha}`;
    case "codeberg":  return `${CODEBERG_API}/repos/${p.owner}/${p.repo}/git/commits/${sha}`;
    case "sourcehut": return `${SOURCEHUT_API}/${p.owner}/${p.repo}/log/${sha}`;
    default: return null;
  }
}

export function tagUrl(p, tag) {
  const t = encodeURIComponent(tag);
  switch (p.host) {
    case "github":    return `${GITHUB_API}/repos/${p.owner}/${p.repo}/git/ref/tags/${tag}`;
    case "gitlab":    return `${GITLAB_API}/projects/${encodeURIComponent(p.project)}/repository/tags/${t}`;
    case "bitbucket": return `${BITBUCKET_API}/repositories/${p.owner}/${p.repo}/refs/tags/${t}`;
    case "codeberg":  return `${CODEBERG_API}/repos/${p.owner}/${p.repo}/tags/${t}`;
    case "sourcehut": return `${SOURCEHUT_API}/${p.owner}/${p.repo}/refs/${tag}`;
    default: return null;
  }
}

export async function verifyCommit(p, sha) {
  try {
    const url = commitUrl(p, sha);
    if (!url) return null;
    const res = await fetch(url, { headers: p.host === "github" ? GH_HEADERS : DEFAULT_HEADERS });
    return res.status === 200;
  } catch { return null; }
}

export async function verifyTag(p, version) {
  const tags = [`v${version}`, version];
  try {
    for (const tag of tags) {
      const url = tagUrl(p, tag);
      if (!url) return null;
      const res = await fetch(url, { headers: p.host === "github" ? GH_HEADERS : DEFAULT_HEADERS });
      if (res.status === 200) return true;
    }
    return false;
  } catch { return null; }
}

export async function cachedVerify(cacheKey, verifyFn) {
  const cache = caches.default;
  const cacheReq = new Request(cacheKey);

  try {
    const cached = await cache.match(cacheReq);
    if (cached) return (await cached.json()).ok;
  } catch {}

  const result = await verifyFn();

  if (result !== null) {
    try {
      await cache.put(cacheReq, new Response(JSON.stringify({ ok: result }), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": `public, max-age=${VERIFY_CACHE_TTL}`,
        },
      }));
    } catch {}
  }

  return result;
}

export async function cachedVerifyCommit(p, sha) {
  const cacheKey = `${CACHE_ORIGIN}/${CACHE_VERSION}/commit/${p.host}/${p.owner}/${p.repo}/${sha}`;
  return cachedVerify(cacheKey, () => verifyCommit(p, sha));
}

export async function cachedVerifyTag(p, version) {
  const cacheKey = `${CACHE_ORIGIN}/${CACHE_VERSION}/tag/${p.host}/${p.owner}/${p.repo}/${version}`;
  return cachedVerify(cacheKey, () => verifyTag(p, version));
}
```

- [ ] **Step 2: Commit**

```bash
git add src/git.js
git commit -m "refactor: extract git verification module"
```

---

## Task 4: Create `src/checks.js`

**Files:**
- Create: `src/checks.js`

- [ ] **Step 1: Create the file**

```js
import { SUSPICIOUS_EMAIL_DOMAINS, TRUSTED_TARBALL_HOSTS, CI_PUBLISHER_RE } from "./constants.js";
import { hasValidGitHead, hasProvenanceSignatures } from "./utils.js";
import { extractRepoUrl, parseRepoUrl, cachedVerifyCommit, cachedVerifyTag } from "./git.js";

export function sevForCheck(num) {
  if (num < 100) return "CRITICAL";
  if (num < 200) return "HIGH";
  if (num < 300) return "MEDIUM";
  return "LOW";
}

export function isCriticalOrHigh(num) {
  return num < 200;
}

/** Create a finding object with severity derived from the check number */
export function finding(num, check, message) {
  return { severity: sevForCheck(num), check, num, message };
}

export async function runChecks(meta, priorMeta, repoUrl, repoParsed, enabledChecks) {
  const findings = [];
  let blocked = false;

  // ── CRITICAL checks (1–99) ─────────────────────────────────────────

  // 1: missing gitHead
  if (enabledChecks.has(1)) {
    if (!hasValidGitHead(meta) && !hasProvenanceSignatures(meta)) {
      findings.push(finding(1, "missing-githead",
        "Published without gitHead and without provenance signatures"));
      blocked = true;
    }
  }

  // 3: trusted publisher dropped
  if (enabledChecks.has(3) && priorMeta) {
    if (priorMeta._npmUser?.trustedPublisher && !meta._npmUser?.trustedPublisher) {
      findings.push(finding(3, "trusted-publisher-dropped",
        "Prior version used OIDC trusted publishing; this version does not"));
      blocked = true;
    }
  }

  // ── HIGH checks (100–199) ──────────────────────────────────────────

  // 101: suspicious publisher email
  if (enabledChecks.has(101)) {
    const email = meta._npmUser?.email || "";
    const domain = email.split("@")[1]?.toLowerCase() || "";
    if (domain && SUSPICIOUS_EMAIL_DOMAINS.has(domain)) {
      findings.push(finding(101, "suspicious-publisher-email",
        `Publisher email uses anonymous provider: ${email}`));
      blocked = true;
    }
  }

  // 102: publisher changed from CI to human
  if (enabledChecks.has(102) && priorMeta) {
    const priorName = priorMeta._npmUser?.name || "";
    const currName = meta._npmUser?.name || "";
    if (priorName && currName && priorName !== currName && CI_PUBLISHER_RE.test(priorName)) {
      findings.push(finding(102, "publisher-changed",
        `Publisher changed from "${priorName}" to "${currName}"`));
      blocked = true;
    }
  }

  // 103: provenance signatures dropped
  if (enabledChecks.has(103) && priorMeta) {
    if (priorMeta.dist?.signatures?.length > 0 && !(meta.dist?.signatures?.length > 0)) {
      findings.push(finding(103, "signatures-dropped",
        "Prior version had provenance signatures; this version does not"));
      blocked = true;
    }
  }

  // 104: install scripts added
  if (enabledChecks.has(104) && priorMeta) {
    const priorScripts = priorMeta.scripts || {};
    const currScripts = meta.scripts || {};
    const added = [];
    if (currScripts.preinstall && !priorScripts.preinstall) added.push("preinstall");
    if (currScripts.install && !priorScripts.install) added.push("install");
    if (currScripts.postinstall && !priorScripts.postinstall) added.push("postinstall");
    if (added.length > 0) {
      findings.push(finding(104, "install-scripts-added",
        `Install lifecycle scripts added: ${added.join(", ")}`));
      blocked = true;
    }
  }

  // 106: repo URL changed from prior version
  if (enabledChecks.has(106) && priorMeta && repoUrl) {
    const priorRepoUrl = extractRepoUrl(priorMeta);
    if (priorRepoUrl && priorRepoUrl !== repoUrl) {
      const priorParsed = parseRepoUrl(priorRepoUrl);
      const priorOwner = priorParsed ? `${priorParsed.owner}/${priorParsed.repo}` : "";
      const currOwner = repoParsed ? `${repoParsed.owner}/${repoParsed.repo}` : "";
      const priorHost = priorParsed?.host || "";
      const currHost = repoParsed?.host || "";
      if (priorHost !== currHost || priorOwner !== currOwner) {
        findings.push(finding(106, "repo-url-changed",
          `Repo URL changed from ${priorRepoUrl} to ${repoUrl}`));
        blocked = true;
      }
    }
  }

  // 107: bin field added
  if (enabledChecks.has(107) && priorMeta) {
    const priorHasBin = priorMeta.bin && Object.keys(priorMeta.bin).length > 0;
    const currBin = meta.bin;
    const currHasBin = currBin && Object.keys(currBin).length > 0;
    if (!priorHasBin && currHasBin) {
      findings.push(finding(107, "bin-field-added",
        `Executable bin field added: ${Object.keys(currBin).join(", ")}`));
      blocked = true;
    }
  }

  // 108: license removed
  if (enabledChecks.has(108) && priorMeta) {
    if (priorMeta.license && !meta.license) {
      findings.push(finding(108, "license-removed",
        `License removed (was "${priorMeta.license}")`));
      blocked = true;
    }
  }

  // 109: tarball hosted on untrusted domain
  if (enabledChecks.has(109)) {
    const tarball = meta.dist?.tarball || "";
    if (tarball) {
      try {
        const tarballHost = new URL(tarball).hostname;
        if (!TRUSTED_TARBALL_HOSTS.has(tarballHost)) {
          findings.push(finding(109, "tarball-host-suspicious",
            `Tarball hosted on untrusted domain: ${tarballHost}`));
          blocked = true;
        }
      } catch {
        findings.push(finding(109, "tarball-host-suspicious",
          `Tarball URL is malformed: ${tarball}`));
        blocked = true;
      }
    }
  }

  // 110: publisher not in maintainers list
  if (enabledChecks.has(110)) {
    const publisherName = meta._npmUser?.name;
    const maintainers = meta.maintainers;
    if (publisherName && Array.isArray(maintainers) && maintainers.length > 0) {
      const maintainerNames = new Set(maintainers.map(m => m.name));
      if (!maintainerNames.has(publisherName)) {
        findings.push(finding(110, "publisher-not-maintainer",
          `Publisher "${publisherName}" is not in the maintainers list`));
        blocked = true;
      }
    }
  }

  // 111: native bindings added
  if (enabledChecks.has(111) && priorMeta) {
    if (!priorMeta.gypfile && meta.gypfile) {
      findings.push(finding(111, "native-bindings-added",
        "Native bindings added (gypfile: true) — can execute arbitrary code at install time"));
      blocked = true;
    }
  }

  // ── MEDIUM checks (200–299) ────────────────────────────────────────

  // 201: publisher email changed
  if (enabledChecks.has(201) && priorMeta) {
    const priorEmail = priorMeta._npmUser?.email || "";
    const currEmail = meta._npmUser?.email || "";
    if (priorEmail && currEmail && priorEmail !== currEmail) {
      findings.push(finding(201, "publisher-email-changed",
        `Publisher email changed from ${priorEmail} to ${currEmail}`));
    }
  }

  // 202: new dependencies added
  if (enabledChecks.has(202) && priorMeta) {
    const currDeps = meta.dependencies;
    if (currDeps) {
      const priorDeps = priorMeta.dependencies;
      const priorKeys = priorDeps ? Object.keys(priorDeps) : [];
      const priorSet = priorKeys.length > 0 ? new Set(priorKeys) : null;
      const newDeps = priorSet
        ? Object.keys(currDeps).filter(d => !priorSet.has(d))
        : Object.keys(currDeps);
      if (newDeps.length > 0) {
        findings.push(finding(202, "new-dependencies",
          `New dependencies added: ${newDeps.join(", ")}`));
      }
    }
  }

  // 203: unverifiable repo
  if (enabledChecks.has(203) && repoUrl && (!repoParsed || !repoParsed.host)) {
    findings.push(finding(203, "unverifiable-repo",
      `Repo URL points to an unrecognized host — cannot verify: ${repoUrl}`));
  }

  // 204: missing repository field entirely
  if (enabledChecks.has(204) && !repoUrl) {
    findings.push(finding(204, "missing-repository",
      "Package has no repository field — source cannot be verified"));
  }

  // ── Network checks (cached, skipped if already blocked) ────────────

  const needsCheck2 = enabledChecks.has(2) && repoUrl && repoParsed?.host && hasValidGitHead(meta);
  const needsCheck105 = enabledChecks.has(105) && repoUrl && repoParsed?.host && meta.version;

  if (!blocked && (needsCheck2 || needsCheck105)) {
    const promises = [];
    if (needsCheck2) promises.push(cachedVerifyCommit(repoParsed, meta.gitHead));
    if (needsCheck105) promises.push(cachedVerifyTag(repoParsed, meta.version));

    if (promises.length > 0) {
      const results = await Promise.all(promises);
      let ri = 0;

      if (needsCheck2) {
        const r = results[ri];
        if (r === false) {
          findings.push(finding(2, "githead-verification",
            `gitHead ${meta.gitHead} does not exist in ${repoUrl}`));
        } else if (r === null) {
          findings.push(finding(203, "githead-verification-unavailable",
            `Could not verify gitHead ${meta.gitHead} — git host unreachable`));
        }
        ri++;
      }

      if (needsCheck105) {
        const r = results[ri];
        if (r === false) {
          findings.push(finding(105, "missing-git-tag",
            `No git tag for v${meta.version} or ${meta.version} in ${repoUrl}`));
        } else if (r === null) {
          findings.push(finding(203, "tag-verification-unavailable",
            `Could not verify git tag for ${meta.version} — git host unreachable`));
        }
      }
    }
  }

  return findings;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/checks.js
git commit -m "refactor: extract checks module"
```

---

## Task 5: Create `src/responses.js`

**Files:**
- Create: `src/responses.js`

- [ ] **Step 1: Create the file**

```js
export function copyHeaders(h) {
  const out = new Headers();
  for (const [k, v] of h.entries()) {
    if (k === "content-encoding" || k === "transfer-encoding" || k === "content-length") continue;
    out.set(k, v);
  }
  return out;
}

export function warningHeaders(findings, mode) {
  return {
    "x-registry-proxy-warnings": [...new Set(findings.map(f => f.id || "unknown"))].join(", "),
    "x-registry-proxy-checks-triggered": [...new Set(findings.map(f => `${f.num}:${f.check}`))].join(", "),
    "x-registry-proxy-action": mode === "block" ? "blocked" : "warn-only",
  };
}

export function passthrough(res, extraHeaders = {}) {
  const headers = new Headers(res.headers);
  headers.set("x-registry-proxy", "githead-guard/1.0");
  for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  return new Response(res.body, { status: res.status, headers });
}

export function rawResponse(rawText, upstreamRes, extraHeaders = {}) {
  const headers = copyHeaders(upstreamRes.headers);
  headers.set("content-type", "application/json");
  headers.set("x-registry-proxy", "githead-guard/1.0");
  for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  return new Response(rawText, { status: upstreamRes.status, headers });
}

export function rawResponseDirect(rawText, upstreamRes, extraHeaders = {}) {
  const headers = new Headers(upstreamRes.headers);
  headers.set("x-registry-proxy", "githead-guard/1.0");
  for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  return new Response(rawText, { status: upstreamRes.status, headers });
}

export function jsonResponse(body, upstreamRes, extraHeaders = {}) {
  const headers = copyHeaders(upstreamRes.headers);
  headers.set("content-type", "application/json");
  headers.set("x-registry-proxy", "githead-guard/1.0");
  for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  return new Response(JSON.stringify(body), { status: upstreamRes.status, headers });
}

export function blockResponse(pkgName, version, findings, enabledChecks) {
  const findingsText = findings
    .map(f => `    [${f.severity}] #${f.num} ${f.check}: ${f.message}`)
    .join("\n");
  const checksUsed = [...enabledChecks].sort((a, b) => a - b).join(",");

  const message = [
    ``,
    `══════════════════════════════════════════════════════════════`,
    `  BLOCKED by npm-githead-guard`,
    `══════════════════════════════════════════════════════════════`,
    ``,
    `  Package:  ${pkgName}@${version}`,
    `  Checks:   ${checksUsed}`,
    ``,
    `  Findings:`,
    findingsText,
    ``,
    `  This version has metadata anomalies consistent with a`,
    `  supply-chain attack (compromised maintainer account,`,
    `  CI/CD bypass, or unauthorized publish).`,
    ``,
    `  What you should do:`,
    `    1. Do NOT install this version.`,
    `    2. Check the package's GitHub releases/tags to see`,
    `       if this version exists in the official repo.`,
    `    3. Pin to the last known-good version instead.`,
    `    4. Report to npm: https://docs.npmjs.com/reporting-malware`,
    ``,
    `══════════════════════════════════════════════════════════════`,
    ``,
  ].join("\n");

  return new Response(JSON.stringify({ error: message }), {
    status: 403,
    headers: {
      "content-type": "application/json",
      "x-registry-proxy": "githead-guard/1.0",
      "x-registry-proxy-action": "blocked",
      "x-registry-proxy-blocked": `${pkgName}@${version}`,
    },
  });
}

export function blockResponseMulti(pkgName, versionsToBlock, allFindings, enabledChecks) {
  const blocked = [...versionsToBlock];
  const label = blocked.length === 1
    ? `${pkgName}@${blocked[0]}`
    : `${pkgName} (${blocked.map(v => `@${v}`).join(", ")})`;

  const findingsText = allFindings
    .filter(f => versionsToBlock.has(f.version))
    .map(f => `    [${f.severity}] #${f.num} ${f.check} (${f.version}): ${f.message}`)
    .join("\n");
  const checksUsed = [...enabledChecks].sort((a, b) => a - b).join(",");

  const message = [
    ``,
    `══════════════════════════════════════════════════════════════`,
    `  BLOCKED by npm-githead-guard`,
    `══════════════════════════════════════════════════════════════`,
    ``,
    `  Package:  ${label}`,
    `  Checks:   ${checksUsed}`,
    ``,
    `  One or more dist-tag versions failed security checks:`,
    ``,
    findingsText,
    ``,
    `  What you should do:`,
    `    1. Do NOT install these versions.`,
    `    2. Check the package's GitHub releases/tags.`,
    `    3. Pin to the last known-good version.`,
    `    4. Report to npm: https://docs.npmjs.com/reporting-malware`,
    ``,
    `══════════════════════════════════════════════════════════════`,
    ``,
  ].join("\n");

  return new Response(JSON.stringify({ error: message }), {
    status: 403,
    headers: {
      "content-type": "application/json",
      "x-registry-proxy": "githead-guard/1.0",
      "x-registry-proxy-action": "blocked",
      "x-registry-proxy-blocked": blocked.map(v => `${pkgName}@${v}`).join(", "),
    },
  });
}
```

- [ ] **Step 2: Commit**

```bash
git add src/responses.js
git commit -m "refactor: extract responses module"
```

---

## Task 6: Create `src/handlers.js`

**Files:**
- Create: `src/handlers.js`

- [ ] **Step 1: Create the file**

```js
import { UPSTREAM, CORGI_HEADERS, DEFAULT_HEADERS, MAX_PACKUMENT_BYTES } from "./constants.js";
import { compareSemver, highestSeverity, log } from "./utils.js";
import { extractRepoUrl, parseRepoUrl } from "./git.js";
import { runChecks } from "./checks.js";
import {
  passthrough, rawResponse, rawResponseDirect, jsonResponse,
  blockResponse, blockResponseMulti, warningHeaders,
} from "./responses.js";

export async function checkViaCorgi(npmPath, enabledChecks) {
  let corgi;
  try {
    const corgiRes = await fetch(UPSTREAM + npmPath, { headers: CORGI_HEADERS });
    corgi = await corgiRes.json();
  } catch {
    return null;
  }

  const distTags = corgi["dist-tags"];
  if (!distTags || typeof distTags !== "object") return null;

  const pkgName = corgi.name || npmPath.replace(/^\//, "");
  const distTagVersions = new Set(Object.values(distTags));

  const allVersionKeys = corgi.versions ? Object.keys(corgi.versions) : [];
  const allVersionsSorted = allVersionKeys.sort(compareSemver);
  const versionIndex = new Map();
  for (let i = 0; i < allVersionsSorted.length; i++) {
    versionIndex.set(allVersionsSorted[i], i);
  }

  const versionsToFetch = new Set();
  const priorVersionMap = new Map();

  for (const version of distTagVersions) {
    versionsToFetch.add(version);
    const idx = versionIndex.get(version);
    if (idx > 0) {
      const prior = allVersionsSorted[idx - 1];
      versionsToFetch.add(prior);
      priorVersionMap.set(version, prior);
    }
  }

  const versionDocs = new Map();
  await Promise.all([...versionsToFetch].map(async (version) => {
    try {
      const res = await fetch(UPSTREAM + npmPath + "/" + version, { headers: DEFAULT_HEADERS });
      if (res.ok) versionDocs.set(version, await res.json());
    } catch {}
  }));

  let repoUrl = extractRepoUrl(corgi);
  if (!repoUrl) {
    for (const doc of versionDocs.values()) {
      repoUrl = extractRepoUrl(doc);
      if (repoUrl) break;
    }
  }
  const repoParsed = repoUrl ? parseRepoUrl(repoUrl) : null;

  const allFindings = [];
  const versionsToBlock = new Set();

  for (const version of distTagVersions) {
    const meta = versionDocs.get(version);
    if (!meta) continue;

    const priorVersion = priorVersionMap.get(version);
    const priorMeta = priorVersion ? versionDocs.get(priorVersion) : null;
    const findings = await runChecks(meta, priorMeta, repoUrl, repoParsed, enabledChecks);

    if (findings.length > 0) {
      const maxSev = highestSeverity(findings);
      const id = `${pkgName}@${version}`;
      for (const f of findings) allFindings.push({ ...f, version, id });
      if (maxSev === "CRITICAL" || maxSev === "HIGH") versionsToBlock.add(version);
    }
  }

  return { allFindings, versionsToBlock, pkgName };
}

export async function handleSmallPayload(upstreamRes, npmPath, mode, enabledChecks) {
  let rawText;
  let body;
  try {
    rawText = await upstreamRes.text();
    if (rawText.length > MAX_PACKUMENT_BYTES) {
      return handleLargePackumentFallback(rawText, upstreamRes, npmPath, mode, enabledChecks);
    }
    body = JSON.parse(rawText);
  } catch {
    log("skip", npmPath, mode, enabledChecks, { reason: "json-parse-error" });
    return new Response(rawText || "", {
      status: upstreamRes.status,
      headers: upstreamRes.headers,
    });
  }

  // Single version doc
  if (body.version && !body.versions) {
    const pkgName = body.name || "";
    const version = body.version;
    const repoUrl = extractRepoUrl(body);
    const repoParsed = repoUrl ? parseRepoUrl(repoUrl) : null;
    const findings = await runChecks(body, null, repoUrl, repoParsed, enabledChecks);

    if (findings.length === 0) {
      log("pass", `${pkgName}@${version}`, mode, enabledChecks);
      return rawResponse(rawText, upstreamRes);
    }

    const maxSev = highestSeverity(findings);
    if (mode === "block" && (maxSev === "CRITICAL" || maxSev === "HIGH")) {
      log("block", `${pkgName}@${version}`, mode, enabledChecks, { findings });
      return blockResponse(pkgName, version, findings, enabledChecks);
    }
    log("warn", `${pkgName}@${version}`, mode, enabledChecks, { findings });
    return rawResponse(rawText, upstreamRes, warningHeaders(findings, mode));
  }

  // Full packument
  if (!body.versions || typeof body.versions !== "object") {
    log("pass", body.name || npmPath.replace(/^\//, ""), mode, enabledChecks, { reason: "no-versions-object" });
    return rawResponse(rawText, upstreamRes);
  }

  const pkgName = body.name || npmPath.replace(/^\//, "");
  const repoUrl = extractRepoUrl(body);
  const repoParsed = repoUrl ? parseRepoUrl(repoUrl) : null;

  const distTagVersions = body["dist-tags"]
    ? new Set(Object.values(body["dist-tags"]))
    : new Set();

  const allVersionsSorted = Object.keys(body.versions).sort(compareSemver);
  const versionIndex = new Map();
  for (let i = 0; i < allVersionsSorted.length; i++) {
    versionIndex.set(allVersionsSorted[i], i);
  }

  const allFindings = [];
  const versionsToBlock = new Set();

  for (const version of distTagVersions) {
    const meta = body.versions[version];
    if (!meta) continue;

    const idx = versionIndex.get(version);
    const priorMeta = idx > 0 ? body.versions[allVersionsSorted[idx - 1]] : null;
    const findings = await runChecks(meta, priorMeta, repoUrl, repoParsed, enabledChecks);

    if (findings.length > 0) {
      const maxSev = highestSeverity(findings);
      const id = `${pkgName}@${version}`;
      for (const f of findings) allFindings.push({ ...f, version, id });
      if (maxSev === "CRITICAL" || maxSev === "HIGH") versionsToBlock.add(version);
    }
  }

  if (allFindings.length === 0) {
    log("pass", pkgName, mode, enabledChecks);
    return rawResponse(rawText, upstreamRes);
  }

  if (mode === "warn") {
    log("warn", pkgName, mode, enabledChecks, { findings: allFindings });
    return rawResponse(rawText, upstreamRes, warningHeaders(allFindings, "warn"));
  }

  for (const v of versionsToBlock) {
    delete body.versions[v];
    if (body.time) delete body.time[v];
  }
  if (body["dist-tags"]) {
    for (const [tag, tagVer] of Object.entries(body["dist-tags"])) {
      if (versionsToBlock.has(tagVer)) delete body["dist-tags"][tag];
    }
  }

  if (versionsToBlock.size > 0) {
    log("block", pkgName, mode, enabledChecks, {
      blockedVersions: [...versionsToBlock],
      findings: allFindings.filter(f => versionsToBlock.has(f.version)),
    });
  } else {
    log("warn", pkgName, mode, enabledChecks, { findings: allFindings });
  }
  return jsonResponse(body, upstreamRes, warningHeaders(allFindings, "block"));
}

export async function handleLargePackument(fullPackumentRes, npmPath, mode, enabledChecks) {
  const result = await checkViaCorgi(npmPath, enabledChecks);
  if (!result) {
    log("skip", npmPath, mode, enabledChecks, { reason: "corgi fetch failed, checks not applied" });
    return passthrough(fullPackumentRes, {
      "x-registry-proxy-skipped": "corgi fetch failed, checks not applied",
    });
  }

  const { allFindings, versionsToBlock, pkgName } = result;

  if (allFindings.length === 0) {
    log("pass", pkgName, mode, enabledChecks);
    return passthrough(fullPackumentRes);
  }

  if (mode === "warn") {
    log("warn", pkgName, mode, enabledChecks, { findings: allFindings });
    return passthrough(fullPackumentRes, warningHeaders(allFindings, "warn"));
  }

  log("block", pkgName, mode, enabledChecks, {
    blockedVersions: [...versionsToBlock],
    findings: allFindings.filter(f => versionsToBlock.has(f.version)),
  });
  return blockResponseMulti(pkgName, versionsToBlock, allFindings, enabledChecks);
}

export async function handleLargePackumentFallback(rawText, upstreamRes, npmPath, mode, enabledChecks) {
  const result = await checkViaCorgi(npmPath, enabledChecks);
  if (!result) {
    log("skip", npmPath, mode, enabledChecks, { reason: "corgi fetch failed, checks not applied" });
    return rawResponseDirect(rawText, upstreamRes, {
      "x-registry-proxy-skipped": "corgi fetch failed, checks not applied",
    });
  }

  const { allFindings, versionsToBlock, pkgName } = result;

  if (allFindings.length === 0) {
    log("pass", pkgName, mode, enabledChecks);
    return rawResponseDirect(rawText, upstreamRes);
  }

  if (mode === "warn") {
    log("warn", pkgName, mode, enabledChecks, { findings: allFindings });
    return rawResponseDirect(rawText, upstreamRes, warningHeaders(allFindings, "warn"));
  }

  log("block", pkgName, mode, enabledChecks, {
    blockedVersions: [...versionsToBlock],
    findings: allFindings.filter(f => versionsToBlock.has(f.version)),
  });
  return blockResponseMulti(pkgName, versionsToBlock, allFindings, enabledChecks);
}
```

- [ ] **Step 2: Commit**

```bash
git add src/handlers.js
git commit -m "refactor: extract handlers module"
```

---

## Task 7: Rewrite `src/index.js`

**Files:**
- Modify: `src/index.js` (replace entire contents)

- [ ] **Step 1: Replace the entire file**

```js
import { ALL_CHECK_IDS, UPSTREAM, MAX_PACKUMENT_BYTES } from "./constants.js";
import { log } from "./utils.js";
import { passthrough } from "./responses.js";
import { handleSmallPayload, handleLargePackument } from "./handlers.js";

function parseProxyUrl(pathname) {
  const segments = pathname.split("/").filter(Boolean);
  let mode = "block";
  const checkIds = [];
  let consumed = 0;

  for (const seg of segments) {
    const lower = seg.toLowerCase();
    if (lower === "block" || lower === "warn") {
      mode = lower;
      consumed++;
    } else if (/^\d+$/.test(seg)) {
      const n = parseInt(seg, 10);
      if (ALL_CHECK_IDS.has(n)) {
        checkIds.push(n);
        consumed++;
      } else {
        break;
      }
    } else {
      break;
    }
  }

  const npmPath = "/" + segments.slice(consumed).join("/");
  const enabledChecks = checkIds.length > 0 ? new Set(checkIds) : ALL_CHECK_IDS;

  return { mode, enabledChecks, npmPath };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { mode, enabledChecks, npmPath } = parseProxyUrl(url.pathname);

    const isTarball = npmPath.includes("/-/") && request.method === "GET";

    const upstreamURL = UPSTREAM + npmPath + url.search;
    const reqHeaders = new Headers(request.headers);
    reqHeaders.set("Host", "registry.npmjs.org");

    const fetchOpts = {
      method: request.method,
      headers: reqHeaders,
      body: request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
      redirect: "follow",
    };
    if (isTarball) {
      fetchOpts.cf = { cacheEverything: true, cacheTtl: 86400 * 30 };
    }

    const upstreamRes = await fetch(upstreamURL, fetchOpts);

    const ct = upstreamRes.headers.get("content-type") || "";
    const isJSON = ct.includes("application/json") || ct.includes("application/vnd.npm.install");
    if (request.method !== "GET" || !isJSON || isTarball) {
      log("pass", npmPath, mode, enabledChecks, { reason: "passthrough" });
      return passthrough(upstreamRes);
    }

    const contentLength = parseInt(upstreamRes.headers.get("content-length") || "0", 10);

    if (contentLength > MAX_PACKUMENT_BYTES) {
      return handleLargePackument(upstreamRes, npmPath, mode, enabledChecks);
    }

    return handleSmallPayload(upstreamRes, npmPath, mode, enabledChecks);
  },
};
```

- [ ] **Step 2: Build-check — verify Wrangler can bundle the split modules**

```bash
npx wrangler deploy --dry-run --outdir /tmp/spxy-build
```

Expected: output like `Total Upload: XX KiB / gzip: XX KiB` with no errors. If you see `Cannot find module` or `SyntaxError`, check the import paths in the file reported.

- [ ] **Step 3: Commit**

```bash
git add src/index.js
git commit -m "refactor: slim index.js to entry point, wire up module imports"
```

---

## Task 8: Smoke Test

- [ ] **Step 1: Start the local dev server**

```bash
npx wrangler dev
```

Expected: `Ready on http://localhost:8787`

- [ ] **Step 2: Verify a clean pass request**

```bash
curl -s http://localhost:8787/is-odd | head -c 200
```

Expected: JSON packument data starting with `{"_id":"is-odd"` (or similar npm metadata). No `403`.

- [ ] **Step 3: Verify structured logging appears in the wrangler dev output**

Look for a line like:
```json
{"ts":"...","action":"pass","pkg":"/is-odd","mode":"block","checks":[0],"reason":"passthrough"}
```
or (for the packument response):
```json
{"ts":"...","action":"pass","pkg":"is-odd","mode":"block","checks":[0]}
```

- [ ] **Step 4: Commit if smoke test passed (nothing to commit — already committed in Task 7)**

No commit needed. The refactor is complete.
