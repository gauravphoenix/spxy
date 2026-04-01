import {
  GITHUB_API, GITLAB_API, BITBUCKET_API, CODEBERG_API, SOURCEHUT_API,
  CACHE_ORIGIN, CACHE_VERSION, VERIFY_CACHE_TTL,
  GH_HEADERS, DEFAULT_HEADERS,
} from "./constants.js";

let _githubToken = null;
export function setGithubToken(token) { _githubToken = token; }

function gitHeaders(host) {
  const base = host === "github" ? GH_HEADERS : DEFAULT_HEADERS;
  if (host === "github" && _githubToken) {
    return { ...base, Authorization: `token ${_githubToken}` };
  }
  return base;
}

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
    const res = await fetch(url, { headers: gitHeaders(p.host) });
    if (res.status === 200) return true;
    if (res.status === 404) return false;
    return null; // rate limit, server error, etc. — inconclusive
  } catch { return null; }
}

export async function verifyTag(p, version, pkgName) {
  const tags = [`v${version}`, version];
  if (pkgName) tags.push(`${pkgName}@${version}`);
  try {
    for (const tag of tags) {
      const url = tagUrl(p, tag);
      if (!url) return null;
      const res = await fetch(url, { headers: gitHeaders(p.host) });
      if (res.status === 200) return true;
      if (res.status !== 404) return null; // rate limit, server error — inconclusive
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

export async function cachedVerifyTag(p, version, pkgName) {
  const cacheKey = `${CACHE_ORIGIN}/${CACHE_VERSION}/tag/${p.host}/${p.owner}/${p.repo}/${version}`;
  return cachedVerify(cacheKey, () => verifyTag(p, version, pkgName));
}
