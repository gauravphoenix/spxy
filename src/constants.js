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
