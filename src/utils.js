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
