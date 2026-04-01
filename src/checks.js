import { SUSPICIOUS_EMAIL_DOMAINS, TRUSTED_TARBALL_HOSTS, CI_PUBLISHER_RE } from "./constants.js";
import { hasValidGitHead, hasProvenanceSignatures, highestSeverity } from "./utils.js";
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

  // 2: gitHead verification (network, deferred to end)

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
      const priorOwner = priorParsed?.owner?.toLowerCase() || "";
      const currOwner = repoParsed?.owner?.toLowerCase() || "";
      const priorHost = priorParsed?.host || "";
      const currHost = repoParsed?.host || "";
      if (priorHost !== currHost || priorOwner !== currOwner) {
        findings.push({ severity: "MEDIUM", check: "repo-url-changed", num: 106,
          message: `Repo URL changed from ${priorRepoUrl} to ${repoUrl}` });
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
    if (publisherName && !CI_PUBLISHER_RE.test(publisherName) &&
        Array.isArray(maintainers) && maintainers.length > 0) {
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
  //      Elevated to HIGH when gitHead is also missing (stronger signal)
  if (enabledChecks.has(204) && !repoUrl) {
    if (!hasValidGitHead(meta) && !hasProvenanceSignatures(meta)) {
      findings.push({ severity: "HIGH", check: "missing-repository", num: 204,
        message: "Package has no repository field and no gitHead — source cannot be verified" });
      blocked = true;
    } else {
      findings.push(finding(204, "missing-repository",
        "Package has no repository field — source cannot be verified"));
    }
  }

  // ── Network checks (cached, skipped if already blocked) ────────────

  const needsCheck2 = enabledChecks.has(2) && repoUrl && repoParsed?.host && hasValidGitHead(meta);
  const needsCheck105 = enabledChecks.has(105) && repoUrl && repoParsed?.host && meta.version;

  if (!blocked && (needsCheck2 || needsCheck105)) {
    const promises = [];
    if (needsCheck2) promises.push(cachedVerifyCommit(repoParsed, meta.gitHead));
    if (needsCheck105) promises.push(cachedVerifyTag(repoParsed, meta.version, meta.name));

    if (promises.length > 0) {
      const results = await Promise.all(promises);
      let ri = 0;

      if (needsCheck2) {
        const r = results[ri];
        if (r === false) {
          findings.push({ severity: "MEDIUM", check: "githead-verification", num: 2,
            message: `gitHead ${meta.gitHead} does not exist in ${repoUrl}` });
        } else if (r === null) {
          findings.push(finding(203, "githead-verification-unavailable",
            `Could not verify gitHead ${meta.gitHead} — git host unreachable`));
        }
        ri++;
      }

      if (needsCheck105) {
        const r = results[ri];
        if (r === false) {
          findings.push({ severity: "MEDIUM", check: "missing-git-tag", num: 105,
            message: `No git tag for v${meta.version}, ${meta.version}, or ${meta.name}@${meta.version} in ${repoUrl}` });
        } else if (r === null) {
          findings.push(finding(203, "tag-verification-unavailable",
            `Could not verify git tag for ${meta.version} — git host unreachable`));
        }
      }
    }
  }

  return findings;
}
