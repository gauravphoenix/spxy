import { UPSTREAM, MAX_PACKUMENT_BYTES, CORGI_HEADERS, DEFAULT_HEADERS } from "./constants.js";
import { compareSemver, highestSeverity, log } from "./utils.js";
import { extractRepoUrl, parseRepoUrl } from "./git.js";
import { runChecks } from "./checks.js";
import {
  passthrough, rawResponse, rawResponseDirect, jsonResponse,
  blockResponse, blockResponseMulti, warningHeaders,
} from "./responses.js";

function filterAllowed(findings, allowedChecks) {
  if (!allowedChecks || allowedChecks.size === 0) return findings;
  return findings.filter(f => !allowedChecks.has(f.num));
}

export async function checkViaCorgi(npmPath, enabledChecks, allowedChecks) {
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
  const latestVersion = distTags.latest;
  if (!latestVersion) return null;
  const distTagVersions = new Set([latestVersion]);

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
    const rawFindings = await runChecks(meta, priorMeta, repoUrl, repoParsed, enabledChecks);
    const findings = filterAllowed(rawFindings, allowedChecks);

    if (findings.length > 0) {
      const maxSev = highestSeverity(findings);
      const id = `${pkgName}@${version}`;
      for (const f of findings) allFindings.push({ ...f, version, id });
      if (maxSev === "CRITICAL" || maxSev === "HIGH") versionsToBlock.add(version);
    }
  }

  return { allFindings, versionsToBlock, pkgName };
}

export async function handleSmallPayload(upstreamRes, npmPath, mode, enabledChecks, allowedChecks) {
  let rawText;
  let body;
  try {
    rawText = await upstreamRes.text();
    if (rawText.length > MAX_PACKUMENT_BYTES) {
      return handleLargePackumentFallback(rawText, upstreamRes, npmPath, mode, enabledChecks, allowedChecks);
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
    const rawFindings = await runChecks(body, null, repoUrl, repoParsed, enabledChecks);
    const findings = filterAllowed(rawFindings, allowedChecks);

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

  const latestVersion = body["dist-tags"]?.latest;
  const distTagVersions = latestVersion ? new Set([latestVersion]) : new Set();

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
    const rawFindings = await runChecks(meta, priorMeta, repoUrl, repoParsed, enabledChecks);
    const findings = filterAllowed(rawFindings, allowedChecks);

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

  if (versionsToBlock.size > 0) {
    log("block", pkgName, mode, enabledChecks, {
      blockedVersions: [...versionsToBlock],
      findings: allFindings.filter(f => versionsToBlock.has(f.version)),
    });
    return blockResponseMulti(pkgName, versionsToBlock, allFindings, enabledChecks);
  }

  log("warn", pkgName, mode, enabledChecks, { findings: allFindings });
  return rawResponse(rawText, upstreamRes, warningHeaders(allFindings, "block"));
}

export async function handleLargePackument(fullPackumentRes, npmPath, mode, enabledChecks, allowedChecks) {
  const result = await checkViaCorgi(npmPath, enabledChecks, allowedChecks);
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

  if (mode === "warn" || versionsToBlock.size === 0) {
    log("warn", pkgName, mode, enabledChecks, { findings: allFindings });
    return passthrough(fullPackumentRes, warningHeaders(allFindings, mode));
  }

  log("block", pkgName, mode, enabledChecks, {
    blockedVersions: [...versionsToBlock],
    findings: allFindings.filter(f => versionsToBlock.has(f.version)),
  });
  return blockResponseMulti(pkgName, versionsToBlock, allFindings, enabledChecks);
}

export async function handleLargePackumentFallback(rawText, upstreamRes, npmPath, mode, enabledChecks, allowedChecks) {
  const result = await checkViaCorgi(npmPath, enabledChecks, allowedChecks);
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

  if (mode === "warn" || versionsToBlock.size === 0) {
    log("warn", pkgName, mode, enabledChecks, { findings: allFindings });
    return rawResponseDirect(rawText, upstreamRes, warningHeaders(allFindings, mode));
  }

  log("block", pkgName, mode, enabledChecks, {
    blockedVersions: [...versionsToBlock],
    findings: allFindings.filter(f => versionsToBlock.has(f.version)),
  });
  return blockResponseMulti(pkgName, versionsToBlock, allFindings, enabledChecks);
}
