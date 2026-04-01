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
  const bypassHints = [...new Set(findings.map(f => f.num))].map(n => `${n}-allow`).join("/");

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
    `  To bypass a specific check (use with caution):`,
    `    npm --registry <proxy>/${bypassHints}/ i ${pkgName}`,
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
  const blockFindings = allFindings.filter(f => versionsToBlock.has(f.version));
  const bypassHints = [...new Set(blockFindings.map(f => f.num))].map(n => `${n}-allow`).join("/");

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
    `  To bypass a specific check (use with caution):`,
    `    npm --registry <proxy>/${bypassHints}/ i ${pkgName}`,
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
