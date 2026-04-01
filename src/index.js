/**
 * npm-githead-guard — Cloudflare Worker
 *
 * A paranoid npm registry proxy that inspects package metadata for signs
 * of supply-chain compromise. All configuration lives in the URL.
 *
 * URL format:
 *   https://proxy.dev/<mode?>/<check-numbers...>/<npm-path>
 *
 *   /block/1/3/101/104/axios   → block mode, checks 1, 3, 101, 104
 *   /warn/1/101/axios          → warn mode, checks 1, 101
 *   /axios                     → block mode, all checks
 *
 * See src/constants.js for the full check catalog.
 */

import { UPSTREAM, MAX_PACKUMENT_BYTES, ALL_CHECK_IDS } from "./constants.js";
import { log } from "./utils.js";
import { setGithubToken } from "./git.js";
import { passthrough } from "./responses.js";
import { handleSmallPayload, handleLargePackument } from "./handlers.js";

function parseProxyUrl(pathname) {
  const segments = pathname.split("/").filter(Boolean);
  let mode = "block";
  const checkIds = [];
  const allowedChecks = new Set();
  let consumed = 0;

  for (const seg of segments) {
    const lower = seg.toLowerCase();
    if (lower === "block" || lower === "warn") {
      mode = lower;
      consumed++;
    } else if (/^\d+-allow$/.test(lower)) {
      const n = parseInt(seg, 10);
      if (ALL_CHECK_IDS.has(n)) {
        allowedChecks.add(n);
        consumed++;
      } else {
        break;
      }
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

  return { mode, enabledChecks, allowedChecks, npmPath };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const authMode = (env.AUTH_MODE || "on").toLowerCase();
    const isAuthExempt = url.pathname.startsWith("/-/npm/");
    if (authMode === "on" && !isAuthExempt) {
      if (!env.AUTH_TOKEN) {
        return new Response(JSON.stringify({
          error: [
            "",
            "npm-githead-guard: authentication is enabled but no AUTH_TOKEN is configured.",
            "",
            "To set a token:",
            "  npx wrangler secret put AUTH_TOKEN",
            "",
            "To disable authentication:",
            "  npx wrangler secret put AUTH_MODE   (enter: off)",
            "",
            "For local dev, add to .dev.vars:",
            "  AUTH_TOKEN=your-secret-token",
            "",
          ].join("\n"),
        }), { status: 500, headers: { "content-type": "application/json" } });
      }

      const authHeader = request.headers.get("authorization") || "";
      const token = authHeader.startsWith("Bearer ")
        ? authHeader.slice(7)
        : request.headers.get("npm-auth-token") || "";
      if (token !== env.AUTH_TOKEN) {
        return new Response(JSON.stringify({
          error: "Unauthorized. Set your auth token in .npmrc:\n\n"
            + "  //your-proxy.workers.dev/:_authToken=YOUR_TOKEN\n",
        }), { status: 401, headers: { "content-type": "application/json" } });
      }
    }

    setGithubToken(env.GITHUB_TOKEN || null);
    const { mode, enabledChecks, allowedChecks, npmPath } = parseProxyUrl(url.pathname);

    const isTarball = npmPath.includes("/-/") && request.method === "GET";

    const upstreamURL = UPSTREAM + npmPath + url.search;
    const reqHeaders = new Headers(request.headers);
    reqHeaders.set("Host", "registry.npmjs.org");

    const isPassthrough = request.method !== "GET" || isTarball;
    if (!isPassthrough) {
      reqHeaders.delete("if-none-match");
      reqHeaders.delete("if-modified-since");
    }

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
      return handleLargePackument(upstreamRes, npmPath, mode, enabledChecks, allowedChecks);
    }

    return handleSmallPayload(upstreamRes, npmPath, mode, enabledChecks, allowedChecks);
  },
};
