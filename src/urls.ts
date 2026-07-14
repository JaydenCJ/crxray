/**
 * Endpoint extraction and classification.
 *
 * Every http(s)/ws(s) URL literal in the package's text files is pulled
 * out, deduplicated, and classified: known tracker networks, hardcoded
 * raw-IP endpoints (no DNS trail, a classic C2 pattern), punycode hosts
 * (homograph risk), plaintext transports, loopback. Classification feeds
 * findings; the full list is available via `crxray urls`.
 */
import type { Finding, Severity } from "./types.js";
import { lookupTracker, type TrackerCategory } from "./trackers.js";

/** How an endpoint is judged. Exactly one kind per endpoint. */
export type EndpointKind =
  | "tracker"
  | "raw-ip"
  | "punycode"
  | "insecure-ws"
  | "insecure-http"
  | "loopback"
  | "plain";

/** One distinct endpoint with every file it appears in. */
export interface Endpoint {
  url: string;
  scheme: string;
  host: string;
  kind: EndpointKind;
  trackerCategory?: TrackerCategory;
  files: string[];
}

const URL_RE = /\b(?:https?|wss?):\/\/[^\s"'`<>\\)}\],;]+/g;

/** Extract URL literals from text, trimming trailing punctuation. */
export function extractUrls(text: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(text)) !== null) {
    const url = m[0].replace(/[.,;:!?'")\]}]+$/, "");
    // Require something after "://" beyond a bare scheme.
    if (/:\/\/./.test(url)) out.push(url);
  }
  return out;
}

/** Pull scheme and host (lowercased, port stripped) out of a URL string. */
export function splitUrl(url: string): { scheme: string; host: string } | null {
  const m = /^([a-z]+):\/\/([^/?#]+)/i.exec(url);
  if (!m) return null;
  let host = (m[2] as string).toLowerCase();
  const at = host.lastIndexOf("@"); // strip credentials
  if (at !== -1) host = host.slice(at + 1);
  host = host.replace(/:\d+$/, "");
  return { scheme: (m[1] as string).toLowerCase(), host };
}

const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

function isLoopback(host: string): boolean {
  return (
    host === "localhost" ||
    host === "[::1]" ||
    host.startsWith("127.") ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".test")
  );
}

function classify(scheme: string, host: string): { kind: EndpointKind; trackerCategory?: TrackerCategory } {
  const tracker = lookupTracker(host);
  if (tracker !== null) return { kind: "tracker", trackerCategory: tracker };
  if (isLoopback(host)) return { kind: "loopback" };
  if (IPV4_RE.test(host) || host.startsWith("[")) return { kind: "raw-ip" };
  if (host.split(".").some((label) => label.startsWith("xn--"))) return { kind: "punycode" };
  if (scheme === "ws") return { kind: "insecure-ws" };
  if (scheme === "http") return { kind: "insecure-http" };
  return { kind: "plain" };
}

/**
 * Deduplicate and classify per-file URL lists into distinct endpoints,
 * sorted by URL for deterministic output.
 */
export function collectEndpoints(perFile: { file: string; urls: string[] }[]): Endpoint[] {
  const byUrl = new Map<string, Endpoint>();
  for (const { file, urls } of perFile) {
    for (const url of urls) {
      const parts = splitUrl(url);
      if (parts === null) continue;
      let ep = byUrl.get(url);
      if (ep === undefined) {
        ep = { url, ...parts, ...classify(parts.scheme, parts.host), files: [] };
        byUrl.set(url, ep);
      }
      if (!ep.files.includes(file)) ep.files.push(file);
    }
  }
  return [...byUrl.values()].sort((a, b) => (a.url < b.url ? -1 : a.url > b.url ? 1 : 0));
}

const TRACKER_SEVERITY: Record<TrackerCategory, Severity> = {
  "session-replay": "high", // records what users see and type
  analytics: "medium",
  ads: "medium",
  push: "low",
  "error-tracking": "low",
};

/**
 * Findings from classified endpoints. One finding per distinct host (not
 * per URL) so a chatty SDK cannot flood the report, with loopback and
 * plain endpoints exempt.
 */
export function endpointFindings(endpoints: Endpoint[]): Finding[] {
  const findings: Finding[] = [];
  const seenHosts = new Set<string>();
  for (const ep of endpoints) {
    const hostKey = `${ep.kind}:${ep.host}`;
    if (seenHosts.has(hostKey)) continue;
    seenHosts.add(hostKey);
    const files = ep.files.join(", ");
    if (ep.kind === "tracker") {
      const category = ep.trackerCategory as TrackerCategory;
      findings.push({
        rule: "NET_TRACKER",
        severity: TRACKER_SEVERITY[category],
        category: "network",
        title: `${category} endpoint: ${ep.host}`,
        detail: `known ${category} network referenced from ${files}`,
        file: ep.files[0],
        evidence: ep.url,
      });
    } else if (ep.kind === "raw-ip") {
      findings.push({
        rule: "NET_RAW_IP",
        severity: "high",
        category: "network",
        title: `hardcoded IP endpoint: ${ep.host}`,
        detail: `numeric address leaves no DNS trail and dodges domain reputation — referenced from ${files}`,
        file: ep.files[0],
        evidence: ep.url,
      });
    } else if (ep.kind === "punycode") {
      findings.push({
        rule: "NET_PUNYCODE_HOST",
        severity: "medium",
        category: "network",
        title: `punycode hostname: ${ep.host}`,
        detail: `xn-- hosts can visually impersonate familiar domains — referenced from ${files}`,
        file: ep.files[0],
        evidence: ep.url,
      });
    } else if (ep.kind === "insecure-ws") {
      findings.push({
        rule: "NET_INSECURE_WS",
        severity: "medium",
        category: "network",
        title: `unencrypted WebSocket: ${ep.host}`,
        detail: `ws:// traffic is readable and modifiable on-path — referenced from ${files}`,
        file: ep.files[0],
        evidence: ep.url,
      });
    } else if (ep.kind === "insecure-http") {
      findings.push({
        rule: "NET_INSECURE_HTTP",
        severity: "low",
        category: "network",
        title: `plaintext http endpoint: ${ep.host}`,
        detail: `unencrypted transport — referenced from ${files}`,
        file: ep.files[0],
        evidence: ep.url,
      });
    }
  }
  return findings;
}
