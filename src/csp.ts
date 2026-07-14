/**
 * Content-Security-Policy forensics for extension manifests.
 *
 * The CSP is where MV2 extensions legally opened the remote-code door:
 * whitelisting an https origin in script-src let them <script src> code
 * that store review never saw. crxray parses the declared policy and
 * flags eval enablement, remote script origins and other weakenings.
 */
import type { Finding } from "./types.js";
import type { ManifestSummary } from "./manifest.js";

/** Parse a CSP string into directive → source list. Keys lowercased. */
export function parseCsp(policy: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const part of policy.split(";")) {
    const tokens = part.trim().split(/\s+/).filter((t) => t.length > 0);
    if (tokens.length === 0) continue;
    const name = (tokens[0] as string).toLowerCase();
    if (!map.has(name)) map.set(name, tokens.slice(1));
  }
  return map;
}

/** Sources for script execution: script-src, else default-src, else none. */
export function scriptSources(policy: string): string[] {
  const map = parseCsp(policy);
  return map.get("script-src") ?? map.get("default-src") ?? [];
}

const SAFE_SCRIPT_SOURCES = new Set([
  "'self'",
  "'none'",
  "'wasm-unsafe-eval'",
  "'unsafe-inline'", // graded separately below
  "'unsafe-eval'", // graded separately below
  "'report-sample'",
  "'strict-dynamic'",
]);

/** Audit the manifest-declared CSP for extension pages and sandbox. */
export function auditCsp(m: ManifestSummary): Finding[] {
  const findings: Finding[] = [];
  const policy = m.cspExtensionPages;
  if (policy === undefined) return findings;

  const sources = scriptSources(policy);
  const evidence = policy.length > 100 ? `${policy.slice(0, 100)}…` : policy;

  for (const src of sources) {
    const lower = src.toLowerCase();
    if (lower === "'unsafe-eval'") {
      findings.push({
        rule: "CSP_UNSAFE_EVAL",
        severity: "high",
        category: "csp",
        title: "CSP enables eval for extension pages",
        detail: "'unsafe-eval' in script-src lets any string become code — pairs badly with fetched data",
        file: "manifest.json",
        evidence,
      });
    } else if (lower === "'unsafe-inline'") {
      findings.push({
        rule: "CSP_UNSAFE_INLINE",
        severity: "low",
        category: "csp",
        title: "CSP attempts to allow inline script",
        detail: "'unsafe-inline' in script-src — browsers ignore it for extension pages, but it signals intent",
        file: "manifest.json",
        evidence,
      });
    } else if (lower.startsWith("blob:")) {
      findings.push({
        rule: "CSP_BLOB_SCRIPT",
        severity: "medium",
        category: "csp",
        title: "CSP allows blob: scripts",
        detail: "blob: in script-src lets dynamically assembled code run as a script",
        file: "manifest.json",
        evidence,
      });
    } else if (/^(https?|wss?|ftp):/.test(lower) || lower === "https:" || lower === "*") {
      findings.push({
        rule: "CSP_REMOTE_SCRIPT_SRC",
        severity: "critical",
        category: "csp",
        title: `CSP whitelists remote scripts from ${src}`,
        detail:
          "extension pages may load and run code from this origin — the code that runs is not the code that was reviewed",
        file: "manifest.json",
        evidence,
      });
    } else if (!SAFE_SCRIPT_SOURCES.has(lower) && !lower.startsWith("'sha") && !lower.startsWith("'nonce-")) {
      // Bare hostnames ("cdn.example.test") are scheme-less remote origins.
      if (/^[a-z0-9*][a-z0-9.*-]*(:\d+)?$/.test(lower)) {
        findings.push({
          rule: "CSP_REMOTE_SCRIPT_SRC",
          severity: "critical",
          category: "csp",
          title: `CSP whitelists remote scripts from ${src}`,
          detail:
            "extension pages may load and run code from this origin — the code that runs is not the code that was reviewed",
          file: "manifest.json",
          evidence,
        });
      }
    }
  }
  return findings;
}
