/**
 * The permission rubric: what each browser-extension permission actually
 * lets an attacker do, graded by worst-case impact. Severities follow the
 * documented rubric (docs/rubric.md): the grade reflects what the
 * permission *enables*, not what the extension claims to use it for —
 * a compromised update inherits every granted permission.
 */
import type { Finding, Severity } from "./types.js";
import { severityRank } from "./types.js";
import type { ManifestSummary } from "./manifest.js";

/** One graded permission (API name or host pattern). */
export interface PermissionAssessment {
  permission: string;
  kind: "api" | "host";
  optional: boolean;
  severity: Severity;
  reason: string;
}

/** API permission grades. Unlisted permissions grade as info. */
const API_GRADES: Record<string, { severity: Severity; reason: string }> = {
  debugger: { severity: "critical", reason: "full DevTools protocol control over any tab: read/inject anything" },
  proxy: { severity: "critical", reason: "can route all browser traffic through an attacker-chosen proxy" },
  nativeMessaging: { severity: "high", reason: "talks to native binaries outside the browser sandbox" },
  cookies: { severity: "high", reason: "reads cookies (session tokens) for permitted hosts" },
  history: { severity: "high", reason: "reads the full browsing history" },
  webRequest: { severity: "medium", reason: "observes network requests for permitted hosts" },
  webRequestBlocking: { severity: "high", reason: "can modify or cancel network requests in flight" },
  management: { severity: "high", reason: "can enumerate and disable other extensions (incl. blockers)" },
  privacy: { severity: "high", reason: "can flip browser privacy settings" },
  contentSettings: { severity: "high", reason: "can change per-site security settings (JS, camera, popups)" },
  pageCapture: { severity: "high", reason: "can snapshot the full content of any permitted page" },
  desktopCapture: { severity: "high", reason: "can capture the screen beyond the browser" },
  tabCapture: { severity: "high", reason: "can record audio/video of tabs" },
  clipboardRead: { severity: "high", reason: "reads the clipboard (passwords travel through it)" },
  geolocation: { severity: "high", reason: "reads the device's physical location" },
  declarativeNetRequestWithHostAccess: { severity: "high", reason: "rewrites requests on hosts it has access to" },
  browsingData: { severity: "medium", reason: "can wipe history/cookies (covering tracks)" },
  declarativeNetRequest: { severity: "medium", reason: "installs rules that redirect or block requests" },
  scripting: { severity: "medium", reason: "injects scripts into permitted pages" },
  tabs: { severity: "medium", reason: "sees URL and title of every open tab" },
  webNavigation: { severity: "medium", reason: "observes every navigation event" },
  downloads: { severity: "medium", reason: "can start and manage downloads" },
  bookmarks: { severity: "medium", reason: "reads and edits bookmarks" },
  topSites: { severity: "medium", reason: "reads the most-visited sites list" },
  sessions: { severity: "medium", reason: "reads recently closed tabs and devices" },
  identity: { severity: "medium", reason: "can obtain OAuth tokens for the signed-in user" },
  clipboardWrite: { severity: "low", reason: "writes the clipboard (paste-hijack vector)" },
  notifications: { severity: "low", reason: "can show OS notifications (phishing surface)" },
  activeTab: { severity: "low", reason: "temporary access to the current tab after a user gesture" },
  unlimitedStorage: { severity: "low", reason: "unbounded local storage" },
  storage: { severity: "info", reason: "extension-local key-value storage" },
  alarms: { severity: "info", reason: "timers for background work" },
  contextMenus: { severity: "info", reason: "adds right-click menu items" },
  offscreen: { severity: "info", reason: "runs an offscreen document" },
  idle: { severity: "info", reason: "detects user idle state" },
};

/** Grade a host match pattern by how much of the web it opens up. */
export function classifyHostPattern(pattern: string): { severity: Severity; reason: string } {
  if (pattern === "<all_urls>") {
    return { severity: "critical", reason: "read and modify data on every website" };
  }
  const m = /^(\*|https?|wss?|ftp|file|chrome-extension):\/\/([^/]*)(\/.*)?$/.exec(pattern);
  if (!m) return { severity: "low", reason: "unrecognized match pattern" };
  const scheme = m[1] as string;
  const host = m[2] as string;
  if (scheme === "file") {
    return { severity: "high", reason: "access to local files opened in the browser" };
  }
  if (host === "*" || host === "") {
    return { severity: "critical", reason: "read and modify data on every website" };
  }
  if (host.startsWith("*.")) {
    return { severity: "medium", reason: `every subdomain of ${host.slice(2)}` };
  }
  return { severity: "low", reason: `single host: ${host}` };
}

function isBroadHost(pattern: string): boolean {
  return classifyHostPattern(pattern).severity === "critical";
}

/** Grade every declared permission. Optional grants step down one level. */
export function assessPermissions(m: ManifestSummary): PermissionAssessment[] {
  const out: PermissionAssessment[] = [];
  const stepDown = (s: Severity): Severity =>
    s === "critical" ? "high" : s === "high" ? "medium" : s === "medium" ? "low" : "info";

  const push = (permission: string, kind: "api" | "host", optional: boolean) => {
    const grade =
      kind === "api"
        ? (API_GRADES[permission] ?? {
            severity: "info" as Severity,
            reason: "not in the rubric (browser-specific or unrecognized)",
          })
        : classifyHostPattern(permission);
    out.push({
      permission,
      kind,
      optional,
      severity: optional ? stepDown(grade.severity) : grade.severity,
      reason: optional ? `${grade.reason} (optional: requestable at runtime)` : grade.reason,
    });
  };

  for (const p of m.apiPermissions) push(p, "api", false);
  for (const p of m.hostPermissions) push(p, "host", false);
  for (const p of m.optionalApiPermissions) push(p, "api", true);
  for (const p of m.optionalHostPermissions) push(p, "host", true);
  return out;
}

/**
 * Turn graded permissions into findings. Individual permissions of grade
 * medium or worse each yield one finding; two combinations that together
 * amount to full traffic or session compromise are escalated explicitly.
 */
export function permissionFindings(m: ManifestSummary): Finding[] {
  const findings: Finding[] = [];
  const assessments = assessPermissions(m);

  for (const a of assessments) {
    if (severityRank(a.severity) < severityRank("medium")) continue;
    findings.push({
      rule: a.kind === "host" ? "PERM_HOST" : "PERM_API",
      severity: a.severity,
      category: "permissions",
      title: `${a.optional ? "optional " : ""}permission: ${a.permission}`,
      detail: a.reason,
      file: "manifest.json",
    });
  }

  const api = new Set(m.apiPermissions);
  const broadHost = m.hostPermissions.some(isBroadHost);
  // Content scripts matching <all_urls> grant the same reach as a broad
  // host permission — code runs inside every page.
  const broadContentScript = m.contentScripts.some((cs) => cs.matches.some(isBroadHost));

  if (api.has("webRequest") && api.has("webRequestBlocking") && broadHost) {
    findings.push({
      rule: "PERM_COMBO_INTERCEPT",
      severity: "critical",
      category: "permissions",
      title: "combination: webRequest + webRequestBlocking + broad hosts",
      detail: "can observe, modify and cancel all web traffic in flight — proxy-grade interception",
      file: "manifest.json",
    });
  }
  if (api.has("cookies") && broadHost) {
    findings.push({
      rule: "PERM_COMBO_COOKIES",
      severity: "critical",
      category: "permissions",
      title: "combination: cookies + broad hosts",
      detail: "can read session cookies for every site — account-takeover grade",
      file: "manifest.json",
    });
  }
  if (broadContentScript) {
    findings.push({
      rule: "PERM_CONTENT_SCRIPT_ALL",
      severity: "high",
      category: "permissions",
      title: "content script injected into every website",
      detail: `content_scripts matches ${m.contentScripts
        .flatMap((cs) => cs.matches.filter(isBroadHost))
        .join(", ")} — code runs inside every page the user visits`,
      file: "manifest.json",
    });
  }
  return findings;
}
