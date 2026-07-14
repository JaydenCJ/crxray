/**
 * Tolerant manifest.json parsing and MV2/MV3 normalization.
 *
 * Chrome historically accepted // and block comments in manifests and many
 * shipped extensions carry them, so the parser strips comments (and
 * trailing commas) before JSON.parse — while recording that it had to,
 * because a manifest that only parses leniently is itself weak evidence.
 * The normalizer folds the MV2/MV3 and Chrome/Firefox differences into one
 * shape the rest of the pipeline consumes.
 */

export class ManifestError extends Error {}

/** One content-script injection group. */
export interface ContentScriptRef {
  matches: string[];
  js: string[];
}

/** Manifest facts, normalized across MV2/MV3 and Chrome/Firefox. */
export interface ManifestSummary {
  name: string;
  version: string;
  manifestVersion: number;
  /** API permissions (e.g. "cookies"), required. */
  apiPermissions: string[];
  /** API permissions the extension may request later. */
  optionalApiPermissions: string[];
  /** Host match patterns, required (MV2 mixes them into `permissions`). */
  hostPermissions: string[];
  /** Host match patterns requestable later. */
  optionalHostPermissions: string[];
  contentScripts: ContentScriptRef[];
  /** Background entry points: service worker, scripts or page. */
  background: { kind: "service_worker" | "scripts" | "page" | "none"; files: string[] };
  /** Content-Security-Policy for extension pages, when declared. */
  cspExtensionPages?: string;
  /** Sandboxed-pages CSP (MV3 object form only). */
  cspSandbox?: string;
  updateUrl?: string;
  /** Firefox add-on id from browser_specific_settings/applications. */
  geckoId?: string;
  /** Chrome packing key (base64 DER SPKI), when pinned in the manifest. */
  key?: string;
  webAccessibleResources: string[];
  externallyConnectable: string[];
  /** True when comments/trailing commas had to be stripped to parse. */
  lenientParse: boolean;
}

/**
 * Strip // and block comments plus trailing commas from JSON-ish text,
 * respecting string literals. Replaced spans become spaces so any offsets
 * derived later still line up.
 */
export function stripJsonComments(text: string): string {
  let out = "";
  let i = 0;
  let inString = false;
  while (i < text.length) {
    const ch = text[i] as string;
    if (inString) {
      out += ch;
      if (ch === "\\" && i + 1 < text.length) {
        out += text[i + 1];
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i++;
    } else if (ch === '"') {
      inString = true;
      out += ch;
      i++;
    } else if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") {
        out += " ";
        i++;
      }
    } else if (ch === "/" && text[i + 1] === "*") {
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) {
        out += text[i] === "\n" ? "\n" : " ";
        i++;
      }
      out += "  ";
      i += 2;
    } else {
      out += ch;
      i++;
    }
  }
  // Trailing commas: `, }` and `, ]` (whitespace allowed between).
  return out.replace(/,(\s*[}\]])/g, " $1");
}

/** Does this permission string look like a host match pattern? */
export function isHostPattern(p: string): boolean {
  return p === "<all_urls>" || /^(\*|https?|wss?|ftp|file|chrome-extension):\/\//.test(p);
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string");
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * Parse manifest text (raw bytes decoded as UTF-8, BOM tolerated) into a
 * normalized summary. Throws ManifestError when it is not JSON at all.
 */
export function parseManifest(text: string): ManifestSummary {
  const clean = text.replace(/^﻿/, "");
  let raw: Record<string, unknown>;
  let lenientParse = false;
  try {
    raw = record(JSON.parse(clean));
  } catch {
    try {
      raw = record(JSON.parse(stripJsonComments(clean)));
      lenientParse = true;
    } catch {
      throw new ManifestError("manifest.json is not valid JSON, even after stripping comments");
    }
  }

  const manifestVersion = typeof raw.manifest_version === "number" ? raw.manifest_version : 0;
  const declaredPermissions = strings(raw.permissions);
  const declaredOptional = strings(raw.optional_permissions);

  // MV2 mixes host patterns into `permissions`; MV3 separates them.
  const apiPermissions = declaredPermissions.filter((p) => !isHostPattern(p));
  const hostFromPermissions = declaredPermissions.filter(isHostPattern);
  const hostPermissions = [...hostFromPermissions, ...strings(raw.host_permissions)];
  const optionalApiPermissions = declaredOptional.filter((p) => !isHostPattern(p));
  const optionalHostPermissions = [
    ...declaredOptional.filter(isHostPattern),
    ...strings(raw.optional_host_permissions),
  ];

  const contentScripts: ContentScriptRef[] = [];
  if (Array.isArray(raw.content_scripts)) {
    for (const cs of raw.content_scripts) {
      const r = record(cs);
      contentScripts.push({ matches: strings(r.matches), js: strings(r.js) });
    }
  }

  const bg = record(raw.background);
  let background: ManifestSummary["background"] = { kind: "none", files: [] };
  if (typeof bg.service_worker === "string") {
    background = { kind: "service_worker", files: [bg.service_worker] };
  } else if (Array.isArray(bg.scripts)) {
    background = { kind: "scripts", files: strings(bg.scripts) };
  } else if (typeof bg.page === "string") {
    background = { kind: "page", files: [bg.page] };
  }

  // CSP: MV2 uses a bare string, MV3 an object with per-context policies.
  let cspExtensionPages: string | undefined;
  let cspSandbox: string | undefined;
  if (typeof raw.content_security_policy === "string") {
    cspExtensionPages = raw.content_security_policy;
  } else {
    const csp = record(raw.content_security_policy);
    if (typeof csp.extension_pages === "string") cspExtensionPages = csp.extension_pages;
    if (typeof csp.sandbox === "string") cspSandbox = csp.sandbox;
  }

  // web_accessible_resources: MV2 flat strings, MV3 {resources, matches}.
  const war: string[] = [];
  if (Array.isArray(raw.web_accessible_resources)) {
    for (const item of raw.web_accessible_resources) {
      if (typeof item === "string") war.push(item);
      else war.push(...strings(record(item).resources));
    }
  }

  const gecko = record(record(raw.browser_specific_settings).gecko);
  const geckoLegacy = record(record(raw.applications).gecko);
  const geckoId =
    typeof gecko.id === "string"
      ? gecko.id
      : typeof geckoLegacy.id === "string"
        ? geckoLegacy.id
        : undefined;

  return {
    name: typeof raw.name === "string" ? raw.name : "",
    version: typeof raw.version === "string" ? raw.version : "",
    manifestVersion,
    apiPermissions,
    optionalApiPermissions,
    hostPermissions,
    optionalHostPermissions,
    contentScripts,
    background,
    cspExtensionPages,
    cspSandbox,
    updateUrl: typeof raw.update_url === "string" ? raw.update_url : undefined,
    geckoId,
    key: typeof raw.key === "string" ? raw.key : undefined,
    webAccessibleResources: war,
    externallyConnectable: strings(record(raw.externally_connectable).matches),
    lenientParse,
  };
}
