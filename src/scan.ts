/**
 * The audit pipeline: opened package in, full report data out.
 *
 * Pure by construction — scanPackage() takes decompressed bytes and
 * returns plain data; only the CLI touches the filesystem. The pipeline
 * runs, in order: archive hygiene → manifest identity → permission
 * rubric → CSP → per-file code + obfuscation scans → endpoint
 * classification → rubric scoring.
 */
import { createHash } from "node:crypto";

import type { Finding, PackageFile, PackageInput, RiskScore } from "./types.js";
import { parseContainer, idFromPublicKey, type ContainerInfo } from "./crx.js";
import { listEntries, readEntry, sanitizeEntryPath, ZipError } from "./zip.js";
import { parseManifest, ManifestError, type ManifestSummary } from "./manifest.js";
import { assessPermissions, permissionFindings, type PermissionAssessment } from "./permissions.js";
import { auditCsp } from "./csp.js";
import { scanCode } from "./jsscan.js";
import { auditScript } from "./obfuscation.js";
import { collectEndpoints, endpointFindings, extractUrls, splitUrl, type Endpoint } from "./urls.js";
import { scoreFindings, sortFindings } from "./rubric.js";

export class ScanError extends Error {}

/** Everything a report needs; serialized as-is by `--json`. */
export interface ScanResult {
  package: {
    source: string;
    format: PackageInput["format"];
    sha256?: string;
    bytes?: number;
    fileCount: number;
  };
  identity: {
    crxId?: string;
    geckoId?: string;
    proofs?: { rsa: number; ecdsa: number };
    name?: string;
    version?: string;
    manifestVersion?: number;
  };
  permissions: PermissionAssessment[];
  endpoints: Endpoint[];
  findings: Finding[];
  risk: RiskScore;
}

/** Update servers operated by the browser stores themselves. */
const STORE_UPDATE_HOSTS = new Set([
  "clients2.google.com",
  "clients2.googleusercontent.com",
  "edge.microsoft.com",
  "addons.mozilla.org",
  "versioncheck.addons.mozilla.org",
]);

/**
 * Open a CRX/XPI/ZIP archive from raw bytes into a PackageInput.
 * Throws ScanError with a human-readable reason on malformed input.
 */
export function openArchive(buf: Bytes, source: string): PackageInput {
  let container: ContainerInfo;
  try {
    container = parseContainer(buf);
  } catch (err) {
    throw new ScanError(err instanceof Error ? err.message : String(err));
  }
  const payload = buf.subarray(container.zipOffset);
  const files: PackageFile[] = [];
  try {
    for (const entry of listEntries(payload)) {
      if (entry.isDirectory) continue;
      const { data, crcOk } = readEntry(payload, entry);
      files.push({ path: entry.path, data, crcOk });
    }
  } catch (err) {
    if (err instanceof ZipError) throw new ScanError(err.message);
    throw err;
  }
  const format =
    container.format === "zip" ? (source.toLowerCase().endsWith(".xpi") ? "xpi" : "zip") : container.format;
  return {
    source,
    format,
    crxId: container.crxId,
    proofs: container.proofs,
    sha256: createHash("sha256").update(buf).digest("hex"),
    bytes: buf.length,
    files,
  };
}

// --- file-level forensics ---

const EXECUTABLE_EXTENSIONS = new Set(["exe", "dll", "so", "dylib", "scr", "bat", "cmd", "msi"]);

function magicName(data: Bytes): string | null {
  if (data.length < 4) return null;
  if (data[0] === 0x4d && data[1] === 0x5a) return "PE/Windows (MZ)";
  if (data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46) return "ELF";
  const magic = data.readUInt32LE(0);
  if (magic === 0xfeedface || magic === 0xfeedfacf || magic === 0xbebafeca || magic === 0xcafebabe) {
    return "Mach-O";
  }
  return null;
}

function isProbablyText(data: Bytes): boolean {
  const probe = data.subarray(0, 512);
  for (let i = 0; i < probe.length; i++) {
    if (probe[i] === 0) return false;
  }
  return true;
}

function fileFindings(files: PackageFile[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    if (sanitizeEntryPath(f.path) === null) {
      findings.push({
        rule: "FILE_UNSAFE_PATH",
        severity: "high",
        category: "files",
        title: "zip-slip entry path",
        detail: `entry "${f.path}" tries to escape the extraction directory`,
        file: f.path,
      });
    }
    if (seen.has(f.path)) {
      findings.push({
        rule: "FILE_DUPLICATE_ENTRY",
        severity: "medium",
        category: "files",
        title: "duplicate archive entry",
        detail: `"${f.path}" appears more than once — extractors disagree on which copy wins`,
        file: f.path,
      });
    }
    seen.add(f.path);
    if (!f.crcOk) {
      findings.push({
        rule: "FILE_CRC_MISMATCH",
        severity: "medium",
        category: "files",
        title: "CRC-32 mismatch",
        detail: `stored checksum for "${f.path}" does not match its contents — the archive was modified after packing`,
        file: f.path,
      });
    }
    const magic = magicName(f.data);
    const ext = f.path.toLowerCase().split(".").pop() ?? "";
    if (magic !== null) {
      findings.push({
        rule: "FILE_NATIVE_BINARY",
        severity: "critical",
        category: "files",
        title: `native executable inside the package (${magic})`,
        detail: `"${f.path}" is compiled native code — far outside what an extension needs`,
        file: f.path,
      });
    } else if (EXECUTABLE_EXTENSIONS.has(ext)) {
      findings.push({
        rule: "FILE_EXECUTABLE_EXT",
        severity: "high",
        category: "files",
        title: `executable file extension: .${ext}`,
        detail: `"${f.path}" carries an executable extension`,
        file: f.path,
      });
    }
    if (/\.(pem|p12|pfx|key)$/i.test(f.path)) {
      findings.push({
        rule: "FILE_KEY_MATERIAL",
        severity: "medium",
        category: "files",
        title: "key material shipped in the package",
        detail: `"${f.path}" looks like a private key or keystore`,
        file: f.path,
      });
    }
  }
  return findings;
}

// --- identity forensics ---

function identityFindings(
  pkg: PackageInput,
  manifest: ManifestSummary | null,
): Finding[] {
  const findings: Finding[] = [];
  if (manifest === null) {
    findings.push({
      rule: "ID_NO_MANIFEST",
      severity: "high",
      category: "identity",
      title: "no parseable manifest.json",
      detail: "the package has no readable top-level manifest — not a valid extension, or hiding one",
    });
    return findings;
  }
  if (manifest.lenientParse) {
    findings.push({
      rule: "ID_LENIENT_MANIFEST",
      severity: "info",
      category: "identity",
      title: "manifest needed lenient parsing",
      detail: "comments or trailing commas had to be stripped before manifest.json parsed",
      file: "manifest.json",
    });
  }
  if (manifest.name === "" || manifest.version === "") {
    findings.push({
      rule: "ID_INCOMPLETE",
      severity: "low",
      category: "identity",
      title: "manifest is missing name or version",
      detail: "a store-distributed extension always declares both",
      file: "manifest.json",
    });
  }
  if (manifest.key !== undefined && pkg.crxId !== undefined) {
    let derived: string | null = null;
    try {
      derived = idFromPublicKey(Buffer.from(manifest.key, "base64"));
    } catch {
      derived = null;
    }
    if (derived !== null && derived !== pkg.crxId) {
      findings.push({
        rule: "ID_KEY_MISMATCH",
        severity: "high",
        category: "identity",
        title: "manifest key does not match the CRX id",
        detail: `manifest "key" derives id ${derived} but the container declares ${pkg.crxId} — repackaging or impersonation`,
        file: "manifest.json",
      });
    }
  }
  if (manifest.updateUrl !== undefined) {
    const parts = splitUrl(manifest.updateUrl);
    const host = parts?.host ?? "";
    if (!STORE_UPDATE_HOSTS.has(host)) {
      findings.push({
        rule: "ID_SELF_HOSTED_UPDATE",
        severity: "high",
        category: "identity",
        title: `self-hosted update server: ${host || manifest.updateUrl}`,
        detail: "updates bypass store review — whoever controls this host can replace the extension silently",
        file: "manifest.json",
        evidence: manifest.updateUrl,
      });
    }
  }
  return findings;
}

// --- the pipeline ---

const TEXT_SCAN_EXTENSIONS = new Set(["js", "mjs", "cjs", "html", "htm", "json", "css", "txt", "xml", "svg"]);
/** Files larger than this are skipped by the text scanners (bytes). */
const MAX_TEXT_SCAN_BYTES = 8 * 1024 * 1024;

function findManifest(files: PackageFile[]): PackageFile | null {
  // Top-level manifest.json only; some XPIs nest one under META-INF etc.
  return files.find((f) => sanitizeEntryPath(f.path) === "manifest.json") ?? null;
}

/** Run the full audit over an opened package. */
export function scanPackage(pkg: PackageInput): ScanResult {
  const findings: Finding[] = [];
  findings.push(...fileFindings(pkg.files));

  const manifestFile = findManifest(pkg.files);
  let manifest: ManifestSummary | null = null;
  if (manifestFile !== null) {
    try {
      manifest = parseManifest(manifestFile.data.toString("utf8"));
    } catch (err) {
      if (!(err instanceof ManifestError)) throw err;
      manifest = null;
    }
  }
  findings.push(...identityFindings(pkg, manifest));

  let permissions: PermissionAssessment[] = [];
  const contentScriptFiles = new Set<string>();
  if (manifest !== null) {
    permissions = assessPermissions(manifest);
    findings.push(...permissionFindings(manifest));
    findings.push(...auditCsp(manifest));
    for (const cs of manifest.contentScripts) {
      for (const js of cs.js) contentScriptFiles.add(js.replace(/^\.?\//, ""));
    }
  }

  const perFileUrls: { file: string; urls: string[] }[] = [];
  for (const f of pkg.files) {
    const clean = sanitizeEntryPath(f.path);
    if (clean === null) continue;
    const ext = clean.toLowerCase().split(".").pop() ?? "";
    if (!TEXT_SCAN_EXTENSIONS.has(ext)) continue;
    if (f.data.length > MAX_TEXT_SCAN_BYTES || !isProbablyText(f.data)) continue;
    const text = f.data.toString("utf8");
    const isHtml = ext === "html" || ext === "htm";
    const isScript = ext === "js" || ext === "mjs" || ext === "cjs";
    if (isHtml || isScript) {
      findings.push(
        ...scanCode(text, {
          file: clean,
          isContentScript: contentScriptFiles.has(clean),
          isHtml,
        }),
      );
    }
    if (isScript) findings.push(...auditScript(clean, text));
    perFileUrls.push({ file: clean, urls: extractUrls(text) });
  }

  const endpoints = collectEndpoints(perFileUrls);
  findings.push(...endpointFindings(endpoints));

  const sorted = sortFindings(findings);
  return {
    package: {
      source: pkg.source,
      format: pkg.format,
      sha256: pkg.sha256,
      bytes: pkg.bytes,
      fileCount: pkg.files.length,
    },
    identity: {
      crxId: pkg.crxId,
      geckoId: manifest?.geckoId,
      proofs: pkg.proofs,
      name: manifest?.name === "" ? undefined : manifest?.name,
      version: manifest?.version === "" ? undefined : manifest?.version,
      manifestVersion: manifest?.manifestVersion === 0 ? undefined : manifest?.manifestVersion,
    },
    permissions,
    endpoints,
    findings: sorted,
    risk: scoreFindings(sorted),
  };
}
