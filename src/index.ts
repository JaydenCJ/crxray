/**
 * Public programmatic API. Everything the CLI can do is reachable here:
 * open an archive, scan it, and inspect the typed result — no child
 * process, no filesystem requirements beyond providing the bytes.
 */
export { openArchive, scanPackage, ScanError, type ScanResult } from "./scan.js";
export { parseContainer, idFromPublicKey, idFromCrxIdBytes, CrxError, type ContainerInfo } from "./crx.js";
export { listEntries, readEntry, sanitizeEntryPath, crc32, ZipError, type ZipEntry } from "./zip.js";
export {
  parseManifest,
  stripJsonComments,
  isHostPattern,
  ManifestError,
  type ManifestSummary,
  type ContentScriptRef,
} from "./manifest.js";
export {
  assessPermissions,
  permissionFindings,
  classifyHostPattern,
  type PermissionAssessment,
} from "./permissions.js";
export { auditCsp, parseCsp, scriptSources } from "./csp.js";
export { scanCode, blankComments, type ScanContext } from "./jsscan.js";
export {
  measure,
  verdict,
  auditScript,
  shannonEntropy,
  type ObfuscationMetrics,
  type ObfuscationVerdict,
} from "./obfuscation.js";
export {
  extractUrls,
  splitUrl,
  collectEndpoints,
  endpointFindings,
  type Endpoint,
  type EndpointKind,
} from "./urls.js";
export { lookupTracker, TRACKER_DOMAINS, type TrackerCategory } from "./trackers.js";
export {
  scoreFindings,
  sortFindings,
  levelRank,
  SEVERITY_WEIGHTS,
  CATEGORY_CAP,
} from "./rubric.js";
export { VERSION } from "./version.js";
export type {
  Severity,
  Category,
  Finding,
  PackageFile,
  PackageFormat,
  PackageInput,
  RiskLevel,
  RiskScore,
} from "./types.js";
