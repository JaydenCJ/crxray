/**
 * Shared types for crxray: findings, severities, package shapes and the
 * final report. Everything here is plain data — modules stay pure and
 * unit-testable, and the JSON report is just these structures serialized.
 */

/** Finding severity, ordered from least to most severe. */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Ordered list used for comparisons and stable sorting. */
export const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

/** Numeric rank of a severity (info = 0 … critical = 4). */
export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

/** The rubric's audit axes. Every finding belongs to exactly one. */
export type Category =
  | "identity"
  | "permissions"
  | "csp"
  | "remote-code"
  | "obfuscation"
  | "network"
  | "privacy"
  | "files";

/** One audit finding, keyed by a stable rule id (e.g. "RCL_EVAL"). */
export interface Finding {
  rule: string;
  severity: Severity;
  category: Category;
  title: string;
  detail: string;
  /** Path inside the package the finding points at, when applicable. */
  file?: string;
  /** 1-based line number inside `file`, when applicable. */
  line?: number;
  /** Truncated source snippet backing the finding, when applicable. */
  evidence?: string;
}

/** One file inside an opened package, fully decompressed. */
export interface PackageFile {
  /** Entry path exactly as stored in the archive (or relative on disk). */
  path: string;
  data: Bytes;
  /** False when the archive CRC did not match the decompressed bytes. */
  crcOk: boolean;
}

/** Container formats crxray understands. */
export type PackageFormat = "crx2" | "crx3" | "xpi" | "zip" | "directory";

/** An opened, decompressed package ready for scanning. Pure data. */
export interface PackageInput {
  /** Display name: the input path or file name. */
  source: string;
  format: PackageFormat;
  /** Extension id declared by the CRX container, when present. */
  crxId?: string;
  /** Signature proof counts from a CRX3 header (not verified). */
  proofs?: { rsa: number; ecdsa: number };
  /** SHA-256 of the archive bytes (absent for directories). */
  sha256?: string;
  /** Size of the archive in bytes (absent for directories). */
  bytes?: number;
  files: PackageFile[];
}

/** Overall risk level derived from the rubric score. */
export type RiskLevel = "minimal" | "low" | "medium" | "high" | "critical";

/** Ordered list used for `--fail-on` threshold comparisons. */
export const RISK_LEVELS: readonly RiskLevel[] = ["minimal", "low", "medium", "high", "critical"];

/** Rubric output: 0–100 score, level, and per-category subtotals. */
export interface RiskScore {
  score: number;
  level: RiskLevel;
  byCategory: Partial<Record<Category, number>>;
}
