/**
 * The risk rubric: findings → 0–100 score → level.
 *
 * Design (specified in docs/rubric.md):
 *   - every severity has a fixed weight;
 *   - each category is capped, so twenty tracker hits cannot outscore a
 *     genuine remote-code hole;
 *   - the level is bucketed from the score, then floored by the single
 *     worst finding — one critical finding can never be shrugged off as
 *     "minimal" no matter how quiet the rest of the package is.
 * Fully deterministic: same findings, same score, byte-identical reports.
 */
import type { Category, Finding, RiskLevel, RiskScore, Severity } from "./types.js";
import { severityRank } from "./types.js";

/** Points per finding by severity. */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 30,
  high: 12,
  medium: 5,
  low: 2,
  info: 0,
};

/** Maximum points any single category can contribute. */
export const CATEGORY_CAP = 45;

/** Score buckets (inclusive lower bounds). */
const LEVEL_BOUNDS: { min: number; level: RiskLevel }[] = [
  { min: 70, level: "critical" },
  { min: 45, level: "high" },
  { min: 20, level: "medium" },
  { min: 5, level: "low" },
  { min: 0, level: "minimal" },
];

/** A critical finding floors the level at high; a high finding at medium. */
const SEVERITY_FLOORS: Partial<Record<Severity, RiskLevel>> = {
  critical: "high",
  high: "medium",
};

const LEVEL_ORDER: RiskLevel[] = ["minimal", "low", "medium", "high", "critical"];

/** Numeric rank of a risk level (minimal = 0 … critical = 4). */
export function levelRank(level: RiskLevel): number {
  return LEVEL_ORDER.indexOf(level);
}

function bucket(score: number): RiskLevel {
  for (const { min, level } of LEVEL_BOUNDS) {
    if (score >= min) return level;
  }
  return "minimal";
}

/** Compute the rubric score for a set of findings. */
export function scoreFindings(findings: Finding[]): RiskScore {
  const byCategory: Partial<Record<Category, number>> = {};
  for (const f of findings) {
    const current = byCategory[f.category] ?? 0;
    byCategory[f.category] = Math.min(CATEGORY_CAP, current + SEVERITY_WEIGHTS[f.severity]);
  }
  let score = 0;
  for (const points of Object.values(byCategory)) score += points;
  score = Math.min(100, score);

  let level = bucket(score);
  for (const f of findings) {
    const floor = SEVERITY_FLOORS[f.severity];
    if (floor !== undefined && levelRank(floor) > levelRank(level)) level = floor;
  }
  return { score, level, byCategory };
}

const CATEGORY_ORDER: Category[] = [
  "identity",
  "permissions",
  "csp",
  "remote-code",
  "obfuscation",
  "network",
  "privacy",
  "files",
];

/**
 * Deterministic report order: severity (worst first), then category, then
 * rule id, then file. Stable across runs and platforms.
 */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    const cat = CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category);
    if (cat !== 0) return cat;
    if (a.rule !== b.rule) return a.rule < b.rule ? -1 : 1;
    const fa = a.file ?? "";
    const fb = b.file ?? "";
    return fa < fb ? -1 : fa > fb ? 1 : 0;
  });
}
