/**
 * Obfuscation forensics for JavaScript sources.
 *
 * Minification is normal shipping practice; obfuscation — hex-renamed
 * identifiers, string arrays fed through decoders, packer eval wrappers,
 * dense escape sequences — exists to defeat exactly the review this tool
 * performs, so it is graded as a signal in its own right. The metrics are
 * cheap, deterministic and explainable; the verdict lists which signals
 * fired so a human can check the receipt.
 */
import type { Finding } from "./types.js";

/** Raw measurements over one source file. */
export interface ObfuscationMetrics {
  bytes: number;
  lines: number;
  /** Average bytes per line — minified bundles run very high. */
  avgLine: number;
  /** Identifiers like _0x4f2a — the javascript-obfuscator signature. */
  hexIdCount: number;
  /** \xNN and \uNNNN escapes per source character. */
  escapeRatio: number;
  fromCharCodeCount: number;
  atobCount: number;
  /** Shannon entropy (bits/char) over long string literals, 0 if none. */
  stringEntropy: number;
  /** Total characters inside those long string literals. */
  stringBytes: number;
  /** eval(function(p,a,c,k,e,…) packer wrapper present. */
  packerSignature: boolean;
}

/** The verdict: minified is informational, obfuscated is a red flag. */
export interface ObfuscationVerdict {
  minified: boolean;
  obfuscated: boolean;
  signals: string[];
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const n of counts.values()) {
    const p = n / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Extract string literals of at least `minLen` chars ('…', "…", `…`). */
function longStringLiterals(code: string, minLen: number): string[] {
  const out: string[] = [];
  const re = /(['"`])((?:\\.|(?!\1)[^\\\n])*)\1/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const body = m[2] as string;
    if (body.length >= minLen) out.push(body);
  }
  return out;
}

/** Measure one file. Pure string math — no parsing, no ambiguity. */
export function measure(code: string): ObfuscationMetrics {
  const bytes = code.length;
  const lines = bytes === 0 ? 0 : code.split("\n").length;
  const hexIdCount = (code.match(/\b_0x[0-9a-fA-F]{2,}\b/g) ?? []).length;
  const escapes = (code.match(/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g) ?? []).length;
  const literals = longStringLiterals(code, 24);
  const joined = literals.join("");
  return {
    bytes,
    lines,
    avgLine: lines === 0 ? 0 : bytes / lines,
    hexIdCount,
    escapeRatio: bytes === 0 ? 0 : escapes / bytes,
    fromCharCodeCount: (code.match(/String\.fromCharCode/g) ?? []).length,
    atobCount: (code.match(/\batob\s*\(/g) ?? []).length,
    stringEntropy: shannonEntropy(joined),
    stringBytes: joined.length,
    packerSignature: /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,/.test(code),
  };
}

/** Thresholds are documented in docs/rubric.md; changing them is a PR. */
export function verdict(m: ObfuscationMetrics): ObfuscationVerdict {
  const signals: string[] = [];
  if (m.packerSignature) signals.push("eval packer wrapper (p,a,c,k,e,…)");
  if (m.hexIdCount >= 5) signals.push(`${m.hexIdCount} hex-pattern identifiers (_0x…)`);
  if (m.escapeRatio > 0.04 && m.bytes > 200) {
    signals.push(`dense \\x/\\u escape sequences (${(m.escapeRatio * 100).toFixed(1)}% of source)`);
  }
  if (m.stringEntropy > 5.0 && m.stringBytes >= 256 && m.atobCount + m.fromCharCodeCount > 0) {
    signals.push(
      `high-entropy string payload (${m.stringEntropy.toFixed(2)} bits/char) feeding a decoder`,
    );
  }
  const minified = m.lines > 0 && m.avgLine > 250;
  return { minified, obfuscated: signals.length > 0, signals };
}

/**
 * Grade one script. Obfuscation is high severity; a large high-entropy
 * payload without a visible decoder is still worth a medium (the decoder
 * may live elsewhere); bare minification is informational only.
 */
export function auditScript(file: string, code: string): Finding[] {
  const m = measure(code);
  const v = verdict(m);
  if (v.obfuscated) {
    return [
      {
        rule: "OBF_OBFUSCATED",
        severity: "high",
        category: "obfuscation",
        title: "obfuscated JavaScript",
        detail: v.signals.join("; "),
        file,
      },
    ];
  }
  if (m.stringEntropy > 5.5 && m.stringBytes >= 1024) {
    return [
      {
        rule: "OBF_OPAQUE_PAYLOAD",
        severity: "medium",
        category: "obfuscation",
        title: "large opaque string payload",
        detail: `${m.stringBytes} chars of string literals at ${m.stringEntropy.toFixed(2)} bits/char — content cannot be reviewed as source`,
        file,
      },
    ];
  }
  if (v.minified) {
    return [
      {
        rule: "OBF_MINIFIED",
        severity: "info",
        category: "obfuscation",
        title: "minified JavaScript",
        detail: `average line length ${Math.round(m.avgLine)} bytes — normal for bundles, but unreviewable by eye`,
        file,
      },
    ];
  }
  return [];
}
