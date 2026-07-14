/**
 * Static source scanning for remote-code-loading vectors and privacy
 * red flags. Pattern-based by design: no JS parser dependency, resilient
 * to half-broken or obfuscated code, and every rule anchors on a
 * structural token (not an entropy guess) to keep false positives rare.
 * Comments are blanked before matching so a commented-out eval() is not
 * a finding.
 */
import type { Category, Finding, Severity } from "./types.js";

/** Where the scanned file runs — some rules only matter in one context. */
export interface ScanContext {
  file: string;
  /** True when the manifest injects this file into web pages. */
  isContentScript: boolean;
  /** True for HTML documents (enables markup rules). */
  isHtml: boolean;
}

interface CodeRule {
  rule: string;
  severity: Severity;
  category: Category;
  pattern: RegExp;
  title: string;
  detail: string;
  /** Restrict the rule to a context; undefined = applies everywhere. */
  only?: "content-script" | "html";
}

const RULES: CodeRule[] = [
  {
    rule: "RCL_EVAL",
    severity: "high",
    category: "remote-code",
    pattern: /\beval\s*\(/g,
    title: "eval() call",
    detail: "turns strings into code; combined with any fetch, this is remote code execution",
  },
  {
    rule: "RCL_NEW_FUNCTION",
    severity: "high",
    category: "remote-code",
    pattern: /\bnew\s+Function\s*\(/g,
    title: "new Function() constructor",
    detail: "compiles strings into functions — an eval() in a trenchcoat",
  },
  {
    rule: "RCL_TIMER_STRING",
    severity: "medium",
    category: "remote-code",
    pattern: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/g,
    title: "setTimeout/setInterval with a string body",
    detail: "string timer bodies are evaluated as code",
  },
  {
    rule: "RCL_IMPORTSCRIPTS_REMOTE",
    severity: "critical",
    category: "remote-code",
    pattern: /\bimportScripts\s*\(\s*["'`]https?:/g,
    title: "importScripts() from a remote URL",
    detail: "the worker executes whatever that server returns today",
  },
  {
    rule: "RCL_IMPORTSCRIPTS_DYNAMIC",
    severity: "medium",
    category: "remote-code",
    pattern: /\bimportScripts\s*\(\s*(?!["'`])[A-Za-z_$[]/g,
    title: "importScripts() with a computed argument",
    detail: "the script source is decided at runtime, not visible to static review",
  },
  {
    rule: "RCL_REMOTE_IMPORT",
    severity: "critical",
    category: "remote-code",
    pattern: /\bimport\s*\(\s*["'`]https?:/g,
    title: "dynamic import() of a remote URL",
    detail: "module code is fetched and executed from a remote origin",
  },
  {
    rule: "RCL_EXECUTE_SCRIPT_CODE",
    severity: "high",
    category: "remote-code",
    // Allows an optional leading tab-id argument: executeScript(id, {code}).
    pattern: /\bexecuteScript\s*\(\s*(?:[^{}()]{0,40},\s*)?\{[\s\S]{0,120}?\bcode\s*:/g,
    title: "tabs.executeScript with a code string",
    detail: "injects an arbitrary string as code into pages (classic MV2 remote-code vector)",
  },
  {
    rule: "RCL_SCRIPT_ELEMENT",
    severity: "medium",
    category: "remote-code",
    pattern: /createElement\s*\(\s*["'`]script["'`]\s*\)/g,
    title: "dynamic <script> element creation",
    detail: "scripts assembled at runtime bypass what static review can see",
  },
  {
    rule: "RCL_DOC_WRITE",
    severity: "low",
    category: "remote-code",
    pattern: /\bdocument\.write(?:ln)?\s*\(/g,
    title: "document.write() call",
    detail: "can splice new script tags into a live document",
  },
  {
    rule: "RCL_WASM_REMOTE",
    severity: "medium",
    category: "remote-code",
    pattern: /\binstantiateStreaming\s*\(\s*fetch\s*\(/g,
    title: "WebAssembly instantiated from fetch()",
    detail: "executable wasm is pulled from the network at runtime",
  },
  {
    rule: "RCL_REMOTE_SCRIPT_TAG",
    severity: "critical",
    category: "remote-code",
    pattern: /<script[^>]+src\s*=\s*["']?(?:https?:)?\/\//gi,
    title: "remote <script src> in an extension page",
    detail: "the page executes whatever this origin serves — store review never saw that code",
    only: "html",
  },
  {
    rule: "PRIV_KEY_LISTENER",
    severity: "high",
    category: "privacy",
    pattern: /addEventListener\s*\(\s*["'`](?:keydown|keypress|keyup)["'`]/g,
    title: "keystroke listener in a content script",
    detail: "captures keys typed into the host page — the keylogger primitive",
    only: "content-script",
  },
  {
    rule: "PRIV_CLIPBOARD_READ",
    severity: "medium",
    category: "privacy",
    pattern: /navigator\.clipboard\.readText|execCommand\s*\(\s*["'`]paste["'`]/g,
    title: "clipboard read",
    detail: "reads clipboard contents (passwords and 2FA codes travel through it)",
  },
  {
    rule: "PRIV_COOKIES_GETALL",
    severity: "medium",
    category: "privacy",
    pattern: /\bcookies\.getAll(?:CookieStores)?\s*\(/g,
    title: "bulk cookie read (cookies.getAll)",
    detail: "harvests cookies across sites rather than reading one known value",
  },
];

/**
 * Blank JS comments (// and /* *​/) with spaces, preserving newlines and
 * string/template literals, so rule offsets and line numbers stay honest.
 * Regex literals are left alone — the worst case is a missed comment, not
 * a false finding.
 */
export function blankComments(code: string): string {
  let out = "";
  let i = 0;
  let mode: "code" | "single" | "double" | "template" | "line" | "block" = "code";
  while (i < code.length) {
    const ch = code[i] as string;
    const next = code[i + 1];
    switch (mode) {
      case "code":
        if (ch === "/" && next === "/") {
          mode = "line";
          out += "  ";
          i += 2;
        } else if (ch === "/" && next === "*") {
          mode = "block";
          out += "  ";
          i += 2;
        } else {
          if (ch === "'") mode = "single";
          else if (ch === '"') mode = "double";
          else if (ch === "`") mode = "template";
          out += ch;
          i++;
        }
        break;
      case "single":
      case "double":
      case "template": {
        if (ch === "\\" && i + 1 < code.length) {
          out += ch + next;
          i += 2;
          break;
        }
        if (
          (mode === "single" && (ch === "'" || ch === "\n")) ||
          (mode === "double" && (ch === '"' || ch === "\n")) ||
          (mode === "template" && ch === "`")
        ) {
          mode = "code";
        }
        out += ch;
        i++;
        break;
      }
      case "line":
        if (ch === "\n") {
          mode = "code";
          out += "\n";
        } else {
          out += " ";
        }
        i++;
        break;
      case "block":
        if (ch === "*" && next === "/") {
          mode = "code";
          out += "  ";
          i += 2;
        } else {
          out += ch === "\n" ? "\n" : " ";
          i++;
        }
        break;
    }
  }
  return out;
}

/** 1-based line number of a character offset. */
function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

/** The trimmed source line around an offset, truncated for reports. */
function snippetAt(original: string, index: number): string {
  let start = original.lastIndexOf("\n", index) + 1;
  let end = original.indexOf("\n", index);
  if (end === -1) end = original.length;
  // For minified single-line files, window around the match instead.
  if (end - start > 160) {
    start = Math.max(start, index - 40);
    end = Math.min(end, index + 80);
  }
  const line = original.slice(start, end).trim();
  return line.length > 96 ? `${line.slice(0, 96)}…` : line;
}

/**
 * Scan one source file. Each rule reports at most once per file, with the
 * first match as evidence and the total occurrence count in the detail —
 * one eval-heavy file should read as one finding, not fifty.
 */
export function scanCode(source: string, ctx: ScanContext): Finding[] {
  const findings: Finding[] = [];
  const code = ctx.isHtml ? source : blankComments(source);
  for (const rule of RULES) {
    if (rule.only === "html" && !ctx.isHtml) continue;
    if (rule.only === "content-script" && !ctx.isContentScript) continue;
    rule.pattern.lastIndex = 0;
    const first = rule.pattern.exec(code);
    if (first === null) continue;
    let count = 1;
    while (rule.pattern.exec(code) !== null) count++;
    findings.push({
      rule: rule.rule,
      severity: rule.severity,
      category: rule.category,
      title: rule.title,
      detail: count > 1 ? `${rule.detail} (×${count} in this file)` : rule.detail,
      file: ctx.file,
      line: lineOf(code, first.index),
      evidence: snippetAt(source, first.index),
    });
  }
  return findings;
}
