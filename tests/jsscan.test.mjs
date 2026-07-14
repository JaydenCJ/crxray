// Code scanning: remote-code-loading vectors, privacy red flags,
// context-sensitivity (content script vs extension page vs HTML), comment
// blanking and per-file aggregation.
import test from "node:test";
import assert from "node:assert/strict";

import { scanCode, blankComments } from "../dist/jsscan.js";

const js = (file) => ({ file, isContentScript: false, isHtml: false });
const cs = (file) => ({ file, isContentScript: true, isHtml: false });
const html = (file) => ({ file, isContentScript: false, isHtml: true });

function rules(findings) {
  return findings.map((f) => f.rule);
}

test("eval() is found with file, line, evidence and per-file occurrence count", () => {
  const findings = scanCode('const x = 1;\nconst y = eval("x + 1");\n', js("bg.js"));
  const f = findings.find((x) => x.rule === "RCL_EVAL");
  assert.equal(f.severity, "high");
  assert.equal(f.file, "bg.js");
  assert.equal(f.line, 2);
  assert.match(f.evidence, /eval\("x \+ 1"\)/);
  // One rule reports once per file, with the total count in the detail.
  const many = scanCode("eval(a);\neval(b);\neval(c);\n", js("x.js"));
  assert.equal(many.filter((x) => x.rule === "RCL_EVAL").length, 1);
  assert.match(many[0].detail, /×3 in this file/);
});

test("a commented-out eval is not a finding — comments are blanked first", () => {
  const code = "// eval(payload)\n/* eval(more) */\nconst ok = 1;\n";
  assert.deepEqual(scanCode(code, js("a.js")), []);
  // Blanking preserves line numbers and string contents exactly.
  const mixed = `const url = "https://example.test/x"; // trailing note\n/* block\n comment */ eval(x);`;
  const blanked = blankComments(mixed);
  assert.equal(blanked.split("\n").length, mixed.split("\n").length);
  assert.match(blanked, /https:\/\/example\.test\/x/); // strings survive
  assert.doesNotMatch(blanked, /trailing note/);
  assert.equal(scanCode(mixed, js("a.js")).find((f) => f.rule === "RCL_EVAL").line, 3);
});

test("new Function() and string timer bodies are graded separately", () => {
  const findings = scanCode(
    'const f = new Function("a", "return a");\nsetTimeout("doWork()", 100);\nsetTimeout(work, 100);\n',
    js("bg.js"),
  );
  assert.equal(findings.find((f) => f.rule === "RCL_NEW_FUNCTION").severity, "high");
  assert.equal(findings.find((f) => f.rule === "RCL_TIMER_STRING").severity, "medium");
  // setTimeout with a function reference is fine — exactly one timer finding.
  assert.equal(findings.filter((f) => f.rule === "RCL_TIMER_STRING").length, 1);
});

test("remote module loading: importScripts and import() literals are critical", () => {
  const remote = scanCode('importScripts("https://cdn.example.net/lib.js");', js("w.js"));
  assert.equal(remote.find((f) => f.rule === "RCL_IMPORTSCRIPTS_REMOTE").severity, "critical");
  const dynamic = scanCode("importScripts(urlFromConfig);", js("w.js"));
  assert.equal(dynamic.find((f) => f.rule === "RCL_IMPORTSCRIPTS_DYNAMIC").severity, "medium");
  const esm = scanCode('await import("https://cdn.example.net/mod.js");', js("bg.js"));
  assert.equal(esm.find((f) => f.rule === "RCL_REMOTE_IMPORT").severity, "critical");
  // Loading code bundled inside the package is normal.
  assert.deepEqual(rules(scanCode('importScripts("vendor/lib.js");', js("w.js"))), []);
  assert.deepEqual(rules(scanCode('await import("./mod.js");', js("bg.js"))), []);
});

test("executeScript with a code string fires; with files it does not", () => {
  const code = 'chrome.tabs.executeScript(tab.id, { code: "document.title" });';
  assert.ok(rules(scanCode(code, js("bg.js"))).includes("RCL_EXECUTE_SCRIPT_CODE"));
  const files = 'chrome.scripting.executeScript({ target, files: ["cs.js"] });';
  assert.deepEqual(rules(scanCode(files, js("bg.js"))), []);
});

test("remote <script src> fires in HTML only — including protocol-relative", () => {
  const markup = '<html><script src="//cdn.example.net/a.js"></script></html>';
  const inHtml = scanCode(markup, html("popup.html"));
  assert.equal(inHtml.find((f) => f.rule === "RCL_REMOTE_SCRIPT_TAG").severity, "critical");
  // The same bytes in a .js template string are not an HTML page.
  assert.ok(!rules(scanCode(markup, js("tpl.js"))).includes("RCL_REMOTE_SCRIPT_TAG"));
  // A packaged script reference is fine.
  assert.deepEqual(rules(scanCode('<script src="popup.js"></script>', html("p.html"))), []);
});

test("keystroke listeners flag in content scripts, not in extension UI", () => {
  const code = 'document.addEventListener("keydown", capture);';
  const inCs = scanCode(code, cs("cs.js"));
  assert.equal(inCs.find((f) => f.rule === "PRIV_KEY_LISTENER").severity, "high");
  assert.deepEqual(rules(scanCode(code, js("popup.js"))), []);
});

test("clipboard reads and bulk cookie reads are privacy findings", () => {
  const findings = scanCode(
    'navigator.clipboard.readText().then(send);\nchrome.cookies.getAll({}, exfil);\ndocument.execCommand("paste");\n',
    js("bg.js"),
  );
  assert.equal(findings.find((f) => f.rule === "PRIV_CLIPBOARD_READ").severity, "medium");
  assert.equal(findings.find((f) => f.rule === "PRIV_COOKIES_GETALL").severity, "medium");
});

test("boring, honest code produces zero findings", () => {
  const code = `
    const state = { count: 0 };
    document.querySelector("#go").addEventListener("click", () => {
      state.count += 1;
      chrome.storage.local.set(state);
    });
    fetch("https://api.example.test/v1/sync", { method: "POST" });
  `;
  assert.deepEqual(scanCode(code, js("popup.js")), []);
});
