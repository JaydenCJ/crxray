// Obfuscation forensics: the metrics, the signal thresholds, and the
// deliberate distinction between minified (normal) and obfuscated
// (adversarial) JavaScript.
import test from "node:test";
import assert from "node:assert/strict";

import { measure, verdict, auditScript, shannonEntropy } from "../dist/obfuscation.js";

test("shannonEntropy: constant string is 0 bits, two symbols are 1 bit", () => {
  assert.equal(shannonEntropy(""), 0);
  assert.equal(shannonEntropy("aaaaaaaa"), 0);
  assert.equal(shannonEntropy("abababab"), 1);
  // And the empty file measures cleanly end to end.
  const empty = measure("");
  assert.equal(empty.bytes, 0);
  assert.equal(empty.lines, 0);
  assert.equal(empty.stringEntropy, 0);
  assert.deepEqual(auditScript("empty.js", ""), []);
});

test("hex-pattern identifiers (_0x…) mark javascript-obfuscator output", () => {
  const code = Array.from(
    { length: 8 },
    (_, i) => `var _0x${(0x1a00 + i).toString(16)} = _0x${(0x2b00 + i).toString(16)}[${i}];`,
  ).join("\n");
  const v = verdict(measure(code));
  assert.equal(v.obfuscated, true);
  assert.match(v.signals.join(";"), /hex-pattern identifiers/);
});

test("the eval packer wrapper is recognized verbatim", () => {
  const code = "eval(function(p,a,c,k,e,d){return p}('payload',62,0,''.split('|')))";
  const v = verdict(measure(code));
  assert.equal(v.obfuscated, true);
  assert.match(v.signals.join(";"), /packer/);
});

test("dense \\x escape sequences trip the escape-density signal", () => {
  const escaped = "\\x68\\x74\\x74\\x70".repeat(30);
  const code = `var s = "${escaped}"; use(s);`;
  const m = measure(code);
  assert.ok(m.escapeRatio > 0.04);
  assert.equal(verdict(m).obfuscated, true);
});

test("high-entropy string payload plus a decoder is the smoking-gun combo", () => {
  // Deterministic pseudo-random base64-ish payload (no Math.random).
  // Lehmer LCG: multiplier small enough to stay exact in float64.
  let seed = 41;
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let payload = "";
  for (let i = 0; i < 400; i++) {
    seed = (seed * 48271) % 2147483647;
    payload += chars[seed % chars.length];
  }
  const code = `var blob = "${payload}";\nvar out = atob(blob);\n`;
  const m = measure(code);
  assert.ok(m.stringEntropy > 5.0, `entropy was ${m.stringEntropy}`);
  assert.ok(m.atobCount > 0);
  const v = verdict(m);
  assert.equal(v.obfuscated, true);
  assert.match(v.signals.join(";"), /high-entropy string payload/);
  // The same payload with no decoder in the file is only an opaque blob.
  const noDecoder = measure(`var blob = "${payload.repeat(3)}"; export default blob;`);
  assert.equal(verdict(noDecoder).obfuscated, false);
  const findings = auditScript("payload.js", `var blob = "${payload.repeat(3)}";`);
  assert.deepEqual(
    findings.map((f) => [f.rule, f.severity]),
    [["OBF_OPAQUE_PAYLOAD", "medium"]],
  );
});

test("minified bundles grade info, never high — minification is normal", () => {
  const oneLiner = `function a(){return 1}${"var x=a();x+=1;".repeat(200)}`;
  const m = measure(oneLiner);
  const v = verdict(m);
  assert.equal(v.minified, true);
  assert.equal(v.obfuscated, false);
  const findings = auditScript("bundle.min.js", oneLiner);
  assert.deepEqual(
    findings.map((f) => [f.rule, f.severity]),
    [["OBF_MINIFIED", "info"]],
  );
});

test("readable, honest source yields no metrics findings at all", () => {
  const code = `
    /** Adds a bookmark row to the popup list. */
    export function addRow(list, item) {
      const li = document.createElement("li");
      li.textContent = item.title;
      list.append(li);
    }
  `;
  assert.deepEqual(auditScript("popup.js", code), []);
  assert.equal(verdict(measure(code)).obfuscated, false);
});

test("auditScript reports one OBF_OBFUSCATED finding listing every signal", () => {
  const code =
    "eval(function(p,a,c,k,e,d){return p}('x',1,1,''.split('|')));" +
    Array.from({ length: 6 }, (_, i) => `var _0xab${i}c = ${i};`).join("");
  const findings = auditScript("evil.js", code);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule, "OBF_OBFUSCATED");
  assert.equal(findings[0].severity, "high");
  assert.match(findings[0].detail, /packer/);
  assert.match(findings[0].detail, /hex-pattern/);
});
