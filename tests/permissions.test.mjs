// The permission rubric: individual grades, host-pattern breadth,
// optional-permission discounting and the escalated combinations that
// amount to traffic interception or session theft.
import test from "node:test";
import assert from "node:assert/strict";

import { parseManifest } from "../dist/manifest.js";
import { assessPermissions, permissionFindings, classifyHostPattern } from "../dist/permissions.js";

function manifestWith(fields) {
  return parseManifest(
    JSON.stringify({ manifest_version: 3, name: "P", version: "1", ...fields }),
  );
}

function gradeOf(assessments, permission) {
  return assessments.find((a) => a.permission === permission)?.severity;
}

test("API grades follow the rubric: debugger > cookies > tabs > storage", () => {
  const a = assessPermissions(
    manifestWith({ permissions: ["debugger", "cookies", "tabs", "storage", "madeUpPermission"] }),
  );
  assert.equal(gradeOf(a, "debugger"), "critical");
  assert.equal(gradeOf(a, "cookies"), "high");
  assert.equal(gradeOf(a, "tabs"), "medium");
  assert.equal(gradeOf(a, "storage"), "info");
  // Anything outside the rubric grades info, with an honest reason.
  const unknown = a.find((x) => x.permission === "madeUpPermission");
  assert.equal(unknown.severity, "info");
  assert.match(unknown.reason, /not in the rubric/);
});

test("optional permissions step down exactly one grade", () => {
  const a = assessPermissions(
    manifestWith({ optional_permissions: ["debugger", "cookies", "tabs"] }),
  );
  assert.equal(gradeOf(a, "debugger"), "high"); // critical - 1
  assert.equal(gradeOf(a, "cookies"), "medium"); // high - 1
  assert.equal(gradeOf(a, "tabs"), "low"); // medium - 1
  assert.ok(a.every((x) => x.optional && /optional/.test(x.reason)));
});

test("host pattern breadth: everything > subdomain wildcard > single host", () => {
  assert.equal(classifyHostPattern("<all_urls>").severity, "critical");
  assert.equal(classifyHostPattern("*://*/*").severity, "critical");
  assert.equal(classifyHostPattern("https://*/*").severity, "critical");
  assert.equal(classifyHostPattern("https://*.example.com/*").severity, "medium");
  assert.equal(classifyHostPattern("https://api.example.com/*").severity, "low");
  assert.equal(classifyHostPattern("file:///*").severity, "high");
});

test("findings include medium and worse, never low/info noise", () => {
  const findings = permissionFindings(
    manifestWith({ permissions: ["storage", "activeTab", "tabs", "cookies"] }),
  );
  const rules = findings.map((f) => `${f.rule}:${f.title}`).join("\n");
  assert.match(rules, /tabs/);
  assert.match(rules, /cookies/);
  assert.doesNotMatch(rules, /storage/);
  assert.doesNotMatch(rules, /activeTab/);
});

test("interception combo requires webRequest + blocking + broad hosts", () => {
  const full = permissionFindings(
    manifestWith({
      manifest_version: 2,
      permissions: ["webRequest", "webRequestBlocking", "<all_urls>"],
    }),
  );
  assert.ok(full.some((f) => f.rule === "PERM_COMBO_INTERCEPT" && f.severity === "critical"));
  // Missing any leg of the tripod → no combo escalation.
  const noBlocking = permissionFindings(
    manifestWith({ manifest_version: 2, permissions: ["webRequest", "<all_urls>"] }),
  );
  assert.ok(!noBlocking.some((f) => f.rule === "PERM_COMBO_INTERCEPT"));
  const narrowHost = permissionFindings(
    manifestWith({
      manifest_version: 2,
      permissions: ["webRequest", "webRequestBlocking", "https://api.example.com/*"],
    }),
  );
  assert.ok(!narrowHost.some((f) => f.rule === "PERM_COMBO_INTERCEPT"));
});

test("cookies + broad hosts escalates to account-takeover grade", () => {
  const findings = permissionFindings(
    manifestWith({ permissions: ["cookies"], host_permissions: ["<all_urls>"] }),
  );
  const combo = findings.find((f) => f.rule === "PERM_COMBO_COOKIES");
  assert.equal(combo.severity, "critical");
  assert.match(combo.detail, /session cookies/);
});

test("a content script matching every site is its own high finding", () => {
  const findings = permissionFindings(
    manifestWith({ content_scripts: [{ matches: ["<all_urls>"], js: ["cs.js"] }] }),
  );
  const f = findings.find((x) => x.rule === "PERM_CONTENT_SCRIPT_ALL");
  assert.equal(f.severity, "high");
  // A narrowly-scoped content script is normal and must not fire.
  const narrow = permissionFindings(
    manifestWith({ content_scripts: [{ matches: ["https://example.com/*"], js: ["cs.js"] }] }),
  );
  assert.ok(!narrow.some((x) => x.rule === "PERM_CONTENT_SCRIPT_ALL"));
});
