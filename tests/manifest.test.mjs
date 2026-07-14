// Manifest parsing and MV2/MV3 normalization: permission splitting,
// tolerant JSON (comments, trailing commas, BOM), CSP shapes, background
// variants and Firefox identity fields.
import test from "node:test";
import assert from "node:assert/strict";

import { parseManifest, stripJsonComments, isHostPattern, ManifestError } from "../dist/manifest.js";

test("MV3 basics: name, version, manifest_version, host_permissions", () => {
  const m = parseManifest(
    JSON.stringify({
      manifest_version: 3,
      name: "Sample",
      version: "2.1.0",
      permissions: ["storage", "tabs"],
      host_permissions: ["https://example.com/*"],
      optional_host_permissions: ["https://*.example.org/*"],
    }),
  );
  assert.equal(m.name, "Sample");
  assert.equal(m.version, "2.1.0");
  assert.equal(m.manifestVersion, 3);
  assert.deepEqual(m.apiPermissions, ["storage", "tabs"]);
  assert.deepEqual(m.hostPermissions, ["https://example.com/*"]);
  assert.deepEqual(m.optionalHostPermissions, ["https://*.example.org/*"]);
  assert.equal(m.lenientParse, false);
});

test("content scripts and externally_connectable normalize to plain lists", () => {
  const m = parseManifest(
    JSON.stringify({
      manifest_version: 3,
      name: "C",
      version: "1",
      content_scripts: [{ matches: ["https://example.com/*"], js: ["cs.js"], css: ["x.css"] }],
      externally_connectable: { matches: ["https://app.example.com/*"] },
    }),
  );
  assert.deepEqual(m.contentScripts, [{ matches: ["https://example.com/*"], js: ["cs.js"] }]);
  assert.deepEqual(m.externallyConnectable, ["https://app.example.com/*"]);
});

test("MV2 mixes host patterns into permissions — the normalizer splits them", () => {
  const m = parseManifest(
    JSON.stringify({
      manifest_version: 2,
      name: "Legacy",
      version: "1.0",
      permissions: ["cookies", "<all_urls>", "http://*/*", "tabs"],
      optional_permissions: ["history", "https://example.com/*"],
    }),
  );
  assert.deepEqual(m.apiPermissions, ["cookies", "tabs"]);
  assert.deepEqual(m.hostPermissions, ["<all_urls>", "http://*/*"]);
  assert.deepEqual(m.optionalApiPermissions, ["history"]);
  assert.deepEqual(m.optionalHostPermissions, ["https://example.com/*"]);
  // The splitter itself: match patterns yes, API names no.
  assert.equal(isHostPattern("<all_urls>"), true);
  assert.equal(isHostPattern("*://*/*"), true);
  assert.equal(isHostPattern("file:///*"), true);
  assert.equal(isHostPattern("cookies"), false);
  assert.equal(isHostPattern("declarativeNetRequest"), false);
});

test("comments and trailing commas parse leniently — and are recorded", () => {
  const text = `{
    // extension metadata
    "manifest_version": 3,
    "name": "Commented", /* legacy name */
    "version": "1.0",
    "permissions": ["storage",],
  }`;
  const m = parseManifest(text);
  assert.equal(m.name, "Commented");
  assert.deepEqual(m.apiPermissions, ["storage"]);
  assert.equal(m.lenientParse, true); // weak evidence, surfaced later as a finding
  // A UTF-8 BOM alone is tolerated without even counting as lenient.
  const bom = parseManifest(`﻿{"manifest_version": 3, "name": "Bom", "version": "1.0"}`);
  assert.equal(bom.name, "Bom");
  assert.equal(bom.lenientParse, false);
});

test("stripJsonComments leaves // and /* inside string values alone", () => {
  const text = '{"homepage": "https://example.test/a//b", "note": "keep /* this */"}';
  const stripped = stripJsonComments(text);
  const parsed = JSON.parse(stripped);
  assert.equal(parsed.homepage, "https://example.test/a//b");
  assert.equal(parsed.note, "keep /* this */");
});

test("CSP: MV2 string and MV3 object forms both normalize", () => {
  const mv2 = parseManifest(
    JSON.stringify({
      manifest_version: 2,
      name: "A",
      version: "1",
      content_security_policy: "script-src 'self' 'unsafe-eval'; object-src 'self'",
    }),
  );
  assert.equal(mv2.cspExtensionPages, "script-src 'self' 'unsafe-eval'; object-src 'self'");
  const mv3 = parseManifest(
    JSON.stringify({
      manifest_version: 3,
      name: "B",
      version: "1",
      content_security_policy: {
        extension_pages: "script-src 'self'",
        sandbox: "sandbox allow-scripts; script-src 'self' blob:",
      },
    }),
  );
  assert.equal(mv3.cspExtensionPages, "script-src 'self'");
  assert.equal(mv3.cspSandbox, "sandbox allow-scripts; script-src 'self' blob:");
});

test("background: service worker, script list, page and absent all normalize", () => {
  const base = { manifest_version: 3, name: "X", version: "1" };
  const sw = parseManifest(JSON.stringify({ ...base, background: { service_worker: "bg.js" } }));
  assert.deepEqual(sw.background, { kind: "service_worker", files: ["bg.js"] });
  const scripts = parseManifest(
    JSON.stringify({ ...base, background: { scripts: ["a.js", "b.js"] } }),
  );
  assert.deepEqual(scripts.background, { kind: "scripts", files: ["a.js", "b.js"] });
  const page = parseManifest(JSON.stringify({ ...base, background: { page: "bg.html" } }));
  assert.deepEqual(page.background, { kind: "page", files: ["bg.html"] });
  const none = parseManifest(JSON.stringify(base));
  assert.deepEqual(none.background, { kind: "none", files: [] });
});

test("Firefox id: browser_specific_settings preferred, legacy applications honored", () => {
  const modern = parseManifest(
    JSON.stringify({
      manifest_version: 2,
      name: "F",
      version: "1",
      browser_specific_settings: { gecko: { id: "notes@example.test" } },
    }),
  );
  assert.equal(modern.geckoId, "notes@example.test");
  const legacy = parseManifest(
    JSON.stringify({
      manifest_version: 2,
      name: "F",
      version: "1",
      applications: { gecko: { id: "legacy@example.test" } },
    }),
  );
  assert.equal(legacy.geckoId, "legacy@example.test");
});

test("web_accessible_resources: MV2 flat list and MV3 objects both flatten", () => {
  const mv2 = parseManifest(
    JSON.stringify({
      manifest_version: 2,
      name: "W",
      version: "1",
      web_accessible_resources: ["img/*.png", "inject.js"],
    }),
  );
  assert.deepEqual(mv2.webAccessibleResources, ["img/*.png", "inject.js"]);
  const mv3 = parseManifest(
    JSON.stringify({
      manifest_version: 3,
      name: "W",
      version: "1",
      web_accessible_resources: [{ resources: ["frame.html"], matches: ["<all_urls>"] }],
    }),
  );
  assert.deepEqual(mv3.webAccessibleResources, ["frame.html"]);
});

test("text that is not JSON at all raises ManifestError", () => {
  assert.throws(() => parseManifest("<xml>nope</xml>"), ManifestError);
  assert.throws(() => parseManifest(""), ManifestError);
});
