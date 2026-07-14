// CSP forensics: directive parsing, script-source fallback, and the
// gradations from 'unsafe-inline' (ignored by browsers) up to remote
// script origins (the MV2 remote-code loophole).
import test from "node:test";
import assert from "node:assert/strict";

import { parseCsp, scriptSources, auditCsp } from "../dist/csp.js";
import { parseManifest } from "../dist/manifest.js";

function manifestWithCsp(policy) {
  return parseManifest(
    JSON.stringify({
      manifest_version: 2,
      name: "C",
      version: "1",
      content_security_policy: policy,
    }),
  );
}

test("parseCsp splits directives and sources; scriptSources falls back to default-src", () => {
  const map = parseCsp("default-src 'self'; script-src 'self' blob:; object-src 'none'");
  assert.deepEqual(map.get("script-src"), ["'self'", "blob:"]);
  assert.deepEqual(map.get("object-src"), ["'none'"]);
  assert.deepEqual(scriptSources("default-src 'self' https://cdn.example.net"), [
    "'self'",
    "https://cdn.example.net",
  ]);
  assert.deepEqual(scriptSources("img-src *"), []);
});

test("'unsafe-eval' in script-src is a high finding", () => {
  const findings = auditCsp(manifestWithCsp("script-src 'self' 'unsafe-eval'; object-src 'self'"));
  const f = findings.find((x) => x.rule === "CSP_UNSAFE_EVAL");
  assert.equal(f.severity, "high");
  assert.equal(f.file, "manifest.json");
});

test("remote script origins are critical — URL form and bare-host form", () => {
  const url = auditCsp(manifestWithCsp("script-src 'self' https://cdn.example.net"));
  assert.ok(url.some((f) => f.rule === "CSP_REMOTE_SCRIPT_SRC" && f.severity === "critical"));
  const bareHost = auditCsp(manifestWithCsp("script-src 'self' cdn.example.net:443"));
  assert.ok(bareHost.some((f) => f.rule === "CSP_REMOTE_SCRIPT_SRC" && f.severity === "critical"));
  // blob: is local but still dynamic code — one notch down.
  const blob = auditCsp(manifestWithCsp("script-src 'self' blob:"));
  assert.deepEqual(
    blob.map((f) => [f.rule, f.severity]),
    [["CSP_BLOB_SCRIPT", "medium"]],
  );
});

test("'unsafe-inline' grades low (browsers ignore it for extension pages)", () => {
  const findings = auditCsp(manifestWithCsp("script-src 'self' 'unsafe-inline'"));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule, "CSP_UNSAFE_INLINE");
  assert.equal(findings[0].severity, "low");
});

test("a tight policy and an absent policy both produce zero findings", () => {
  assert.deepEqual(auditCsp(manifestWithCsp("script-src 'self'; object-src 'self'")), []);
  const noCsp = parseManifest(JSON.stringify({ manifest_version: 3, name: "N", version: "1" }));
  assert.deepEqual(auditCsp(noCsp), []);
  // Hashes and nonces are integrity mechanisms, not remote origins.
  assert.deepEqual(
    auditCsp(manifestWithCsp("script-src 'self' 'sha256-AbCd123=' 'nonce-xyz'")),
    [],
  );
});
