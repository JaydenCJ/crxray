// CLI integration: the built binary run against real files in fresh temp
// dirs — commands, flags, exit codes (0 ok / 1 threshold / 2 usage),
// JSON output and safe unpacking.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import {
  ROOT,
  buildExtensionZip,
  buildZip,
  wrapCrx3,
  makeManifest,
  makeDir,
  runCli,
  CRX_ID_STRING,
} from "./helpers.mjs";
import { VERSION } from "../dist/version.js";

const CLEAN_FILES = {
  "manifest.json": makeManifest({ permissions: ["storage"] }),
  "background.js": "chrome.storage.local.set({ ok: true });\n",
};

const DIRTY_CRX = wrapCrx3(
  buildExtensionZip({
    "manifest.json": makeManifest({
      manifest_version: 2,
      permissions: ["cookies", "<all_urls>"],
      update_url: "https://updates.example-attacker.net/feed.xml",
    }),
    "bg.js": 'eval(atob(p));\nfetch("https://www.google-analytics.com/collect");\n',
  }),
);

test("--version matches package.json; --help documents commands and exit codes", () => {
  const version = runCli(["--version"]);
  assert.equal(version.status, 0);
  assert.equal(version.stdout.trim(), VERSION);
  assert.equal(
    version.stdout.trim(),
    JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version,
  );
  const help = runCli(["--help"]);
  assert.equal(help.status, 0);
  for (const word of ["scan", "unpack", "manifest", "urls", "id", "--fail-on", "Exit codes"]) {
    assert.ok(help.stdout.includes(word), `help missing ${word}`);
  }
});

test("usage errors exit 2: unknown flags, missing input, missing files", () => {
  assert.equal(runCli(["scan", "x.crx", "--frobnicate"]).status, 2);
  assert.equal(runCli(["scan"]).status, 2);
  assert.equal(runCli(["scan", "does-not-exist.crx"]).status, 2);
  assert.equal(runCli(["scan", "x.crx", "--fail-on", "sometimes"]).status, 2);
  const badFlag = runCli(["scan", "x.crx", "--frobnicate"]);
  assert.match(badFlag.stderr, /unknown option: --frobnicate/);
});

test("scan: a clean extension prints minimal and exits 0; bare path defaults to scan", () => {
  const { dir, cleanup } = makeDir({ "clean.zip": buildExtensionZip(CLEAN_FILES) });
  try {
    const { status, stdout } = runCli(["scan", "clean.zip"], { cwd: dir });
    assert.equal(status, 0);
    assert.match(stdout, /risk\s+0\/100 · MINIMAL/);
    assert.match(stdout, /none — nothing in the rubric fired/);
    // `crxray <file>` with no command word behaves identically.
    const bare = runCli(["clean.zip"], { cwd: dir });
    assert.equal(bare.status, 0);
    assert.match(bare.stdout, /static extension audit/);
  } finally {
    cleanup();
  }
});

test("scan: a hostile crx exceeds the threshold; --fail-on tunes the gate", () => {
  const { dir, cleanup } = makeDir({ "dirty.crx": DIRTY_CRX });
  try {
    const { status, stdout } = runCli(["scan", "dirty.crx"], { cwd: dir });
    assert.equal(status, 1); // default gate: high
    assert.match(stdout, /PERM_COMBO_COOKIES/);
    assert.match(stdout, /RCL_EVAL/);
    assert.match(stdout, /NET_TRACKER/);
    assert.match(stdout, /ID_SELF_HOSTED_UPDATE/);
    assert.equal(runCli(["scan", "dirty.crx", "--fail-on", "never"], { cwd: dir }).status, 0);
    assert.equal(runCli(["scan", "dirty.crx", "--fail-on", "critical"], { cwd: dir }).status, 1);
    assert.equal(runCli(["scan", "dirty.crx", "--fail-on=low"], { cwd: dir }).status, 1);
  } finally {
    cleanup();
  }
});

test("scan --json emits the full machine-readable result", () => {
  const { dir, cleanup } = makeDir({ "dirty.crx": DIRTY_CRX });
  try {
    const { status, stdout } = runCli(["scan", "dirty.crx", "--json"], { cwd: dir });
    assert.equal(status, 1); // threshold still applies with --json
    const result = JSON.parse(stdout);
    assert.equal(result.package.format, "crx3");
    assert.equal(result.identity.crxId, CRX_ID_STRING);
    assert.ok(Array.isArray(result.findings) && result.findings.length > 0);
    assert.ok(result.risk.score > 0);
    assert.ok(result.findings.every((f) => f.rule && f.severity && f.category));
  } finally {
    cleanup();
  }
});

test("scan accepts an unpacked directory as input", () => {
  const { dir, cleanup } = makeDir({
    "ext/manifest.json": makeManifest({ permissions: ["storage"] }),
    "ext/background.js": "chrome.storage.local.get(null);\n",
  });
  try {
    const { status, stdout } = runCli(["scan", "ext"], { cwd: dir });
    assert.equal(status, 0);
    assert.match(stdout, /directory · 2 files/);
  } finally {
    cleanup();
  }
});

test("unpack extracts the payload and derives a default directory name", () => {
  const { dir, cleanup } = makeDir({ "sample.crx": DIRTY_CRX });
  try {
    const { status, stdout } = runCli(["unpack", "sample.crx"], { cwd: dir });
    assert.equal(status, 0);
    assert.match(stdout, /unpacked 2 files to sample-unpacked/);
    const manifest = JSON.parse(readFileSync(join(dir, "sample-unpacked", "manifest.json"), "utf8"));
    assert.equal(manifest.name, "Fixture Extension");
    assert.ok(existsSync(join(dir, "sample-unpacked", "bg.js")));
  } finally {
    cleanup();
  }
});

test("unpack refuses zip-slip entries and reports them (exit 1)", () => {
  const hostile = buildZip([
    { path: "manifest.json", data: JSON.stringify(makeManifest()) },
    { path: "../escape.txt", data: "gotcha" },
  ]);
  const { dir, cleanup } = makeDir({ "hostile.zip": hostile });
  try {
    const out = join(dir, "safe");
    const { status, stderr } = runCli(["unpack", "hostile.zip", "-o", out], { cwd: dir });
    assert.equal(status, 1);
    assert.match(stderr, /refused unsafe entry path: \.\.\/escape\.txt/);
    assert.ok(existsSync(join(out, "manifest.json")));
    assert.ok(!existsSync(join(dir, "escape.txt"))); // nothing escaped
  } finally {
    cleanup();
  }
});

test("unpack refuses a non-empty destination unless --force", () => {
  const { dir, cleanup } = makeDir({
    "sample.zip": buildExtensionZip(CLEAN_FILES),
    "out/existing.txt": "already here",
  });
  try {
    const refused = runCli(["unpack", "sample.zip", "-o", "out"], { cwd: dir });
    assert.equal(refused.status, 2);
    assert.match(refused.stderr, /not empty/);
    const forced = runCli(["unpack", "sample.zip", "-o", "out", "--force"], { cwd: dir });
    assert.equal(forced.status, 0);
    assert.ok(existsSync(join(dir, "out", "manifest.json")));
  } finally {
    cleanup();
  }
});

test("manifest: graded permission table in text, structured facts in JSON", () => {
  const { dir, cleanup } = makeDir({
    "ext.zip": buildExtensionZip({
      "manifest.json": makeManifest({ permissions: ["cookies", "storage"] }),
    }),
  });
  try {
    const text = runCli(["manifest", "ext.zip"], { cwd: dir });
    assert.equal(text.status, 0);
    assert.match(text.stdout, /cookies/);
    assert.match(text.stdout, /session tokens/);
    const json = runCli(["manifest", "ext.zip", "--json"], { cwd: dir });
    const parsed = JSON.parse(json.stdout);
    assert.equal(parsed.manifest.name, "Fixture Extension");
    assert.equal(parsed.permissions.length, 2);
  } finally {
    cleanup();
  }
});

test("manifest: a package without manifest.json exits 2 with a clear error", () => {
  const { dir, cleanup } = makeDir({
    "bare.zip": buildZip([{ path: "just-data.txt", data: "hello" }]),
  });
  try {
    const { status, stderr } = runCli(["manifest", "bare.zip"], { cwd: dir });
    assert.equal(status, 2);
    assert.match(stderr, /no top-level manifest\.json/);
  } finally {
    cleanup();
  }
});


test("urls lists every endpoint with its classification", () => {
  const { dir, cleanup } = makeDir({
    "ext.zip": buildExtensionZip({
      "manifest.json": makeManifest(),
      "bg.js": 'fetch("https://api.example.net/v1"); fetch("https://www.google-analytics.com/collect");',
    }),
  });
  try {
    const { status, stdout } = runCli(["urls", "ext.zip"], { cwd: dir });
    assert.equal(status, 0);
    assert.match(stdout, /tracker:analytics\s+www\.google-analytics\.com/);
    assert.match(stdout, /plain\s+api\.example\.net/);
    const json = runCli(["urls", "ext.zip", "--json"], { cwd: dir });
    assert.equal(JSON.parse(json.stdout).length, 2);
  } finally {
    cleanup();
  }
});

test("id prints identity evidence: crx id, sha256, unverified proofs", () => {
  const { dir, cleanup } = makeDir({ "sample.crx": DIRTY_CRX });
  try {
    const { status, stdout } = runCli(["id", "sample.crx"], { cwd: dir });
    assert.equal(status, 0);
    assert.match(stdout, new RegExp(`crx id\\s+${CRX_ID_STRING}`));
    assert.match(stdout, /sha256\s+[0-9a-f]{64}/);
    assert.match(stdout, /1 rsa, 0 ecdsa \(present, not verified\)/);
    const json = runCli(["id", "sample.crx", "--json"], { cwd: dir });
    assert.equal(JSON.parse(json.stdout).identity.crxId, CRX_ID_STRING);
  } finally {
    cleanup();
  }
});
