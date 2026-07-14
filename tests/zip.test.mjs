// ZIP reader: central-directory listing, decompression, CRC verification,
// hostile-path sanitization and malformed-archive rejection. The writer in
// helpers.mjs uses its own CRC implementation, so reader and writer
// cross-check each other.
import test from "node:test";
import assert from "node:assert/strict";

import { listEntries, readEntry, sanitizeEntryPath, crc32, ZipError } from "../dist/zip.js";
import { buildZip } from "./helpers.mjs";

test("lists entries with names, sizes and method from the central directory", () => {
  const zip = buildZip([
    { path: "manifest.json", data: "{}", method: 8 },
    { path: "assets/icon.png", data: Buffer.from([1, 2, 3]), method: 0 },
  ]);
  const entries = listEntries(zip);
  assert.equal(entries.length, 2);
  assert.equal(entries[0].path, "manifest.json");
  assert.equal(entries[0].method, 8);
  assert.equal(entries[0].size, 2);
  assert.equal(entries[1].path, "assets/icon.png");
  assert.equal(entries[1].method, 0);
  assert.equal(entries[1].size, 3);
});

test("readEntry returns byte-identical content for stored and deflated entries", () => {
  const text = "const answer = 42;\n".repeat(50);
  const zip = buildZip([
    { path: "deflated.js", data: text, method: 8 },
    { path: "stored.js", data: text, method: 0 },
  ]);
  const [deflated, stored] = listEntries(zip);
  const a = readEntry(zip, deflated);
  const b = readEntry(zip, stored);
  assert.equal(a.data.toString("utf8"), text);
  assert.equal(b.data.toString("utf8"), text);
  assert.equal(a.crcOk, true);
  assert.equal(b.crcOk, true);
});

test("a lying checksum is reported, not trusted: crcOk === false", () => {
  const zip = buildZip([{ path: "tampered.js", data: "alert(1)", corruptCrc: true }]);
  const [entry] = listEntries(zip);
  const { data, crcOk } = readEntry(zip, entry);
  assert.equal(data.toString("utf8"), "alert(1)"); // content still extracted
  assert.equal(crcOk, false);
  // The implementation matches the classic IEEE check vector.
  assert.equal(crc32(Buffer.from("123456789")), 0xcbf43926);
  assert.equal(crc32(Buffer.alloc(0)), 0);
});

test("UTF-8 entry names round-trip (flag bit 11)", () => {
  const zip = buildZip([{ path: "локали/メモ.json", data: "{}" }]);
  assert.equal(listEntries(zip)[0].path, "локали/メモ.json");
});

test("EOCD is found even behind a trailing archive comment", () => {
  const zip = buildZip([{ path: "a.txt", data: "hi" }], { comment: "x".repeat(300) });
  const entries = listEntries(zip);
  assert.equal(entries.length, 1);
  assert.equal(readEntry(zip, entries[0]).data.toString("utf8"), "hi");
});

test("archives with stale internal offsets (stripped prefix) still read", () => {
  // Some tooling wraps an existing ZIP without rewriting its offsets;
  // the reader must locate the real central directory by size.
  const zip = buildZip([{ path: "app.js", data: "let x = 1;" }]);
  const shifted = Buffer.concat([Buffer.from("JUNKJUNK"), zip]);
  const entries = listEntries(shifted);
  assert.equal(entries.length, 1);
  assert.equal(readEntry(shifted, entries[0]).data.toString("utf8"), "let x = 1;");
});

test("garbage, truncated directories and unknown methods raise ZipError", () => {
  assert.throws(() => listEntries(Buffer.from("not a zip at all, sorry")), ZipError);
  const zip = buildZip([{ path: "a.txt", data: "hello world" }]);
  assert.throws(() => listEntries(zip.subarray(0, 30)), ZipError); // no EOCD
  const weird = buildZip([{ path: "a.bin", data: "x", method: 0 }]);
  // Rewrite method 0 → 99 in both headers (offset 8 local, +10 central).
  const cdPos = weird.length - 22 - 46 - "a.bin".length;
  weird.writeUInt16LE(99, 8);
  weird.writeUInt16LE(99, cdPos + 10);
  const [entry] = listEntries(weird);
  assert.throws(() => readEntry(weird, entry), /unsupported compression method 99/);
});

test("sanitizeEntryPath normalizes safe paths and rejects escapes", () => {
  assert.equal(sanitizeEntryPath("src/app.js"), "src/app.js");
  assert.equal(sanitizeEntryPath("./a//b/./c.js"), "a/b/c.js");
  assert.equal(sanitizeEntryPath("dir\\file.js"), "dir/file.js");
  // Hostile shapes: traversal, absolute, drive letters — all refused.
  assert.equal(sanitizeEntryPath("../evil.js"), null);
  assert.equal(sanitizeEntryPath("a/../../evil.js"), null);
  assert.equal(sanitizeEntryPath("a/../b.js"), null); // even balanced ".." is refused
  assert.equal(sanitizeEntryPath("/etc/passwd"), null);
  assert.equal(sanitizeEntryPath("C:\\Windows\\evil.dll"), null);
  assert.equal(sanitizeEntryPath(""), null);
});
