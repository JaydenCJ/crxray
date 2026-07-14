// CRX container forensics: format detection, ZIP payload location,
// protobuf header parsing and extension-id derivation for both CRX
// generations. Fixtures are built byte-by-byte in helpers.mjs.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { parseContainer, idFromCrxIdBytes, idFromPublicKey, CrxError } from "../dist/crx.js";
import { listEntries } from "../dist/zip.js";
import { buildZip, wrapCrx2, wrapCrx3, CRX_ID_BYTES, CRX_ID_STRING, FAKE_KEY } from "./helpers.mjs";

const ZIP = buildZip([{ path: "manifest.json", data: "{}" }]);

test("a bare ZIP (which is what an XPI is) parses with zipOffset 0", () => {
  const info = parseContainer(ZIP);
  assert.equal(info.format, "zip");
  assert.equal(info.zipOffset, 0);
  assert.equal(info.crxId, undefined);
});

test("CRX3: payload located, format detected, entries readable", () => {
  const crx = wrapCrx3(ZIP);
  const info = parseContainer(crx);
  assert.equal(info.format, "crx3");
  assert.ok(info.zipOffset > 12);
  const entries = listEntries(crx.subarray(info.zipOffset));
  assert.equal(entries[0].path, "manifest.json");
});

test("CRX3: crx_id inside signed_header_data becomes the a-p extension id", () => {
  const info = parseContainer(wrapCrx3(ZIP));
  assert.equal(info.crxId, CRX_ID_STRING);
  // The nibble → a-p mapping itself, on known bytes.
  assert.equal(idFromCrxIdBytes(CRX_ID_BYTES), CRX_ID_STRING);
  assert.equal(idFromCrxIdBytes(Buffer.from([0xff, 0x00])), "ppaa");
});

test("CRX3: RSA and ECDSA proof counts are reported (never verified)", () => {
  const info = parseContainer(wrapCrx3(ZIP, { rsaProofs: 2, ecdsaProofs: 1 }));
  assert.deepEqual(info.proofs, { rsa: 2, ecdsa: 1 });
});

test("CRX3 without signed header data has no declared id", () => {
  const info = parseContainer(wrapCrx3(ZIP, { idBytes: null }));
  assert.equal(info.crxId, undefined);
  assert.deepEqual(info.proofs, { rsa: 1, ecdsa: 0 });
});

test("CRX2: id is derived by hashing the embedded public key", () => {
  const crx = wrapCrx2(ZIP);
  const info = parseContainer(crx);
  assert.equal(info.format, "crx2");
  const digest = createHash("sha256").update(FAKE_KEY).digest();
  assert.equal(info.crxId, idFromCrxIdBytes(digest.subarray(0, 16)));
  assert.equal(info.crxId, idFromPublicKey(FAKE_KEY));
  const entries = listEntries(crx.subarray(info.zipOffset));
  assert.equal(entries[0].path, "manifest.json");
});

test("bad magic, future versions and truncated headers raise CrxError", () => {
  assert.throws(() => parseContainer(Buffer.from("MZ\x90\x00 definitely not a crx")), CrxError);
  const v4 = Buffer.from(wrapCrx3(ZIP));
  v4.writeUInt32LE(4, 4);
  assert.throws(() => parseContainer(v4), /unsupported CRX format version 4/);
  const truncated = Buffer.from(wrapCrx3(ZIP).subarray(0, 14));
  assert.throws(() => parseContainer(truncated), CrxError);
  const overrun = Buffer.from(wrapCrx3(ZIP));
  overrun.writeUInt32LE(0x7fffffff, 8); // header length beyond the file
  assert.throws(() => parseContainer(overrun), /overruns/);
});
