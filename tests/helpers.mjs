// Shared test helpers: a deterministic ZIP writer, CRX2/CRX3 wrappers, an
// extension factory, temp dirs with cleanup, and a runner for the built
// CLI. Everything is deterministic — fixed archive timestamps, fixed key
// bytes, fresh mkdtemp directories, no network, no clocks.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "dist", "cli.js");

// --- CRC-32 (independent implementation, so src/zip.ts is cross-checked) ---

const CRC_TABLE = (() => {
  const t = new Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// --- ZIP writer ---

const FIXED_DOS_TIME = 0x6000; // 12:00:00
const FIXED_DOS_DATE = 0x5ceb; // a fixed, valid DOS date

function u16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n >>> 0, 0);
  return b;
}

function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}

/**
 * Build a ZIP archive. `files` is an array of
 *   { path, data, method (0|8, default 8), corruptCrc (default false) }
 * with `data` a string or Buffer. Paths are stored verbatim, so hostile
 * names like "../evil.js" can be produced on purpose.
 */
export function buildZip(files, { comment = "" } = {}) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const f of files) {
    const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data ?? "", "utf8");
    const method = f.method ?? 8;
    const compressed = method === 8 ? deflateRawSync(data) : data;
    const name = Buffer.from(f.path, "utf8");
    let crc = crc32(data);
    if (f.corruptCrc) crc = (crc ^ 0xdeadbeef) >>> 0;
    const local = Buffer.concat([
      u32(0x04034b50),
      u16(20), // version needed
      u16(0x800), // flags: UTF-8 names
      u16(method),
      u16(FIXED_DOS_TIME),
      u16(FIXED_DOS_DATE),
      u32(crc),
      u32(compressed.length),
      u32(data.length),
      u16(name.length),
      u16(0), // extra length
      name,
      compressed,
    ]);
    const central = Buffer.concat([
      u32(0x02014b50),
      u16(20), // version made by
      u16(20), // version needed
      u16(0x800),
      u16(method),
      u16(FIXED_DOS_TIME),
      u16(FIXED_DOS_DATE),
      u32(crc),
      u32(compressed.length),
      u32(data.length),
      u16(name.length),
      u16(0), // extra
      u16(0), // comment
      u16(0), // disk
      u16(0), // internal attrs
      u32(0), // external attrs
      u32(offset),
      name,
    ]);
    locals.push(local);
    centrals.push(central);
    offset += local.length;
  }
  const centralBuf = Buffer.concat(centrals);
  const commentBuf = Buffer.from(comment, "utf8");
  const eocd = Buffer.concat([
    u32(0x06054b50),
    u16(0),
    u16(0),
    u16(files.length),
    u16(files.length),
    u32(centralBuf.length),
    u32(offset),
    u16(commentBuf.length),
    commentBuf,
  ]);
  return Buffer.concat([...locals, centralBuf, eocd]);
}

// --- protobuf encoding (for CRX3 headers) ---

function varint(n) {
  const bytes = [];
  let v = n;
  do {
    let byte = v & 0x7f;
    v = Math.floor(v / 128);
    if (v > 0) byte |= 0x80;
    bytes.push(byte);
  } while (v > 0);
  return Buffer.from(bytes);
}

function lenField(fieldNo, payload) {
  return Buffer.concat([varint(fieldNo * 8 + 2), varint(payload.length), payload]);
}

/** Deterministic fake key/signature bytes for CRX proofs. */
export const FAKE_KEY = Buffer.alloc(64).fill(0x42);
const FAKE_SIG = Buffer.alloc(64).fill(0x24);

/** 16 fixed id bytes; expected a–p id below must match idFromCrxIdBytes. */
export const CRX_ID_BYTES = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
export const CRX_ID_STRING = "aaabacadaeafagahaiajakalamanaoap";

/**
 * Wrap a ZIP payload in a CRX3 container: magic, version 3, header
 * length, protobuf CrxFileHeader with `rsaProofs` sha256_with_rsa proofs
 * and a SignedData carrying `idBytes` (default CRX_ID_BYTES).
 */
export function wrapCrx3(zipBuf, { idBytes = CRX_ID_BYTES, rsaProofs = 1, ecdsaProofs = 0 } = {}) {
  const proof = Buffer.concat([lenField(1, FAKE_KEY), lenField(2, FAKE_SIG)]);
  const parts = [];
  for (let i = 0; i < rsaProofs; i++) parts.push(lenField(2, proof));
  for (let i = 0; i < ecdsaProofs; i++) parts.push(lenField(3, proof));
  if (idBytes !== null) parts.push(lenField(10000, lenField(1, idBytes)));
  const header = Buffer.concat(parts);
  return Buffer.concat([
    Buffer.from("Cr24", "latin1"),
    u32(3),
    u32(header.length),
    header,
    zipBuf,
  ]);
}

/** Wrap a ZIP payload in a legacy CRX2 container with `key` as public key. */
export function wrapCrx2(zipBuf, { key = FAKE_KEY } = {}) {
  return Buffer.concat([
    Buffer.from("Cr24", "latin1"),
    u32(2),
    u32(key.length),
    u32(FAKE_SIG.length),
    key,
    FAKE_SIG,
    zipBuf,
  ]);
}

// --- extension factory ---

/** A minimal, clean MV3 manifest; spread overrides on top. */
export function makeManifest(overrides = {}) {
  return {
    manifest_version: 3,
    name: "Fixture Extension",
    version: "1.0.0",
    ...overrides,
  };
}

/**
 * Build a packed extension ZIP from { path: content } where objects are
 * JSON-stringified and strings/Buffers stored as-is.
 */
export function buildExtensionZip(files) {
  const list = Object.entries(files).map(([path, content]) => ({
    path,
    data:
      typeof content === "string" || Buffer.isBuffer(content)
        ? content
        : JSON.stringify(content, null, 2),
  }));
  return buildZip(list);
}

// --- temp dirs and CLI runner ---

/** Create a temp dir with the given files (subdirs allowed in names). */
export function makeDir(files = {}) {
  const dir = mkdtempSync(join(tmpdir(), "crxray-test-"));
  for (const [name, content] of Object.entries(files)) {
    const target = join(dir, ...name.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    const data =
      typeof content === "string" || Buffer.isBuffer(content)
        ? content
        : JSON.stringify(content, null, 2);
    writeFileSync(target, data);
  }
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/**
 * Run the built CLI synchronously. Returns { status, stdout, stderr }.
 * Pass `cwd` to control relative paths.
 */
export function runCli(args, { cwd } = {}) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    cwd: cwd ?? ROOT,
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}
