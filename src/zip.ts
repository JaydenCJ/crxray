/**
 * Minimal, dependency-free ZIP reader. Reads the central directory (the
 * authoritative index — local headers can lie when bit 3 "data descriptor"
 * is set), decompresses stored and deflated entries via node:zlib, and
 * verifies CRC-32 so tampered payloads are surfaced instead of trusted.
 *
 * Scope: classic ZIP only. ZIP64 archives are rejected with a clear error;
 * browser stores do not produce them for extensions.
 */
import { inflateRawSync } from "node:zlib";

const EOCD_SIG = 0x06054b50;
const CEN_SIG = 0x02014b50;
const LOC_SIG = 0x04034b50;
/** EOCD is 22 bytes + up to 65535 bytes of archive comment. */
const EOCD_SEARCH_MAX = 22 + 0xffff;

export class ZipError extends Error {}

/** One central-directory record; `data` is materialized by readEntry(). */
export interface ZipEntry {
  /** Entry name as stored (UTF-8 when flagged, latin1 otherwise). */
  path: string;
  method: number;
  flags: number;
  crc32: number;
  compressedSize: number;
  size: number;
  headerOffset: number;
  isDirectory: boolean;
}

/** Locate the End Of Central Directory record, scanning back over a comment. */
function findEocd(buf: Bytes): number {
  const from = Math.max(0, buf.length - EOCD_SEARCH_MAX);
  for (let i = buf.length - 22; i >= from; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  throw new ZipError("not a ZIP archive: end-of-central-directory record not found");
}

/**
 * List all central-directory entries of the archive in `buf`.
 *
 * Tolerates archives whose internal offsets assume a stripped prefix
 * (common when a ZIP is re-wrapped into a container): if the central
 * directory is not where the EOCD says, the shift between the actual and
 * declared position is applied to every entry offset.
 */
export function listEntries(buf: Bytes): ZipEntry[] {
  const eocd = findEocd(buf);
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  let cdOffset = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdOffset === 0xffffffff) {
    throw new ZipError("ZIP64 archives are not supported");
  }
  let shift = 0;
  if (cdOffset + 4 > buf.length || buf.readUInt32LE(cdOffset) !== CEN_SIG) {
    // The directory really starts cdSize bytes before the EOCD.
    const actual = eocd - cdSize;
    if (actual < 0 || buf.readUInt32LE(actual) !== CEN_SIG) {
      throw new ZipError("central directory not found where the EOCD points");
    }
    shift = actual - cdOffset;
    cdOffset = actual;
  }

  const entries: ZipEntry[] = [];
  let pos = cdOffset;
  for (let i = 0; i < count; i++) {
    if (pos + 46 > buf.length || buf.readUInt32LE(pos) !== CEN_SIG) {
      throw new ZipError(`central directory truncated at entry ${i} of ${count}`);
    }
    const flags = buf.readUInt16LE(pos + 8);
    const method = buf.readUInt16LE(pos + 10);
    const crc32 = buf.readUInt32LE(pos + 16);
    const compressedSize = buf.readUInt32LE(pos + 20);
    const size = buf.readUInt32LE(pos + 24);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const headerOffset = buf.readUInt32LE(pos + 42) + shift;
    const nameBytes = buf.subarray(pos + 46, pos + 46 + nameLen);
    // Bit 11 marks UTF-8 names; everything else is treated as latin1.
    const path = nameBytes.toString((flags & 0x800) !== 0 ? "utf8" : "latin1");
    entries.push({
      path,
      method,
      flags,
      crc32,
      compressedSize,
      size,
      headerOffset,
      isDirectory: path.endsWith("/"),
    });
    pos += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/**
 * Decompress one entry. Sizes come from the central directory, so entries
 * written with streaming data descriptors (zeroed local sizes) still read
 * correctly. Returns the bytes plus whether the stored CRC-32 matched.
 */
export function readEntry(buf: Bytes, entry: ZipEntry): { data: Bytes; crcOk: boolean } {
  const off = entry.headerOffset;
  if (off + 30 > buf.length || buf.readUInt32LE(off) !== LOC_SIG) {
    throw new ZipError(`local header missing for "${entry.path}"`);
  }
  // The local header's own name/extra lengths decide where data starts.
  const nameLen = buf.readUInt16LE(off + 26);
  const extraLen = buf.readUInt16LE(off + 28);
  const dataStart = off + 30 + nameLen + extraLen;
  const raw = buf.subarray(dataStart, dataStart + entry.compressedSize);
  if (raw.length < entry.compressedSize) {
    throw new ZipError(`entry "${entry.path}" is truncated`);
  }
  let data: Bytes;
  if (entry.method === 0) {
    data = raw;
  } else if (entry.method === 8) {
    try {
      data = inflateRawSync(raw);
    } catch {
      throw new ZipError(`entry "${entry.path}" has a corrupt deflate stream`);
    }
  } else {
    throw new ZipError(`entry "${entry.path}" uses unsupported compression method ${entry.method}`);
  }
  return { data, crcOk: crc32(data) === entry.crc32 };
}

/**
 * Normalize an entry path for extraction, or return null when the path is
 * unsafe (absolute, drive-letter, or escaping via ".."). This is the
 * zip-slip guard: unpack refuses these, scan reports them.
 */
export function sanitizeEntryPath(path: string): string | null {
  const unified = path.replace(/\\/g, "/");
  if (unified.startsWith("/") || /^[a-zA-Z]:/.test(unified)) return null;
  const out: string[] = [];
  for (const part of unified.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") return null; // never allow climbing out, even if balanced
    out.push(part);
  }
  return out.length === 0 ? null : out.join("/");
}

// --- CRC-32 (IEEE 802.3 polynomial, table-driven) ---

const CRC_TABLE: number[] = (() => {
  const table = new Array<number>(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

/** CRC-32 of a byte buffer, as an unsigned 32-bit integer. */
export function crc32(data: Bytes): number {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    c = (CRC_TABLE[(c ^ (data[i] as number)) & 0xff] as number) ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}
