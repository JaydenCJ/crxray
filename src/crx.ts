/**
 * Container detection and CRX header forensics.
 *
 * A CRX file is a signed wrapper around a ZIP: magic "Cr24", a format
 * version, a header, then the ZIP payload. Version 2 stores a raw RSA
 * public key + signature; version 3 stores a protobuf CrxFileHeader whose
 * signed_header_data carries the 16-byte crx_id — the same bytes Chrome
 * turns into the familiar 32-character a–p extension id. XPI files are
 * plain ZIPs (Firefox keeps its signature *inside*, at META-INF/).
 *
 * crxray reads the header for identity evidence; it does not verify
 * signatures (an explicit non-goal for an offline triage tool — the
 * README says so).
 */
import { createHash } from "node:crypto";

export class CrxError extends Error {}

/** What the container told us before the ZIP payload starts. */
export interface ContainerInfo {
  format: "crx2" | "crx3" | "zip";
  /** Byte offset where the ZIP payload begins. */
  zipOffset: number;
  /** 32-char a–p extension id declared by the container, when present. */
  crxId?: string;
  /** Number of signature proofs in a CRX3 header (not verified). */
  proofs?: { rsa: number; ecdsa: number };
}

const CRX_MAGIC = 0x34327243; // "Cr24" little-endian
const ZIP_MAGIC = 0x04034b50; // "PK\x03\x04"

/** Format Chrome's 16 raw id bytes as the a–p alphabet extension id. */
export function idFromCrxIdBytes(bytes: Bytes): string {
  let out = "";
  for (let i = 0; i < bytes.length && i < 16; i++) {
    const b = bytes[i] as number;
    out += String.fromCharCode(97 + (b >> 4)) + String.fromCharCode(97 + (b & 0x0f));
  }
  return out;
}

/** Derive the extension id from a DER SPKI public key (manifest "key"). */
export function idFromPublicKey(spki: Bytes): string {
  const digest = createHash("sha256").update(spki).digest();
  return idFromCrxIdBytes(digest.subarray(0, 16));
}

// --- Minimal protobuf wire-format walker (varints + length-delimited) ---

interface ProtoField {
  field: number;
  wire: number;
  /** Payload bytes for wire type 2; varint value for wire type 0. */
  bytes?: Bytes;
  varint?: number;
}

function readVarint(buf: Bytes, pos: number): { value: number; next: number } {
  let value = 0;
  let shift = 0;
  let next = pos;
  for (;;) {
    if (next >= buf.length) throw new CrxError("CRX3 header: truncated varint");
    const byte = buf[next++] as number;
    value += (byte & 0x7f) * 2 ** shift; // avoids 32-bit overflow for field 10000
    if ((byte & 0x80) === 0) return { value, next };
    shift += 7;
    if (shift > 35) throw new CrxError("CRX3 header: varint too long");
  }
}

/** Walk every top-level field of a protobuf message. */
function protoFields(buf: Bytes): ProtoField[] {
  const fields: ProtoField[] = [];
  let pos = 0;
  while (pos < buf.length) {
    const tag = readVarint(buf, pos);
    const field = Math.floor(tag.value / 8);
    const wire = tag.value % 8;
    pos = tag.next;
    if (wire === 0) {
      const v = readVarint(buf, pos);
      fields.push({ field, wire, varint: v.value });
      pos = v.next;
    } else if (wire === 2) {
      const len = readVarint(buf, pos);
      const end = len.next + len.value;
      if (end > buf.length) throw new CrxError("CRX3 header: length-delimited field overruns");
      fields.push({ field, wire, bytes: buf.subarray(len.next, end) });
      pos = end;
    } else if (wire === 5) {
      pos += 4;
    } else if (wire === 1) {
      pos += 8;
    } else {
      throw new CrxError(`CRX3 header: unsupported wire type ${wire}`);
    }
    if (pos > buf.length) throw new CrxError("CRX3 header: field overruns buffer");
  }
  return fields;
}

// CrxFileHeader field numbers (crx3.proto):
const F_PROOF_RSA = 2; //   repeated AsymmetricKeyProof sha256_with_rsa
const F_PROOF_ECDSA = 3; // repeated AsymmetricKeyProof sha256_with_ecdsa
const F_SIGNED_DATA = 10000; // bytes signed_header_data → SignedData{crx_id}

function parseCrx3Header(header: Bytes): { crxId?: string; proofs: { rsa: number; ecdsa: number } } {
  const proofs = { rsa: 0, ecdsa: 0 };
  let crxId: string | undefined;
  for (const f of protoFields(header)) {
    if (f.field === F_PROOF_RSA && f.wire === 2) proofs.rsa++;
    else if (f.field === F_PROOF_ECDSA && f.wire === 2) proofs.ecdsa++;
    else if (f.field === F_SIGNED_DATA && f.wire === 2 && f.bytes) {
      for (const inner of protoFields(f.bytes)) {
        if (inner.field === 1 && inner.wire === 2 && inner.bytes && inner.bytes.length === 16) {
          crxId = idFromCrxIdBytes(inner.bytes);
        }
      }
    }
  }
  return { crxId, proofs };
}

/**
 * Identify the container in `buf` and locate its ZIP payload.
 * Accepts CRX2, CRX3 and bare ZIP (which covers XPI). Throws CrxError on
 * anything else — including truncated or future-versioned CRX files.
 */
export function parseContainer(buf: Bytes): ContainerInfo {
  if (buf.length >= 4 && buf.readUInt32LE(0) === ZIP_MAGIC) {
    return { format: "zip", zipOffset: 0 };
  }
  if (buf.length < 16 || buf.readUInt32LE(0) !== CRX_MAGIC) {
    throw new CrxError("not a CRX, XPI or ZIP file (bad magic bytes)");
  }
  const version = buf.readUInt32LE(4);
  if (version === 2) {
    const keyLen = buf.readUInt32LE(8);
    const sigLen = buf.readUInt32LE(12);
    const zipOffset = 16 + keyLen + sigLen;
    if (zipOffset > buf.length) throw new CrxError("CRX2 header overruns the file");
    const publicKey = buf.subarray(16, 16 + keyLen);
    return { format: "crx2", zipOffset, crxId: idFromPublicKey(publicKey) };
  }
  if (version === 3) {
    const headerLen = buf.readUInt32LE(8);
    const zipOffset = 12 + headerLen;
    if (zipOffset > buf.length) throw new CrxError("CRX3 header overruns the file");
    const { crxId, proofs } = parseCrx3Header(buf.subarray(12, zipOffset));
    return { format: "crx3", zipOffset, crxId, proofs };
  }
  throw new CrxError(`unsupported CRX format version ${version}`);
}
