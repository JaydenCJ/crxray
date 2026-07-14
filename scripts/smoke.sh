#!/usr/bin/env bash
# Smoke test for crxray: exercises the real CLI end to end against the
# bundled example fixtures. No network, idempotent, runs from a clean
# checkout (after `npm install`). Prints "SMOKE OK" on success.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$(pwd)"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $1" >&2
  exit 1
}

# 1. Build (idempotent).
npm run build >/dev/null 2>&1 || fail "npm run build failed"
CLI="node $ROOT/dist/cli.js"
echo "[smoke] build ok"

# 2. --version matches package.json; --help documents every command.
PKG_VERSION="$(node -p "require('$ROOT/package.json').version")"
CLI_VERSION="$($CLI --version)"
[ "$CLI_VERSION" = "$PKG_VERSION" ] || fail "--version mismatch: $CLI_VERSION != $PKG_VERSION"
HELP="$($CLI --help)"
for word in scan unpack manifest urls id --fail-on --json; do
  echo "$HELP" | grep -q -- "$word" || fail "--help missing $word"
done
echo "[smoke] --help/--version ok ($CLI_VERSION)"

# 3. Error handling: bad flags and bad input exit 2.
set +e
$CLI scan examples/suspicious.crx --frobnicate >/dev/null 2>&1; [ $? -eq 2 ] || { set -e; fail "unknown flag should exit 2"; }
$CLI scan >/dev/null 2>&1; [ $? -eq 2 ] || { set -e; fail "missing input should exit 2"; }
$CLI scan does-not-exist.crx >/dev/null 2>&1; [ $? -eq 2 ] || { set -e; fail "missing file should exit 2"; }
printf 'MZ this is not a crx' > "$WORKDIR/bad.crx"
$CLI scan "$WORKDIR/bad.crx" >/dev/null 2>&1; [ $? -eq 2 ] || { set -e; fail "bad magic should exit 2"; }
set -e
echo "[smoke] error handling ok (exit 2)"

# 4. The clean example scores minimal and exits 0.
CLEAN="$($CLI scan examples/clean-notes)"
echo "$CLEAN" | grep -q "MINIMAL" || fail "clean example should grade MINIMAL"
echo "$CLEAN" | grep -q "none — nothing in the rubric fired" || fail "clean example should have no findings"
$CLI scan examples/clean-notes >/dev/null || fail "clean example should exit 0"
echo "[smoke] clean example ok (exit 0, minimal)"

# 5. The suspicious CRX trips every axis and exits 1 at the default gate.
set +e
DIRTY="$($CLI scan examples/suspicious.crx)"; DIRTY_EXIT=$?
set -e
[ "$DIRTY_EXIT" -eq 1 ] || fail "suspicious.crx should exit 1, got $DIRTY_EXIT"
echo "$DIRTY" | grep -q "CRITICAL" || fail "suspicious.crx should grade CRITICAL"
for rule in PERM_COMBO_COOKIES PERM_COMBO_INTERCEPT CSP_REMOTE_SCRIPT_SRC \
            RCL_IMPORTSCRIPTS_REMOTE RCL_EVAL OBF_OBFUSCATED \
            NET_RAW_IP NET_TRACKER PRIV_KEY_LISTENER ID_SELF_HOSTED_UPDATE; do
  echo "$DIRTY" | grep -q "$rule" || fail "scan output missing $rule"
done
echo "[smoke] suspicious scan ok (exit 1, every axis)"

# 6. --fail-on tunes the exit gate; a scan is deterministic.
# Note: scan exits 1 on findings, so `--json` captures use `--fail-on never`
# to keep the exit status 0 under `set -e`.
$CLI scan examples/suspicious.crx --fail-on never >/dev/null || fail "--fail-on never should exit 0"
set +e
$CLI scan examples/suspicious.crx --fail-on critical >/dev/null; [ $? -eq 1 ] || { set -e; fail "--fail-on critical should exit 1"; }
set -e
A="$($CLI scan examples/suspicious.crx --json --fail-on never)"
B="$($CLI scan examples/suspicious.crx --json --fail-on never)"
[ "$A" = "$B" ] || fail "scan --json is not deterministic"
echo "[smoke] --fail-on + determinism ok"

# 7. --json is valid and carries the identity, findings and risk score.
echo "$A" | node -e "
  const r = JSON.parse(require('fs').readFileSync(0, 'utf8'));
  if (r.package.format !== 'crx3') throw new Error('format');
  if (!r.identity.crxId) throw new Error('crx id');
  if (!(r.findings.length >= 15)) throw new Error('findings');
  if (r.risk.level !== 'critical') throw new Error('risk level');
  if (r.identity.proofs.rsa !== 1) throw new Error('proofs');
" || fail "scan --json is not structurally intact"
echo "[smoke] --json ok"

# 8. unpack extracts the payload safely and re-scanning the dir agrees.
$CLI unpack examples/suspicious.crx -o "$WORKDIR/unpacked" >/dev/null || fail "unpack failed"
[ -f "$WORKDIR/unpacked/manifest.json" ] || fail "unpack did not write manifest.json"
[ -f "$WORKDIR/unpacked/background.js" ] || fail "unpack did not write background.js"
$CLI scan "$WORKDIR/unpacked" --fail-on never | grep -q "CRITICAL" \
  || fail "re-scanning the unpacked directory disagrees"
echo "[smoke] unpack ok (payload extracted, re-scan agrees)"

# 9. unpack refuses zip-slip entries and never writes outside the target.
HOSTILE_ZIP="$WORKDIR/hostile.zip" node <<'EOF'
// Build a two-entry ZIP (stored, no compression) whose second entry tries
// to escape the extraction directory via "../".
const { writeFileSync } = require("node:fs");
const T = (() => { const t = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = (d) => { let c = 0xffffffff; for (const b of d) c = T[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n, 0); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0, 0); return b; };
const files = [
  ["manifest.json", '{"manifest_version":3,"name":"hostile","version":"1.0"}'],
  ["../evil.txt", "escaped"],
];
const locals = [], centrals = [];
let off = 0;
for (const [path, text] of files) {
  const data = Buffer.from(text), name = Buffer.from(path), c = crc32(data);
  const local = Buffer.concat([u32(0x04034b50), u16(20), u16(0x800), u16(0), u16(0), u16(0),
    u32(c), u32(data.length), u32(data.length), u16(name.length), u16(0), name, data]);
  centrals.push(Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(0x800), u16(0), u16(0), u16(0),
    u32(c), u32(data.length), u32(data.length), u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(off), name]));
  locals.push(local);
  off += local.length;
}
const cd = Buffer.concat(centrals);
const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(2), u16(2), u32(cd.length), u32(off), u16(0)]);
writeFileSync(process.env.HOSTILE_ZIP, Buffer.concat([...locals, cd, eocd]));
EOF
set +e
SLIP_ERR="$($CLI unpack "$WORKDIR/hostile.zip" -o "$WORKDIR/slip-out" 2>&1 >/dev/null)"; SLIP_EXIT=$?
set -e
[ "$SLIP_EXIT" -eq 1 ] || fail "zip-slip unpack should exit 1, got $SLIP_EXIT"
echo "$SLIP_ERR" | grep -q "refused unsafe entry path" || fail "zip-slip refusal not reported on stderr"
[ ! -e "$WORKDIR/evil.txt" ] || fail "zip-slip entry escaped the unpack directory"
[ -f "$WORKDIR/slip-out/manifest.json" ] || fail "safe entries should still be extracted"
echo "[smoke] zip-slip refusal ok (exit 1, nothing escaped)"

# 10. The example fixture rebuilds byte-for-byte (deterministic generator).
cp examples/suspicious.crx "$WORKDIR/committed.crx"
node examples/build-suspicious-crx.mjs >/dev/null || fail "fixture rebuild failed"
cmp -s "$WORKDIR/committed.crx" examples/suspicious.crx || fail "fixture generator is not deterministic"
echo "[smoke] fixture rebuild ok (byte-identical)"

# 11. manifest / urls / id subcommands each produce their view.
$CLI manifest examples/suspicious.crx | grep -q "cookies" || fail "manifest view missing permission grades"
$CLI urls examples/suspicious.crx | grep -q "tracker:analytics" || fail "urls view missing tracker classification"
$CLI id examples/suspicious.crx | grep -q "not verified" || fail "id view missing signature honesty note"
echo "[smoke] manifest/urls/id views ok"

echo "SMOKE OK"
