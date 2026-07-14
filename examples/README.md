# crxray examples

Two fixtures, one clean and one hostile, to try every command against. All
commands below run from the repository root after `npm install && npm run
build`; replace `node dist/cli.js` with `crxray` if you installed the
package globally.

## Files

- `clean-notes/` — an unpacked, honest MV3 extension: a toolbar note pad
  that uses only `storage`, has no host permissions, no content scripts and
  no dynamic code. `crxray scan examples/clean-notes` reports **zero
  findings** and grades `minimal`. This is the shape a clean audit takes.
- `suspicious.crx` — a packed CRX3 that is deliberately hostile (but inert:
  every endpoint is an RFC-5737 documentation IP or an `.example`/`.test`
  host, and every "secret" is fake). It trips a rule on every axis:
  broad-host + cookie + intercept permission combos, a self-hosted update
  server, a CSP that whitelists a remote script origin, `importScripts()`
  from a remote URL, a remote `<script>` in a page, an `eval(atob(...))`,
  hex-identifier obfuscation, a keystroke listener in a content script, a
  hardcoded-IP beacon, an analytics endpoint and a punycode host.
- `build-suspicious-crx.mjs` — the deterministic generator for
  `suspicious.crx`. Self-contained (no build step, no dependencies); run
  `node examples/build-suspicious-crx.mjs` to rebuild the fixture
  byte-for-byte.

## Audit the hostile package

```bash
node dist/cli.js scan examples/suspicious.crx          # table, exit 1
node dist/cli.js scan examples/suspicious.crx --json    # machine-readable
```

The exit code is `1` because the risk level (`critical`) is at or above the
default `--fail-on high` gate — wire that straight into CI.

## Confirm the clean package is clean

```bash
node dist/cli.js scan examples/clean-notes             # MINIMAL, exit 0
```

## Look at just one axis

```bash
node dist/cli.js manifest examples/suspicious.crx      # graded permission table
node dist/cli.js urls examples/suspicious.crx          # every endpoint, classified
node dist/cli.js id examples/suspicious.crx            # crx id, sha256, signatures
```

## Unpack the payload safely

```bash
node dist/cli.js unpack examples/suspicious.crx -o /tmp/coupon-helper
node dist/cli.js scan /tmp/coupon-helper               # re-scan the extracted dir
```

`unpack` refuses any archive entry whose path escapes the destination
(zip-slip), so extracting an untrusted CRX can never write outside the
target directory.
