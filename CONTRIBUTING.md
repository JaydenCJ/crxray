# Contributing to crxray

Issues, discussions and pull requests are all welcome — this project
aims to stay small, zero-dependency at runtime, and honest about what
it can and cannot prove.

## Getting started

Requirements: Node.js >= 22.13 (for the stable `node:test` runner used by the suite).

```bash
git clone https://github.com/JaydenCJ/crxray.git
cd crxray
npm install            # installs typescript, the only devDependency
npm run build          # compile TypeScript to dist/
npm test               # build + 90 node:test tests
bash scripts/smoke.sh  # end-to-end CLI check against examples/
```

`scripts/smoke.sh` exercises the real CLI (format detection, scan exit
codes and the `--fail-on` gate, JSON output, safe unpack with zip-slip
refusal, deterministic re-runs, and the manifest/urls/id views) against
the bundled example fixtures and must print `SMOKE OK`.

## Before you open a pull request

1. `npx tsc -p tsconfig.json --noEmit` — the tree must type-check clean (strict mode is enforced).
2. `npm test` — all tests must pass.
3. `bash scripts/smoke.sh` — must print `SMOKE OK`.
4. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (the scanners take bytes and return findings — only `cli.ts`
   touches the filesystem or the process).
5. Changes to the rubric, permission grades or detector patterns are
   security-relevant: explain in the PR what new false positives or
   negatives they can cause, and update [docs/rubric.md](docs/rubric.md)
   when the scoring contract changes.

## Ground rules

- **No runtime dependencies.** The zero-dependency install is a core
  feature; adding one needs justification in the PR and will usually be
  declined. The ZIP, CRX, protobuf and CRC-32 readers are in-repo on
  purpose.
- No network calls, ever — crxray reads local bytes only, and a security
  auditor that phones home would defeat its own purpose.
- Determinism is API: same input bytes and same version, byte-identical
  score, level and finding order — no clocks, no randomness, no
  locale-dependent comparisons.
- Grade capability, not intent: a permission is scored by what it
  enables if the extension is compromised, never by the benign purpose
  the listing claims.
- New detector patterns must anchor on a structural token (a keyword, a
  URL scheme, a header shape), not an entropy guess — false positives
  waste the auditor's trust.
- Code comments and doc comments are written in English.

## Reporting bugs

Please include: `crxray --version` output, the exact command line, and a
*minimal* extension (or a hand-built fixture) that reproduces the
problem — a false negative the scanner missed, or a false positive it
raised. The `examples/build-suspicious-crx.mjs` generator is a good
template for a self-contained repro.

## Security

Do not open public issues for security problems (e.g. an evasion that
slips a real remote-code loader past every detector); use GitHub private
vulnerability reporting on this repository instead.
